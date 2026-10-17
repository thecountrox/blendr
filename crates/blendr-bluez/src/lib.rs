//! Blendr Linux BLE transport adapter built on BlueZ via `bluer`.
//!
//! Implements the shared [`blendr_transport`] contract over real BlueZ D-Bus
//! operations: `LEAdvertisingManager1` advertisements carrying only the fixed
//! service UUID (plus a transient token only when it fits the 31-byte legacy
//! payload), application-filtered LE scanning with peer aging and opaque locators,
//! and a GATT server/client pair where RX (write-IO) and TX (notify-IO)
//! streams are paired per remote device address through
//! `characteristic_control` events. Framing, reassembly bounds, and sequence
//! checks live in [`FramedLink`].
//!
//! Deterministic connection election: the side with the numerically smaller
//! adapter address initiates; both nodes compute the same outcome from the
//! two addresses, so simultaneous dual connections collapse to one link
//! without a handshake.
//!
//! Hardware addresses never appear in locators, log messages, or errors.
//! The adapter never powers the controller on or reconfigures unrelated
//! BlueZ state; an unpowered adapter fails explicitly.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bluer::adv::{Advertisement, AdvertisementHandle};
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicWrite, CharacteristicWriteMethod, ReqError, Service, characteristic_control,
};
use bluer::gatt::{CharacteristicReader, CharacteristicWriter};
use bluer::{
    Adapter, AdapterEvent, Address, Device, DeviceEvent, DeviceProperty, DiscoveryFilter,
    DiscoveryTransport, Session,
};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use uuid::Uuid;

mod discovery;

use discovery::SeenQueue;

use blendr_transport::{
    BleTransport, FramedLink, LinkConfig, LinkRole, PacketIo, PeerEvent, PeerLink, PeerLocator,
    Result, TransportError,
};

/// Maximum bytes of a classic (non-extended) BLE advertising payload.
const LEGACY_ADV_MAX: usize = 31;
/// Bound on peer events queued for `watch_peers` consumers.
const PEER_EVENT_QUEUE: usize = 64;
/// Bound on inbound links queued for `accept_links` consumers.
const LINK_QUEUE: usize = 16;
/// Bound on unpaired GATT IO halves held per transport.
const PENDING_HALVES_MAX: usize = 8;
/// How long a lone GATT IO half waits for its counterpart before the peer's
/// link is disconnected.
const PAIR_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound for the peer-aging sweeper tick.
const SWEEP_MAX: Duration = Duration::from_secs(30);

/// Maximum concurrent per-device property evaluations during a scan cycle.
const SEEN_EVAL_CONCURRENCY: usize = 4;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Transport-relevant settings parsed out of [`blendr_config::Config`].
///
/// `transport.ble.adapter` and `discovery.enabled` are private fields in the
/// config schema, so they are read through `serde_json::to_value` per the
/// established pattern.
#[derive(Debug, Clone)]
struct Settings {
    adapter_name: String,
    service_uuid: Uuid,
    rx_char_uuid: Uuid,
    tx_char_uuid: Uuid,
    preferred_mtu: usize,
    max_frame_bytes: usize,
    reassembly_timeout: Duration,
    connection_timeout: Duration,
    max_links: usize,
    connect_retry_attempts: u32,
    connect_retry_backoff: Duration,
    discovery_enabled: bool,
    advertise_enabled: bool,
    scan_enabled: bool,
    scan_service_uuid: Uuid,
    scan_window: Duration,
    scan_interval: Duration,
    peer_stale_after: Duration,
}

fn parse_uuid(field: &str, value: &str) -> Result<Uuid> {
    value
        .parse::<Uuid>()
        .map_err(|e| TransportError::Platform(format!("invalid {field} `{value}`: {e}")))
}

fn get_bool(value: &serde_json::Value, ptr: &str, default: bool) -> bool {
    value
        .pointer(ptr)
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

impl Settings {
    fn from_config(config: &blendr_config::Config) -> Result<Self> {
        let value = serde_json::to_value(config).map_err(|e| {
            TransportError::Platform(format!("cannot serialize config for BLE settings: {e}"))
        })?;
        let adapter_name = value
            .pointer("/transport/ble/adapter")
            .and_then(|v| v.as_str())
            .unwrap_or("auto")
            .to_string();

        let ble = &config.transport.ble;
        let disc = &config.discovery;

        let scan_window = Duration::from_millis(disc.scan_window_ms);
        Ok(Self {
            adapter_name,
            service_uuid: parse_uuid("transport.ble.gatt_service_uuid", &ble.gatt_service_uuid)?,
            rx_char_uuid: parse_uuid(
                "transport.ble.gatt_rx_characteristic_uuid",
                &ble.gatt_rx_characteristic_uuid,
            )?,
            tx_char_uuid: parse_uuid(
                "transport.ble.gatt_tx_characteristic_uuid",
                &ble.gatt_tx_characteristic_uuid,
            )?,
            preferred_mtu: ble.preferred_mtu as usize,
            max_frame_bytes: ble.max_frame_payload_bytes as usize,
            reassembly_timeout: Duration::from_millis(ble.reassembly_timeout_ms),
            connection_timeout: Duration::from_millis(ble.connection_timeout_ms),
            max_links: ble.max_concurrent_links as usize,
            connect_retry_attempts: ble.connect_retry_attempts as u32,
            connect_retry_backoff: Duration::from_millis(ble.connect_retry_backoff_ms),
            discovery_enabled: get_bool(&value, "/discovery/enabled", true),
            advertise_enabled: disc.advertise,
            scan_enabled: disc.scan,
            scan_service_uuid: parse_uuid("discovery.service_uuid", &disc.service_uuid)?,
            scan_window,
            scan_interval: Duration::from_millis(disc.scan_interval_ms)
                .max(scan_window + Duration::from_millis(200)),
            peer_stale_after: Duration::from_secs(disc.peer_stale_after_seconds),
        })
    }
}

// ---------------------------------------------------------------------------
// Error helpers — scrub hardware addresses before errors reach logs/callers
// ---------------------------------------------------------------------------

/// Replace Bluetooth addresses (colon- or underscore-separated hex quads,
/// including `dev_XX_…` D-Bus object-path suffixes) with `<addr>`.
fn scrub_addrs(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let is_addr = |j: usize, sep: char| {
            j + 16 < chars.len()
                && (0..6).all(|k| {
                    chars[j + 3 * k].is_ascii_hexdigit()
                        && chars[j + 3 * k + 1].is_ascii_hexdigit()
                        && (k == 5 || chars[j + 3 * k + 2] == sep)
                })
        };
        if is_addr(i, ':') || is_addr(i, '_') {
            out.push_str("<addr>");
            i += 17;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn platform<E: fmt::Display>(context: &'static str) -> impl FnOnce(E) -> TransportError {
    move |e| TransportError::Platform(format!("{context}: {}", scrub_addrs(&e.to_string())))
}

fn disconnected_io(context: &'static str) -> impl FnOnce(std::io::Error) -> TransportError {
    move |e| match e.kind() {
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::UnexpectedEof => TransportError::Disconnected,
        _ => TransportError::Platform(format!("{context}: {}", scrub_addrs(&e.to_string()))),
    }
}

/// Run `fut` bounded by link-level cancellation and `timeout`.
async fn with_cancel_timeout<F, T>(
    cancel: &CancellationToken,
    timeout: Duration,
    context: &'static str,
    fut: F,
) -> Result<T>
where
    F: Future<Output = std::result::Result<T, bluer::Error>>,
{
    log::debug!("blendr-bluez: {context} start");
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(TransportError::Cancelled),
        _ = tokio::time::sleep(timeout) => Err(TransportError::Timeout),
        res = fut => res.map_err(platform(context)),
    };
    match &result {
        Ok(_) => log::debug!("blendr-bluez: {context} complete"),
        Err(e) => log::debug!("blendr-bluez: {context} failed: {e}"),
    }
    result
}

// ---------------------------------------------------------------------------
// Peer tracking, link election, GATT IO pairing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PeerEntry {
    locator: PeerLocator,
    last_seen: Instant,
}

/// One half of a GATT IO pair arriving via `characteristic_control` events.
enum InboundHalf {
    /// Peer acquired write-IO on our RX characteristic: our packet reader.
    Reader(CharacteristicReader),
    /// Peer started notify-IO on our TX characteristic: our packet writer.
    Writer(CharacteristicWriter),
}

struct PendingHalf {
    half: InboundHalf,
    device: Device,
    deadline: Instant,
}

/// Book-keeping for one live link toward a remote device.
struct LinkRecord {
    /// Strong ref held by the live link; `strong_count()==0` once it drops.
    token: Weak<()>,
    /// Hard-kill switch wired into the link's packet IO (election loser).
    kill: CancellationToken,
    role: LinkRole,
    device: Device,
}

#[derive(Default)]
struct Links {
    /// Live links (either direction) keyed by remote device address.
    active: HashMap<Address, LinkRecord>,
    /// `connect()` calls currently dialing a remote device.
    outbound_inflight: HashSet<Address>,
    /// Peers whose elected link is waiting for Device1.Disconnect.
    closing: HashSet<Address>,
}

impl Links {
    fn prune(&mut self) {
        self.active.retain(|_, rec| rec.token.strong_count() > 0);
    }

    fn live_count(&mut self) -> usize {
        self.prune();
        self.active.len()
    }

    /// Deterministic election: `true` when this node must initiate toward
    /// `remote` — the node with the numerically smaller adapter address wins.
    fn initiator_is_us(local: Address, remote: Address) -> bool {
        local < remote
    }
}

// ---------------------------------------------------------------------------
// PacketIo over a pair of GATT IO streams
// ---------------------------------------------------------------------------

// BlueZ may retain acquired server sockets across an ACL reconnect. Socket EOF
// alone therefore cannot delimit a PeerLink's physical connection lifetime.
struct ConnectedDevice {
    device: Device,
    watch: DropGuard,
}

impl ConnectedDevice {
    async fn new(device: Device, cancel: &CancellationToken, timeout: Duration) -> Result<Self> {
        let events =
            with_cancel_timeout(cancel, timeout, "watch connection", device.events()).await?;
        if !with_cancel_timeout(cancel, timeout, "connection state", device.is_connected()).await? {
            return Err(TransportError::Disconnected);
        }
        let kill = CancellationToken::new();
        let watch = kill.clone().drop_guard();
        tokio::spawn(async move {
            tokio::pin!(events);
            loop {
                tokio::select! {
                    biased;
                    _ = kill.cancelled() => break,
                    event = events.next() => match event {
                        None | Some(DeviceEvent::PropertyChanged(DeviceProperty::Connected(false))) => {
                            kill.cancel();
                            break;
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok(Self { device, watch })
    }
}

/// One packet per GATT write (peer→us) or notification (us→peer).
///
/// `bluer`'s IO sockets preserve ATT packet boundaries, so `send`/`recv` map
/// directly onto `PacketIo`; segmentation and reassembly belong to
/// [`FramedLink`].
struct GattPacketIo {
    reader: CharacteristicReader,
    writer: CharacteristicWriter,
    mtu: usize,
    kill: CancellationToken,
}

impl Drop for GattPacketIo {
    fn drop(&mut self) {
        self.kill.cancel();
    }
}

impl GattPacketIo {
    fn check_kill(&self) -> Result<()> {
        if self.kill.is_cancelled() {
            Err(TransportError::Disconnected)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl PacketIo for GattPacketIo {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn send_packet(&mut self, packet: &[u8], cancel: &CancellationToken) -> Result<()> {
        self.check_kill()?;
        if packet.len() > self.mtu {
            return Err(TransportError::InvalidFrame(format!(
                "packet of {} bytes exceeds link MTU {}",
                packet.len(),
                self.mtu
            )));
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(TransportError::Cancelled),
            _ = self.kill.cancelled() => Err(TransportError::Disconnected),
            res = self.writer.send(packet) => res.map_err(disconnected_io("gatt send")),
        }
    }

    async fn recv_packet(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        self.check_kill()?;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(TransportError::Cancelled),
            _ = self.kill.cancelled() => Err(TransportError::Disconnected),
            res = self.reader.recv() => {
                let pkt = res.map_err(disconnected_io("gatt recv"))?;
                if pkt.is_empty() {
                    Err(TransportError::Disconnected)
                } else {
                    Ok(pkt)
                }
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.kill.cancel();
        // Only the elected initiator disconnects the shared ACL. A competing
        // responder teardown could abort the next connection or another profile.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PeerLink wrapper with link-table cleanup on close/drop
// ---------------------------------------------------------------------------

struct GuardedLink {
    inner: FramedLink<GattPacketIo>,
    token: Arc<()>,
    owner: Weak<Inner>,
    addr: Address,
    finished: bool,
}

/// Keep the peer unavailable for a new link until disconnect completes.
struct ClosingLink {
    owner: Arc<Inner>,
    addr: Address,
    device: Device,
}

impl ClosingLink {
    async fn disconnect(&self) -> Result<()> {
        tokio::time::timeout(
            self.owner.settings.connection_timeout,
            self.device.disconnect(),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(platform("close elected link"))
    }
}

impl Drop for ClosingLink {
    fn drop(&mut self) {
        self.owner
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closing
            .remove(&self.addr);
        self.owner.closing_done.notify_waiters();
    }
}

impl GuardedLink {
    fn finish(&mut self) -> Option<ClosingLink> {
        if self.finished {
            return None;
        }
        self.finished = true;
        let owner = self.owner.upgrade()?;
        let device = {
            let mut links = owner.links.lock().unwrap_or_else(|e| e.into_inner());
            // An election loser must neither remove nor disconnect its winner.
            if !links
                .active
                .get(&self.addr)
                .is_some_and(|rec| rec.token.as_ptr() == Arc::as_ptr(&self.token))
            {
                return None;
            }
            let record = links.active.remove(&self.addr)?;
            if record.role != LinkRole::Initiator {
                return None;
            }
            links.closing.insert(self.addr);
            record.device
        };
        Some(ClosingLink {
            owner,
            addr: self.addr,
            device,
        })
    }
}

impl Drop for GuardedLink {
    fn drop(&mut self) {
        if let Some(closing) = self.finish() {
            tokio::spawn(async move {
                let _ = closing.disconnect().await;
            });
        }
    }
}

#[async_trait]
impl PeerLink for GuardedLink {
    fn locator(&self) -> &PeerLocator {
        self.inner.locator()
    }

    fn role(&self) -> LinkRole {
        self.inner.role()
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }

    async fn send_frame(&mut self, frame: &[u8], cancel: &CancellationToken) -> Result<()> {
        self.inner.send_frame(frame, cancel).await
    }

    async fn recv_frame(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        self.inner.recv_frame(cancel).await
    }

    async fn close(&mut self) -> Result<()> {
        let res = self.inner.close().await;
        let disconnected = if let Some(closing) = self.finish() {
            // Keep cleanup alive, and the peer reserved, if the caller cancels
            // close while BlueZ is still disconnecting the shared ACL.
            tokio::spawn(async move { closing.disconnect().await })
                .await
                .map_err(|_| TransportError::Platform("link cleanup task failed".into()))?
        } else {
            Ok(())
        };
        res.and(disconnected)
    }
}

// ---------------------------------------------------------------------------
// BluezTransport
// ---------------------------------------------------------------------------

/// Linux BLE transport backed by BlueZ.
///
/// Create with [`BluezTransport::new`]; it opens the D-Bus session, selects
/// the configured adapter, registers the GATT application, and spawns the
/// bounded background tasks (accept pairing, scan scheduler, peer sweeper).
/// Call [`BluezTransport::shutdown`] for ordered teardown; `Drop` performs
/// best-effort cleanup as well.
pub struct BluezTransport {
    inner: Arc<Inner>,
}

struct Inner {
    /// D-Bus session; held so registrations stay alive. Never read directly.
    _session: Session,
    adapter: Adapter,
    settings: Settings,
    /// Own adapter address; used only for election, never logged.
    local_addr: Address,
    app_handle: Mutex<Option<ApplicationHandle>>,
    adv_handle: Mutex<Option<AdvertisementHandle>>,
    peers: Mutex<HashMap<Address, PeerEntry>>,
    links: Mutex<Links>,
    closing_done: Notify,
    peer_tx: mpsc::Sender<PeerEvent>,
    peer_rx: AsyncMutex<Option<mpsc::Receiver<PeerEvent>>>,
    link_tx: mpsc::Sender<Box<dyn PeerLink>>,
    link_rx: AsyncMutex<Option<mpsc::Receiver<Box<dyn PeerLink>>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown_token: CancellationToken,
    shutdown_flag: AtomicBool,
}

impl BluezTransport {
    /// Open the BlueZ session, resolve the configured adapter (`auto` picks
    /// the default), verify it is powered, and register the Blendr GATT
    /// application. No advertising or scanning starts until requested.
    pub async fn new(config: &blendr_config::Config) -> Result<Self> {
        let settings = Settings::from_config(config)?;
        let session = Session::new().await.map_err(platform("bluez session"))?;
        let adapter = match settings.adapter_name.as_str() {
            "auto" => session
                .default_adapter()
                .await
                .map_err(platform("default adapter"))?,
            name => session.adapter(name).map_err(platform("adapter"))?,
        };
        if !adapter
            .is_powered()
            .await
            .map_err(platform("adapter power state"))?
        {
            return Err(TransportError::Platform(format!(
                "adapter {} is not powered; refusing to power-toggle",
                adapter.name()
            )));
        }
        let local_addr = adapter
            .address()
            .await
            .map_err(platform("adapter address"))?;

        // GATT application: RX accepts write-IO, TX provides notify-IO.
        let (rx_control, rx_handle) = characteristic_control();
        let (tx_control, tx_handle) = characteristic_control();
        let app = Application {
            services: vec![Service {
                uuid: settings.service_uuid,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: settings.rx_char_uuid,
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: rx_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: settings.tx_char_uuid,
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: tx_handle,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = adapter
            .serve_gatt_application(app)
            .await
            .map_err(platform("register gatt application"))?;

        let (peer_tx, peer_rx) = mpsc::channel(PEER_EVENT_QUEUE);
        let (link_tx, link_rx) = mpsc::channel(LINK_QUEUE);

        let inner = Arc::new(Inner {
            _session: session,
            adapter,
            settings,
            local_addr,
            app_handle: Mutex::new(Some(app_handle)),
            adv_handle: Mutex::new(None),
            peers: Mutex::new(HashMap::new()),
            links: Mutex::new(Links::default()),
            closing_done: Notify::new(),
            peer_tx,
            peer_rx: AsyncMutex::new(Some(peer_rx)),
            link_tx,
            link_rx: AsyncMutex::new(Some(link_rx)),
            tasks: Mutex::new(Vec::new()),
            shutdown_token: CancellationToken::new(),
            shutdown_flag: AtomicBool::new(false),
        });

        let mut tasks = inner.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.push(tokio::spawn(accept_task(
            inner.clone(),
            rx_control,
            tx_control,
        )));
        tasks.push(tokio::spawn(sweeper_task(inner.clone())));
        if inner.settings.discovery_enabled && inner.settings.scan_enabled {
            tasks.push(tokio::spawn(scan_task(inner.clone())));
        }
        drop(tasks);

        Ok(Self { inner })
    }

    /// Ordered teardown: cancel tasks, unregister advertisement and GATT
    /// application, and disconnect every link. Idempotent.
    pub async fn shutdown(&self) -> Result<()> {
        if self.inner.shutdown_flag.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.inner.shutdown_token.cancel();
        let tasks: Vec<JoinHandle<()>> = {
            let mut t = self.inner.tasks.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *t)
        };
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        if let Some(handle) = self
            .inner
            .adv_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            drop(handle); // unregisters the advertisement
        }
        if let Some(handle) = self
            .inner
            .app_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            drop(handle); // unregisters the GATT application
        }
        let devices: Vec<Device> = {
            let mut links = self.inner.links.lock().unwrap_or_else(|e| e.into_inner());
            for rec in links.active.values() {
                rec.kill.cancel();
            }
            links.active.drain().map(|(_, rec)| rec.device).collect()
        };
        for dev in devices {
            let _ = dev.disconnect().await;
        }
        // Failed dials and dropped initiators own asynchronous ACL cleanup.
        // Do not report shutdown complete while that cleanup can still run.
        tokio::time::timeout(self.inner.settings.connection_timeout, async {
            loop {
                let changed = self.inner.closing_done.notified();
                if self
                    .inner
                    .links
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .closing
                    .is_empty()
                {
                    break;
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| TransportError::Timeout)?;
        self.inner
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Ok(())
    }

    /// Adapter name (e.g. `hci0`) — safe to display.
    pub fn adapter_name(&self) -> &str {
        self.inner.adapter.name()
    }
}

impl Drop for BluezTransport {
    fn drop(&mut self) {
        self.inner.shutdown_token.cancel();
        if let Ok(mut tasks) = self.inner.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        // Dropping handles asks BlueZ to unregister; best effort without a
        // runtime.
        let _ = self.inner.adv_handle.lock().map(|mut h| h.take());
        let _ = self.inner.app_handle.lock().map(|mut h| h.take());
    }
}

impl Inner {
    fn locator_for(&self, peers: &mut HashMap<Address, PeerEntry>, addr: Address) -> PeerLocator {
        peers
            .entry(addr)
            .or_insert_with(|| PeerEntry {
                locator: PeerLocator(format!("ble:{}", Uuid::new_v4().as_simple())),
                last_seen: Instant::now(),
            })
            .locator
            .clone()
    }

    fn link_config(&self) -> LinkConfig {
        LinkConfig {
            max_frame_bytes: self.settings.max_frame_bytes,
            reassembly_timeout: self.settings.reassembly_timeout,
        }
    }

    /// Wrap a paired GATT IO into a framed, guarded [`PeerLink`] and register
    /// it in the link table. Caller performs election checks first.
    fn install_link(
        self: &Arc<Self>,
        addr: Address,
        locator: PeerLocator,
        role: LinkRole,
        reader: CharacteristicReader,
        writer: CharacteristicWriter,
        connection: ConnectedDevice,
    ) -> Result<Box<dyn PeerLink>> {
        let reader_mtu = reader.mtu();
        let writer_mtu = writer.mtu();
        let mtu = reader_mtu.min(writer_mtu).min(self.settings.preferred_mtu);
        if mtu == 0 {
            return Err(TransportError::Platform(
                "peer negotiated zero ATT MTU".into(),
            ));
        }
        let kill = connection.watch.disarm();
        let io = GattPacketIo {
            reader,
            writer,
            mtu,
            kill: kill.clone(),
        };
        let framed = FramedLink::new(io, locator, role, self.link_config())?;
        log::info!(
            "blendr-bluez: link ready role={role:?} read_packet_mtu={reader_mtu} write_packet_mtu={writer_mtu} packet_mtu={mtu} frame_limit={}",
            self.settings.max_frame_bytes
        );

        let token = Arc::new(());
        let token_weak = Arc::downgrade(&token);
        let mut links = self.links.lock().unwrap_or_else(|e| e.into_inner());
        links.active.insert(
            addr,
            LinkRecord {
                token: token_weak,
                kill,
                role,
                device: connection.device,
            },
        );
        Ok(Box::new(GuardedLink {
            inner: framed,
            token,
            owner: Arc::downgrade(self),
            addr,
            finished: false,
        }))
    }
}

// ---------------------------------------------------------------------------
// BleTransport implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl BleTransport for BluezTransport {
    async fn start_advertising(&self, service: Uuid) -> Result<()> {
        let inner = &self.inner;
        if !inner.settings.discovery_enabled || !inner.settings.advertise_enabled {
            return Err(TransportError::Platform(
                "BLE advertising disabled by configuration".into(),
            ));
        }
        {
            let guard = inner.adv_handle.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_some() {
                return Err(TransportError::ResourceLimit("already advertising".into()));
            }
        }

        // Legacy 31-byte budget: flags (3) + complete 128-bit service UUID
        // list (18) = 21 bytes; a 128-bit service-data element costs 18+N,
        // so a transient token is advertised only when it truly fits.
        const FIXED: usize = 3 + 18;
        let mut adv = Advertisement {
            service_uuids: [service].into_iter().collect(),
            // Do not inherit the desktop adapter's usually-hidden state.
            // Scope discoverability to this LE advertisement, not BR/EDR.
            discoverable: Some(true),
            ..Default::default()
        };
        if let Some(token) = transient_token() {
            let needed = FIXED + 18 + token.len();
            if needed <= LEGACY_ADV_MAX {
                adv.service_data.insert(service, token);
            }
        }

        let handle = inner
            .adapter
            .advertise(adv)
            .await
            .map_err(platform("start advertising"))?;
        {
            let mut guard = inner.adv_handle.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_some() {
                // Lost a start race; drop this handle to unregister it.
                drop(handle);
                return Err(TransportError::ResourceLimit("already advertising".into()));
            }
            *guard = Some(handle);
        }
        log::info!(
            "blendr-bluez: advertising service UUID on {}",
            inner.adapter.name()
        );
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<()> {
        let mut guard = self
            .inner
            .adv_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if guard.take().is_some() {
            log::info!(
                "blendr-bluez: advertising stopped on {}",
                self.inner.adapter.name()
            );
        }
        Ok(())
    }

    async fn watch_peers(&self) -> Result<mpsc::Receiver<PeerEvent>> {
        self.inner
            .peer_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| TransportError::ResourceLimit("watch_peers already taken".into()))
    }

    async fn connect(
        &self,
        peer: PeerLocator,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PeerLink>> {
        let inner = &self.inner;
        if inner.shutdown_flag.load(Ordering::SeqCst) {
            return Err(TransportError::Cancelled);
        }
        if cancel.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        // Resolve the opaque locator through the peer table.
        let addr = {
            let peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers
                .iter()
                .find(|(_, e)| e.locator == peer)
                .map(|(a, _)| *a)
                .ok_or_else(|| TransportError::Platform("unknown or expired peer locator".into()))?
        };

        // Election pre-check.
        {
            let mut links = inner.links.lock().unwrap_or_else(|e| e.into_inner());
            links.prune();
            if links.closing.contains(&addr) {
                return Err(TransportError::ResourceLimit("link is closing".into()));
            }
            if let Some(rec) = links.active.get(&addr) {
                match (rec.role, Links::initiator_is_us(inner.local_addr, addr)) {
                    (LinkRole::Responder, false) => {
                        // Peer initiates; the elected inbound link exists.
                        return Err(TransportError::ResourceLimit(
                            "link to peer already exists".into(),
                        ));
                    }
                    (LinkRole::Responder, true) => {
                        // We initiate; the inbound copy loses the election.
                        rec.kill.cancel();
                        links.active.remove(&addr);
                    }
                    (LinkRole::Initiator, _) => {
                        // We already hold the elected outbound link.
                        return Err(TransportError::ResourceLimit(
                            "link to peer already exists".into(),
                        ));
                    }
                }
            }
            if !links.outbound_inflight.insert(addr) {
                return Err(TransportError::ResourceLimit(
                    "connect already in progress to peer".into(),
                ));
            }
            if links.live_count() >= inner.settings.max_links {
                links.outbound_inflight.remove(&addr);
                return Err(TransportError::ResourceLimit(
                    "max concurrent links reached".into(),
                ));
            }
        }
        let mut inflight = InflightGuard {
            inner,
            addr,
            device: None,
            armed: true,
        };

        let device = inner
            .adapter
            .device(addr)
            .map_err(platform("device handle"))?;
        inflight.device = Some(device.clone());
        let timeout = inner.settings.connection_timeout;
        let attempts = inner.settings.connect_retry_attempts.max(1);
        let mut last_err = TransportError::Disconnected;
        let mut connected = false;
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::select! {
                    _ = cancel.cancelled() => { return Err(TransportError::Cancelled); }
                    _ = tokio::time::sleep(inner.settings.connect_retry_backoff) => {}
                }
            }
            match with_cancel_timeout(cancel, timeout, "connect", device.connect()).await {
                Ok(()) => {
                    connected = true;
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        // A late reply loss can still leave the link up; confirm via state.
        if !connected && device.is_connected().await.unwrap_or(false) {
            connected = true;
        }
        if !connected {
            return Err(last_err);
        }

        // Resolve service + characteristics, then acquire packet IO.
        let (writer, reader) = acquire_client_io(
            &device,
            inner.settings.service_uuid,
            inner.settings.rx_char_uuid,
            inner.settings.tx_char_uuid,
            cancel,
            timeout,
        )
        .await?;
        let connection = ConnectedDevice::new(device, cancel, timeout).await?;

        // Post-dial election: an inbound pair may have formed while dialing.
        {
            let mut links = inner.links.lock().unwrap_or_else(|e| e.into_inner());
            links.prune();
            if let Some(rec) = links.active.get(&addr) {
                match (rec.role, Links::initiator_is_us(inner.local_addr, addr)) {
                    (LinkRole::Responder, false) => {
                        return Err(TransportError::ResourceLimit(
                            "link to peer already exists".into(),
                        ));
                    }
                    (LinkRole::Responder, true) => {
                        rec.kill.cancel();
                        links.active.remove(&addr);
                    }
                    (LinkRole::Initiator, _) => {
                        return Err(TransportError::ResourceLimit(
                            "link to peer already exists".into(),
                        ));
                    }
                }
            }
            links.outbound_inflight.remove(&addr);
            drop(links);
            let result =
                inner.install_link(addr, peer, LinkRole::Initiator, reader, writer, connection);
            inflight.armed = result.is_err();
            result
        }
    }

    async fn accept_links(&self) -> Result<mpsc::Receiver<Box<dyn PeerLink>>> {
        self.inner
            .link_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| TransportError::ResourceLimit("accept_links already taken".into()))
    }
}

/// Failed/cancelled dials disconnect only when no elected link owns the ACL.
struct InflightGuard<'a> {
    inner: &'a Arc<Inner>,
    addr: Address,
    device: Option<Device>,
    armed: bool,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let closing = {
            let mut links = self.inner.links.lock().unwrap_or_else(|e| e.into_inner());
            links.outbound_inflight.remove(&self.addr);
            if !self.armed
                || links.active.contains_key(&self.addr)
                || links.closing.contains(&self.addr)
            {
                return;
            }
            let Some(device) = self.device.take() else {
                return;
            };
            links.closing.insert(self.addr);
            ClosingLink {
                owner: self.inner.clone(),
                addr: self.addr,
                device,
            }
        };
        tokio::spawn(async move {
            let _ = closing.disconnect().await;
        });
    }
}

/// Optional transient discovery token source; none is configured in the v1
/// schema, so the beacon carries only the service UUID.
fn transient_token() -> Option<Vec<u8>> {
    None
}

// ---------------------------------------------------------------------------
// Client-side GATT IO acquisition
// ---------------------------------------------------------------------------

/// Find the peer's Blendr service, verify both characteristics exist, and
/// acquire write-IO (toward peer RX) plus notify-IO (from peer TX).
async fn acquire_client_io(
    device: &Device,
    service_uuid: Uuid,
    rx_uuid: Uuid,
    tx_uuid: Uuid,
    cancel: &CancellationToken,
    timeout: Duration,
) -> Result<(CharacteristicWriter, CharacteristicReader)> {
    let services =
        with_cancel_timeout(cancel, timeout, "resolve services", device.services()).await?;
    let mut service = None;
    for svc in services {
        let uuid = svc.uuid().await.map_err(platform("service uuid"))?;
        if uuid == service_uuid {
            service = Some(svc);
            break;
        }
    }
    let service = service.ok_or_else(|| {
        TransportError::Platform("peer does not expose the blendr service".into())
    })?;

    let chars = with_cancel_timeout(
        cancel,
        timeout,
        "resolve characteristics",
        service.characteristics(),
    )
    .await?;
    let mut rx = None;
    let mut tx = None;
    for ch in chars {
        let uuid = ch.uuid().await.map_err(platform("characteristic uuid"))?;
        if uuid == rx_uuid {
            rx = Some(ch);
        } else if uuid == tx_uuid {
            tx = Some(ch);
        }
    }
    let rx = rx.ok_or_else(|| TransportError::Platform("peer missing RX characteristic".into()))?;
    let tx = tx.ok_or_else(|| TransportError::Platform("peer missing TX characteristic".into()))?;

    let writer = with_cancel_timeout(cancel, timeout, "acquire write io", rx.write_io()).await?;
    let reader = with_cancel_timeout(cancel, timeout, "acquire notify io", tx.notify_io()).await?;
    Ok((writer, reader))
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

/// Merge RX/TX characteristic control events, pair reader+writer by remote
/// device address, run election, and enqueue framed inbound links.
async fn accept_task(
    inner: Arc<Inner>,
    rx_control: CharacteristicControl,
    tx_control: CharacteristicControl,
) {
    tokio::pin!(rx_control);
    tokio::pin!(tx_control);
    let cancel = inner.shutdown_token.clone();
    let mut pending: HashMap<Address, PendingHalf> = HashMap::new();
    let mut prune_tick = tokio::time::interval(Duration::from_secs(5));
    prune_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let next_deadline = pending.values().map(|p| p.deadline).min();
        tokio::select! {
            _ = cancel.cancelled() => break,
            evt = rx_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Write(req)) => {
                        let addr = req.device_address();
                        match inner.adapter.device(addr) {
                            Ok(device) => match req.accept() {
                                Ok(reader) => {
                                    push_half(&inner, &mut pending, addr, InboundHalf::Reader(reader), device).await;
                                }
                                Err(e) => {
                                    log::warn!("blendr-bluez: accept write io failed: {}", scrub_addrs(&e.to_string()));
                                }
                            },
                            Err(e) => {
                                log::warn!("blendr-bluez: write io for unknown device");
                                let _ = e;
                                req.reject(ReqError::Failed);
                            }
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            evt = tx_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Notify(writer)) => {
                        let addr = writer.device_address();
                        match inner.adapter.device(addr) {
                            Ok(device) => {
                                push_half(&inner, &mut pending, addr, InboundHalf::Writer(writer), device).await;
                            }
                            Err(_) => {
                                log::warn!("blendr-bluez: notify io for unknown device");
                            }
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_deadline.unwrap_or_else(|| Instant::now() + PAIR_TIMEOUT))), if next_deadline.is_some() => {
                expire_pending(&mut pending);
            }
            _ = prune_tick.tick() => {
                expire_pending(&mut pending);
            }
        }
    }
    // Teardown: pending halves drop here, ending their ATT sessions.
    pending.clear();
}

/// Store a freshly arrived IO half and attempt to complete a link.
async fn push_half(
    inner: &Arc<Inner>,
    pending: &mut HashMap<Address, PendingHalf>,
    addr: Address,
    half: InboundHalf,
    device: Device,
) {
    if pending.len() >= PENDING_HALVES_MAX {
        log::warn!("blendr-bluez: pending GATT halves full; dropping oldest");
        if let Some(&old_addr) = pending
            .iter()
            .min_by_key(|(_, p)| p.deadline)
            .map(|(a, _)| a)
        {
            // Dropping the half closes its ATT acquire session; the shared
            // ACL stays up for the other direction if any.
            pending.remove(&old_addr);
        }
    }
    match pending.remove(&addr) {
        None => {
            pending.insert(
                addr,
                PendingHalf {
                    half,
                    device,
                    deadline: Instant::now() + PAIR_TIMEOUT,
                },
            );
        }
        Some(existing) => {
            let (reader, writer, device) = match (existing.half, half) {
                (InboundHalf::Reader(r), InboundHalf::Writer(w)) => (r, w, device),
                (InboundHalf::Writer(w), InboundHalf::Reader(r)) => (r, w, existing.device),
                // Same-kind re-acquire: keep the newer half.
                (InboundHalf::Reader(_), n @ InboundHalf::Reader(_))
                | (InboundHalf::Writer(_), n @ InboundHalf::Writer(_)) => {
                    pending.insert(
                        addr,
                        PendingHalf {
                            half: n,
                            device,
                            deadline: Instant::now() + PAIR_TIMEOUT,
                        },
                    );
                    return;
                }
            };
            complete_inbound(inner, addr, reader, writer, device).await;
        }
    }
}

/// Run election and bounded-queue admission for a fully paired inbound link.
async fn complete_inbound(
    inner: &Arc<Inner>,
    addr: Address,
    reader: CharacteristicReader,
    writer: CharacteristicWriter,
    device: Device,
) {
    let connection = match ConnectedDevice::new(
        device,
        &inner.shutdown_token,
        inner.settings.connection_timeout,
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            log::warn!("blendr-bluez: inbound connection watch failed: {error}");
            return;
        }
    };
    {
        let mut links = inner.links.lock().unwrap_or_else(|e| e.into_inner());
        links.prune();
        if links.closing.contains(&addr) {
            log::debug!("blendr-bluez: refusing inbound link during disconnect");
            return;
        }
        if let Some(rec) = links.active.get(&addr) {
            match (rec.role, Links::initiator_is_us(inner.local_addr, addr)) {
                (LinkRole::Responder, _) => {
                    // Already have an inbound link; supersede it.
                    rec.kill.cancel();
                    links.active.remove(&addr);
                }
                (LinkRole::Initiator, true) => {
                    // Our outbound link wins the election; refuse inbound.
                    // Both directions share one ACL, so we only drop the
                    // acquired IO halves — never disconnect the device.
                    log::info!("blendr-bluez: dropping inbound link (election: outbound wins)");
                    return;
                }
                (LinkRole::Initiator, false) => {
                    // Peer initiates; our outbound link loses.
                    rec.kill.cancel();
                    links.active.remove(&addr);
                }
            }
        }
        if links.outbound_inflight.contains(&addr) && Links::initiator_is_us(inner.local_addr, addr)
        {
            // We are mid-dial and win the election; refuse inbound by
            // dropping the halves (a device disconnect would kill our dial).
            log::info!("blendr-bluez: dropping inbound link during own dial (election)");
            return;
        }
        if links.live_count() >= inner.settings.max_links {
            log::warn!("blendr-bluez: max concurrent links; refusing inbound");
            return;
        }
    }

    // Register the peer and emit discovery for an unseen inbound connect.
    let locator = {
        let mut peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
        let locator = inner.locator_for(&mut peers, addr);
        if let Some(entry) = peers.get_mut(&addr) {
            entry.last_seen = Instant::now();
        }
        locator
    };
    let _ = inner
        .peer_tx
        .try_send(PeerEvent::Discovered(locator.clone()));

    match inner.install_link(
        addr,
        locator,
        LinkRole::Responder,
        reader,
        writer,
        connection,
    ) {
        Ok(link) => {
            if inner.link_tx.try_send(link).is_err() {
                log::warn!("blendr-bluez: accept_links queue full; inbound link dropped");
            }
        }
        Err(e) => {
            log::warn!("blendr-bluez: inbound link setup failed: {e}");
        }
    }
}

/// Drop timed-out IO halves. Dropping the acquired socket ends that ATT
/// acquire session; the shared ACL is left for BlueZ to reap.
fn expire_pending(pending: &mut HashMap<Address, PendingHalf>) {
    let now = Instant::now();
    let expired: Vec<Address> = pending
        .iter()
        .filter(|(_, p)| p.deadline <= now)
        .map(|(a, _)| *a)
        .collect();
    for addr in expired {
        if pending.remove(&addr).is_some() {
            log::info!("blendr-bluez: GATT IO pairing timed out; dropping half");
        }
    }
}

/// Duty-cycled LE scanning with service UUID admission in [`handle_seen`].
///
/// Explicit transitions: each cycle sets the discovery filter, starts a
/// bounded discovery window, then stops scanning for the remainder of the
/// configured interval so scanning and advertising share airtime
/// predictably. Filter setup and discovery startup are bounded by the
/// cycle deadline so a stuck D-Bus call can never stall the task past its
/// cycle.
///
/// `discover_devices_with_changes` replays every device object BlueZ has
/// cached — including devices not currently in range — before streaming
/// live events. Evaluating a sighting costs two D-Bus property reads
/// (`UUIDs`, `RSSI`); awaiting them inline serializes the cache flood
/// ahead of real advertisements and can starve the whole window.
/// Sightings are deduplicated into [`SeenQueue`] and evaluated with
/// bounded concurrency ([`SEEN_EVAL_CONCURRENCY`]) through a single
/// named future type, so `evals` never mixes distinct async-block types.
/// A sighting queued while its address is already under evaluation stays
/// queued and is re-evaluated after that evaluation finishes — never
/// evaluated twice concurrently. `DeviceRemoved` drops the pending
/// sighting, cancels a live evaluation, and the cancelled evaluation
/// cannot register or announce the peer when it wakes. Evaluations keep
/// running through the off part of the cycle and are cancelled at the
/// cycle deadline; any sighting still unevaluated is retried next cycle —
/// either carried in `queued` or replayed as a cached `DeviceAdded`.
async fn scan_task(inner: Arc<Inner>) {
    let cancel = inner.shutdown_token.clone();
    let window = inner.settings.scan_window;
    let interval = inner.settings.scan_interval;
    let mut queued = SeenQueue::default();

    loop {
        let cycle_deadline = tokio::time::Instant::now() + interval;
        // Cycle boundary markers let a debug capture distinguish a stuck
        // filter/startup call from a window that saw no events.
        log::debug!("blendr-bluez: scan cycle start");

        // Restrict BlueZ to LE, but leave its UUID list empty. BlueZ 5.87
        // can call a UUID string as a function when a filter matches:
        // https://github.com/bluez/bluez/issues/2282
        // handle_seen enforces our service UUID and RSSI checks instead;
        // the bounded queue/concurrency contain unrelated BLE sightings.
        // If setup fails, skip this cycle rather than use stale settings.
        let filter = DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            ..Default::default()
        };
        match with_cancel_timeout(
            &cancel,
            cycle_deadline.saturating_duration_since(tokio::time::Instant::now()),
            "set discovery filter",
            inner.adapter.set_discovery_filter(filter),
        )
        .await
        {
            Ok(()) => {}
            Err(TransportError::Cancelled) => return,
            Err(e) => {
                log::warn!("blendr-bluez: {e}");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep_until(cycle_deadline) => continue,
                }
            }
        }

        let mut evals = FuturesUnordered::new();
        let mut active: HashMap<Address, CancellationToken> = HashMap::new();
        {
            // Scan window: consume adapter events until the deadline. The
            // drain only pushes onto `queued`; property reads run in
            // `evals` so a large cached-device replay cannot block
            // real-time events.
            let stream = match with_cancel_timeout(
                &cancel,
                cycle_deadline.saturating_duration_since(tokio::time::Instant::now()),
                "start discovery",
                inner.adapter.discover_devices_with_changes(),
            )
            .await
            {
                Ok(s) => s,
                Err(TransportError::Cancelled) => return,
                Err(e) => {
                    log::warn!("blendr-bluez: {e}");
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep_until(cycle_deadline) => continue,
                    }
                }
            };
            tokio::pin!(stream);
            let window_deadline = tokio::time::Instant::now() + window;
            log::debug!("blendr-bluez: scan window start");
            loop {
                // Start evaluations only for queued addresses not already
                // under evaluation; re-sightings stay queued for
                // reevaluation once the in-flight one completes.
                while evals.len() < SEEN_EVAL_CONCURRENCY
                    && let Some(addr) = queued.pop_ready(|a| !active.contains_key(a))
                {
                    let token = CancellationToken::new();
                    active.insert(addr, token.clone());
                    evals.push(eval_seen(inner.clone(), addr, token));
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep_until(window_deadline) => break,
                    evt = stream.next() => {
                        match evt {
                            Some(AdapterEvent::DeviceAdded(addr)) => queued.push(addr),
                            Some(AdapterEvent::DeviceRemoved(addr)) => {
                                // Drop pending re-sightings and cancel any
                                // live evaluation before unregistering the
                                // peer; its waking future checks the token
                                // and must not recreate it.
                                queued.remove(addr);
                                if let Some(token) = active.get(&addr) {
                                    token.cancel();
                                }
                                handle_removed(&inner, addr);
                            }
                            Some(AdapterEvent::PropertyChanged(_)) => {}
                            None => break,
                        }
                    }
                    done = evals.next(), if !evals.is_empty() => {
                        if let Some(addr) = done {
                            active.remove(&addr);
                        }
                    }
                }
            }
            log::debug!("blendr-bluez: scan window end");
            // End the scope to drop the owned stream (StopDiscovery), not
            // only its pinned reference.
        }

        // Off part of the cycle: finish pending evaluations without
        // scanning, bounded by the cycle deadline.
        loop {
            while evals.len() < SEEN_EVAL_CONCURRENCY
                && let Some(addr) = queued.pop_ready(|a| !active.contains_key(a))
            {
                let token = CancellationToken::new();
                active.insert(addr, token.clone());
                evals.push(eval_seen(inner.clone(), addr, token));
            }
            if evals.is_empty() {
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep_until(cycle_deadline) => break,
                done = evals.next() => {
                    if let Some(addr) = done {
                        active.remove(&addr);
                    }
                }
            }
        }
        drop(evals);

        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep_until(cycle_deadline) => {}
        }
        log::debug!("blendr-bluez: scan cycle end");
    }
}

/// Run one queued sighting's evaluation under per-candidate cancellation.
///
/// Every entry pushed into `evals` is this single future type. The token
/// exists so `DeviceRemoved` can stop a live evaluation of the removed
/// address: a cancelled future skips `handle_seen` entirely, and a
/// cancelled future can never register or announce the removed peer on
/// wake. Returns the evaluated address so the caller drops the matching
/// entry in `active` — keeping the entry keyed until completion prevents
/// a re-sighting from spawning a parallel duplicate evaluation.
async fn eval_seen(inner: Arc<Inner>, addr: Address, token: CancellationToken) -> Address {
    tokio::select! {
        biased;
        _ = token.cancelled() => {}
        _ = inner.shutdown_token.cancelled() => {}
        _ = handle_seen(&inner, addr) => {}
    }
    addr
}

/// Admit a discovered device if it advertises the service UUID and is
/// actually in range (has a live RSSI reading).
async fn handle_seen(inner: &Arc<Inner>, addr: Address) {
    let device = match inner.adapter.device(addr) {
        Ok(d) => d,
        Err(_) => return,
    };
    let service_match = matches!(device.uuids().await, Ok(Some(u)) if u.contains(&inner.settings.scan_service_uuid));
    let live_rssi = matches!(device.rssi().await, Ok(Some(_)));
    // Admission booleans only — no identifiers — so a debug capture can
    // tell "device seen but rejected" apart from "no events at all".
    log::debug!("blendr-bluez: scan candidate service_match={service_match} live_rssi={live_rssi}");
    if !service_match || !live_rssi {
        return;
    }
    let mut peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
    let new = !peers.contains_key(&addr);
    let locator = inner.locator_for(&mut peers, addr);
    if let Some(entry) = peers.get_mut(&addr) {
        entry.last_seen = Instant::now();
    }
    drop(peers);
    if new {
        let _ = inner.peer_tx.try_send(PeerEvent::Discovered(locator));
    }
}

fn handle_removed(inner: &Arc<Inner>, addr: Address) {
    let mut peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = peers.remove(&addr) {
        drop(peers);
        let _ = inner.peer_tx.try_send(PeerEvent::Lost(entry.locator));
    }
}

/// Periodic peer aging: emit `Lost` for peers unseen beyond
/// `peer_stale_after_seconds`.
async fn sweeper_task(inner: Arc<Inner>) {
    let cancel = inner.shutdown_token.clone();
    let stale = inner.settings.peer_stale_after;
    let tick = (stale / 4).clamp(Duration::from_secs(1), SWEEP_MAX);
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                let now = Instant::now();
                let mut lost = Vec::new();
                {
                    let mut links = inner.links.lock().unwrap_or_else(|e| e.into_inner());
                    links.prune();
                    let mut peers = inner.peers.lock().unwrap_or_else(|e| e.into_inner());
                    peers.retain(|addr, e| {
                        // Never age out a peer while a link to it lives;
                        // the locator must stay resolvable.
                        if links.active.contains_key(addr) {
                            return true;
                        }
                        if now.duration_since(e.last_seen) > stale {
                            lost.push(e.locator.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                for locator in lost {
                    let _ = inner.peer_tx.try_send(PeerEvent::Lost(locator));
                }
            }
        }
    }
}
