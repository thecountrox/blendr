//! In-memory `BleTransport` simulator with a bounded, fault-injectable radio
//! model. Used for multi-node tests (7 nodes / 5 jumps) before real hardware.
//!
//! Model:
//! * A [`MemoryNetwork`] is one radio domain with a fixed `packet_mtu` and a
//!   bounded per-link packet queue (`queue_capacity`).
//! * [`MemoryNetwork::node`] creates a [`MemoryTransport`]. Nodes discover each
//!   other iff the advertiser advertises, the watcher watches, and the pair is
//!   in range (default: in range).
//! * `connect` binds two `PacketIo` endpoints over bounded queues, applies the
//!   deterministic tie-break (the connection initiated by the lexicographically
//!   smaller node name wins), prevents duplicate concurrent sessions, and
//!   enforces the accept-queue bound.
//! * Range loss severs live links; a fresh connection resumes clean because
//!   every link gets fresh `FramedLink` state.
//! * [`MemoryFaults`] injects per-packet delay, deterministic packet loss, and
//!   disconnect-after-N-packets on every link in the domain.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    BleTransport, FRAGMENT_HEADER_LEN, FramedLink, LinkConfig, LinkRole, PacketIo, PeerEvent,
    PeerLink, PeerLocator, Result, TransportError,
};

/// Bound on per-node discovery-event queues.
const EVENT_QUEUE_CAPACITY: usize = 64;
/// Locator prefix for in-memory rendezvous tokens.
const LOCATOR_PREFIX: &str = "mem://";

/// Radio faults applied to every packet of every link in a [`MemoryNetwork`].
#[derive(Debug, Clone, Default)]
pub struct MemoryFaults {
    /// Delay before each packet is delivered (simulated airtime).
    pub delay: Duration,
    /// Silently drop every n-th packet per link (1 = drop all).
    pub drop_every_nth_packet: Option<u64>,
    /// Sever the link once this many packets total have been accepted.
    pub disconnect_after_packets: Option<u64>,
}

struct Node {
    /// Advertised service while `Some`; beacon is service-only.
    advertising: Option<Uuid>,
    /// Locator tokens this node currently advertises: token -> PeerLocator.
    locators: HashMap<String, PeerLocator>,
    /// Bounded discovery watcher channels.
    watchers: Vec<mpsc::Sender<PeerEvent>>,
    /// Bounded accept queue; `Some` after `accept_links`.
    accept_tx: Option<mpsc::Sender<Box<dyn PeerLink>>>,
    /// Framing config applied to accepted links.
    link_config: LinkConfig,
}

struct Conn {
    id: u64,
    initiator: String,
    core: Arc<LinkCore>,
}

struct LinkCore {
    mtu: usize,
    packets: AtomicU64,
    closed: watch::Sender<bool>,
}

struct NetworkState {
    packet_mtu: usize,
    queue_capacity: usize,
    faults: MemoryFaults,
    nodes: HashMap<String, Node>,
    /// Locator token -> advertising node name, for `connect` resolution.
    locator_index: HashMap<String, String>,
    /// Live links keyed by unordered name pair.
    connections: HashMap<(String, String), Conn>,
    /// Currently visible (locator token, watcher node) edges for event diffing.
    visible: HashSet<(String, String)>,
    /// Symmetric out-of-range pairs; absent = in range.
    out_of_range: HashSet<(String, String)>,
    next_locator: u64,
    next_link: u64,
}

fn locknet(net: &Mutex<NetworkState>) -> MutexGuard<'_, NetworkState> {
    net.lock().unwrap_or_else(|e| e.into_inner())
}

fn pair_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.into(), b.into())
    } else {
        (b.into(), a.into())
    }
}

impl NetworkState {
    fn in_range(&self, a: &str, b: &str) -> bool {
        !self.out_of_range.contains(&pair_key(a, b))
    }

    /// Recompute visible (locator token, watcher node) edges and emit the
    /// difference as `Discovered`/`Lost` events over bounded queues.
    fn sync_visibility(&mut self) {
        let mut desired: HashSet<(String, String)> = HashSet::new();
        for (adv_name, adv) in &self.nodes {
            if adv.advertising.is_none() {
                continue;
            }
            for (watcher_name, watcher) in &self.nodes {
                if watcher_name == adv_name
                    || watcher.watchers.is_empty()
                    || !self.in_range(adv_name, watcher_name)
                {
                    continue;
                }
                for token in adv.locators.keys() {
                    desired.insert((token.clone(), watcher_name.clone()));
                }
            }
        }

        let lost: Vec<(String, String)> = self.visible.difference(&desired).cloned().collect();
        for edge in &lost {
            self.visible.remove(edge);
            let locator = PeerLocator(format!("{LOCATOR_PREFIX}{}", edge.0));
            if let Some(node) = self.nodes.get_mut(&edge.1) {
                for tx in &node.watchers {
                    let _ = tx.try_send(PeerEvent::Lost(locator.clone()));
                }
            }
        }

        let found: Vec<(String, String)> = desired.difference(&self.visible).cloned().collect();
        for (token, watcher) in found {
            let locator = self
                .locator_index
                .get(&token)
                .and_then(|owner| self.nodes.get(owner))
                .and_then(|n| n.locators.get(&token))
                .cloned();
            let Some(locator) = locator else { continue };
            if let Some(node) = self.nodes.get_mut(&watcher) {
                for tx in &node.watchers {
                    let _ = tx.try_send(PeerEvent::Discovered(locator.clone()));
                }
            }
            self.visible.insert((token, watcher));
        }

        for node in self.nodes.values_mut() {
            node.watchers.retain(|tx| !tx.is_closed());
        }
    }

    /// Close and forget any live link between the pair.
    fn sever_pair(&mut self, a: &str, b: &str) {
        if let Some(conn) = self.connections.remove(&pair_key(a, b)) {
            conn.core.closed.send_replace(true);
        }
    }
}

/// One radio domain. `MemoryTransport`s share it through an `Arc`.
pub struct MemoryNetwork {
    state: Arc<Mutex<NetworkState>>,
}

impl MemoryNetwork {
    /// Create a radio domain. `packet_mtu` must fit the 12-byte fragment
    /// header plus payload. `queue_capacity` bounds per-link packet queues and
    /// per-node accept queues, giving real backpressure.
    pub fn new(packet_mtu: usize, queue_capacity: usize) -> Result<Self> {
        if packet_mtu <= FRAGMENT_HEADER_LEN {
            return Err(TransportError::ResourceLimit(format!(
                "packet_mtu {packet_mtu} too small for BLENDR/1 header \
                 ({FRAGMENT_HEADER_LEN} bytes + payload)"
            )));
        }
        if queue_capacity == 0 {
            return Err(TransportError::ResourceLimit(
                "queue_capacity must be non-zero".into(),
            ));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(NetworkState {
                packet_mtu,
                queue_capacity,
                faults: MemoryFaults::default(),
                nodes: HashMap::new(),
                locator_index: HashMap::new(),
                connections: HashMap::new(),
                visible: HashSet::new(),
                out_of_range: HashSet::new(),
                next_locator: 0,
                next_link: 0,
            })),
        })
    }

    /// Add a named node; names must be unique and non-empty.
    pub fn node(&self, name: &str, link_config: LinkConfig) -> Result<MemoryTransport> {
        link_config.validate()?;
        if name.is_empty() {
            return Err(TransportError::Platform("node name is empty".into()));
        }
        let mut s = locknet(&self.state);
        if s.nodes.contains_key(name) {
            return Err(TransportError::Platform(format!(
                "node `{name}` already exists"
            )));
        }
        s.nodes.insert(
            name.to_string(),
            Node {
                advertising: None,
                locators: HashMap::new(),
                watchers: Vec::new(),
                accept_tx: None,
                link_config,
            },
        );
        Ok(MemoryTransport {
            name: name.to_string(),
            link_config,
            network: Arc::clone(&self.state),
        })
    }

    /// Set symmetric radio range. Range loss immediately severs any live link
    /// between the pair; range gain emits discovery events.
    pub fn set_in_range(&self, a: &str, b: &str, in_range: bool) -> Result<()> {
        let mut s = locknet(&self.state);
        if !s.nodes.contains_key(a) || !s.nodes.contains_key(b) {
            return Err(TransportError::Platform(format!(
                "unknown node(s): {a}, {b}"
            )));
        }
        if in_range {
            s.out_of_range.remove(&pair_key(a, b));
        } else {
            s.out_of_range.insert(pair_key(a, b));
            s.sever_pair(a, b);
        }
        s.sync_visibility();
        Ok(())
    }

    /// Replace the radio fault model; applies to all links.
    pub fn set_faults(&self, faults: MemoryFaults) -> Result<()> {
        locknet(&self.state).faults = faults;
        Ok(())
    }
}

/// A node's transport handle inside a [`MemoryNetwork`].
pub struct MemoryTransport {
    name: String,
    link_config: LinkConfig,
    network: Arc<Mutex<NetworkState>>,
}

impl MemoryTransport {
    /// Node name inside the simulation (never a wire identity).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Remove the node: severs its links, revokes locators, drops it from the
    /// domain. Further transport calls fail with `Platform`.
    pub fn shutdown(&self) {
        let mut s = locknet(&self.network);
        let pairs: Vec<(String, String)> = s
            .connections
            .keys()
            .filter(|(a, b)| *a == self.name || *b == self.name)
            .cloned()
            .collect();
        for (a, b) in pairs {
            s.sever_pair(&a, &b);
        }
        if let Some(node) = s.nodes.remove(&self.name) {
            for token in node.locators.keys() {
                s.locator_index.remove(token);
            }
        }
        let live: HashSet<String> = s.locator_index.keys().cloned().collect();
        s.visible
            .retain(|(t, w)| w != &self.name && live.contains(t));
        s.sync_visibility();
    }

    fn require_node(s: &NetworkState, name: &str) -> Result<()> {
        if s.nodes.contains_key(name) {
            Ok(())
        } else {
            Err(TransportError::Platform(format!("node `{name}` shut down")))
        }
    }
}

#[async_trait]
impl BleTransport for MemoryTransport {
    async fn start_advertising(&self, service: Uuid) -> Result<()> {
        let mut s = locknet(&self.network);
        Self::require_node(&s, &self.name)?;
        s.next_locator += 1;
        // One beacon token per advertising epoch; revoke stale ones.
        let token = format!("{}", s.next_locator);
        let node = s.nodes.get_mut(&self.name).expect("checked above");
        node.advertising = Some(service);
        // Take the stale tokens so the node borrow ends before index edits.
        let stale = std::mem::take(&mut node.locators);
        node.locators.insert(
            token.clone(),
            PeerLocator(format!("{LOCATOR_PREFIX}{token}")),
        );
        for t in stale.keys() {
            s.locator_index.remove(t);
        }
        s.locator_index.insert(token, self.name.clone());
        s.sync_visibility();
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<()> {
        let mut s = locknet(&self.network);
        Self::require_node(&s, &self.name)?;
        let node = s.nodes.get_mut(&self.name).expect("checked above");
        node.advertising = None;
        let stale = std::mem::take(&mut node.locators);
        for t in stale.keys() {
            s.locator_index.remove(t);
        }
        s.sync_visibility();
        Ok(())
    }

    async fn watch_peers(&self) -> Result<mpsc::Receiver<PeerEvent>> {
        let mut s = locknet(&self.network);
        Self::require_node(&s, &self.name)?;
        let (tx, rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        // Snapshot currently visible advertisers to the new watcher only.
        let mut eligible: Vec<(String, PeerLocator)> = Vec::new();
        for (adv_name, adv) in &s.nodes {
            if adv_name == &self.name
                || adv.advertising.is_none()
                || !s.in_range(adv_name, &self.name)
            {
                continue;
            }
            for (token, loc) in &adv.locators {
                eligible.push((token.clone(), loc.clone()));
            }
        }
        for (token, loc) in eligible {
            let _ = tx.try_send(PeerEvent::Discovered(loc));
            s.visible.insert((token, self.name.clone()));
        }
        s.nodes
            .get_mut(&self.name)
            .expect("node checked above")
            .watchers
            .push(tx);
        Ok(rx)
    }

    async fn connect(
        &self,
        peer: PeerLocator,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PeerLink>> {
        if cancel.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        let token = peer
            .0
            .strip_prefix(LOCATOR_PREFIX)
            .unwrap_or(peer.0.as_str())
            .to_string();
        let responder_config;
        let accept_tx;
        let io_a;
        let io_b;
        {
            let mut s = locknet(&self.network);
            Self::require_node(&s, &self.name)?;

            let target = s
                .locator_index
                .get(&token)
                .cloned()
                .ok_or_else(|| TransportError::Platform("unknown peer locator".into()))?;
            if target == self.name {
                return Err(TransportError::Platform("cannot connect to self".into()));
            }
            if !s.in_range(&self.name, &target) {
                return Err(TransportError::Timeout);
            }

            let key = pair_key(&self.name, &target);
            if let Some(existing) = s.connections.get(&key) {
                // Deterministic tie-break: the connection initiated by the
                // lexicographically smaller node name wins; the loser is
                // severed.
                if existing.initiator <= self.name {
                    return Err(TransportError::ResourceLimit(format!(
                        "duplicate connection between {} and {}",
                        key.0, key.1
                    )));
                }
                s.sever_pair(&key.0, &key.1);
            }

            accept_tx = s
                .nodes
                .get(&target)
                .and_then(|n| n.accept_tx.clone())
                .ok_or_else(|| {
                    TransportError::Platform(format!("peer `{target}` is not accepting links"))
                })?;
            responder_config = s
                .nodes
                .get(&target)
                .map(|n| n.link_config)
                .unwrap_or_default();

            // Bounded packet link.
            s.next_link += 1;
            let link_id = s.next_link;
            let (closed_tx, closed_rx) = watch::channel(false);
            let core = Arc::new(LinkCore {
                mtu: s.packet_mtu,
                packets: AtomicU64::new(0),
                closed: closed_tx,
            });
            let (ab_tx, ab_rx) = mpsc::channel(s.queue_capacity);
            let (ba_tx, ba_rx) = mpsc::channel(s.queue_capacity);
            io_a = MemoryPacketIo {
                net: Arc::clone(&self.network),
                core: Arc::clone(&core),
                link_id,
                endpoints: key.clone(),
                tx: ab_tx,
                rx: ba_rx,
                closed_rx: closed_rx.clone(),
                local_closed: false,
            };
            io_b = MemoryPacketIo {
                net: Arc::clone(&self.network),
                core: Arc::clone(&core),
                link_id,
                endpoints: key.clone(),
                tx: ba_tx,
                rx: ab_rx,
                closed_rx,
                local_closed: false,
            };
            s.connections.insert(
                key,
                Conn {
                    id: link_id,
                    initiator: self.name.clone(),
                    core,
                },
            );
        }
        // Lock released before try_send: on failure the responder endpoint
        // drops, and its Drop locks the network to sever the half-made link.
        let responder_locator = PeerLocator(format!("{LOCATOR_PREFIX}peer:{}", self.name));
        let responder = FramedLink::new(
            io_b,
            responder_locator,
            LinkRole::Responder,
            responder_config,
        )?;
        accept_tx
            .try_send(Box::new(responder))
            .map_err(|_| TransportError::ResourceLimit("accept queue full".into()))?;

        let initiator = FramedLink::new(io_a, peer, LinkRole::Initiator, self.link_config)?;
        Ok(Box::new(initiator))
    }

    async fn accept_links(&self) -> Result<mpsc::Receiver<Box<dyn PeerLink>>> {
        let mut s = locknet(&self.network);
        let cap = s.queue_capacity;
        Self::require_node(&s, &self.name)?;
        let node = s.nodes.get_mut(&self.name).expect("checked above");
        if node.accept_tx.is_some() {
            return Err(TransportError::ResourceLimit(
                "accept_links already called".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(cap);
        node.accept_tx = Some(tx);
        Ok(rx)
    }
}

/// One direction-aware `PacketIo` endpoint of a simulated link.
struct MemoryPacketIo {
    net: Arc<Mutex<NetworkState>>,
    core: Arc<LinkCore>,
    link_id: u64,
    endpoints: (String, String),
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    closed_rx: watch::Receiver<bool>,
    local_closed: bool,
}

impl MemoryPacketIo {
    fn mark_closed(&mut self) {
        if self.local_closed {
            return;
        }
        self.local_closed = true;
        self.core.closed.send_replace(true);
        let mut s = locknet(&self.net);
        if matches!(s.connections.get(&self.endpoints), Some(c) if c.id == self.link_id) {
            let (a, b) = self.endpoints.clone();
            s.sever_pair(&a, &b);
        }
    }
}

impl Drop for MemoryPacketIo {
    fn drop(&mut self) {
        self.mark_closed();
    }
}

#[async_trait]
impl PacketIo for MemoryPacketIo {
    fn mtu(&self) -> usize {
        self.core.mtu
    }

    async fn send_packet(&mut self, packet: &[u8], cancel: &CancellationToken) -> Result<()> {
        if packet.len() > self.core.mtu {
            return Err(TransportError::ResourceLimit(format!(
                "packet {} bytes exceeds mtu {}",
                packet.len(),
                self.core.mtu
            )));
        }
        let (delay, drop_nth, dc_after) = {
            let f = &locknet(&self.net).faults;
            (f.delay, f.drop_every_nth_packet, f.disconnect_after_packets)
        };
        if self.local_closed || *self.closed_rx.borrow() {
            return Err(TransportError::Disconnected);
        }
        let n = self.core.packets.fetch_add(1, Ordering::SeqCst) + 1;
        if dc_after.is_some_and(|limit| n > limit) {
            self.mark_closed();
            return Err(TransportError::Disconnected);
        }
        if drop_nth.is_some_and(|m| n.is_multiple_of(m)) {
            // Radio lost the packet; the sender sees success.
            return Ok(());
        }
        if !delay.is_zero() {
            tokio::select! {
                () = cancel.cancelled() => return Err(TransportError::Cancelled),
                _ = self.closed_rx.changed() => return Err(TransportError::Disconnected),
                () = tokio::time::sleep(delay) => {}
            }
        }
        tokio::select! {
            () = cancel.cancelled() => Err(TransportError::Cancelled),
            _ = self.closed_rx.changed() => Err(TransportError::Disconnected),
            permit = self.tx.reserve() => {
                match permit {
                    Ok(p) => {
                        p.send(packet.to_vec());
                        Ok(())
                    }
                    Err(_) => Err(TransportError::Disconnected),
                }
            }
        }
    }

    async fn recv_packet(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        if self.local_closed || *self.closed_rx.borrow() {
            return Err(TransportError::Disconnected);
        }
        tokio::select! {
            () = cancel.cancelled() => Err(TransportError::Cancelled),
            _ = self.closed_rx.changed() => Err(TransportError::Disconnected),
            pkt = self.rx.recv() => match pkt {
                Some(p) if *self.closed_rx.borrow() => {
                    drop(p);
                    Err(TransportError::Disconnected)
                }
                Some(p) => Ok(p),
                None => Err(TransportError::Disconnected),
            },
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.mark_closed();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "c2f60001-e7ca-4ac2-b6cd-10d5c0bf0001";

    fn svc() -> Uuid {
        Uuid::parse_str(SERVICE).unwrap()
    }

    fn cfg() -> LinkConfig {
        LinkConfig {
            max_frame_bytes: 4096,
            reassembly_timeout: Duration::from_millis(200),
        }
    }

    async fn pair(
        net: &MemoryNetwork,
    ) -> (
        MemoryTransport,
        MemoryTransport,
        Box<dyn PeerLink>,
        Box<dyn PeerLink>,
        PeerLocator,
        mpsc::Receiver<Box<dyn PeerLink>>,
    ) {
        let a = net.node("alice", cfg()).unwrap();
        let b = net.node("bob", cfg()).unwrap();
        b.start_advertising(svc()).await.unwrap();
        let mut watch = a.watch_peers().await.unwrap();
        let bob_locator = match watch.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!("expected Discovered"),
        };
        let accept = b.accept_links().await.unwrap();
        let c = CancellationToken::new();
        let a_link = a.connect(bob_locator.clone(), &c).await.unwrap();
        let mut accept = accept;
        let b_link = accept.recv().await.unwrap();
        (a, b, a_link, b_link, bob_locator, accept)
    }

    #[tokio::test]
    async fn discover_connect_and_bidirectional_fragmented_exchange() {
        let net = MemoryNetwork::new(20, 8).unwrap();
        let (_a, _b, mut a_link, mut b_link, _, _accept) = pair(&net).await;
        let c = CancellationToken::new();

        assert_eq!(a_link.role(), LinkRole::Initiator);
        assert_eq!(b_link.role(), LinkRole::Responder);
        assert_eq!(a_link.mtu(), 4096);

        // 20-byte packets -> 8-byte payload stride.
        let f1: Vec<u8> = (0u8..200).collect();
        let f2: Vec<u8> = (0u8..=255).cycle().take(37).collect();
        let f3 = b"hello blendr".to_vec();

        let (r1, r2) = tokio::join!(a_link.send_frame(&f1, &c), b_link.recv_frame(&c));
        r1.unwrap();
        assert_eq!(r2.unwrap(), f1);

        let (r1, r2) = tokio::join!(b_link.send_frame(&f2, &c), a_link.recv_frame(&c));
        r1.unwrap();
        assert_eq!(r2.unwrap(), f2);

        let (r1, r2) = tokio::join!(a_link.send_frame(&f3, &c), b_link.recv_frame(&c));
        r1.unwrap();
        assert_eq!(r2.unwrap(), f3);
    }

    #[tokio::test]
    async fn range_loss_severs_link_and_reconnect_is_clean() {
        let net = MemoryNetwork::new(20, 8).unwrap();
        let (a, b, mut a_link, mut b_link, bob_locator, mut accept) = pair(&net).await;
        let c = CancellationToken::new();

        net.set_in_range("alice", "bob", false).unwrap();
        // Both directions observe disconnection.
        let err = a_link.send_frame(b"still here?", &c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));
        let err = b_link.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));

        // Out of range: connect fails fast.
        let err = a
            .connect(bob_locator, &c)
            .await
            .err()
            .expect("connection must be rejected");
        assert!(matches!(err, TransportError::Timeout));

        // Back in range: reconnect resumes clean — no stale reassembly.
        net.set_in_range("alice", "bob", true).unwrap();
        let mut watch = a.watch_peers().await.unwrap();
        let loc2 = match watch.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!("expected Discovered"),
        };
        let mut a_link2 = a.connect(loc2, &c).await.unwrap();
        let mut b_link2 = accept.recv().await.unwrap();
        // A dropped responder endpoint must not block the reconnect above;
        // the fresh link resumes clean.
        let (s, r) = tokio::join!(
            a_link2.send_frame(b"back again", &c),
            b_link2.recv_frame(&c)
        );
        s.unwrap();
        assert_eq!(r.unwrap(), b"back again");
        drop(b);
    }

    #[tokio::test]
    async fn duplicate_connections_and_tie_break() {
        let net = MemoryNetwork::new(20, 8).unwrap();
        let (a, b, mut a_link, _b_link, bob_locator, _accept) = pair(&net).await;
        let c = CancellationToken::new();

        // Duplicate connect by the same initiator is rejected.
        let err = a
            .connect(bob_locator, &c)
            .await
            .err()
            .expect("connection must be rejected");
        assert!(matches!(err, TransportError::ResourceLimit(_)));

        // Simultaneous reverse attempt: "alice" initiated the existing link
        // and "alice" < "bob", so bob's attempt loses deterministically.
        // Bob needs Alice's locator; Alice never advertised. Give Alice one.
        a.start_advertising(svc()).await.unwrap();
        let mut bw = b.watch_peers().await.unwrap();
        let a_locator = loop {
            match bw.recv().await.unwrap() {
                PeerEvent::Discovered(l) => break l,
                PeerEvent::Lost(_) => continue,
            }
        };
        // Alice must be accepting for bob's connect to proceed far enough.
        let mut a_accept = a.accept_links().await.unwrap();
        let err = b
            .connect(a_locator, &c)
            .await
            .err()
            .expect("connection must be rejected");
        assert!(matches!(err, TransportError::ResourceLimit(_)));
        assert!(a_accept.try_recv().is_err());

        // Original link still works.
        a_link.send_frame(b"alive", &c).await.unwrap();
    }

    #[tokio::test]
    async fn tie_break_prefers_smaller_initiator() {
        // "zoe" connects first; then "amy" attempts and wins (amy < zoe), so
        // zoe's link is severed and amy's is established.
        let net = MemoryNetwork::new(20, 8).unwrap();
        let amy = net.node("amy", cfg()).unwrap();
        let zoe = net.node("zoe", cfg()).unwrap();
        amy.start_advertising(svc()).await.unwrap();
        let mut zoe_watch = zoe.watch_peers().await.unwrap();
        let amy_loc = match zoe_watch.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        let mut amy_accept = amy.accept_links().await.unwrap();
        let c = CancellationToken::new();
        let mut zoe_link = zoe.connect(amy_loc, &c).await.unwrap();
        let mut amy_side = amy_accept.recv().await.unwrap();

        // Zoe's link works before the competing attempt.
        let (s, r) = tokio::join!(zoe_link.send_frame(b"one", &c), amy_side.recv_frame(&c));
        s.unwrap();
        assert_eq!(r.unwrap(), b"one");

        // Now amy tries to connect to zoe; zoe never advertised, so give zoe
        // a beacon. amy's attempt wins the tie-break (amy < zoe).
        zoe.start_advertising(svc()).await.unwrap();
        let mut amy_watch = amy.watch_peers().await.unwrap();
        let zoe_loc = match amy_watch.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        let mut zoe_accept = zoe.accept_links().await.unwrap();
        let mut amy_link = amy.connect(zoe_loc, &c).await.unwrap();
        let mut zoe_side = zoe_accept.recv().await.unwrap();

        // Old link is severed.
        let err = zoe_link.send_frame(b"dead", &c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));
        let err = amy_side.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));

        // New link is clean.
        let (s, r) = tokio::join!(amy_link.send_frame(b"winner", &c), zoe_side.recv_frame(&c));
        s.unwrap();
        assert_eq!(r.unwrap(), b"winner");
    }

    #[tokio::test]
    async fn accept_queue_backpressure_rejects_surplus() {
        let net = MemoryNetwork::new(20, 1).unwrap(); // accept queue cap = 1
        let a = net.node("a", cfg()).unwrap();
        let b = net.node("b", cfg()).unwrap();
        let hub = net.node("hub", cfg()).unwrap();
        hub.start_advertising(svc()).await.unwrap();
        let mut aw = a.watch_peers().await.unwrap();
        let hub_loc = match aw.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        let _accept = hub.accept_links().await.unwrap();
        let c = CancellationToken::new();
        a.connect(hub_loc.clone(), &c).await.unwrap();
        // Second connect: hub's accept queue is full AND a-b different pair.
        let err = b
            .connect(hub_loc, &c)
            .await
            .err()
            .expect("connection must be rejected");
        assert!(matches!(err, TransportError::ResourceLimit(_)));
    }

    #[tokio::test]
    async fn faults_drop_packets_and_disconnect() {
        // disconnect_after_packets: sever after N accepted packets.
        let net = MemoryNetwork::new(20, 64).unwrap();
        let (_a, _b, mut a_link, mut b_link, _) = {
            let a = net.node("a", cfg()).unwrap();
            let b = net.node("b", cfg()).unwrap();
            b.start_advertising(svc()).await.unwrap();
            let mut w = a.watch_peers().await.unwrap();
            let loc = match w.recv().await.unwrap() {
                PeerEvent::Discovered(l) => l,
                _ => panic!(),
            };
            let mut acc = b.accept_links().await.unwrap();
            let c = CancellationToken::new();
            let al = a.connect(loc, &c).await.unwrap();
            let bl = acc.recv().await.unwrap();
            (a, b, al, bl, ())
        };
        net.set_faults(MemoryFaults {
            disconnect_after_packets: Some(2),
            ..Default::default()
        })
        .unwrap();
        let c = CancellationToken::new();
        // More than two packets: the configured third packet severs the link.
        let err = a_link.send_frame(&[1u8; 24], &c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));
        let err = b_link.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));

        // drop_every_nth_packet: silent loss triggers reassembly timeout.
        let net2 = MemoryNetwork::new(20, 64).unwrap();
        let a2 = net2.node("a", cfg()).unwrap();
        let b2 = net2.node("b", cfg()).unwrap();
        b2.start_advertising(svc()).await.unwrap();
        let mut w2 = a2.watch_peers().await.unwrap();
        let loc2 = match w2.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        let mut acc2 = b2.accept_links().await.unwrap();
        let mut al2 = a2.connect(loc2, &c).await.unwrap();
        let mut bl2 = acc2.recv().await.unwrap();
        net2.set_faults(MemoryFaults {
            drop_every_nth_packet: Some(2),
            ..Default::default()
        })
        .unwrap();
        let frame = vec![7u8; 2 * (20 - crate::FRAGMENT_HEADER_LEN)];
        al2.send_frame(&frame, &c).await.unwrap(); // second of two fragments dropped
        let err = bl2.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Timeout));
    }

    #[tokio::test]
    async fn stop_advertising_emits_lost_and_revokes_locator() {
        let net = MemoryNetwork::new(64, 8).unwrap();
        let a = net.node("a", cfg()).unwrap();
        let b = net.node("b", cfg()).unwrap();
        b.start_advertising(svc()).await.unwrap();
        let mut w = a.watch_peers().await.unwrap();
        let loc = match w.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        b.stop_advertising().await.unwrap();
        match w.recv().await.unwrap() {
            PeerEvent::Lost(l) => assert_eq!(l, loc),
            _ => panic!("expected Lost"),
        }
        let c = CancellationToken::new();
        let err = a
            .connect(loc, &c)
            .await
            .err()
            .expect("connection must be rejected");
        assert!(matches!(err, TransportError::Platform(_)));
    }

    #[tokio::test]
    async fn shutdown_disconnects_peers() {
        let net = MemoryNetwork::new(64, 8).unwrap();
        let a = net.node("a", cfg()).unwrap();
        let b = net.node("b", cfg()).unwrap();
        b.start_advertising(svc()).await.unwrap();
        let mut w = a.watch_peers().await.unwrap();
        let loc = match w.recv().await.unwrap() {
            PeerEvent::Discovered(l) => l,
            _ => panic!(),
        };
        let mut acc = b.accept_links().await.unwrap();
        let c = CancellationToken::new();
        let _al = a.connect(loc, &c).await.unwrap();
        let mut bl = acc.recv().await.unwrap();
        b.shutdown();
        let err = bl.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));
        let err = b.start_advertising(svc()).await.unwrap_err();
        assert!(matches!(err, TransportError::Platform(_)));
    }
}
