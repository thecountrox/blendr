//! `blendr-transport` — transport boundary for the Blendr node.
//!
//! This crate defines the platform-neutral traits the protocol core uses
//! ([`BleTransport`], [`PeerLink`], [`PacketIo`]) and the single shared
//! `BLENDR/1` fragment framing ([`FramedLink`]) used identically by the BlueZ
//! adapter and the in-memory simulator ([`memory`]).
//!
//! # Wire format (`BLENDR/1`)
//!
//! ATT payloads are small; with a 20-byte MTU only ~17 bytes are usable after
//! opcode/attribute overhead. Every packet is a fragment with a fixed 13-byte
//! header, leaving 7 payload bytes at the legacy 20-byte size:
//!
//! ```text
//! 0        2     3        4      5          7           9        13
//! +--------+-----+--------+------+----------+-----------+--------+
//! | "B1"   | ver | flags  | seq  | frag_idx | frag_cnt  | frame_len |
//! +--------+-----+--------+------+----------+-----------+--------+
//! |                fragment payload (stride bytes max)            |
//! +---------------------------------------------------------------+
//! ```
//!
//! * `ver` is `0x01`; `flags` bit0 = START (frag_idx == 0), bit1 = END
//!   (frag_idx == frag_cnt - 1). All reserved bits must be zero.
//! * `seq` is a per-link frame counter that wraps modulo 256; consecutive
//!   frames carry consecutive `seq` values.
//! * `frag_idx`/`frag_cnt` and `frame_len` are big-endian. `frag_cnt` is
//!   derived from `frame_len` and the fragment stride; every non-last
//!   fragment carries exactly `stride` payload bytes.
//! * Reassembly is strictly sequential. Out-of-order, duplicated, oversized,
//!   or contradictory fragments are rejected with
//!   [`TransportError::InvalidFrame`], the partial frame is discarded, and the
//!   link is unfit for further use. Cancellation or
//!   `reassembly_timeout` mid-frame discards the partial frame and leaves the
//!   link usable for the next frame.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub mod memory;

/// `BLENDR/1` fragment header length in bytes. A link whose packet MTU is
/// no larger than this cannot carry any payload and is rejected.
pub const FRAGMENT_HEADER_LEN: usize = 13;

const MAGIC: [u8; 2] = *b"B1";
const WIRE_VERSION: u8 = 1;
const FLAG_START: u8 = 0b0000_0001;
const FLAG_END: u8 = 0b0000_0010;
const KNOWN_FLAGS: u8 = FLAG_START | FLAG_END;

/// Maximum fragment count representable in the wire header.
const MAX_FRAGMENTS: usize = u16::MAX as usize;
/// Maximum frame length representable in the wire header.
const MAX_WIRE_FRAME_LEN: u64 = u32::MAX as u64;

/// Errors produced by transports and links.
///
/// Variants are intentionally coarse; `String` payloads carry non-secret
/// diagnostic detail only.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The operation was cancelled through its [`CancellationToken`].
    #[error("operation cancelled")]
    Cancelled,
    /// The link or link setup was severed: peer went out of range, closed the
    /// connection, or the radio path was lost.
    #[error("link disconnected")]
    Disconnected,
    /// A bounded wait expired (for example, frame reassembly timed out).
    #[error("operation timed out")]
    Timeout,
    /// A wire fragment or frame violated the `BLENDR/1` format.
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    /// A bounded resource (queue, frame size, fragment count) was exhausted.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    /// Platform-specific failure not covered by the other variants.
    #[error("platform error: {0}")]
    Platform(String),
}

/// Transport result type. The error parameter defaults to [`TransportError`]
/// but can be overridden where a wider error is needed.
pub type Result<T, E = TransportError> = std::result::Result<T, E>;

/// Opaque transport-layer address of a discovered peer.
///
/// The content is transport-specific (for example a BlueZ object path or an
/// in-memory rendezvous token). It is NEVER a Blendr identity: never parse a
/// BID out of it, never persist it across sessions, and never log it in a way
/// that confuses it with identity. `Debug` is intentionally redacted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PeerLocator(pub String);

impl PeerLocator {
    /// Borrow the opaque locator payload.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PeerLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerLocator(<redacted>)")
    }
}

/// Which side of a link this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    /// This endpoint initiated the connection.
    Initiator,
    /// This endpoint accepted the connection.
    Responder,
}

/// Peer visibility events from scanning/discovery.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// A candidate peer advertising the Blendr service came into view.
    Discovered(PeerLocator),
    /// A previously discovered peer vanished (range loss, stopped advertising).
    Lost(PeerLocator),
}

/// One end of a framed link to a single peer.
///
/// Frames are whole application messages; fragmentation over short packets is
/// the transport's problem. All async methods accept a [`CancellationToken`]
/// and return [`TransportError::Cancelled`] promptly when it fires.
#[async_trait]
pub trait PeerLink: Send {
    /// Opaque transport address of the remote peer.
    fn locator(&self) -> &PeerLocator;
    /// Whether this endpoint initiated or accepted the link.
    fn role(&self) -> LinkRole;
    /// Maximum application frame size in bytes this link accepts.
    fn mtu(&self) -> usize;
    /// Send one complete frame, fragmenting as needed.
    async fn send_frame(&mut self, frame: &[u8], cancel: &CancellationToken) -> Result<()>;
    /// Receive one complete reassembled frame.
    async fn recv_frame(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>>;
    /// Close the link; idempotent.
    async fn close(&mut self) -> Result<()>;
}

/// The platform BLE transport adapter.
///
/// Concrete adapters: `blendr-bluez` (Linux/BlueZ), [`memory::MemoryTransport`]
/// (simulator), and later a Kotlin/JNI adapter on Android.
#[async_trait]
pub trait BleTransport: Send + Sync {
    /// Start advertising the given Blendr service UUID (service-only beacon).
    async fn start_advertising(&self, service: Uuid) -> Result<()>;
    /// Stop advertising.
    async fn stop_advertising(&self) -> Result<()>;
    /// Open a bounded stream of peer discovery events.
    async fn watch_peers(&self) -> Result<mpsc::Receiver<PeerEvent>>;
    /// Connect to a discovered peer; returns the initiator-side framed link.
    async fn connect(
        &self,
        peer: PeerLocator,
        cancel: &CancellationToken,
    ) -> Result<Box<dyn PeerLink>>;
    /// Open a bounded queue of inbound accepted links (responder side).
    async fn accept_links(&self) -> Result<mpsc::Receiver<Box<dyn PeerLink>>>;
}

/// Byte-packet sink/source used by [`FramedLink`].
///
/// One `PacketIo` call = one atomic packet delivery up to `mtu()` bytes.
/// Ordering is guaranteed (BLE writes/notifies on one characteristic are
/// ordered); duplication and loss are not.
#[async_trait]
pub trait PacketIo: Send {
    /// Maximum packet size in bytes accepted by `send_packet`.
    fn mtu(&self) -> usize;
    /// Send one packet; fails with [`TransportError::ResourceLimit`] if
    /// `packet.len() > mtu()`. May block on bounded-queue backpressure.
    async fn send_packet(&mut self, packet: &[u8], cancel: &CancellationToken) -> Result<()>;
    /// Receive the next packet; [`TransportError::Disconnected`] when the link
    /// is gone.
    async fn recv_packet(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>>;
    /// Close the packet path; idempotent.
    async fn close(&mut self) -> Result<()>;
}

/// Framing limits for [`FramedLink`].
#[derive(Debug, Clone, Copy)]
pub struct LinkConfig {
    /// Maximum application frame size in bytes. Larger sends and larger
    /// declared incoming frames are rejected before allocation.
    pub max_frame_bytes: usize,
    /// Maximum wait between consecutive fragments of one frame. Expiry
    /// discards the partial frame and returns [`TransportError::Timeout`].
    pub reassembly_timeout: Duration,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            // Default application frame budget for v1.
            max_frame_bytes: 256 * 1024,
            reassembly_timeout: Duration::from_secs(10),
        }
    }
}

impl LinkConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_frame_bytes == 0 {
            return Err(TransportError::ResourceLimit(
                "max_frame_bytes must be non-zero".into(),
            ));
        }
        if self.max_frame_bytes as u64 > MAX_WIRE_FRAME_LEN {
            return Err(TransportError::ResourceLimit(
                "max_frame_bytes exceeds the u32 wire ceiling".into(),
            ));
        }
        if self.reassembly_timeout.is_zero() {
            return Err(TransportError::ResourceLimit(
                "reassembly_timeout must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

struct FragmentHeader {
    flags: u8,
    seq: u8,
    index: u16,
    count: u16,
    frame_len: u32,
}

fn encode_header(buf: &mut Vec<u8>, h: &FragmentHeader) {
    buf.reserve(FRAGMENT_HEADER_LEN);
    buf.extend_from_slice(&MAGIC);
    buf.push(WIRE_VERSION);
    buf.push(h.flags);
    buf.push(h.seq);
    buf.extend_from_slice(&h.index.to_be_bytes());
    buf.extend_from_slice(&h.count.to_be_bytes());
    buf.extend_from_slice(&h.frame_len.to_be_bytes());
}

fn decode_header(packet: &[u8]) -> Result<FragmentHeader> {
    if packet.len() < FRAGMENT_HEADER_LEN {
        return Err(TransportError::InvalidFrame(
            "fragment shorter than header".into(),
        ));
    }
    if !packet.starts_with(&MAGIC) {
        return Err(TransportError::InvalidFrame("bad magic".into()));
    }
    if packet[2] != WIRE_VERSION {
        return Err(TransportError::InvalidFrame(format!(
            "unsupported wire version {}",
            packet[2]
        )));
    }
    let flags = packet[3];
    if flags & !KNOWN_FLAGS != 0 {
        return Err(TransportError::InvalidFrame(format!(
            "reserved flag bits set: {flags:#04x}"
        )));
    }
    let index = u16::from_be_bytes([packet[5], packet[6]]);
    let count = u16::from_be_bytes([packet[7], packet[8]]);
    let frame_len = u32::from_be_bytes([packet[9], packet[10], packet[11], packet[12]]);
    if count == 0 {
        return Err(TransportError::InvalidFrame("frag_cnt is zero".into()));
    }
    if index >= count {
        return Err(TransportError::InvalidFrame(format!(
            "frag_idx {index} out of frag_cnt {count}"
        )));
    }
    // START iff first fragment; END iff last fragment.
    if (flags & FLAG_START != 0) != (index == 0) {
        return Err(TransportError::InvalidFrame(
            "START flag disagrees with frag_idx".into(),
        ));
    }
    if (flags & FLAG_END != 0) != (index == count - 1) {
        return Err(TransportError::InvalidFrame(
            "END flag disagrees with frag_idx/frag_cnt".into(),
        ));
    }
    if frame_len == 0 {
        return Err(TransportError::InvalidFrame("frame_len is zero".into()));
    }
    if index == 0 && packet.len() == FRAGMENT_HEADER_LEN {
        return Err(TransportError::InvalidFrame(
            "first fragment carries no payload".into(),
        ));
    }
    Ok(FragmentHeader {
        flags,
        seq: packet[4],
        index,
        count,
        frame_len,
    })
}

/// In-progress reassembly state. At most one partial frame is ever held.
struct PartialFrame {
    seq: u8,
    buf: Vec<u8>,
    /// Payload bytes per non-last fragment, taken from fragment 0.
    stride: usize,
    /// Index of the next expected fragment.
    next_index: u16,
    /// Expected total fragment count.
    count: u16,
}

/// Shared bounded deterministic `BLENDR/1` framing over a [`PacketIo`].
///
/// `FramedLink` is constructed identically by the BlueZ adapter and
/// [`memory::MemoryTransport`], so both expose exactly the same [`PeerLink`]
/// semantics:
///
/// * sends fragment a frame by the packet `mtu()` of the link;
/// * at most one frame is reassembled at a time and the reassembly buffer is
///   allocated only after `frame_len` passes `max_frame_bytes`;
/// * order, duplicates, truncation, size contradictions, and header violations
///   are hard [`TransportError::InvalidFrame`] errors;
/// * cancellation or `reassembly_timeout` discards the partial frame and the
///   next `recv_frame` starts fresh.
pub struct FramedLink<T: PacketIo> {
    io: T,
    locator: PeerLocator,
    role: LinkRole,
    config: LinkConfig,
    send_seq: u8,
    recv_state: Option<PartialFrame>,
}

impl<T: PacketIo> FramedLink<T> {
    /// Validate config and packet MTU; the packet channel must already exist.
    pub fn new(io: T, locator: PeerLocator, role: LinkRole, config: LinkConfig) -> Result<Self> {
        config.validate()?;
        if io.mtu() <= FRAGMENT_HEADER_LEN {
            return Err(TransportError::ResourceLimit(format!(
                "packet mtu {} smaller than fragment header {FRAGMENT_HEADER_LEN}",
                io.mtu()
            )));
        }
        Ok(Self {
            io,
            locator,
            role,
            config,
            send_seq: 0,
            recv_state: None,
        })
    }

    fn stride(&self) -> usize {
        self.io.mtu() - FRAGMENT_HEADER_LEN
    }

    /// Apply one decoded fragment to reassembly state. Returns the complete
    /// frame when the last fragment lands.
    fn ingest(&mut self, h: &FragmentHeader, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        if h.index == 0 {
            if self.recv_state.is_some() {
                // A new frame start while another is incomplete is a protocol
                // violation (a compliant sender finished or the link died).
                self.recv_state = None;
                return Err(TransportError::InvalidFrame(
                    "new frame started while reassembly incomplete".into(),
                ));
            }
            let frame_len = h.frame_len as usize;
            if frame_len > self.config.max_frame_bytes {
                return Err(TransportError::InvalidFrame(format!(
                    "declared frame_len {frame_len} exceeds max {}",
                    self.config.max_frame_bytes
                )));
            }
            let stride = payload.len();
            if stride == 0 {
                return Err(TransportError::InvalidFrame(
                    "first fragment carries no payload".into(),
                ));
            }
            if stride > frame_len {
                return Err(TransportError::InvalidFrame(format!(
                    "first fragment payload {stride} exceeds frame_len {frame_len}"
                )));
            }
            let expected_count = frame_len.div_ceil(stride);
            if expected_count != h.count as usize {
                return Err(TransportError::InvalidFrame(format!(
                    "frag_cnt {} disagrees with frame_len {frame_len} and stride {stride}",
                    h.count
                )));
            }
            if h.count == 1 {
                if frame_len != stride {
                    return Err(TransportError::InvalidFrame(format!(
                        "single-fragment frame_len {frame_len} != payload {stride}"
                    )));
                }
                return Ok(Some(payload.to_vec()));
            }
            let mut buf = vec![0u8; frame_len];
            buf[..stride].copy_from_slice(payload);
            self.recv_state = Some(PartialFrame {
                seq: h.seq,
                buf,
                stride,
                next_index: 1,
                count: h.count,
            });
            return Ok(None);
        }

        let Some(p) = &mut self.recv_state else {
            return Err(TransportError::InvalidFrame(
                "continuation fragment without a frame in progress".into(),
            ));
        };
        if h.seq != p.seq {
            let err = TransportError::InvalidFrame(format!(
                "fragment seq {} while reassembling seq {}",
                h.seq, p.seq
            ));
            self.recv_state = None;
            return Err(err);
        }
        if h.count != p.count {
            let err = TransportError::InvalidFrame(format!(
                "frag_cnt {} disagrees with frame start {}",
                h.count, p.count
            ));
            self.recv_state = None;
            return Err(err);
        }
        if h.index != p.next_index {
            let err = TransportError::InvalidFrame(format!(
                "fragment {} while expecting {} (out-of-order or duplicate)",
                h.index, p.next_index
            ));
            self.recv_state = None;
            return Err(err);
        }
        let offset = h.index as usize * p.stride;
        let last = h.index == p.count - 1;
        let expected_payload = if last { p.buf.len() - offset } else { p.stride };
        if payload.len() != expected_payload {
            self.recv_state = None;
            return Err(TransportError::InvalidFrame(format!(
                "fragment {} payload {} bytes, expected {}",
                h.index,
                payload.len(),
                expected_payload
            )));
        }
        p.buf[offset..offset + payload.len()].copy_from_slice(payload);
        p.next_index += 1;
        if last {
            let done = self.recv_state.take().expect("state checked above");
            Ok(Some(done.buf))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl<T: PacketIo> PeerLink for FramedLink<T> {
    fn locator(&self) -> &PeerLocator {
        &self.locator
    }

    fn role(&self) -> LinkRole {
        self.role
    }

    /// Maximum application frame size (not the packet MTU).
    fn mtu(&self) -> usize {
        self.config.max_frame_bytes
    }

    async fn send_frame(&mut self, frame: &[u8], cancel: &CancellationToken) -> Result<()> {
        if frame.is_empty() {
            return Err(TransportError::InvalidFrame(
                "empty frames are not representable in BLENDR/1".into(),
            ));
        }
        if frame.len() > self.config.max_frame_bytes {
            return Err(TransportError::InvalidFrame(format!(
                "frame {} bytes exceeds max {}",
                frame.len(),
                self.config.max_frame_bytes
            )));
        }
        let stride = self.stride();
        let count = frame.len().div_ceil(stride);
        if count > MAX_FRAGMENTS {
            return Err(TransportError::InvalidFrame(format!(
                "frame needs {count} fragments, wire maximum is {MAX_FRAGMENTS}"
            )));
        }
        let seq = self.send_seq;
        for index in 0..count {
            let start = index * stride;
            let end = (start + stride).min(frame.len());
            let mut flags = 0u8;
            if index == 0 {
                flags |= FLAG_START;
            }
            if index == count - 1 {
                flags |= FLAG_END;
            }
            let header = FragmentHeader {
                flags,
                seq,
                index: index as u16,
                count: count as u16,
                frame_len: frame.len() as u32,
            };
            let mut packet = Vec::with_capacity(FRAGMENT_HEADER_LEN + (end - start));
            encode_header(&mut packet, &header);
            packet.extend_from_slice(&frame[start..end]);
            self.io.send_packet(&packet, cancel).await?;
        }
        // seq advances only once the whole frame went out.
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(())
    }

    async fn recv_frame(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
        loop {
            let in_progress = self.recv_state.is_some();
            let packet = {
                let recv = self.io.recv_packet(cancel);
                tokio::pin!(recv);
                if in_progress {
                    match tokio::time::timeout(self.config.reassembly_timeout, &mut recv).await {
                        Ok(r) => r,
                        Err(_) => {
                            self.recv_state = None;
                            return Err(TransportError::Timeout);
                        }
                    }
                } else {
                    recv.await
                }
            };
            let packet = match packet {
                Ok(p) => p,
                Err(e) => {
                    // Any receive failure (Cancelled, Disconnected) discards
                    // the incomplete frame.
                    self.recv_state = None;
                    return Err(e);
                }
            };
            let header = decode_header(&packet)?;
            if let Some(frame) = self.ingest(&header, &packet[FRAGMENT_HEADER_LEN..])? {
                return Ok(frame);
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.recv_state = None;
        self.io.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory `PacketIo` pair for framing tests: the exact same
    /// channel shape the BlueZ characteristic notifies/writes provide.
    struct PipeIo {
        mtu: usize,
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    fn pipe(mtu: usize) -> (PipeIo, PipeIo) {
        let (ab_tx, ab_rx) = mpsc::channel(8);
        let (ba_tx, ba_rx) = mpsc::channel(8);
        (
            PipeIo {
                mtu,
                tx: ab_tx,
                rx: ba_rx,
            },
            PipeIo {
                mtu,
                tx: ba_tx,
                rx: ab_rx,
            },
        )
    }

    #[async_trait]
    impl PacketIo for PipeIo {
        fn mtu(&self) -> usize {
            self.mtu
        }
        async fn send_packet(&mut self, packet: &[u8], cancel: &CancellationToken) -> Result<()> {
            if packet.len() > self.mtu {
                return Err(TransportError::ResourceLimit("packet exceeds mtu".into()));
            }
            tokio::select! {
                () = cancel.cancelled() => Err(TransportError::Cancelled),
                r = self.tx.send(packet.to_vec()) => r.map_err(|_| TransportError::Disconnected),
            }
        }
        async fn recv_packet(&mut self, cancel: &CancellationToken) -> Result<Vec<u8>> {
            tokio::select! {
                () = cancel.cancelled() => Err(TransportError::Cancelled),
                r = self.rx.recv() => r.ok_or(TransportError::Disconnected),
            }
        }
        async fn close(&mut self) -> Result<()> {
            // Replacing the tx half with a dead channel severs the peer's
            // receive path.
            let (stub_tx, _stub_rx) = mpsc::channel(1);
            self.tx = stub_tx;
            Ok(())
        }
    }

    fn link_pair(mtu: usize, config: LinkConfig) -> (FramedLink<PipeIo>, FramedLink<PipeIo>) {
        let (a_io, b_io) = pipe(mtu);
        let a = FramedLink::new(
            a_io,
            PeerLocator("peer-b".into()),
            LinkRole::Initiator,
            config,
        )
        .unwrap();
        let b = FramedLink::new(
            b_io,
            PeerLocator("peer-a".into()),
            LinkRole::Responder,
            config,
        )
        .unwrap();
        (a, b)
    }

    fn nocancel() -> CancellationToken {
        CancellationToken::new()
    }

    #[tokio::test]
    async fn fragmented_bidirectional_roundtrip_at_20_byte_packets() {
        let (mut a, mut b) = link_pair(20, LinkConfig::default());
        let c = nocancel();

        // 20-byte packet MTU -> 8 payload bytes per fragment.
        let frame_a2b: Vec<u8> = (0u8..64).collect(); // 8 fragments
        let frame_b2a: Vec<u8> = (0u8..100).map(|x| x ^ 0x5a).collect(); // 13 fragments

        let send_a = a.send_frame(&frame_a2b, &c);
        let recv_b = b.recv_frame(&c);
        let (sa, rb) = tokio::join!(send_a, recv_b);
        sa.unwrap();
        assert_eq!(rb.unwrap(), frame_a2b);

        let send_b = b.send_frame(&frame_b2a, &c);
        let recv_a = a.recv_frame(&c);
        let (sb, ra) = tokio::join!(send_b, recv_a);
        sb.unwrap();
        assert_eq!(ra.unwrap(), frame_b2a);
    }

    #[tokio::test]
    async fn size_boundaries_exact_stride_and_single_fragment() {
        let (mut a, mut b) = link_pair(20, LinkConfig::default());
        let c = nocancel();
        for len in [1usize, 7, 8, 9, 16, 17] {
            let frame: Vec<u8> = (0..len).map(|i| i as u8).collect();
            a.send_frame(&frame, &c).await.unwrap();
            assert_eq!(b.recv_frame(&c).await.unwrap(), frame);
        }
    }

    #[tokio::test]
    async fn rejects_oversize_frame_before_sending() {
        let (mut a, _b) = link_pair(
            20,
            LinkConfig {
                max_frame_bytes: 16,
                ..Default::default()
            },
        );
        let c = nocancel();
        let err = a.send_frame(&[0u8; 17], &c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));
        // Empty frames are not representable either.
        let err = a.send_frame(&[], &c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));
    }

    /// Build one wire fragment packet for `frame` at `stride` chunk `index` of
    /// `count` with the given `seq`.
    fn make_fragment(seq: u8, index: u16, count: u16, frame: &[u8], stride: usize) -> Vec<u8> {
        let mut flags = 0u8;
        if index == 0 {
            flags |= FLAG_START;
        }
        if index == count - 1 {
            flags |= FLAG_END;
        }
        let start = index as usize * stride;
        let end = (start + stride).min(frame.len());
        let mut p = Vec::new();
        encode_header(
            &mut p,
            &FragmentHeader {
                flags,
                seq,
                index,
                count,
                frame_len: frame.len() as u32,
            },
        );
        p.extend_from_slice(&frame[start..end]);
        p
    }

    #[tokio::test]
    async fn rejects_bad_magic_version_flags_and_truncation() {
        let (mut probe, mut sink) = link_pair(20, LinkConfig::default());
        let c = nocancel();

        // Bad magic.
        let mut bad = make_fragment(0, 0, 1, b"test", 8);
        bad[0] = b'X';
        probe.io.send_packet(&bad, &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Unknown version.
        let mut v = make_fragment(0, 0, 1, b"test", 8);
        v[2] = 9;
        probe.io.send_packet(&v, &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Reserved flag bits.
        let mut f = make_fragment(0, 0, 1, b"test", 8);
        f[3] |= 0x80;
        probe.io.send_packet(&f, &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Truncated fragment (shorter than header).
        probe.io.send_packet(&[b'B', b'1', 1], &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));
    }

    #[tokio::test]
    async fn rejects_out_of_order_and_duplicate_fragments() {
        let (mut probe, mut sink) = link_pair(20, LinkConfig::default());
        let c = nocancel();

        // Exactly three fragments at the configured packet capacity.
        let stride = 20 - FRAGMENT_HEADER_LEN;
        let frame = vec![0xabu8; 3 * stride];
        let frags: Vec<Vec<u8>> = (0..3)
            .map(|i| make_fragment(0, i, 3, &frame, stride))
            .collect();

        // Out-of-order: frag 0 then frag 2.
        probe.io.send_packet(&frags[0], &c).await.unwrap();
        probe.io.send_packet(&frags[2], &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Duplicate: frag 0, frag 1, frag 1.
        probe.io.send_packet(&frags[0], &c).await.unwrap();
        probe.io.send_packet(&frags[1], &c).await.unwrap();
        probe.io.send_packet(&frags[1], &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Continuation with no frame in progress.
        probe.io.send_packet(&frags[1], &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));

        // Wrong seq mid-frame.
        let mut wrong_seq = frags[1].clone();
        wrong_seq[4] = 7;
        probe.io.send_packet(&frags[0], &c).await.unwrap();
        probe.io.send_packet(&wrong_seq, &c).await.unwrap();
        let err = sink.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));
    }

    #[tokio::test]
    async fn partial_frame_times_out_and_link_recovers() {
        let (mut a, mut b) = link_pair(
            20,
            LinkConfig {
                reassembly_timeout: Duration::from_millis(30),
                ..Default::default()
            },
        );
        let c = nocancel();

        // Send only the first fragment of a two-fragment frame.
        let frame = vec![b'0'; 2 * (20 - FRAGMENT_HEADER_LEN)];
        let frag0 = make_fragment(9, 0, 2, &frame, 20 - FRAGMENT_HEADER_LEN);
        a.io.send_packet(&frag0, &c).await.unwrap();

        let err = b.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Timeout));

        // Partial frame was discarded: the link still works.
        let clean = *b"short frame after timeout!!";
        a.send_frame(&clean, &c).await.unwrap();
        assert_eq!(b.recv_frame(&c).await.unwrap(), clean);
    }

    #[tokio::test]
    async fn cancellation_discards_partial_frame() {
        let (mut a, mut b) = link_pair(20, LinkConfig::default());
        let cancel = CancellationToken::new();
        let child = cancel.clone();

        let frame = vec![0xabu8; 2 * (20 - FRAGMENT_HEADER_LEN)];
        let frag0 = make_fragment(0, 0, 2, &frame, 20 - FRAGMENT_HEADER_LEN);
        a.io.send_packet(&frag0, &cancel).await.unwrap();

        let recv = tokio::spawn(async move {
            let c2 = child;
            b.recv_frame(&c2).await
        });
        tokio::task::yield_now().await;
        // Let the first fragment land, then cancel mid-wait.
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();
        let err = recv.await.unwrap().unwrap_err();
        assert!(matches!(err, TransportError::Cancelled));

        // Reconnect-style recovery: a fresh link pair works.
        let (mut a2, mut b2) = link_pair(20, LinkConfig::default());
        let c = nocancel();
        a2.send_frame(b"recovered", &c).await.unwrap();
        assert_eq!(b2.recv_frame(&c).await.unwrap(), b"recovered");
    }

    #[tokio::test]
    async fn disconnect_mid_frame_returns_disconnected_and_discards() {
        let (mut a, mut b) = link_pair(20, LinkConfig::default());
        let c = nocancel();

        let frame = vec![0xabu8; 2 * (20 - FRAGMENT_HEADER_LEN)];
        let frag0 = make_fragment(0, 0, 2, &frame, 20 - FRAGMENT_HEADER_LEN);
        a.io.send_packet(&frag0, &c).await.unwrap();
        a.io.close().await.unwrap();

        let err = b.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::Disconnected));
    }

    #[tokio::test]
    async fn declared_frame_len_over_max_is_rejected_before_alloc() {
        let (mut a, mut b) = link_pair(
            20,
            LinkConfig {
                max_frame_bytes: 64,
                ..Default::default()
            },
        );
        let c = nocancel();
        let mut frag0 = Vec::new();
        encode_header(
            &mut frag0,
            &FragmentHeader {
                flags: FLAG_START,
                seq: 0,
                index: 0,
                count: 2,
                frame_len: 1_000_000,
            },
        );
        frag0.extend_from_slice(&b"12345678"[..20 - FRAGMENT_HEADER_LEN]);
        a.io.send_packet(&frag0, &c).await.unwrap();
        let err = b.recv_frame(&c).await.unwrap_err();
        assert!(matches!(err, TransportError::InvalidFrame(_)));
    }

    #[tokio::test]
    async fn send_seq_wraps_at_256() {
        let (mut a, mut b) = link_pair(64, LinkConfig::default());
        let c = nocancel();
        for i in 0..260u32 {
            let frame = format!("frame-{i}").into_bytes();
            a.send_frame(&frame, &c).await.unwrap();
            assert_eq!(b.recv_frame(&c).await.unwrap(), frame);
        }
    }

    #[tokio::test]
    async fn packet_mtu_below_header_rejected() {
        let (a_io, _b_io) = pipe(FRAGMENT_HEADER_LEN - 1);
        let err = FramedLink::new(
            a_io,
            PeerLocator("x".into()),
            LinkRole::Initiator,
            LinkConfig::default(),
        )
        .err()
        .expect("invalid MTU must be rejected");
        assert!(matches!(err, TransportError::ResourceLimit(_)));
    }
}
