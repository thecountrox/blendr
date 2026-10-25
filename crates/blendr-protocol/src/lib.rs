//! Blendr direct protocol v1. Noise XX authenticates the signed BIS document's
//! X25519 static key; role/nonces/transcript proofs and encrypted capabilities
//! complete authentication before any application frame is exposed. There is no
//! plaintext or unauthenticated fallback. Ordered Noise nonces reject replay.
//!
//! Wire objects use fixed, definite-length canonical CBOR arrays. The parser
//! rejects nonminimal lengths/integers, indefinite values, extra fields/trailing
//! bytes and oversized fields before allocating. Only direct messaging, distinct
//! link/destination receipts, transfer-turn markers and goodbye are supported.
//! HPKE protects persisted messages independently of the live session. Expiry
//! policy is deliberately a caller responsibility so old history stays readable.

mod broadcast;
mod codec;
mod envelope;
mod session;
#[cfg(test)]
mod tests;

pub use broadcast::{BroadcastEnvelope, seal_broadcast};
pub use envelope::{Envelope, EnvelopeMetadata, Receipt, ReceiptKind, open_message, seal_message};
pub use session::{SecureSession, authenticate};

use codec::{Reader, Writer};
use thiserror::Error;

pub const MIN_SECURE_FRAME_BYTES: usize = 1024;
pub const MAX_SECURE_FRAME_BYTES: usize = 65535;
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = MAX_SECURE_FRAME_BYTES - TAG_BYTES - 6;
const TAG_BYTES: usize = 16;

/// Largest envelope carried in a Message frame at this ciphertext ceiling.
/// Invalid (too-small) ceilings carry no messages; Noise always caps at 65535.
pub fn max_message_bytes(frame_bytes: usize) -> usize {
    if frame_bytes < MIN_SECURE_FRAME_BYTES {
        return 0;
    }
    frame_bytes.min(MAX_SECURE_FRAME_BYTES) - TAG_BYTES - 6
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed or noncanonical protocol input")]
    Malformed,
    #[error("unsupported protocol or feature")]
    Unsupported,
    #[error("protocol resource limit exceeded")]
    Limit,
    #[error("cryptographic authentication failed")]
    Authentication,
    #[error("peer rejected by identity policy")]
    PeerRejected,
    #[error("message is not addressed to this identity or retained epoch")]
    Recipient,
    #[error("invalid message metadata or text")]
    InvalidMessage,
    #[error("secure randomness unavailable")]
    Randomness,
    #[error("transport operation failed")]
    Transport,
    #[error("operation cancelled")]
    Cancelled,
    #[error("secure session closed or poisoned")]
    Closed,
}
pub type Result<T, E = Error> = std::result::Result<T, E>;
impl From<snow::Error> for Error {
    fn from(_: snow::Error) -> Self {
        Self::Authentication
    }
}
impl From<blendr_identity::IdentityError> for Error {
    fn from(_: blendr_identity::IdentityError) -> Self {
        Self::Authentication
    }
}
impl From<blendr_transport::TransportError> for Error {
    fn from(e: blendr_transport::TransportError) -> Self {
        match e {
            blendr_transport::TransportError::Cancelled => Self::Cancelled,
            _ => Self::Transport,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub max_frame_bytes: u32,
    pub max_text_bytes: u32,
    pub max_messages: u32,
    pub max_bytes: u32,
    pub link_receipt: bool,
    pub destination_receipt: bool,
    /// This node publishes and accepts public broadcast envelopes.
    pub broadcast_enabled: bool,
    /// Largest broadcast ID inventory advertised per sync direction.
    pub inventory_max_ids: u32,
}
impl Capabilities {
    pub(crate) fn validate(&self) -> Result<()> {
        if !(MIN_SECURE_FRAME_BYTES..=MAX_SECURE_FRAME_BYTES)
            .contains(&(self.max_frame_bytes as usize))
            || self.max_text_bytes == 0
            || self.max_text_bytes as usize > MAX_TEXT_BYTES
            || self.max_messages == 0
            || self.max_messages > 10_000
            || self.max_bytes == 0
            || self.max_bytes > 1024 * 1024 * 1024
            || self.inventory_max_ids == 0
            || self.inventory_max_ids > 4096
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub(crate) fn write(&self, w: &mut Writer) {
        w.array(12);
        w.text("blendr:direct");
        w.uint(1);
        w.text("bis:1");
        w.text("direct-hpke:1");
        w.uint(self.max_frame_bytes.into());
        w.uint(self.max_text_bytes.into());
        w.uint(self.max_messages.into());
        w.uint(self.max_bytes.into());
        w.boolean(self.link_receipt);
        w.boolean(self.destination_receipt);
        w.boolean(self.broadcast_enabled);
        w.uint(self.inventory_max_ids.into());
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        r.array(12)?;
        r.literal("blendr:direct")?;
        if r.uint()? != 1 {
            return Err(Error::Unsupported);
        }
        r.literal("bis:1")?;
        r.literal("direct-hpke:1")?;
        let c = Self {
            max_frame_bytes: r.u32()?,
            max_text_bytes: r.u32()?,
            max_messages: r.u32()?,
            max_bytes: r.u32()?,
            link_receipt: r.boolean()?,
            destination_receipt: r.boolean()?,
            broadcast_enabled: r.boolean()?,
            inventory_max_ids: r.u32()?,
        };
        c.validate()?;
        Ok(c)
    }
}

#[derive(Clone, Debug)]
pub struct SessionOptions {
    pub capabilities: Capabilities,
    pub blocked_bids: Vec<String>,
    pub expected_peer: Option<String>,
}

/// No payload-bearing Debug implementation: frame contents must not enter logs.
#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    /// Encoded direct `Envelope`.
    Message(Vec<u8>),
    LinkAck(Receipt),
    DestinationReceipt(Receipt),
    TurnEnd,
    Goodbye,
    /// Broadcast sync: advertised `BroadcastEnvelope` message IDs, oldest first.
    Inventory(Vec<String>),
    /// Broadcast sync: the subset of offered IDs the receiver wants.
    SyncRequest(Vec<String>),
    /// Broadcast sync: encoded `BroadcastEnvelope` payload.
    BroadcastMessage(Vec<u8>),
    /// Broadcast sync: IDs durably persisted by the receiver (unsigned link ack).
    BroadcastAck(Vec<String>),
    /// End of one broadcast sync direction.
    SyncEnd,
}
impl Frame {
    /// Hard bound for ID-list frames (Inventory/SyncRequest/BroadcastAck).
    pub(crate) const MAX_ID_LIST: usize = 4096;

    fn encode_id_list(w: &mut Writer, ids: &[String], tag: u64) -> Result<()> {
        if ids.len() > Self::MAX_ID_LIST {
            return Err(Error::Limit);
        }
        w.array(3);
        w.uint(1);
        w.uint(tag);
        w.array(ids.len() as u64);
        for id in ids {
            w.text(id);
        }
        Ok(())
    }

    fn decode_id_list(r: &mut Reader<'_>, count: u64) -> Result<Vec<String>> {
        let count = usize::try_from(count).map_err(|_| Error::Limit)?;
        let mut ids = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            ids.push(r.text(64)?.to_owned());
        }
        Ok(ids)
    }

    pub(crate) fn encode(&self, max: usize) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        match self {
            Self::Message(bytes) => {
                if bytes.len() > max.saturating_sub(6) {
                    return Err(Error::Limit);
                }
                w.array(3);
                w.uint(1);
                w.uint(0);
                w.bytes(bytes);
            }
            Self::LinkAck(r) | Self::DestinationReceipt(r) => {
                r.validate()?;
                let expected = if matches!(self, Self::LinkAck(_)) {
                    ReceiptKind::Link
                } else {
                    ReceiptKind::Destination
                };
                if r.kind != expected {
                    return Err(Error::Malformed);
                }
                w.array(3);
                w.uint(1);
                w.uint(if expected == ReceiptKind::Link { 1 } else { 2 });
                r.write(&mut w);
            }
            Self::TurnEnd | Self::Goodbye | Self::SyncEnd => {
                w.array(2);
                w.uint(1);
                w.uint(match self {
                    Self::TurnEnd => 3,
                    Self::Goodbye => 4,
                    _ => 9,
                });
            }
            Self::Inventory(ids) => Self::encode_id_list(&mut w, ids, 5)?,
            Self::SyncRequest(ids) => Self::encode_id_list(&mut w, ids, 6)?,
            Self::BroadcastAck(ids) => Self::encode_id_list(&mut w, ids, 8)?,
            Self::BroadcastMessage(bytes) => {
                if bytes.len() > max.saturating_sub(6) {
                    return Err(Error::Limit);
                }
                w.array(3);
                w.uint(1);
                w.uint(7);
                w.bytes(bytes);
            }
        }
        let bytes = w.finish();
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8], max: usize) -> Result<Self> {
        let mut r = Reader::new(bytes, max)?;
        // Control and data frames have different fixed array lengths.
        let control = bytes.first() == Some(&0x82);
        r.array(if control { 2 } else { 3 })?;
        if r.uint()? != 1 {
            return Err(Error::Unsupported);
        }
        let tag = r.uint()?;
        let frame = match (tag, control) {
            (0, false) => Self::Message(r.bytes(max)?.to_vec()),
            (1, false) => {
                let v = Receipt::read(&mut r)?;
                if v.kind != ReceiptKind::Link {
                    return Err(Error::Malformed);
                }
                Self::LinkAck(v)
            }
            (2, false) => {
                let v = Receipt::read(&mut r)?;
                if v.kind != ReceiptKind::Destination {
                    return Err(Error::Malformed);
                }
                Self::DestinationReceipt(v)
            }
            (3, true) => Self::TurnEnd,
            (4, true) => Self::Goodbye,
            (5, false) => {
                let count = r.array_len(Self::MAX_ID_LIST as u64)?;
                Self::Inventory(Self::decode_id_list(&mut r, count)?)
            }
            (6, false) => {
                let count = r.array_len(Self::MAX_ID_LIST as u64)?;
                Self::SyncRequest(Self::decode_id_list(&mut r, count)?)
            }
            (7, false) => Self::BroadcastMessage(r.bytes(max)?.to_vec()),
            (8, false) => {
                let count = r.array_len(Self::MAX_ID_LIST as u64)?;
                Self::BroadcastAck(Self::decode_id_list(&mut r, count)?)
            }
            (9, true) => Self::SyncEnd,
            _ => return Err(Error::Unsupported),
        };
        r.finish()?;
        Ok(frame)
    }
}
