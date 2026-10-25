//! Signed, unencrypted public broadcast envelopes.
//!
//! Broadcasts are explicitly opted-in public posts: signed by the origin like
//! direct envelopes but intentionally readable by any peer or later relay.
//! Plaintext is the payload, so `text` bounds are enforced at verify/decode
//! time exactly like ciphertext bounds are for direct envelopes.

use crate::{
    Error, MAX_ENVELOPE_BYTES, MAX_TEXT_BYTES, Result,
    codec::{Reader, Writer},
    envelope::{EnvelopeMetadata, valid_bid, valid_id, verify_signature},
};
use blendr_identity::{Identity, IdentityDocument};
use sha2::Digest;

const BROADCAST_DOMAIN: &str = "blendr:broadcast:v1";
const AAD_DOMAIN: &str = "blendr:broadcast-aad:v1";
const SIGN_DOMAIN: &str = "blendr:broadcast-signature:v1";

/// A signed public post. `origin` embeds the full signed identity document so
/// any holder can authenticate the content without prior peer knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastEnvelope {
    pub message_id: String,
    pub origin: IdentityDocument,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub max_jumps: u8,
    pub text: String,
    pub signature: [u8; 64],
}

impl BroadcastEnvelope {
    fn fields(&self, w: &mut Writer) {
        w.text(&self.message_id);
        w.document(&self.origin);
        w.uint(self.created_at_ms as u64);
        w.uint(self.expires_at_ms as u64);
        w.uint(self.max_jumps.into());
    }

    fn aad(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(6);
        w.text(AAD_DOMAIN);
        self.fields(&mut w);
        w.finish()
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(3);
        w.text(SIGN_DOMAIN);
        w.bytes(&self.aad());
        w.bytes(self.text.as_bytes());
        w.finish()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(8);
        w.text(BROADCAST_DOMAIN);
        self.fields(&mut w);
        w.text(&self.text);
        w.bytes(&self.signature);
        w.finish()
    }

    /// Parse and fully verify. `max_text_bytes` applies the caller's
    /// negotiated text ceiling before the storage ceiling is checked.
    pub fn decode(bytes: &[u8], max_bytes: usize, max_text_bytes: usize) -> Result<Self> {
        let mut r = Reader::new(bytes, max_bytes.min(MAX_ENVELOPE_BYTES))?;
        r.array(8)?;
        r.literal(BROADCAST_DOMAIN)?;
        let envelope = Self {
            message_id: r.text(36)?.to_owned(),
            origin: r.document()?,
            created_at_ms: r.timestamp()?,
            expires_at_ms: r.timestamp()?,
            max_jumps: r.uint()?.try_into().map_err(|_| Error::InvalidMessage)?,
            text: r.text(max_text_bytes.min(MAX_TEXT_BYTES))?.to_owned(),
            signature: r.fixed()?,
        };
        r.finish()?;
        envelope.verify(max_text_bytes)?;
        Ok(envelope)
    }

    /// Metadata, text-bound, origin-document, and origin-signature checks.
    pub fn verify(&self, max_text_bytes: usize) -> Result<()> {
        if !valid_id(&self.message_id)
            || self.created_at_ms <= 0
            || self.expires_at_ms <= self.created_at_ms
            || self.max_jumps > 5
        {
            return Err(Error::InvalidMessage);
        }
        if self.text.is_empty()
            || self.text.len() > max_text_bytes.min(MAX_TEXT_BYTES)
            || self.encode().len() > MAX_ENVELOPE_BYTES
        {
            return Err(Error::Limit);
        }
        self.origin.verify()?;
        verify_signature(&self.origin, &self.signing_payload(), &self.signature)
    }

    /// Stable content digest for dedup bookkeeping.
    pub fn digest(&self) -> [u8; 32] {
        sha2::Sha256::digest(self.encode()).into()
    }
}

/// Sign a public broadcast post. `metadata.max_jumps` is the signed relay
/// ceiling; `jumps_used` is not carried because Phase 4 transfers are
/// always directly from a source that holds the message.
pub fn seal_broadcast(
    identity: &Identity,
    text: &str,
    metadata: EnvelopeMetadata,
) -> Result<BroadcastEnvelope> {
    let envelope = BroadcastEnvelope {
        message_id: metadata.message_id,
        origin: identity.document(),
        created_at_ms: metadata.created_at_ms,
        expires_at_ms: metadata.expires_at_ms,
        max_jumps: metadata.max_jumps,
        text: text.to_owned(),
        signature: [0; 64],
    };
    if envelope.text.is_empty() || envelope.text.len() > MAX_TEXT_BYTES {
        return Err(Error::Limit);
    }
    if !valid_bid(identity.bid()) {
        return Err(Error::InvalidMessage);
    }
    let signature = identity.sign_protocol_payload(&envelope.signing_payload());
    let envelope = BroadcastEnvelope {
        signature,
        ..envelope
    };
    envelope.verify(MAX_TEXT_BYTES)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str) -> EnvelopeMetadata {
        EnvelopeMetadata {
            message_id: id.to_owned(),
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
            max_jumps: 3,
        }
    }
    const ID: &str = "3f4b6b9a-5b3a-4b3a-9b3a-5b3a5b3a5b3a";

    #[test]
    fn roundtrip_verify_and_tamper_rejection() {
        let alice = Identity::generate("alice").unwrap();
        let e = seal_broadcast(&alice, "public hello", meta(ID)).unwrap();
        let bytes = e.encode();
        let back = BroadcastEnvelope::decode(&bytes, 8192, 4096).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.digest(), e.digest());
        // Tampered text breaks the signature.
        let mut tampered = back.clone();
        tampered.text.push('!');
        assert!(tampered.verify(4096).is_err());
        // Wrong message ID shape, times, and jumps are invalid metadata.
        let mut bad = back.clone();
        bad.message_id = "not-a-uuid".into();
        assert!(bad.verify(4096).is_err());
        let mut bad = back.clone();
        bad.expires_at_ms = bad.created_at_ms;
        assert!(bad.verify(4096).is_err());
        let mut bad = back.clone();
        bad.max_jumps = 6;
        assert!(bad.verify(4096).is_err());
        // Another identity's signature does not verify this document.
        let bob = Identity::generate("bob").unwrap();
        let mut forged = back.clone();
        forged.origin = bob.document();
        assert!(forged.verify(4096).is_err());
        // Text over the negotiated bound fails even with a valid signature.
        let over = {
            let mut e = seal_broadcast(&alice, "ok", meta(ID)).unwrap();
            e.text = "x".repeat(4097);
            e.signature = alice.sign_protocol_payload(&e.signing_payload());
            e
        };
        assert!(over.verify(4096).is_err());
    }
}
