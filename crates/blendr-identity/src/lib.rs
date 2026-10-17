//! `blendr-identity` — Blendr Identity System (BIS): Ed25519 signing identity,
//! stable BID derivation, canonical-CBOR signed identity documents, X25519
//! encryption-key epochs, transcript-bound proofs, and the encrypted keystore.
//!
//! A **BID** is the RFC 4648 Base32 (uppercase, no padding) encoding of
//! `SHA-256("blendr:identity:v1" || raw_ed25519_public_key)`. The full 52
//! characters are the identifier; suffixes are display conveniences only.
//!
//! Secrets (Ed25519 seed, X25519 static secrets, KDF output, plaintext
//! keystore buffers) live only in this crate, are wiped on drop via `zeroize`,
//! and are never serialized outside the authenticated-encryption keystore in
//! [`keystore`]. No `Debug` impl on [`Identity`] prints secret material.

pub mod keystore;

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Domain separator hashed ahead of the raw Ed25519 public key to derive a BID.
pub const BID_DOMAIN: &[u8] = b"blendr:identity:v1";
/// Domain separator for the canonical CBOR identity-document signing payload.
pub const DOC_SIGNING_DOMAIN: &str = "blendr:identity-doc:v1";
/// Domain separator for session-challenge identity proofs.
pub const PROOF_DOMAIN: &str = "blendr:proof:v1";

/// Length in characters of a full BID: RFC 4648 Base32 (no padding) of a
/// 32-byte SHA-256 digest.
pub const BID_LENGTH: usize = 52;
/// Maximum display-name length after normalization (Unicode scalar values);
/// matches the `node.display_name` bound enforced by `blendr-config`.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Byte length of an Ed25519 signature carried in documents and proofs.
pub const SIGNATURE_LENGTH: usize = 64;

/// Errors produced by identity generation, document verification, proofs,
/// and keystore operations. Messages never include secret material.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The caller supplied an empty or over-long display name.
    #[error("invalid display name: {0}")]
    InvalidDisplayName(String),

    /// The caller supplied an empty or whitespace-only passphrase.
    #[error("invalid passphrase: must be non-empty and not whitespace-only")]
    InvalidPassphrase,

    /// The BID field does not match the carried signing public key, or the
    /// BID text itself is malformed.
    #[error("invalid or mismatched BID")]
    InvalidBid,

    /// `version` or `encryption_epoch` is zero or otherwise unacceptable.
    #[error("invalid version or encryption epoch")]
    InvalidVersion,

    /// The identity-document or proof signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,

    /// A proof was verified against the wrong role, transcript, nonces, or BID.
    #[error("identity proof does not match the expected role, transcript, or nonces")]
    ProofMismatch,

    /// `save_new`/`save_update` refused to write: file already exists, or the
    /// path fails the symlink/permission safety checks.
    #[error("keystore path is unsafe: {0}")]
    UnsafePath(String),

    /// `save_update` or `load` found no keystore at the path.
    #[error("no keystore exists at the requested path")]
    NotFound,

    /// The keystore file is malformed, truncated, or exceeds the size bound.
    #[error("malformed keystore: {0}")]
    MalformedKeystore(String),

    /// The passphrase did not unlock the keystore, or the file was tampered
    /// with. The two cases are intentionally indistinguishable.
    #[error("keystore decryption failed (wrong passphrase or corrupted file)")]
    DecryptionFailed,

    /// The decrypted keystore was structurally inconsistent (a secret did not
    /// match its public counterpart, or a field failed validation).
    #[error("keystore contents failed integrity checks: {0}")]
    KeystoreIntegrity(String),

    /// Keystore KDF parameters were out of the accepted bounds.
    #[error("unsupported or unsafe keystore KDF parameters")]
    InvalidKdfParameters,

    /// An underlying operating-system or I/O failure. Contains only the
    /// platform error text, never secrets.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The OS cryptographically secure RNG failed.
    #[error(transparent)]
    Rng(#[from] getrandom::Error),
}

/// Signed, self-certifying public identity document.
///
/// The signature is Ed25519 over a fixed-length canonical CBOR array under
/// [`DOC_SIGNING_DOMAIN`] covering every other field, so a document is bound
/// to exactly one display name, key epoch, and key pair. `verify()`
/// re-derives the BID from `signing_public_key` and checks everything.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDocument {
    /// Full Base32 BID derived from `signing_public_key`.
    pub bid: String,
    /// User-chosen, non-unique display name.
    pub display_name: String,
    /// Monotonically increasing document revision (starts at 1, +1 per update).
    pub version: u64,
    /// Monotonically increasing X25519 key epoch (starts at 1, +1 per rotation).
    pub encryption_epoch: u64,
    /// Raw Ed25519 verifying key; the BID commits to this.
    pub signing_public_key: [u8; 32],
    /// X25519 public key for addressed offline message encryption.
    pub encryption_public_key: [u8; 32],
    /// Ed25519 signature over the canonical CBOR signing payload.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for IdentityDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityDocument")
            .field("bid", &self.bid)
            .field("display_name", &self.display_name)
            .field("version", &self.version)
            .field("encryption_epoch", &self.encryption_epoch)
            .field("signature_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

impl IdentityDocument {
    /// Canonical deterministic CBOR signing payload:
    /// `["blendr:identity-doc:v1", bid, display_name, version,
    ///   encryption_epoch, signing_public_key, encryption_public_key]`
    /// encoded as a fixed definite-length array. The signature is excluded.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        let mut e = minicbor::Encoder::new(&mut buf);
        e.array(7)
            .expect("encoding to Vec is infallible")
            .str(DOC_SIGNING_DOMAIN)
            .expect("infallible")
            .str(&self.bid)
            .expect("infallible")
            .str(&self.display_name)
            .expect("infallible")
            .u64(self.version)
            .expect("infallible")
            .u64(self.encryption_epoch)
            .expect("infallible")
            .bytes(&self.signing_public_key)
            .expect("infallible")
            .bytes(&self.encryption_public_key)
            .expect("infallible");
        buf
    }

    /// Fully authenticate a document: BID derivation, field sanity, and the
    /// Ed25519 signature over the canonical payload.
    pub fn verify(&self) -> Result<(), IdentityError> {
        validate_display_name(&self.display_name)?;
        if self.version == 0 || self.encryption_epoch == 0 {
            return Err(IdentityError::InvalidVersion);
        }
        if derive_bid(&self.signing_public_key) != self.bid {
            return Err(IdentityError::InvalidBid);
        }
        let sig = Signature::try_from(self.signature.as_slice())
            .map_err(|_| IdentityError::InvalidSignature)?;
        let vk = VerifyingKey::from_bytes(&self.signing_public_key)
            .map_err(|_| IdentityError::InvalidSignature)?;
        vk.verify_strict(&self.signing_payload(), &sig)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

/// Derive the canonical full BID from a raw Ed25519 public key.
///
/// `BID = BASE32_NOPAD(SHA-256("blendr:identity:v1" || pubkey))` — 52 chars.
pub fn derive_bid(signing_public_key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(BID_DOMAIN);
    h.update(signing_public_key);
    data_encoding::BASE32_NOPAD.encode(&h.finalize())
}

/// Canonical payload for a session-challenge proof:
/// `[PROOF_DOMAIN, bid, role, transcript_hash, initiator_nonce,
///   responder_nonce]` as a fixed array. Nonces may be empty for one-sided
/// challenges; `role` distinguishes initiator vs responder signatures so a
/// proof cannot be replayed in the opposite direction.
fn proof_payload(
    bid: &str,
    role: &str,
    transcript_hash: &[u8],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160 + transcript_hash.len());
    let mut e = minicbor::Encoder::new(&mut buf);
    e.array(6)
        .expect("encoding to Vec is infallible")
        .str(PROOF_DOMAIN)
        .expect("infallible")
        .str(bid)
        .expect("infallible")
        .str(role)
        .expect("infallible")
        .bytes(transcript_hash)
        .expect("infallible")
        .bytes(initiator_nonce)
        .expect("infallible")
        .bytes(responder_nonce)
        .expect("infallible");
    buf
}

/// One retained X25519 decryption secret. Old epochs are kept after rotation
/// so previously received ciphertext remains decryptable; the document's
/// `encryption_epoch` names the newest entry.
struct EncryptionEpoch {
    epoch: u64,
    secret: StaticSecret,
}

/// A local Blendr identity: the Ed25519 signing key, the signed identity
/// document, and every retained X25519 decryption secret.
///
/// Not `Debug`/`Clone`-able in a way that leaks secrets; the public state is
/// the [`IdentityDocument`]. Dropping `Identity` wipes all key material
/// (`SigningKey`/`StaticSecret` are `ZeroizeOnDrop`).
pub struct Identity {
    signing_key: SigningKey,
    document: IdentityDocument,
    // Sorted ascending by epoch; last element is the current epoch named by
    // `document.encryption_epoch`. Invariant maintained by every constructor.
    encryption_epochs: Vec<EncryptionEpoch>,
}

impl Identity {
    /// Generate a fresh identity: new Ed25519 signing key, new X25519
    /// encryption key, `version = 1`, `encryption_epoch = 1`, self-signed.
    pub fn generate(display_name: &str) -> Result<Self, IdentityError> {
        let display_name = normalize_display_name(display_name);
        validate_display_name(&display_name)?;
        let signing_key = random_signing_key()?;
        let encryption = random_static_secret()?;
        let mut identity = Identity {
            document: IdentityDocument {
                bid: derive_bid(&signing_key.verifying_key().to_bytes()),
                display_name,
                version: 1,
                encryption_epoch: 1,
                signing_public_key: signing_key.verifying_key().to_bytes(),
                encryption_public_key: X25519PublicKey::from(&encryption).to_bytes(),
                signature: Vec::new(),
            },
            signing_key,
            encryption_epochs: vec![EncryptionEpoch {
                epoch: 1,
                secret: encryption,
            }],
        };
        identity.sign_document();
        Ok(identity)
    }

    /// The latest signed identity document.
    pub fn document(&self) -> IdentityDocument {
        self.document.clone()
    }

    /// Convenience accessor for the full BID string.
    pub fn bid(&self) -> &str {
        &self.document.bid
    }

    /// Change the display name and re-sign: `version` increments by exactly
    /// one; BID and encryption material are untouched.
    pub fn rename(&mut self, name: &str) -> Result<(), IdentityError> {
        let name = normalize_display_name(name);
        validate_display_name(&name)?;
        self.document.display_name = name;
        self.document.version += 1;
        self.sign_document();
        Ok(())
    }

    /// Rotate the X25519 encryption key: a fresh keypair becomes epoch
    /// `n + 1`, the old secret is **retained** for decrypting ciphertext
    /// addressed to earlier epochs, and the document is re-signed with an
    /// incremented `version`.
    pub fn rotate_encryption_key(&mut self) -> Result<(), IdentityError> {
        let secret = random_static_secret()?;
        self.document.encryption_epoch += 1;
        self.document.version += 1;
        self.document.encryption_public_key = X25519PublicKey::from(&secret).to_bytes();
        self.encryption_epochs.push(EncryptionEpoch {
            epoch: self.document.encryption_epoch,
            secret,
        });
        self.sign_document();
        Ok(())
    }

    /// The current X25519 encryption public key.
    pub fn encryption_public_key(&self) -> &[u8; 32] {
        &self.document.encryption_public_key
    }

    /// The retained X25519 secret for the given epoch, if this identity still
    /// holds it. Exposed for later message-decryption use; treat the value as
    /// secret and never log it.
    #[doc(hidden)]
    pub fn encryption_secret_for(&self, epoch: u64) -> Option<&StaticSecret> {
        self.encryption_epochs
            .iter()
            .find(|e| e.epoch == epoch)
            .map(|e| &e.secret)
    }

    /// Sign a fresh session challenge, binding the proof to this BID, the
    /// link `role` (e.g. `"initiator"`/`"responder"`), the running handshake
    /// `transcript_hash`, and both peers' `nonces`. Returns the raw 64-byte
    /// Ed25519 signature.
    pub fn prove(
        &self,
        role: &str,
        transcript_hash: &[u8],
        initiator_nonce: &[u8],
        responder_nonce: &[u8],
    ) -> Vec<u8> {
        let payload = proof_payload(
            &self.document.bid,
            role,
            transcript_hash,
            initiator_nonce,
            responder_nonce,
        );
        self.signing_key.sign(&payload).to_bytes().to_vec()
    }

    /// Verify an `IDENTITY_PROOF` signature purportedly produced by the holder
    /// of `document`. The document itself is fully verified first; the proof
    /// must additionally match the BID, role, transcript, and both nonces, so
    /// a replayed or misdirected proof always fails.
    pub fn verify_proof(
        document: &IdentityDocument,
        role: &str,
        transcript_hash: &[u8],
        initiator_nonce: &[u8],
        responder_nonce: &[u8],
        proof_signature: &[u8],
    ) -> Result<(), IdentityError> {
        document.verify()?;
        let sig =
            Signature::try_from(proof_signature).map_err(|_| IdentityError::InvalidSignature)?;
        let vk = VerifyingKey::from_bytes(&document.signing_public_key)
            .map_err(|_| IdentityError::InvalidSignature)?;
        let payload = proof_payload(
            &document.bid,
            role,
            transcript_hash,
            initiator_nonce,
            responder_nonce,
        );
        vk.verify_strict(&payload, &sig)
            .map_err(|_| IdentityError::ProofMismatch)
    }

    /// Re-sign the current document with the held signing key.
    fn sign_document(&mut self) {
        let sig = self.signing_key.sign(&self.document.signing_payload());
        self.document.signature = sig.to_bytes().to_vec();
    }

    /// Create a new encrypted keystore at `path`. Fails if anything already
    /// exists there — this API never overwrites. See [`keystore`].
    pub fn save_new(&self, path: impl AsRef<Path>, passphrase: &str) -> Result<(), IdentityError> {
        keystore::save_new(self, path.as_ref(), passphrase)
    }

    /// Atomically overwrite the keystore at `path`, after proving the writer
    /// can unlock the existing file with `passphrase` and that it belongs to
    /// this same BID. Intended only for explicitly authorized updates.
    pub fn save_update(
        &self,
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<(), IdentityError> {
        keystore::save_update(self, path.as_ref(), passphrase)
    }

    /// Load an identity from an encrypted keystore. Wrong passphrases and
    /// tampered files are indistinguishable: both yield
    /// [`IdentityError::DecryptionFailed`].
    pub fn load(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, IdentityError> {
        keystore::load(path.as_ref(), passphrase)
    }

    /// Rebuild an `Identity` from decrypted keystore fields. Used by
    /// `keystore::load` after authentication; enforces that every secret
    /// matches the public material committed by the document.
    /// The signing seed and `encryption_secrets` elements arrive `Zeroizing`
    /// so decrypted secrets are scrubbed even if validation fails partway.
    pub(crate) fn from_keystore_parts(
        signing_seed: [u8; 32],
        document: IdentityDocument,
        encryption_secrets: Vec<(u64, Zeroizing<[u8; 32]>)>,
    ) -> Result<Self, IdentityError> {
        let seed = Zeroizing::new(signing_seed);
        let signing_key = SigningKey::from_bytes(&seed);
        if signing_key.verifying_key().to_bytes() != document.signing_public_key {
            return Err(IdentityError::KeystoreIntegrity(
                "signing seed does not match document signing public key".into(),
            ));
        }
        document.verify()?;
        if encryption_secrets.is_empty() {
            return Err(IdentityError::KeystoreIntegrity(
                "no encryption epochs in keystore".into(),
            ));
        }
        let mut encryption_epochs = Vec::with_capacity(encryption_secrets.len());
        let mut last_epoch = 0u64;
        for (epoch, raw) in encryption_secrets {
            if epoch == 0 || epoch <= last_epoch {
                return Err(IdentityError::KeystoreIntegrity(
                    "encryption epochs must be positive and strictly increasing".into(),
                ));
            }
            last_epoch = epoch;
            encryption_epochs.push(EncryptionEpoch {
                epoch,
                secret: StaticSecret::from(*raw),
            });
        }
        let newest = encryption_epochs.last().expect("nonempty checked");
        if newest.epoch != document.encryption_epoch {
            return Err(IdentityError::KeystoreIntegrity(
                "latest encryption epoch does not match document".into(),
            ));
        }
        if X25519PublicKey::from(&newest.secret).to_bytes() != document.encryption_public_key {
            return Err(IdentityError::KeystoreIntegrity(
                "encryption secret does not match document public key".into(),
            ));
        }
        Ok(Identity {
            signing_key,
            document,
            encryption_epochs,
        })
    }

    /// Internal keystore view: the raw Ed25519 seed. The returned buffer is
    /// wiped by the caller's `Zeroizing` wrapper after encryption.
    pub(crate) fn signing_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Internal keystore view: `(epoch, raw secret)` pairs, oldest first.
    pub(crate) fn encryption_secrets(&self) -> Vec<(u64, Zeroizing<[u8; 32]>)> {
        self.encryption_epochs
            .iter()
            .map(|e| (e.epoch, Zeroizing::new(e.secret.to_bytes())))
            .collect()
    }
}

/// Draw a fresh Ed25519 signing key from the OS CSPRNG.
fn random_signing_key() -> Result<SigningKey, IdentityError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Draw a fresh X25519 static secret from the OS CSPRNG.
fn random_static_secret() -> Result<StaticSecret, IdentityError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *raw)?;
    Ok(StaticSecret::from(*raw))
}

/// Whitespace-collapse a display name the same way `blendr-config` does.
fn normalize_display_name(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Display names must be non-empty and bounded.
fn validate_display_name(name: &str) -> Result<(), IdentityError> {
    if name.is_empty() {
        return Err(IdentityError::InvalidDisplayName(
            "display name must be non-empty".into(),
        ));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(IdentityError::InvalidDisplayName(format!(
            "display name exceeds {MAX_DISPLAY_NAME_CHARS} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic vector material: Ed25519 seed `0x00..0x1f`, X25519
    /// secret `0x20..0x3f`, display name "Vector Node". All expected values
    /// were computed independently (RFC 8032 Ed25519, RFC 4648 Base32,
    /// canonical CBOR) and are reproduced here to lock the formats.
    const V_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const V_ENC: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const V_PUB: [u8; 32] = [
        0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0,
        0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55,
        0x31, 0xb8,
    ];
    const V_EPUB: [u8; 32] = [
        0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21,
        0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
        0x62, 0x54,
    ];
    const V_BID: &str = "ATRNDKRAQJ2XY7HGWHWADS3PNFCVYEKUTOGSQIDB645LS5XWGJ6Q";
    const V_NAME: &str = "Vector Node";
    const V_DOC_SIG: [u8; 64] = [
        0x76, 0x4c, 0x7b, 0xe7, 0x19, 0xc6, 0xab, 0x4b, 0x44, 0x1c, 0xca, 0xc9, 0xc8, 0xd9, 0xea,
        0x3f, 0xe9, 0x0f, 0x81, 0xcd, 0xc3, 0x08, 0xdf, 0x3b, 0x03, 0xbb, 0xfe, 0x8c, 0x14, 0x0b,
        0xf3, 0xfc, 0xd2, 0x4d, 0xd5, 0x69, 0x24, 0x82, 0x42, 0xb6, 0xb3, 0xaa, 0x03, 0x5c, 0x83,
        0x4e, 0xe4, 0xd0, 0xa4, 0x5a, 0xd3, 0x7f, 0x5c, 0xa0, 0xc0, 0x47, 0xde, 0xdd, 0x83, 0x28,
        0x40, 0x34, 0x91, 0x03,
    ];
    const V_PROOF_SIG: [u8; 64] = [
        0x96, 0x9d, 0x78, 0xe7, 0xfb, 0x96, 0x48, 0xd2, 0x78, 0xe8, 0x35, 0x3e, 0x19, 0xd8, 0x4d,
        0x8f, 0x04, 0x08, 0x13, 0x3f, 0x9b, 0xf0, 0x1c, 0xe0, 0x1c, 0x88, 0x67, 0xc6, 0x8b, 0xca,
        0xbf, 0xe5, 0xd5, 0x30, 0xa4, 0xf8, 0x06, 0xe7, 0x23, 0xb1, 0x37, 0x50, 0xc0, 0x0c, 0x65,
        0x39, 0x0e, 0xe6, 0x57, 0xab, 0x36, 0x4b, 0x65, 0xc2, 0x14, 0xe4, 0x80, 0xe4, 0x65, 0x84,
        0x89, 0xb1, 0x34, 0x05,
    ];
    const V_TRANSCRIPT: [u8; 32] = [0xa5; 32];
    const V_INONCE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const V_RNONCE: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn vector_identity() -> Identity {
        let document = IdentityDocument {
            bid: V_BID.to_string(),
            display_name: V_NAME.to_string(),
            version: 1,
            encryption_epoch: 1,
            signing_public_key: V_PUB,
            encryption_public_key: V_EPUB,
            signature: V_DOC_SIG.to_vec(),
        };
        Identity::from_keystore_parts(V_SEED, document, vec![(1, Zeroizing::new(V_ENC))])
            .expect("vector identity must self-verify")
    }

    #[test]
    fn deterministic_bid_and_document_signature() {
        assert_eq!(derive_bid(&V_PUB), V_BID);
        assert_eq!(V_BID.len(), BID_LENGTH);
        let identity = vector_identity();
        let doc = identity.document();
        assert_eq!(doc.signature, V_DOC_SIG.to_vec());
        doc.verify().expect("vector document verifies");
    }

    #[test]
    fn deterministic_proof_signature() {
        let identity = vector_identity();
        let proof = identity.prove("initiator", &V_TRANSCRIPT, &V_INONCE, &V_RNONCE);
        assert_eq!(proof, V_PROOF_SIG.to_vec());
        Identity::verify_proof(
            &identity.document(),
            "initiator",
            &V_TRANSCRIPT,
            &V_INONCE,
            &V_RNONCE,
            &proof,
        )
        .expect("vector proof verifies");
    }
}
