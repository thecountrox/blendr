use crate::{
    Error, MAX_ENVELOPE_BYTES, MAX_TEXT_BYTES, Result, TAG_BYTES,
    codec::{Reader, Writer},
};
use blendr_identity::{Identity, IdentityDocument};
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
const HPKE_INFO: &[u8] = b"blendr:direct-hpke:v1:X25519-HKDFSHA256-ChaCha20Poly1305";
const ENVELOPE_DOMAIN: &str = "blendr:envelope:v1";

#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub message_id: String,
    pub origin: IdentityDocument,
    pub destination_bid: String,
    pub recipient_epoch: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub max_jumps: u8,
    pub encapsulated_key: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}
#[derive(Clone)]
pub struct EnvelopeMetadata {
    pub message_id: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub max_jumps: u8,
}

fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|u| {
        u.get_version_num() == 4
            && u.get_variant() == uuid::Variant::RFC4122
            && u.hyphenated().to_string() == id
    })
}
fn valid_bid(bid: &str) -> bool {
    bid.len() == 52
        && data_encoding::BASE32_NOPAD
            .decode(bid.as_bytes())
            .is_ok_and(|v| v.len() == 32 && data_encoding::BASE32_NOPAD.encode(&v) == bid)
}
fn verify_signature(doc: &IdentityDocument, payload: &[u8], signature: &[u8; 64]) -> Result<()> {
    VerifyingKey::from_bytes(&doc.signing_public_key)
        .map_err(|_| Error::Authentication)?
        .verify_strict(payload, &Signature::from_bytes(signature))
        .map_err(|_| Error::Authentication)
}
impl Envelope {
    fn metadata_valid(&self) -> Result<()> {
        if !valid_id(&self.message_id)
            || !valid_bid(&self.destination_bid)
            || self.recipient_epoch == 0
            || self.created_at_ms <= 0
            || self.expires_at_ms <= self.created_at_ms
            || self.max_jumps > 5
        {
            return Err(Error::InvalidMessage);
        }
        self.origin.verify()?;
        Ok(())
    }
    fn fields(&self, w: &mut Writer) {
        w.text(&self.message_id);
        w.document(&self.origin);
        w.text(&self.destination_bid);
        w.uint(self.recipient_epoch);
        w.uint(self.created_at_ms as u64);
        w.uint(self.expires_at_ms as u64);
        w.uint(self.max_jumps.into());
        w.bytes(&self.encapsulated_key);
    }
    fn aad(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(9);
        w.text("blendr:hpke-aad:v1");
        self.fields(&mut w);
        w.finish()
    }
    fn signing_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(3);
        w.text("blendr:envelope-signature:v1");
        w.bytes(&self.aad());
        w.bytes(&self.ciphertext);
        w.finish()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(11);
        w.text(ENVELOPE_DOMAIN);
        self.fields(&mut w);
        w.bytes(&self.ciphertext);
        w.bytes(&self.signature);
        w.finish()
    }
    pub fn decode(bytes: &[u8], max_bytes: usize) -> Result<Self> {
        let mut r = Reader::new(bytes, max_bytes.min(MAX_ENVELOPE_BYTES))?;
        r.array(11)?;
        r.literal(ENVELOPE_DOMAIN)?;
        let envelope = Self {
            message_id: r.text(36)?.to_owned(),
            origin: r.document()?,
            destination_bid: r.text(52)?.to_owned(),
            recipient_epoch: r.uint()?,
            created_at_ms: r.timestamp()?,
            expires_at_ms: r.timestamp()?,
            max_jumps: r.uint()?.try_into().map_err(|_| Error::InvalidMessage)?,
            encapsulated_key: r.fixed()?,
            ciphertext: r.bytes(MAX_ENVELOPE_BYTES)?.to_vec(),
            signature: r.fixed()?,
        };
        r.finish()?;
        envelope.verify()?;
        Ok(envelope)
    }
    pub fn verify(&self) -> Result<()> {
        self.metadata_valid()?;
        if self.ciphertext.len() <= TAG_BYTES || self.ciphertext.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Limit);
        }
        verify_signature(&self.origin, &self.signing_payload(), &self.signature)
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

pub fn seal_message(
    identity: &Identity,
    recipient: &IdentityDocument,
    text: &str,
    metadata: EnvelopeMetadata,
) -> Result<Envelope> {
    recipient.verify()?;
    if text.trim().is_empty()
        || text.len() > MAX_TEXT_BYTES
        || text.len() > MAX_ENVELOPE_BYTES - TAG_BYTES
    {
        return Err(Error::InvalidMessage);
    }
    let mut envelope = Envelope {
        message_id: metadata.message_id,
        origin: identity.document(),
        destination_bid: recipient.bid.clone(),
        recipient_epoch: recipient.encryption_epoch,
        created_at_ms: metadata.created_at_ms,
        expires_at_ms: metadata.expires_at_ms,
        max_jumps: metadata.max_jumps,
        encapsulated_key: [0; 32],
        ciphertext: Vec::new(),
        signature: [0; 64],
    };
    envelope.metadata_valid()?;
    let public = <Kem as KemTrait>::PublicKey::from_bytes(&recipient.encryption_public_key)
        .map_err(|_| Error::Authentication)?;
    let mut rng = StdRng::try_from_os_rng().map_err(|_| Error::Randomness)?;
    let (encapped, mut context) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &public,
        HPKE_INFO,
        &mut rng,
    )
    .map_err(|_| Error::Authentication)?;
    envelope
        .encapsulated_key
        .copy_from_slice(&encapped.to_bytes());
    envelope.ciphertext = context
        .seal(text.as_bytes(), &envelope.aad())
        .map_err(|_| Error::Authentication)?;
    envelope.signature = identity.sign_protocol_payload(&envelope.signing_payload());
    if envelope.encode().len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Limit);
    }
    Ok(envelope)
}

pub fn open_message(
    identity: &Identity,
    envelope: &Envelope,
    max_text_bytes: usize,
) -> Result<String> {
    envelope.verify()?;
    if envelope.destination_bid != identity.bid() {
        return Err(Error::Recipient);
    }
    if envelope.ciphertext.len() - TAG_BYTES > max_text_bytes.min(MAX_TEXT_BYTES) {
        return Err(Error::Limit);
    }
    let secret = identity
        .encryption_secret_for(envelope.recipient_epoch)
        .ok_or(Error::Recipient)?;
    let raw = Zeroizing::new(secret.to_bytes());
    let private =
        <Kem as KemTrait>::PrivateKey::from_bytes(raw.as_ref()).map_err(|_| Error::Recipient)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.encapsulated_key)
        .map_err(|_| Error::Authentication)?;
    let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &private,
        &encapped,
        HPKE_INFO,
    )
    .map_err(|_| Error::Authentication)?;
    let plaintext = Zeroizing::new(
        context
            .open(&envelope.ciphertext, &envelope.aad())
            .map_err(|_| Error::Authentication)?,
    );
    let text = std::str::from_utf8(&plaintext).map_err(|_| Error::InvalidMessage)?;
    if text.trim().is_empty() {
        return Err(Error::InvalidMessage);
    }
    Ok(text.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptKind {
    Link,
    Destination,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Receipt {
    pub message_id: String,
    pub kind: ReceiptKind,
    pub signer_bid: String,
    pub envelope_hash: [u8; 32],
    pub issued_at_ms: i64,
    pub signature: [u8; 64],
}
impl Receipt {
    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_id(&self.message_id) || !valid_bid(&self.signer_bid) || self.issued_at_ms <= 0 {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }
    fn fields(&self, w: &mut Writer) {
        w.text("blendr:receipt:v1");
        w.text(&self.message_id);
        w.uint(if self.kind == ReceiptKind::Link { 0 } else { 1 });
        w.text(&self.signer_bid);
        w.bytes(&self.envelope_hash);
        w.uint(self.issued_at_ms as u64);
    }
    fn payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(6);
        self.fields(&mut w);
        w.finish()
    }
    pub(crate) fn write(&self, w: &mut Writer) {
        w.array(7);
        self.fields(w);
        w.bytes(&self.signature);
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        r.array(7)?;
        r.literal("blendr:receipt:v1")?;
        let receipt = Self {
            message_id: r.text(36)?.to_owned(),
            kind: match r.uint()? {
                0 => ReceiptKind::Link,
                1 => ReceiptKind::Destination,
                _ => return Err(Error::Unsupported),
            },
            signer_bid: r.text(52)?.to_owned(),
            envelope_hash: r.fixed()?,
            issued_at_ms: r.timestamp()?,
            signature: r.fixed()?,
        };
        receipt.validate()?;
        Ok(receipt)
    }
    pub fn issue(
        identity: &Identity,
        envelope: &Envelope,
        kind: ReceiptKind,
        now_ms: i64,
    ) -> Result<Self> {
        envelope.verify()?;
        if identity.bid() != envelope.destination_bid {
            return Err(Error::Recipient);
        }
        let mut receipt = Self {
            message_id: envelope.message_id.clone(),
            kind,
            signer_bid: identity.bid().to_owned(),
            envelope_hash: envelope.digest(),
            issued_at_ms: now_ms,
            signature: [0; 64],
        };
        receipt.validate()?;
        receipt.signature = identity.sign_protocol_payload(&receipt.payload());
        Ok(receipt)
    }
    pub fn verify(&self, signer: &IdentityDocument, envelope: &Envelope) -> Result<()> {
        self.validate()?;
        signer.verify()?;
        envelope.verify()?;
        if self.signer_bid != signer.bid
            || self.signer_bid != envelope.destination_bid
            || self.message_id != envelope.message_id
            || self.envelope_hash != envelope.digest()
        {
            return Err(Error::Authentication);
        }
        verify_signature(signer, &self.payload(), &self.signature)
    }
    pub fn id(&self) -> String {
        let mut w = Writer::new();
        self.write(&mut w);
        data_encoding::HEXLOWER.encode(&Sha256::digest(w.finish()))
    }
}
