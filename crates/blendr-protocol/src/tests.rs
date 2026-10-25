use crate::*;
use async_trait::async_trait;
use blendr_identity::Identity;
use blendr_transport::{
    BleTransport, LinkConfig, LinkRole, PeerEvent, PeerLink, PeerLocator,
    Result as TransportResult, memory::MemoryNetwork,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(crate) fn options() -> SessionOptions {
    SessionOptions {
        capabilities: Capabilities {
            max_frame_bytes: 8192,
            max_text_bytes: 4096,
            max_messages: 32,
            max_bytes: 65536,
            link_receipt: true,
            destination_receipt: true,
        },
        blocked_bids: Vec::new(),
        expected_peer: None,
    }
}
fn metadata() -> EnvelopeMetadata {
    EnvelopeMetadata {
        message_id: "7da84016-18aa-4f08-84f1-f1ccd105fc7f".into(),
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
        max_jumps: 0,
    }
}
#[test]
fn hpke_authenticates_recipient_ciphertext_metadata_and_retained_epoch() {
    let a = Identity::generate("Alice").unwrap();
    let mut b = Identity::generate("Bob").unwrap();
    let c = Identity::generate("Mallory").unwrap();
    let e = seal_message(&a, &b.document(), "private Unicode: 雪", metadata()).unwrap();
    assert_eq!(open_message(&b, &e, 4096).unwrap(), "private Unicode: 雪");
    assert!(open_message(&c, &e, 4096).is_err());
    assert!(open_message(&b, &e, 1).is_err());
    b.rotate_encryption_key().unwrap();
    // History remains readable at old key epochs and after TTL expiry.
    assert_eq!(open_message(&b, &e, 4096).unwrap(), "private Unicode: 雪");
    let mut altered = e.clone();
    altered.ciphertext[0] ^= 1;
    assert!(open_message(&b, &altered, 4096).is_err());
    let mut altered = e.clone();
    altered.destination_bid = c.bid().to_owned();
    assert!(open_message(&c, &altered, 4096).is_err());
    let mut altered = e.clone();
    altered.expires_at_ms += 1;
    assert!(altered.verify().is_err());
    let mut altered = e.clone();
    altered.recipient_epoch += 1;
    assert!(altered.verify().is_err());
    let mut altered = e.clone();
    altered.max_jumps = 1;
    assert!(altered.verify().is_err());
    let mut altered = e.clone();
    altered.encapsulated_key[0] ^= 1;
    assert!(altered.verify().is_err());
    let mut altered = e.clone();
    altered.origin.bid = c.bid().to_owned();
    assert!(altered.verify().is_err());
    let mut altered = e.clone();
    altered.signature[0] ^= 1;
    assert!(altered.verify().is_err());
    assert!(Envelope::decode(&e.encode(), MAX_ENVELOPE_BYTES).is_ok());
}
#[test]
fn receipts_require_destination_signer_and_exact_envelope_and_kind() {
    let a = Identity::generate("Alice").unwrap();
    let b = Identity::generate("Bob").unwrap();
    let c = Identity::generate("Mallory").unwrap();
    let e = seal_message(&a, &b.document(), "message", metadata()).unwrap();
    let link = Receipt::issue(&b, &e, ReceiptKind::Link, 1500).unwrap();
    let destination = Receipt::issue(&b, &e, ReceiptKind::Destination, 1500).unwrap();
    link.verify(&b.document(), &e).unwrap();
    destination.verify(&b.document(), &e).unwrap();
    assert_ne!(link.id(), destination.id());
    assert_eq!(link.id(), link.clone().id());
    assert!(Receipt::issue(&a, &e, ReceiptKind::Link, 1500).is_err());
    assert!(Receipt::issue(&c, &e, ReceiptKind::Destination, 1500).is_err());
    assert!(link.verify(&c.document(), &e).is_err());
    let e2 = seal_message(
        &a,
        &b.document(),
        "different immutable contents",
        metadata(),
    )
    .unwrap();
    assert!(link.verify(&b.document(), &e2).is_err());
    let mut tampered = link.clone();
    tampered.kind = ReceiptKind::Destination;
    assert!(tampered.verify(&b.document(), &e).is_err());
    let mut tampered = link.clone();
    tampered.signature[0] ^= 1;
    assert!(tampered.verify(&b.document(), &e).is_err());
    let mut tampered = link.clone();
    tampered.issued_at_ms += 1;
    assert!(tampered.verify(&b.document(), &e).is_err());
    let mut forged = link;
    forged.signer_bid = c.bid().to_owned();
    assert!(forged.verify(&c.document(), &e).is_err());
    assert!(Frame::LinkAck(destination).encode(8192).is_err());
}
#[test]
fn canonical_input_rejects_ambiguity_truncation_and_unbounded_lengths() {
    let a = Identity::generate("Alice").unwrap();
    let b = Identity::generate("Bob").unwrap();
    let encoded = seal_message(&a, &b.document(), "message", metadata())
        .unwrap()
        .encode();
    for n in 0..encoded.len() {
        assert!(Envelope::decode(&encoded[..n], MAX_ENVELOPE_BYTES).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Envelope::decode(&trailing, MAX_ENVELOPE_BYTES).is_err());
    assert!(Envelope::decode(&encoded, encoded.len() - 1).is_err());
    let mut indefinite = encoded.clone();
    indefinite[0] = 0x9f;
    assert!(Envelope::decode(&indefinite, MAX_ENVELOPE_BYTES).is_err());
    let mut nonminimal = vec![0x98, 11];
    nonminimal.extend_from_slice(&encoded[1..]);
    assert!(Envelope::decode(&nonminimal, MAX_ENVELOPE_BYTES).is_err());
    for bad in [
        vec![0x82, 0x18, 1, 3],
        vec![0x82, 1, 3, 0],
        vec![0x9f, 1, 3, 0xff],
        vec![
            0x83, 1, 0, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        vec![0x83, 1, 0, 0x5f, 0xff],
        vec![0x82, 2, 3],
        vec![0x82, 1, 99],
    ] {
        assert!(Frame::decode(&bad, 8192).is_err());
    }
    let payload = vec![42; max_message_bytes(1024)];
    assert_eq!(
        Frame::Message(payload)
            .encode(1024 - TAG_BYTES)
            .unwrap()
            .len(),
        1024 - TAG_BYTES
    );
    assert!(
        Frame::Message(vec![42; max_message_bytes(1024) + 1])
            .encode(1024 - TAG_BYTES)
            .is_err()
    );
    let mut meta = metadata();
    meta.message_id = meta.message_id.to_uppercase();
    assert!(seal_message(&a, &b.document(), "message", meta).is_err());
    let mut meta = metadata();
    meta.expires_at_ms = meta.created_at_ms;
    assert!(seal_message(&a, &b.document(), "message", meta).is_err());
    assert!(seal_message(&a, &b.document(), "  \n", metadata()).is_err());
}

// The published RFC9180 companion vector exercises this exact ciphersuite,
// independently of our sender/receiver roundtrips (mode0, KEM32, KDF1, AEAD3).
// Source: https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
#[test]
fn published_rfc9180_x25519_sha256_chacha_vector() {
    use hpke::{
        Deserializable, Kem, OpModeR, aead::ChaCha20Poly1305, kdf::HkdfSha256,
        kem::X25519HkdfSha256,
    };
    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&hex(
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    ))
    .unwrap();
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&hex(
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    ))
    .unwrap();
    let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &hex("4f6465206f6e2061204772656369616e2055726e"),
    )
    .unwrap();
    let ct = hex(
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
    );
    assert_eq!(
        ctx.open(&ct, &hex("436f756e742d30")).unwrap(),
        hex("4265617574792069732074727574682c20747275746820626561757479")
    );
}

#[derive(Default)]
struct WireFault {
    capture: bool,
    captured: Vec<u8>,
    replace: Option<Vec<u8>>,
    tamper: bool,
    duplicate: bool,
    hold_next: bool,
    held: Option<Vec<u8>>,
}
struct Intercept {
    inner: Box<dyn PeerLink>,
    fault: Arc<Mutex<WireFault>>,
}
#[async_trait]
impl PeerLink for Intercept {
    fn locator(&self) -> &PeerLocator {
        self.inner.locator()
    }
    fn role(&self) -> LinkRole {
        self.inner.role()
    }
    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
    async fn send_frame(
        &mut self,
        frame: &[u8],
        cancel: &CancellationToken,
    ) -> TransportResult<()> {
        let (wire, duplicate, held) = {
            let mut f = self.fault.lock().unwrap();
            if f.hold_next {
                f.hold_next = false;
                f.held = Some(frame.to_vec());
                return Ok(());
            }
            let mut wire = f.replace.take().unwrap_or_else(|| frame.to_vec());
            if f.tamper {
                let last = wire.len() - 1;
                wire[last] ^= 1;
                f.tamper = false;
            }
            if f.capture {
                f.captured = wire.clone();
            }
            (wire, f.duplicate, f.held.take())
        };
        self.inner.send_frame(&wire, cancel).await?;
        if duplicate {
            self.inner.send_frame(&wire, cancel).await?;
        }
        if let Some(held) = held {
            self.inner.send_frame(&held, cancel).await?;
        }
        Ok(())
    }
    async fn recv_frame(&mut self, cancel: &CancellationToken) -> TransportResult<Vec<u8>> {
        self.inner.recv_frame(cancel).await
    }
    async fn close(&mut self) -> TransportResult<()> {
        self.inner.close().await
    }
}
async fn links() -> (Box<dyn PeerLink>, Box<dyn PeerLink>, Arc<Mutex<WireFault>>) {
    let net = MemoryNetwork::new(128, 256).unwrap();
    let cfg = LinkConfig {
        max_frame_bytes: 8192,
        ..LinkConfig::default()
    };
    let a = net.node("alice", cfg).unwrap();
    let b = net.node("bob", cfg).unwrap();
    let mut events = a.watch_peers().await.unwrap();
    let mut accepted = b.accept_links().await.unwrap();
    b.start_advertising(uuid::Uuid::from_u128(1)).await.unwrap();
    let locator = match events.recv().await.unwrap() {
        PeerEvent::Discovered(l) => l,
        _ => panic!("expected discovery"),
    };
    let al = a.connect(locator, &CancellationToken::new()).await.unwrap();
    let bl = accepted.recv().await.unwrap();
    let fault = Arc::new(Mutex::new(WireFault::default()));
    (
        Box::new(Intercept {
            inner: al,
            fault: fault.clone(),
        }),
        bl,
        fault,
    )
}
async fn sessions(
    a: &Identity,
    b: &Identity,
) -> (SecureSession, SecureSession, Arc<Mutex<WireFault>>) {
    let (al, bl, fault) = links().await;
    let cancel = CancellationToken::new();
    let (a, b) = tokio::join!(
        authenticate(al, a, options(), &cancel),
        authenticate(bl, b, options(), &cancel)
    );
    (a.unwrap(), b.unwrap(), fault)
}
#[tokio::test]
async fn real_memory_transport_authenticates_bidirectional_messages_and_receipts() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let (mut a, mut b, fault) = sessions(&alice, &bob).await;
    assert_eq!(a.peer().bid, bob.bid());
    assert_eq!(b.peer().bid, alice.bid());
    assert_eq!(a.role(), LinkRole::Initiator);
    assert_eq!(b.role(), LinkRole::Responder);
    assert_eq!(a.max_message_bytes(), max_message_bytes(8192));
    let e = seal_message(&alice, &bob.document(), "secret text", metadata()).unwrap();
    let token = CancellationToken::new();
    fault.lock().unwrap().capture = true;
    a.send(&Frame::Message(e.encode()), &token).await.unwrap();
    let received = match b.recv(&token).await.unwrap() {
        Frame::Message(bytes) => Envelope::decode(&bytes, b.max_message_bytes()).unwrap(),
        _ => panic!("expected message"),
    };
    assert_eq!(open_message(&bob, &received, 4096).unwrap(), "secret text");
    let captured = fault.lock().unwrap().captured.clone();
    assert!(
        !captured
            .windows(e.message_id.len())
            .any(|s| s == e.message_id.as_bytes())
    );
    let receipt = Receipt::issue(&bob, &received, ReceiptKind::Destination, 1600).unwrap();
    b.send(&Frame::DestinationReceipt(receipt), &token)
        .await
        .unwrap();
    match a.recv(&token).await.unwrap() {
        Frame::DestinationReceipt(r) => r.verify(&bob.document(), &e).unwrap(),
        _ => panic!("expected receipt"),
    }
    let back = seal_message(&bob, &alice.document(), "reply", metadata()).unwrap();
    b.send(&Frame::Message(back.encode()), &token)
        .await
        .unwrap();
    match a.recv(&token).await.unwrap() {
        Frame::Message(bytes) => assert_eq!(
            open_message(
                &alice,
                &Envelope::decode(&bytes, a.max_message_bytes()).unwrap(),
                4096
            )
            .unwrap(),
            "reply"
        ),
        _ => panic!("expected reply"),
    }
    // Four-message drain protocol leaves the responder alive until disconnect.
    for _ in 0..2 {
        a.send(&Frame::Goodbye, &token).await.unwrap();
        assert!(matches!(b.recv(&token).await.unwrap(), Frame::Goodbye));
        b.send(&Frame::Goodbye, &token).await.unwrap();
        assert!(matches!(a.recv(&token).await.unwrap(), Frame::Goodbye));
    }
    a.close().await.unwrap();
    b.wait_for_disconnect(&token).await.unwrap();
}
#[tokio::test]
async fn tamper_duplicate_reorder_and_cross_session_replay_poison_sessions() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let token = CancellationToken::new();
    let (mut a, mut b, fault) = sessions(&alice, &bob).await;
    fault.lock().unwrap().tamper = true;
    a.send(&Frame::TurnEnd, &token).await.unwrap();
    assert!(matches!(b.recv(&token).await, Err(Error::Authentication)));
    assert!(matches!(b.recv(&token).await, Err(Error::Closed)));
    let (mut a, mut b, fault) = sessions(&alice, &bob).await;
    fault.lock().unwrap().duplicate = true;
    fault.lock().unwrap().capture = true;
    a.send(&Frame::TurnEnd, &token).await.unwrap();
    assert!(matches!(b.recv(&token).await.unwrap(), Frame::TurnEnd));
    assert!(matches!(b.recv(&token).await, Err(Error::Authentication)));
    let captured = fault.lock().unwrap().captured.clone();
    let (mut a, mut b, fault) = sessions(&alice, &bob).await;
    fault.lock().unwrap().replace = Some(captured);
    a.send(&Frame::TurnEnd, &token).await.unwrap();
    assert!(matches!(b.recv(&token).await, Err(Error::Authentication)));
    let (mut a, mut b, fault) = sessions(&alice, &bob).await;
    fault.lock().unwrap().hold_next = true;
    a.send(&Frame::TurnEnd, &token).await.unwrap();
    a.send(&Frame::Goodbye, &token).await.unwrap();
    assert!(matches!(b.recv(&token).await, Err(Error::Authentication)));
}
#[tokio::test]
async fn policy_and_capability_limits_fail_closed() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    for policy in 0..3 {
        let (al, bl, _) = links().await;
        let token = CancellationToken::new();
        let mut opts = options();
        match policy {
            0 => opts.blocked_bids.push(bob.bid().into()),
            1 => opts.expected_peer = Some(alice.bid().into()),
            _ => opts.capabilities.max_frame_bytes = 512,
        }
        let (a, b) = tokio::join!(
            authenticate(al, &alice, opts, &token),
            authenticate(bl, &bob, options(), &token)
        );
        assert!(a.is_err());
        assert!(b.is_err());
    }
    let (al, bl, _) = links().await;
    let token = CancellationToken::new();
    let (a, b) = tokio::join!(
        authenticate(al, &alice, options(), &token),
        authenticate(bl, &alice, options(), &token)
    );
    assert!(a.is_err());
    assert!(b.is_err());
    let (al, bl, _) = links().await;
    let mut small = options();
    small.capabilities.max_frame_bytes = 1024;
    small.capabilities.max_messages = 1;
    let (a, b) = tokio::join!(
        authenticate(al, &alice, options(), &token),
        authenticate(bl, &bob, small, &token)
    );
    let mut a = a.unwrap();
    let mut b = b.unwrap();
    assert_eq!(a.max_message_bytes(), 1002);
    a.send(&Frame::Message(vec![7; 10]), &token).await.unwrap();
    b.recv(&token).await.unwrap();
    assert!(matches!(
        a.send(&Frame::Message(vec![7; 10]), &token).await,
        Err(Error::Limit)
    ));
    assert!(matches!(
        a.send(&Frame::TurnEnd, &token).await,
        Err(Error::Closed)
    ));
}
#[tokio::test]
async fn cancellation_and_dropped_futures_dispose_live_cipher_and_link() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let (al, mut bl, _) = links().await;
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        authenticate(al, &alice, options(), &cancelled).await,
        Err(Error::Cancelled)
    ));
    assert!(bl.recv_frame(&CancellationToken::new()).await.is_err());
    let (mut a, mut b, _) = sessions(&alice, &bob).await;
    let token = CancellationToken::new();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), a.recv(&token))
            .await
            .is_err()
    );
    assert!(matches!(a.recv(&token).await, Err(Error::Closed)));
    b.wait_for_disconnect(&token).await.unwrap();
    let (mut a, mut b, _) = sessions(&alice, &bob).await;
    a.send(&Frame::Goodbye, &token).await.unwrap();
    assert!(matches!(
        b.wait_for_disconnect(&token).await,
        Err(Error::Malformed)
    ));
}
