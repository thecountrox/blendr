//! End-to-end `Node::exchange` over `MemoryTransport`: authentication, queued
//! outbound delivery, distinct receipts, ciphertext-only inbound history, and
//! blocked/impostor rejection. No real BLE involved.

use blendr_identity::Identity;
use blendr_messaging::{Node, Settings, now_ms};
use blendr_protocol::{Capabilities, MIN_SECURE_FRAME_BYTES};
use blendr_storage::{Store, TrustStatus};
use blendr_transport::memory::MemoryNetwork;
use blendr_transport::{BleTransport, LinkConfig, PeerEvent};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn settings() -> Settings {
    Settings {
        capabilities: Capabilities {
            max_frame_bytes: 8192,
            max_text_bytes: 4096,
            max_messages: 20,
            max_bytes: 16_384,
            link_receipt: true,
            destination_receipt: true,
        },
        blocked_bids: Vec::new(),
        ttl_ms: 3_600_000,
        max_jumps: 0,
        direct_enabled: true,
    }
}

fn node(dir: &TempDir, name: &str) -> Node {
    let identity = Identity::generate(name).unwrap();
    let mut store = Store::open(dir.path().join("node.db"), false).unwrap();
    let document = serde_json::to_vec(&identity.document()).unwrap();
    store.set_local_identity(identity.bid(), &document).unwrap();
    Node::new(identity, store, settings()).unwrap()
}

fn memory_pair() -> (
    blendr_transport::memory::MemoryTransport,
    blendr_transport::memory::MemoryTransport,
) {
    let net = MemoryNetwork::new(128, 256).unwrap();
    let cfg = LinkConfig {
        max_frame_bytes: 8192,
        ..LinkConfig::default()
    };
    (
        net.node("alice", cfg).unwrap(),
        net.node("bob", cfg).unwrap(),
    )
}

/// Authenticate once so each peer is pinned, then queue outbound messages and
/// run one full bidirectional exchange.
#[tokio::test(flavor = "current_thread")]
async fn authenticated_exchange_delivers_and_persists() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut alice = node(&dir_a, "alice");
    let mut bob = node(&dir_b, "bob");
    let (ta, tb) = memory_pair();
    let mut events = ta.watch_peers().await.unwrap();
    let mut accepted = tb.accept_links().await.unwrap();
    tb.start_advertising(uuid::Uuid::from_u128(1))
        .await
        .unwrap();
    let locator = match events.recv().await.unwrap() {
        PeerEvent::Discovered(l) => l,
        _ => panic!("expected discovery"),
    };

    let cancel = CancellationToken::new();
    // First exchange authenticates and pins each peer.
    let alice_bid = alice.bid().to_string();
    let bob_bid = bob.bid().to_string();
    let link_a = ta.connect(locator.clone(), &cancel).await.unwrap();
    let link_b = accepted.recv().await.unwrap();
    let (ra, rb) = tokio::join!(
        alice.exchange(link_a, Some(bob_bid.clone()), &cancel),
        bob.exchange(link_b, Some(alice_bid.clone()), &cancel),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.peer.bid, bob.bid());
    assert_eq!(rb.peer.bid, alice.bid());

    // Queue two outbound messages; bob queues one reply.
    let now = now_ms().unwrap();
    let id1 = alice.queue(bob.bid(), "hello bob", now).unwrap();
    let id2 = alice.queue(bob.bid(), "second", now).unwrap();
    let id3 = bob.queue(alice.bid(), "hi alice", now).unwrap();

    let link_a = ta.connect(locator, &cancel).await.unwrap();
    let link_b = accepted.recv().await.unwrap();
    let (ra, rb) = tokio::join!(
        alice.exchange(link_a, Some(bob_bid.clone()), &cancel),
        bob.exchange(link_b, Some(alice_bid.clone()), &cancel),
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    assert_eq!(ra.sent, 2);
    assert_eq!(ra.received, 1);
    assert_eq!(ra.destination_receipts, 2);
    assert_eq!(rb.sent, 1);
    assert_eq!(rb.received, 2);

    // Sender sees destination receipts; receiver history is durable/readable.
    for id in [&id1, &id2] {
        let stored = alice.store().direct_message(id).unwrap().unwrap();
        assert!(
            stored.destination_received,
            "{id} lacks a destination receipt"
        );
    }
    let alice_history = alice.history(Some(bob.bid()), None, 10).unwrap();
    assert_eq!(alice_history.len(), 3);
    let bob_history = bob.history(Some(alice.bid()), None, 10).unwrap();
    assert_eq!(bob_history.len(), 3);
    assert!(
        bob_history
            .iter()
            .any(|m| m.text == "hello bob" && !m.outgoing)
    );
    assert!(alice_history.iter().any(|m| m.id == id3 && !m.outgoing));

    // Inbound rows persist no plaintext.
    let inbound = bob.store().direct_message(&id1).unwrap().unwrap();
    assert_eq!(inbound.own_text, None);
    assert!(!inbound.envelope.is_empty());
}

/// `expected_peer` rejects an authenticated-but-wrong BID; `blocked_bids` and
/// locally blocked peers never authenticate and cannot receive a queue.
#[tokio::test(flavor = "current_thread")]
async fn blocked_and_impostor_peers_fail_closed() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut alice = node(&dir_a, "alice");
    let mut bob = node(&dir_b, "bob");
    let mallory = Identity::generate("mallory").unwrap();
    let (ta, tb) = memory_pair();
    let mut events = ta.watch_peers().await.unwrap();
    let mut accepted = tb.accept_links().await.unwrap();
    tb.start_advertising(uuid::Uuid::from_u128(1))
        .await
        .unwrap();
    let locator = match events.recv().await.unwrap() {
        PeerEvent::Discovered(l) => l,
        _ => panic!("expected discovery"),
    };
    let cancel = CancellationToken::new();

    // Alice demands mallory's BID; the honest bob document is rejected, and
    // bob fails when the link drops mid-handshake.
    let link_a = ta.connect(locator.clone(), &cancel).await.unwrap();
    let link_b = accepted.recv().await.unwrap();
    let (ra, rb) = tokio::join!(
        alice.exchange(link_a, Some(mallory.bid().into()), &cancel),
        bob.exchange(link_b, None, &cancel),
    );
    assert!(ra.is_err());
    assert!(rb.is_err());

    // Config-blocked BID never authenticates.
    let mut blocked_settings = settings();
    blocked_settings.blocked_bids.push(bob.bid().into());
    let identity = Identity::generate("strict").unwrap();
    let mut store = Store::open(dir_a.path().join("strict.db"), false).unwrap();
    let document = serde_json::to_vec(&identity.document()).unwrap();
    store.set_local_identity(identity.bid(), &document).unwrap();
    let mut strict = Node::new(identity, store, blocked_settings).unwrap();
    let link_a = ta.connect(locator, &cancel).await.unwrap();
    let link_b = accepted.recv().await.unwrap();
    let (ra, rb) = tokio::join!(
        strict.exchange(link_a, None, &cancel),
        bob.exchange(link_b, None, &cancel),
    );
    assert!(ra.is_err());
    assert!(rb.is_err());

    // A locally blocked peer cannot even be queued for.
    alice
        .store_mut()
        .remember_peer(&mallory.document(), now_ms().unwrap())
        .unwrap();
    alice
        .store_mut()
        .set_peer_blocked(mallory.bid(), true)
        .unwrap();
    let err = alice.queue(mallory.bid(), "nope", now_ms().unwrap());
    assert!(err.is_err());
}

/// Oversize text and unknown recipients fail at queue time; the frame floor
/// is enforced before any link is attempted.
#[test]
fn queue_rejects_unfit_and_misconfigured_messages() {
    let dir = TempDir::new().unwrap();
    let mut node = node(&dir, "solo");
    let other = Identity::generate("other").unwrap();
    node.store_mut()
        .remember_peer(&other.document(), now_ms().unwrap())
        .unwrap();
    assert_eq!(
        node.store().peer(other.bid()).unwrap().unwrap().trust,
        TrustStatus::Unverified
    );
    let now = now_ms().unwrap();
    // Unknown recipient, empty text, and oversize text all fail closed.
    assert!(node.queue("Z".repeat(52).as_str(), "hi", now).is_err());
    assert!(node.queue(other.bid(), "", now).is_err());
    let huge = "x".repeat(4097);
    assert!(node.queue(other.bid(), &huge, now).is_err());
    // A frame cap below the secure floor fails validation before any link.
    let mut small = settings();
    small.capabilities.max_frame_bytes = (MIN_SECURE_FRAME_BYTES - 1) as u32;
    assert!(small.validate_network().is_err());
}
