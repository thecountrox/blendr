use super::*;
use blendr_identity::derive_bid;
use ed25519_dalek::{Signer, SigningKey};

fn document(seed: u8, version: u64, epoch: u64, encryption: u8) -> IdentityDocument {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let signing_public_key = key.verifying_key().to_bytes();
    let mut document = IdentityDocument {
        bid: derive_bid(&signing_public_key),
        display_name: format!("peer-{seed}-revision-{version}"),
        version,
        encryption_epoch: epoch,
        signing_public_key,
        encryption_public_key: [encryption; 32],
        signature: Vec::new(),
    };
    document.signature = key.sign(&document.signing_payload()).to_bytes().to_vec();
    document
}

fn install(store: &mut Store, document: &IdentityDocument) {
    store
        .set_local_identity(&document.bid, &serde_json::to_vec(document).unwrap())
        .unwrap();
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    owner: IdentityDocument,
    peer: IdentityDocument,
    other: IdentityDocument,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().join("direct.db"), true).unwrap();
        let owner = document(1, 1, 1, 11);
        let peer = document(2, 1, 1, 12);
        let other = document(3, 1, 1, 13);
        install(&mut store, &owner);
        store.remember_peer(&peer, 100).unwrap();
        store.remember_peer(&other, 100).unwrap();
        Self {
            dir,
            store,
            owner,
            peer,
            other,
        }
    }

    fn outgoing(&self, sequence: u64) -> DirectMessage {
        DirectMessage {
            id: format!("00000000-0000-4000-8000-{sequence:012x}"),
            origin_bid: self.owner.bid.clone(),
            destination_bid: self.peer.bid.clone(),
            // Storage accepts opaque bytes only after protocol authentication.
            envelope: vec![sequence as u8; 30],
            own_text: Some(format!("own message {sequence}")),
            created_at_ms: 200,
            expires_at_ms: 1_000,
            // These caller-supplied flags must never inject delivery state.
            status: "delivered".to_owned(),
            link_acknowledged: true,
            destination_received: true,
        }
    }

    fn incoming(&self, sequence: u64) -> DirectMessage {
        let mut message = self.outgoing(sequence);
        message.origin_bid = self.peer.bid.clone();
        message.destination_bid = self.owner.bid.clone();
        message.own_text = None;
        message
    }
}

fn count(store: &Store, table: &str) -> i64 {
    store
        .conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn receipt(message: &DirectMessage, kind: ReceiptKind, sequence: u8) -> StoredReceipt {
    StoredReceipt {
        id: format!("receipt-{sequence}"),
        message_id: message.id.clone(),
        kind,
        signer_bid: message.destination_bid.clone(),
        signature: vec![sequence; 64],
        issued_at_ms: 300,
    }
}

#[test]
fn restart_retains_pins_direct_history_and_ciphertext_only_incoming() {
    let mut f = Fixture::new();
    let outgoing = f.outgoing(1);
    let incoming = f.incoming(2);
    f.store
        .verify_peer(&f.peer.bid, &f.peer.signing_public_key)
        .unwrap();
    f.store
        .insert_local_message("private-note", &f.owner.bid, "never transmit", 200)
        .unwrap();
    assert!(f.store.queue_direct_message(&outgoing).unwrap());
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.peer.bid, 250)
            .unwrap()
    );
    assert!(
        !f.store
            .accept_direct_message(&incoming, &f.peer.bid, 251)
            .unwrap()
    );
    let (body_is_null, jumps, state): (bool, i64, String) = f
        .store
        .conn
        .query_row(
            "SELECT m.body IS NULL, s.best_jumps, l.state FROM messages m
         JOIN seen_messages s USING(message_id) JOIN peer_delivery_ledger l USING(message_id)
         WHERE m.message_id = ?1",
            [&incoming.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(body_is_null);
    assert_eq!(jumps, 0);
    assert_eq!(state, "acknowledged");
    assert_eq!(count(&f.store, "relay_queue"), 0);
    assert_eq!(count(&f.store, "conversations"), 1);
    let path = f.dir.path().join("direct.db");
    drop(f.store);
    let store = Store::open(path, true).unwrap();
    assert_eq!(
        store.peer(&f.peer.bid).unwrap().unwrap().trust,
        TrustStatus::Verified
    );
    assert_eq!(store.peers().unwrap().len(), 2);
    let pending = store
        .pending_direct_messages(&f.peer.bid, 260, 10, 100)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, outgoing.id);
    assert_eq!(pending[0].own_text, outgoing.own_text);
    assert_eq!(pending[0].status, "pending");
    assert!(!pending[0].link_acknowledged);
    assert!(!pending[0].destination_received);
    let received = store.direct_message(&incoming.id).unwrap().unwrap();
    assert_eq!(received.envelope, incoming.envelope);
    assert_eq!(received.own_text, None);
    assert_eq!(received.status, "stored");
    assert_eq!(store.direct_messages(None, 10, 0).unwrap().len(), 2);
    assert_eq!(
        store.local_messages(None, 10).unwrap()[0].text,
        "never transmit"
    );
    assert!(store.direct_message("private-note").unwrap().is_none());
    let version: u32 = store
        .conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(
        version, 1,
        "existing schema remains compatible without migration"
    );
}

#[test]
fn pinned_profiles_reject_signed_equivocation_rollback_and_epoch_key_reuse() {
    let mut f = Fixture::new();
    assert!(f.store.remember_peer(&f.owner, 110).is_err());
    f.store.remember_peer(&f.peer, 101).unwrap();
    assert_eq!(count(&f.store, "profile_versions"), 3);
    let mut modified = f.peer.clone();
    modified.display_name = "tampered".to_owned();
    assert!(f.store.remember_peer(&modified, 102).is_err());
    // A cryptographically valid but different document at the same version.
    let equivocation = document(2, 1, 1, 99);
    assert!(matches!(
        f.store.remember_peer(&equivocation, 102),
        Err(StorageError::ConflictingIdentityDocument)
    ));
    let reused_epoch = document(2, 2, 1, 99);
    assert!(f.store.remember_peer(&reused_epoch, 102).is_err());
    let renamed = document(2, 2, 1, 12);
    f.store.remember_peer(&renamed, 110).unwrap();
    let rotated = document(2, 3, 2, 22);
    f.store.remember_peer(&rotated, 120).unwrap();
    assert!(matches!(
        f.store.remember_peer(&renamed, 121),
        Err(StorageError::NonMonotonicIdentityVersion)
    ));
    let regressed_epoch = document(2, 4, 1, 12);
    assert!(matches!(
        f.store.remember_peer(&regressed_epoch, 121),
        Err(StorageError::NonMonotonicIdentityVersion)
    ));
    let excessive_version = document(2, u64::MAX, 2, 22);
    assert!(f.store.remember_peer(&excessive_version, 121).is_err());
    let mut stolen_bid = f.other.clone();
    stolen_bid.bid = f.peer.bid.clone();
    assert!(f.store.remember_peer(&stolen_bid, 121).is_err());
    let current = f.store.peer(&f.peer.bid).unwrap().unwrap();
    assert_eq!(current.document, rotated);
    assert_eq!(current.first_seen_ms, 100);
    assert_eq!(current.last_seen_ms, 120);
    // Older encounter clocks do not rewind last_seen or rewrite history.
    f.store.remember_peer(&rotated, 105).unwrap();
    assert_eq!(
        f.store.peer(&f.peer.bid).unwrap().unwrap().last_seen_ms,
        120
    );
    assert_eq!(count(&f.store, "profile_versions"), 5);
}

#[test]
fn manual_verification_requires_full_pin_and_never_unblocks() {
    let mut f = Fixture::new();
    assert!(
        f.store
            .verify_peer(&f.peer.bid, &f.other.signing_public_key)
            .is_err()
    );
    assert_eq!(
        f.store.peer(&f.peer.bid).unwrap().unwrap().trust,
        TrustStatus::Unverified
    );
    f.store
        .verify_peer(&f.peer.bid, &f.peer.signing_public_key)
        .unwrap();
    f.store.remember_peer(&document(2, 2, 1, 12), 120).unwrap();
    assert_eq!(
        f.store.peer(&f.peer.bid).unwrap().unwrap().trust,
        TrustStatus::Verified
    );
    f.store.set_peer_blocked(&f.peer.bid, true).unwrap();
    assert!(
        f.store
            .verify_peer(&f.peer.bid, &f.peer.signing_public_key)
            .is_err()
    );
    assert!(f.store.remember_peer(&document(2, 3, 1, 12), 130).is_err());
    let outgoing = f.outgoing(1);
    let incoming = f.incoming(2);
    assert!(f.store.queue_direct_message(&outgoing).is_err());
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.peer.bid, 300)
            .is_err()
    );
    assert!(
        f.store
            .pending_direct_messages(&f.peer.bid, 300, 10, 100)
            .is_err()
    );
    assert_eq!(
        f.store.peer(&f.peer.bid).unwrap().unwrap().trust,
        TrustStatus::Blocked
    );
    f.store.set_peer_blocked(&f.peer.bid, false).unwrap();
    assert_eq!(
        f.store.peer(&f.peer.bid).unwrap().unwrap().trust,
        TrustStatus::Unverified
    );
    assert!(f.store.set_peer_blocked("unknown", false).is_err());
    assert!(f.store.verify_peer("unknown", &[0; 32]).is_err());
    assert!(f.store.queue_direct_message(&outgoing).unwrap());
}

#[test]
fn immutable_dedup_conflicts_do_not_mutate_existing_history() {
    let mut f = Fixture::new();
    let message = f.outgoing(1);
    assert!(f.store.queue_direct_message(&message).unwrap());
    assert!(!f.store.queue_direct_message(&message).unwrap());
    for field in 0..5 {
        let mut changed = message.clone();
        match field {
            0 => changed.envelope[0] ^= 1,
            1 => changed.own_text = Some("changed plaintext".to_owned()),
            2 => changed.destination_bid = f.other.bid.clone(),
            3 => changed.created_at_ms += 1,
            _ => changed.expires_at_ms += 1,
        }
        assert!(matches!(
            f.store.queue_direct_message(&changed),
            Err(StorageError::MessageConflict { .. })
        ));
    }
    let incoming = f.incoming(2);
    f.store
        .accept_direct_message(&incoming, &f.peer.bid, 250)
        .unwrap();
    let mut changed = incoming.clone();
    changed.envelope[0] ^= 1;
    assert!(matches!(
        f.store.accept_direct_message(&changed, &f.peer.bid, 260),
        Err(StorageError::MessageConflict { .. })
    ));
    let note_collision = f.outgoing(3);
    f.store
        .insert_local_message(&note_collision.id, &f.owner.bid, "private", 200)
        .unwrap();
    assert!(matches!(
        f.store.queue_direct_message(&note_collision),
        Err(StorageError::MessageConflict { .. })
    ));
    assert_eq!(count(&f.store, "messages"), 3);
    assert_eq!(count(&f.store, "seen_messages"), 3);
    assert_eq!(count(&f.store, "conversations"), 1);
    assert_eq!(
        f.store
            .direct_message(&message.id)
            .unwrap()
            .unwrap()
            .envelope,
        message.envelope
    );
    assert_eq!(f.store.local_messages(None, 10).unwrap().len(), 1);
}

#[test]
fn incoming_acceptance_rolls_back_all_tables_on_ledger_failure() {
    let mut f = Fixture::new();
    let incoming = f.incoming(1);
    f.store
        .conn
        .execute_batch(
            "CREATE TRIGGER fail_delivery BEFORE INSERT ON peer_delivery_ledger
         BEGIN SELECT RAISE(ABORT, 'test injected ledger failure'); END;",
        )
        .unwrap();
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.peer.bid, 300)
            .is_err()
    );
    for table in [
        "messages",
        "seen_messages",
        "conversations",
        "peer_delivery_ledger",
    ] {
        assert_eq!(count(&f.store, table), 0, "partial transaction in {table}");
    }
    f.store
        .conn
        .execute_batch("DROP TRIGGER fail_delivery")
        .unwrap();
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.peer.bid, 301)
            .unwrap()
    );
}

#[test]
fn ownership_plaintext_and_metadata_bounds_are_enforced_before_writes() {
    let mut f = Fixture::new();
    let incoming = f.incoming(1);
    let mut plaintext = incoming.clone();
    plaintext.own_text = Some("must never touch SQLite".to_owned());
    assert!(
        f.store
            .accept_direct_message(&plaintext, &f.peer.bid, 300)
            .is_err()
    );
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.other.bid, 300)
            .is_err()
    );
    assert!(
        f.store
            .accept_direct_message(&incoming, &f.peer.bid, 1_000)
            .is_err()
    );
    let mut misaddressed = incoming.clone();
    misaddressed.destination_bid = f.other.bid.clone();
    assert!(
        f.store
            .accept_direct_message(&misaddressed, &f.peer.bid, 300)
            .is_err()
    );
    for field in 0..9 {
        let mut bad = f.outgoing(2);
        match field {
            0 => bad.own_text = None,
            1 => bad.own_text = Some(String::new()),
            2 => bad.own_text = Some("x".repeat(MAX_DIRECT_TEXT_BYTES + 1)),
            3 => bad.envelope.clear(),
            4 => bad.envelope = vec![0; MAX_DIRECT_ENVELOPE_BYTES + 1],
            5 => bad.id = "not-canonical-uuid".to_owned(),
            6 => bad.created_at_ms = 0,
            7 => bad.expires_at_ms = bad.created_at_ms,
            _ => bad.origin_bid = f.other.bid.clone(),
        }
        assert!(f.store.queue_direct_message(&bad).is_err());
    }
    assert_eq!(count(&f.store, "messages"), 0);
    assert_eq!(count(&f.store, "conversations"), 0);
    f.store
        .accept_direct_message(&incoming, &f.peer.bid, 300)
        .unwrap();
    // The duplicate shortcut must not bypass plaintext rejection.
    assert!(
        f.store
            .accept_direct_message(&plaintext, &f.peer.bid, 301)
            .is_err()
    );
    assert_eq!(
        f.store
            .direct_message(&incoming.id)
            .unwrap()
            .unwrap()
            .own_text,
        None
    );
}

#[test]
fn outbox_budget_expiry_peer_and_private_note_filters_are_deterministic() {
    let mut f = Fixture::new();
    let mut large = f.outgoing(1);
    large.envelope = vec![1; 200];
    large.created_at_ms = 100;
    f.store.queue_direct_message(&large).unwrap();
    for (sequence, length) in [(2, 30), (3, 20), (4, 10)] {
        let mut message = f.outgoing(sequence);
        message.envelope.resize(length, 1);
        f.store.queue_direct_message(&message).unwrap();
    }
    let mut expired = f.outgoing(5);
    expired.expires_at_ms = 300;
    f.store.queue_direct_message(&expired).unwrap();
    let mut other = f.outgoing(6);
    other.destination_bid = f.other.bid.clone();
    f.store.queue_direct_message(&other).unwrap();
    let incoming = f.incoming(7);
    f.store
        .accept_direct_message(&incoming, &f.peer.bid, 250)
        .unwrap();
    f.store
        .insert_local_message("private-note", &f.owner.bid, "secret", 200)
        .unwrap();
    let batch = f
        .store
        .pending_direct_messages(&f.peer.bid, 300, 10, 60)
        .unwrap();
    assert_eq!(
        batch.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![f.outgoing(2).id, f.outgoing(3).id, f.outgoing(4).id]
    );
    assert_eq!(batch.iter().map(|m| m.envelope.len()).sum::<usize>(), 60);
    assert_eq!(
        f.store
            .pending_direct_messages(&f.peer.bid, 300, 2, 60)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        f.store
            .pending_direct_messages(&f.peer.bid, 300, 10, 40)
            .unwrap()
            .len(),
        1
    );
    assert!(
        f.store
            .pending_direct_messages(&f.peer.bid, 300, 10, 0)
            .unwrap()
            .is_empty()
    );
    assert!(
        f.store
            .pending_direct_messages(&f.peer.bid, 1_000, 10, 10_000)
            .unwrap()
            .is_empty()
    );
    assert!(
        f.store
            .pending_direct_messages(&f.peer.bid, 300, 0, 60)
            .is_err()
    );
    assert!(f.store.direct_messages(None, 10_001, 0).is_err());
    let page = f.store.direct_messages(Some(&f.peer.bid), 2, 1).unwrap();
    assert_eq!(
        page.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![f.outgoing(3).id, f.outgoing(4).id]
    );
    // Expiration removes transfer eligibility, never private/direct history.
    assert_eq!(f.store.direct_messages(None, 10, 0).unwrap().len(), 7);
    assert_eq!(f.store.local_messages(None, 10).unwrap().len(), 1);
}

#[test]
fn only_destination_receipts_finish_outbox_and_states_never_regress() {
    let mut f = Fixture::new();
    let message = f.outgoing(1);
    f.store.queue_direct_message(&message).unwrap();
    assert!(
        f.store
            .mark_direct_transferred(&f.other.bid, &message.id, 300)
            .is_err()
    );
    f.store
        .mark_direct_transferred(&f.peer.bid, &message.id, 300)
        .unwrap();
    let link = receipt(&message, ReceiptKind::Link, 1);
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &link, 301)
            .unwrap()
    );
    assert!(
        !f.store
            .record_direct_receipt(&f.peer.bid, &link, 302)
            .unwrap()
    );
    let stored = f.store.direct_message(&message.id).unwrap().unwrap();
    assert_eq!(stored.status, "sent");
    assert!(stored.link_acknowledged);
    assert!(!stored.destination_received);
    assert_eq!(
        f.store
            .pending_direct_messages(&f.peer.bid, 302, 10, 100)
            .unwrap()
            .len(),
        1
    );
    let destination = receipt(&message, ReceiptKind::Destination, 2);
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &destination, 303)
            .unwrap()
    );
    f.store
        .mark_direct_transferred(&f.peer.bid, &message.id, 290)
        .unwrap();
    assert!(
        f.store
            .pending_direct_messages(&f.peer.bid, 304, 10, 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.store.direct_message(&message.id).unwrap().unwrap().status,
        "delivered"
    );
    let (state, updated): (String, i64) = f
        .store
        .conn
        .query_row(
            "SELECT state, updated_at_ms FROM peer_delivery_ledger WHERE message_id = ?1",
            [&message.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "acknowledged");
    assert_eq!(updated, 303);
    // Freshly signed receipt timestamps on repeated delivery cannot grow storage.
    for sequence in 3..40 {
        let mut fresh = receipt(&message, ReceiptKind::Destination, sequence);
        fresh.issued_at_ms += i64::from(sequence);
        assert!(
            !f.store
                .record_direct_receipt(&f.peer.bid, &fresh, 400)
                .unwrap()
        );
    }
    assert_eq!(count(&f.store, "receipts"), 2);
    let mut conflict = link.clone();
    conflict.signature[0] ^= 1;
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &conflict, 401)
            .is_err()
    );
    let late_message = f.outgoing(2);
    f.store.queue_direct_message(&late_message).unwrap();
    f.store
        .record_direct_receipt(
            &f.peer.bid,
            &receipt(&late_message, ReceiptKind::Destination, 50),
            402,
        )
        .unwrap();
    f.store
        .record_direct_receipt(
            &f.peer.bid,
            &receipt(&late_message, ReceiptKind::Link, 51),
            403,
        )
        .unwrap();
    assert_eq!(
        f.store
            .direct_message(&late_message.id)
            .unwrap()
            .unwrap()
            .status,
        "delivered"
    );
    // Receipt and outbox status survive restart, independently of live sessions.
    let path = f.dir.path().join("direct.db");
    drop(f.store);
    let store = Store::open(path, true).unwrap();
    assert!(
        store
            .direct_message(&message.id)
            .unwrap()
            .unwrap()
            .destination_received
    );
    assert!(
        store
            .pending_direct_messages(&f.peer.bid, 500, 10, 1_000)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn wrong_peer_and_wrong_direction_receipts_cannot_mark_delivery() {
    let mut f = Fixture::new();
    let message = f.outgoing(1);
    f.store.queue_direct_message(&message).unwrap();
    let destination = receipt(&message, ReceiptKind::Destination, 1);
    assert!(
        f.store
            .record_direct_receipt(&f.other.bid, &destination, 301)
            .is_err()
    );
    let mut forged = destination.clone();
    forged.signer_bid = f.other.bid.clone();
    assert!(
        f.store
            .record_direct_receipt(&f.other.bid, &forged, 301)
            .is_err()
    );
    let mut bad_signature = destination.clone();
    bad_signature.signature.pop();
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &bad_signature, 301)
            .is_err()
    );
    let incoming = f.incoming(2);
    f.store
        .accept_direct_message(&incoming, &f.peer.bid, 250)
        .unwrap();
    let mut wrong_direction = receipt(&incoming, ReceiptKind::Destination, 2);
    wrong_direction.signer_bid = f.peer.bid.clone();
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &wrong_direction, 301)
            .is_err()
    );
    assert_eq!(count(&f.store, "receipts"), 0);
    assert_eq!(
        f.store.direct_message(&message.id).unwrap().unwrap().status,
        "pending"
    );
    assert!(
        !f.store
            .direct_message(&message.id)
            .unwrap()
            .unwrap()
            .destination_received
    );
}

#[test]
fn receipt_failure_rolls_back_evidence_ledger_and_delivery_status() {
    let mut f = Fixture::new();
    let message = f.outgoing(1);
    f.store.queue_direct_message(&message).unwrap();
    f.store
        .conn
        .execute_batch(
            "CREATE TRIGGER fail_delivery BEFORE INSERT ON peer_delivery_ledger
         BEGIN SELECT RAISE(ABORT, 'test injected ledger failure'); END;",
        )
        .unwrap();
    let destination = receipt(&message, ReceiptKind::Destination, 1);
    assert!(
        f.store
            .record_direct_receipt(&f.peer.bid, &destination, 300)
            .is_err()
    );
    assert_eq!(count(&f.store, "receipts"), 0);
    assert_eq!(count(&f.store, "peer_delivery_ledger"), 0);
    assert_eq!(
        f.store.direct_message(&message.id).unwrap().unwrap().status,
        "pending"
    );
}
