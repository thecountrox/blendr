//! Authenticated peers and zero-hop direct history/outbox on the v1 schema.
//!
//! The caller authenticates sessions and verifies/decrypts wire envelopes and
//! receipts. This module enforces persistence policy, ownership, immutable
//! deduplication, and monotonic states; it never receives incoming plaintext.

use super::{Result, StorageError, Store, invalid_doc, invalid_input};
use blendr_identity::IdentityDocument;
use rusqlite::{Connection, OptionalExtension, Row, params};
use uuid::{Uuid, Version};

/// Absolute storage ceiling; session negotiation may impose a smaller bound.
pub const MAX_DIRECT_ENVELOPE_BYTES: usize = 65_535;
/// Absolute ceiling for retained, locally authored plaintext (UTF-8 bytes).
pub const MAX_DIRECT_TEXT_BYTES: usize = 65_535;

// Keep the projection in one place without constructing SQL on every read.
macro_rules! direct_select {
    ($suffix:literal) => {
        concat!(
            "SELECT m.message_id, m.origin_bid, m.destination_bid,
                m.signed_envelope, m.body, m.created_at_ms, m.expires_at_ms, m.status,
                EXISTS(SELECT 1 FROM receipts r WHERE r.message_id = m.message_id
                    AND r.kind = 'link' AND r.signer_bid = m.destination_bid),
                EXISTS(SELECT 1 FROM receipts r WHERE r.message_id = m.message_id
                    AND r.kind = 'destination' AND r.signer_bid = m.destination_bid)
                FROM messages m ",
            $suffix
        )
    };
}

/// Social trust is separate from cryptographic TOFU key pinning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustStatus {
    Unverified,
    Verified,
    Blocked,
}

/// A pinned, authenticated remote identity and its encounter times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub document: IdentityDocument,
    pub trust: TrustStatus,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

/// A direct envelope and its local history state.
///
/// Queue/accept ignore the input status and receipt flags. `own_text` is only
/// allowed for locally authored messages; incoming history is ciphertext-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectMessage {
    pub id: String,
    pub origin_bid: String,
    pub destination_bid: String,
    pub envelope: Vec<u8>,
    pub own_text: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub status: String,
    pub link_acknowledged: bool,
    pub destination_received: bool,
}

/// Link persistence and destination acceptance are deliberately distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptKind {
    Link,
    Destination,
}

impl ReceiptKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Destination => "destination",
        }
    }
}

/// Receipt evidence already verified by the protocol against the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredReceipt {
    pub id: String,
    pub message_id: String,
    pub kind: ReceiptKind,
    pub signer_bid: String,
    pub signature: Vec<u8>,
    pub issued_at_ms: i64,
}

impl Store {
    /// Pins a verified identity after a mutually authenticated session.
    ///
    /// Identical documents are idempotent; older versions, epoch regressions,
    /// same-epoch key changes and different same-version documents are errors.
    /// Remembering a peer never changes its trust state or unblocks it.
    pub fn remember_peer(&mut self, document: &IdentityDocument, now_ms: i64) -> Result<()> {
        document
            .verify()
            .map_err(|_| invalid_doc("peer document authentication failed"))?;
        positive_time(now_ms)?;
        let version = i64::try_from(document.version)
            .map_err(|_| invalid_doc("version exceeds the SQLite integer range"))?;
        let epoch = i64::try_from(document.encryption_epoch)
            .map_err(|_| invalid_doc("epoch exceeds the SQLite integer range"))?;
        let bytes =
            serde_json::to_vec(document).map_err(|_| invalid_doc("cannot encode peer document"))?;
        let tx = self.conn.transaction()?;
        let owner = owner_bid(&tx)?;
        if document.bid == owner {
            return Err(invalid_input("local identity cannot be a peer"));
        }
        let pin: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT public_key, trust_status FROM peers WHERE bid = ?1",
                [&document.bid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((key, trust)) = pin {
            if trust == "blocked" {
                return Err(invalid_input("peer is blocked"));
            }
            if key.as_slice() != document.signing_public_key.as_slice() {
                return Err(invalid_doc("peer signing key does not match its pin"));
            }
        }
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT document FROM identities WHERE bid = ?1",
                [&document.bid],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            let old: IdentityDocument = serde_json::from_slice(&previous)
                .map_err(|_| invalid_doc("invalid stored peer document"))?;
            if old.bid != document.bid || old.signing_public_key != document.signing_public_key {
                return Err(invalid_doc("peer identity key changed"));
            }
            if document.version < old.version || document.encryption_epoch < old.encryption_epoch {
                return Err(StorageError::NonMonotonicIdentityVersion);
            }
            if document.version == old.version && *document != old {
                return Err(StorageError::ConflictingIdentityDocument);
            }
            if document.encryption_epoch == old.encryption_epoch
                && document.encryption_public_key != old.encryption_public_key
            {
                return Err(invalid_doc("encryption key changed without a new epoch"));
            }
        }
        tx.execute(
            "INSERT INTO identities (bid, is_local, document, document_version,
                 encryption_epoch, display_name, created_at_ms, updated_at_ms)
             VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(bid) DO UPDATE SET document = excluded.document,
                 document_version = excluded.document_version,
                 encryption_epoch = excluded.encryption_epoch,
                 display_name = excluded.display_name,
                 updated_at_ms = MAX(identities.updated_at_ms, excluded.updated_at_ms)",
            params![
                document.bid,
                bytes,
                version,
                epoch,
                document.display_name,
                now_ms
            ],
        )?;
        tx.execute(
            "INSERT INTO peers (bid, public_key, display_name, trust_status, first_seen_ms, last_seen_ms)
             VALUES (?1, ?2, ?3, 'unverified', ?4, ?4)
             ON CONFLICT(bid) DO UPDATE SET display_name = excluded.display_name,
                 last_seen_ms = MAX(peers.last_seen_ms, excluded.last_seen_ms)",
            params![document.bid, document.signing_public_key.as_slice(), document.display_name, now_ms],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO profile_versions
                 (bid, version, encryption_epoch, display_name, document, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                document.bid,
                version,
                epoch,
                document.display_name,
                bytes,
                now_ms
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Looks up a pinned peer by its full BID, including blocked peers.
    pub fn peer(&self, bid: &str) -> Result<Option<Peer>> {
        let raw = self
            .conn
            .query_row(
                "SELECT i.document, p.trust_status, p.first_seen_ms, p.last_seen_ms
             FROM peers p JOIN identities i ON i.bid = p.bid
             WHERE p.bid = ?1 AND i.is_local = 0",
                [bid],
                raw_peer,
            )
            .optional()?;
        raw.map(decode_peer).transpose()
    }

    /// Lists peers in deterministic full-BID order.
    pub fn peers(&self) -> Result<Vec<Peer>> {
        let mut statement = self.conn.prepare(
            "SELECT i.document, p.trust_status, p.first_seen_ms, p.last_seen_ms
             FROM peers p JOIN identities i ON i.bid = p.bid
             WHERE i.is_local = 0 ORDER BY p.bid ASC",
        )?;
        statement
            .query_map([], raw_peer)?
            .map(|r| decode_peer(r?))
            .collect()
    }

    /// Marks a peer socially verified only after an external full-key match.
    /// A blocked peer must be explicitly unblocked first.
    pub fn verify_peer(&mut self, bid: &str, expected_signing_key: &[u8; 32]) -> Result<()> {
        let tx = self.conn.transaction()?;
        require_peer(&tx, bid)?;
        let key: Vec<u8> =
            tx.query_row("SELECT public_key FROM peers WHERE bid = ?1", [bid], |r| {
                r.get(0)
            })?;
        if key.as_slice() != expected_signing_key {
            return Err(invalid_input(
                "expected signing key does not match pinned peer",
            ));
        }
        tx.execute(
            "UPDATE peers SET trust_status = 'verified' WHERE bid = ?1",
            [bid],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Explicit unblock always resets social trust to Unverified.
    pub fn set_peer_blocked(&mut self, bid: &str, blocked: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE peers SET trust_status = ?2 WHERE bid = ?1",
            params![bid, if blocked { "blocked" } else { "unverified" }],
        )?;
        if changed == 0 {
            return Err(invalid_input("unknown peer"));
        }
        Ok(())
    }

    /// Atomically queues an own direct envelope and immutable authored text.
    /// Wire signatures and envelope/metadata agreement are checked by the caller.
    /// Expiry excludes outbox selection; it never deletes personal history.
    pub fn queue_direct_message(&mut self, message: &DirectMessage) -> Result<bool> {
        validate_message(message)?;
        if message
            .own_text
            .as_ref()
            .is_none_or(|text| text.is_empty() || text.len() > MAX_DIRECT_TEXT_BYTES)
        {
            return Err(invalid_input(
                "own direct message requires bounded nonempty plaintext",
            ));
        }
        let tx = self.conn.transaction()?;
        let owner = owner_bid(&tx)?;
        if message.origin_bid != owner || message.destination_bid == owner {
            return Err(invalid_input("outgoing direct message ownership mismatch"));
        }
        require_peer(&tx, &message.destination_bid)?;
        if duplicate_message(&tx, message)? {
            tx.commit()?;
            return Ok(false);
        }
        persist_message(
            &tx,
            message,
            &owner,
            &message.destination_bid,
            false,
            message.created_at_ms,
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Atomically persists an accepted, unexpired incoming envelope, conversation,
    /// zero-hop dedup entry and delivery ledger before the caller sends any ACK.
    /// Passing decrypted incoming text is always an error, even on a duplicate.
    pub fn accept_direct_message(
        &mut self,
        message: &DirectMessage,
        peer_bid: &str,
        now_ms: i64,
    ) -> Result<bool> {
        validate_message(message)?;
        positive_time(now_ms)?;
        if message.own_text.is_some() {
            return Err(invalid_input(
                "incoming direct plaintext must not be persisted",
            ));
        }
        if message.expires_at_ms <= now_ms {
            return Err(invalid_input("incoming direct message has expired"));
        }
        let tx = self.conn.transaction()?;
        let owner = owner_bid(&tx)?;
        if message.destination_bid != owner || message.origin_bid != peer_bid || peer_bid == owner {
            return Err(invalid_input("incoming direct message ownership mismatch"));
        }
        require_peer(&tx, peer_bid)?;
        if duplicate_message(&tx, message)? {
            tx.commit()?;
            return Ok(false);
        }
        persist_message(&tx, message, &owner, peer_bid, true, now_ms)?;
        tx.commit()?;
        Ok(true)
    }

    /// Oldest-first direct outbox to exactly one nonblocked peer. Link-ACKed
    /// envelopes remain eligible until a destination receipt is persisted.
    /// Only sizes and IDs are read until each envelope fits the remaining budget;
    /// individually oversized envelopes are skipped without allocating their blobs.
    pub fn pending_direct_messages(
        &self,
        peer_bid: &str,
        now_ms: i64,
        limit: u32,
        max_bytes: usize,
    ) -> Result<Vec<DirectMessage>> {
        page_limit(limit)?;
        positive_time(now_ms)?;
        require_peer(&self.conn, peer_bid)?;
        let owner = owner_bid(&self.conn)?;
        let sql_budget = i64::try_from(max_bytes).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT m.message_id, length(m.signed_envelope)
             FROM messages m
             WHERE m.visibility = 'direct' AND m.origin_bid = ?1 AND m.destination_bid = ?2
                 AND m.expires_at_ms > ?3 AND length(m.signed_envelope) <= ?4
                 AND NOT EXISTS (SELECT 1 FROM receipts r WHERE r.message_id = m.message_id
                     AND r.kind = 'destination' AND r.signer_bid = m.destination_bid)
             ORDER BY m.created_at_ms ASC, m.message_id ASC LIMIT ?5",
        )?;
        let mut rows = statement.query(params![owner, peer_bid, now_ms, sql_budget, limit])?;
        let mut remaining = max_bytes;
        let mut messages = Vec::new();
        while let Some(row) = rows.next()? {
            let size: usize = usize::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| invalid_input("stored envelope length is negative"))?;
            if size > remaining {
                break;
            }
            let id = row
                .get_ref(0)?
                .as_str()
                .map_err(|_| invalid_input("stored message ID is not text"))?;
            if let Some(message) = read_direct(&self.conn, id, &owner)? {
                remaining -= size;
                messages.push(message);
            }
        }
        Ok(messages)
    }

    /// Records a completed transfer without downgrading acknowledged/delivered state.
    pub fn mark_direct_transferred(
        &mut self,
        peer_bid: &str,
        message_id: &str,
        now_ms: i64,
    ) -> Result<()> {
        positive_time(now_ms)?;
        let tx = self.conn.transaction()?;
        require_outgoing(&tx, peer_bid, message_id)?;
        tx.execute(
            "UPDATE messages SET status = 'sent' WHERE message_id = ?1 AND status = 'pending'",
            [message_id],
        )?;
        update_ledger(&tx, peer_bid, message_id, "transferred", now_ms)?;
        tx.commit()?;
        Ok(())
    }

    /// Records verified evidence from the actual destination only.
    ///
    /// At most one receipt per message/kind/signer is retained: re-delivery can
    /// produce a newly signed timestamp but cannot grow the receipt table without
    /// bound. An existing receipt ID with different content is always rejected.
    /// Only a destination receipt sets `delivered`; a late link receipt cannot
    /// downgrade it. `Ok(false)` means the evidence was already present.
    pub fn record_direct_receipt(
        &mut self,
        peer_bid: &str,
        receipt: &StoredReceipt,
        received_at_ms: i64,
    ) -> Result<bool> {
        positive_time(received_at_ms)?;
        positive_time(receipt.issued_at_ms)?;
        if receipt.id.is_empty() || receipt.id.len() > 128 || receipt.signature.len() != 64 {
            return Err(invalid_input("invalid receipt ID or signature length"));
        }
        if receipt.signer_bid != peer_bid {
            return Err(invalid_input(
                "receipt signer is not the authenticated peer",
            ));
        }
        let tx = self.conn.transaction()?;
        require_outgoing(&tx, peer_bid, &receipt.message_id)?;
        let existing: Option<bool> = tx
            .query_row(
                "SELECT message_id = ?2 AND kind = ?3 AND signer_bid = ?4
                 AND signature = ?5 AND issued_at_ms = ?6 AND jumps_at_signing = 0
             FROM receipts WHERE receipt_id = ?1",
                params![
                    receipt.id,
                    receipt.message_id,
                    receipt.kind.as_str(),
                    receipt.signer_bid,
                    receipt.signature,
                    receipt.issued_at_ms
                ],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(identical) = existing {
            if !identical {
                return Err(invalid_input("receipt ID conflicts with stored evidence"));
            }
            tx.commit()?;
            return Ok(false);
        }
        let already_recorded: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM receipts WHERE message_id = ?1 AND kind = ?2 AND signer_bid = ?3)",
            params![receipt.message_id, receipt.kind.as_str(), receipt.signer_bid], |r| r.get(0),
        )?;
        if already_recorded {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO receipts (receipt_id, message_id, kind, signer_bid, signature,
                 jumps_at_signing, issued_at_ms, received_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
            params![
                receipt.id,
                receipt.message_id,
                receipt.kind.as_str(),
                receipt.signer_bid,
                receipt.signature,
                receipt.issued_at_ms,
                received_at_ms
            ],
        )?;
        tx.execute(
            "UPDATE messages SET status = CASE WHEN ?2 = 'destination' THEN 'delivered'
                 WHEN status = 'pending' THEN 'sent' ELSE status END WHERE message_id = ?1",
            params![receipt.message_id, receipt.kind.as_str()],
        )?;
        update_ledger(
            &tx,
            peer_bid,
            &receipt.message_id,
            "acknowledged",
            received_at_ms,
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Newest-first direct-only history, including expired/delivered envelopes.
    /// Ties are broken by ascending message ID for deterministic offset pages.
    pub fn direct_messages(
        &self,
        peer_bid: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<DirectMessage>> {
        page_limit(limit)?;
        let owner = owner_bid(&self.conn)?;
        let mut statement = self.conn.prepare_cached(direct_select!(
            "WHERE m.visibility = 'direct'
                 AND (m.origin_bid = ?1 OR m.destination_bid = ?1)
                 AND (?2 IS NULL OR (m.origin_bid = ?1 AND m.destination_bid = ?2)
                     OR (m.destination_bid = ?1 AND m.origin_bid = ?2))
             ORDER BY m.created_at_ms DESC, m.message_id ASC LIMIT ?3 OFFSET ?4"
        ))?;
        Ok(statement
            .query_map(params![owner, peer_bid, limit, offset], direct_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Retrieves the immutable direct envelope for receipt checks and decryption.
    pub fn direct_message(&self, id: &str) -> Result<Option<DirectMessage>> {
        let owner = owner_bid(&self.conn)?;
        read_direct(&self.conn, id, &owner)
    }
}

fn read_direct(conn: &Connection, id: &str, owner: &str) -> Result<Option<DirectMessage>> {
    let mut statement = conn.prepare_cached(direct_select!(
        "WHERE m.visibility = 'direct' AND m.message_id = ?1
             AND (m.origin_bid = ?2 OR m.destination_bid = ?2)"
    ))?;
    Ok(statement
        .query_row(params![id, owner], direct_row)
        .optional()?)
}

fn direct_row(row: &Row<'_>) -> rusqlite::Result<DirectMessage> {
    let text: Option<Vec<u8>> = row.get(4)?;
    let own_text = text.map(String::from_utf8).transpose().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    Ok(DirectMessage {
        id: row.get(0)?,
        origin_bid: row.get(1)?,
        destination_bid: row.get(2)?,
        envelope: row.get(3)?,
        own_text,
        created_at_ms: row.get(5)?,
        expires_at_ms: row.get(6)?,
        status: row.get(7)?,
        link_acknowledged: row.get(8)?,
        destination_received: row.get(9)?,
    })
}

type RawPeer = (Vec<u8>, String, i64, i64);

fn raw_peer(row: &Row<'_>) -> rusqlite::Result<RawPeer> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn decode_peer((bytes, trust, first_seen_ms, last_seen_ms): RawPeer) -> Result<Peer> {
    let document =
        serde_json::from_slice(&bytes).map_err(|_| invalid_doc("invalid stored peer document"))?;
    let trust = match trust.as_str() {
        "unverified" | "pinned" => TrustStatus::Unverified,
        "verified" => TrustStatus::Verified,
        "blocked" => TrustStatus::Blocked,
        _ => return Err(invalid_input("unknown stored peer trust status")),
    };
    Ok(Peer {
        document,
        trust,
        first_seen_ms,
        last_seen_ms,
    })
}

pub(super) fn owner_bid(conn: &Connection) -> Result<String> {
    conn.query_row("SELECT bid FROM identities WHERE is_local = 1", [], |r| {
        r.get(0)
    })
    .optional()?
    .ok_or_else(|| invalid_input("local identity is not installed"))
}

pub(super) fn require_peer(conn: &Connection, bid: &str) -> Result<()> {
    let trust: Option<String> = conn
        .query_row(
            "SELECT p.trust_status FROM peers p JOIN identities i ON i.bid = p.bid
         WHERE p.bid = ?1 AND i.is_local = 0",
            [bid],
            |r| r.get(0),
        )
        .optional()?;
    match trust.as_deref() {
        Some("unverified" | "verified" | "pinned") => Ok(()),
        Some("blocked") => Err(invalid_input("peer is blocked")),
        _ => Err(invalid_input("unknown peer")),
    }
}

pub(super) fn positive_time(time: i64) -> Result<()> {
    if time <= 0 {
        return Err(invalid_input("timestamp must be positive"));
    }
    Ok(())
}

pub(super) fn page_limit(limit: u32) -> Result<()> {
    if limit == 0 || limit > super::MAX_LOCAL_MESSAGE_LIMIT {
        return Err(invalid_input("direct message limit must be in 1..=10000"));
    }
    Ok(())
}

fn validate_message(message: &DirectMessage) -> Result<()> {
    if message.id.len() != 36 {
        return Err(invalid_input("message ID must be a canonical UUIDv4"));
    }
    let id = Uuid::parse_str(&message.id)
        .map_err(|_| invalid_input("message ID must be a canonical UUIDv4"))?;
    let mut canonical = Uuid::encode_buffer();
    let canonical = id.hyphenated().encode_lower(&mut canonical);
    if id.get_variant() != uuid::Variant::RFC4122
        || id.get_version() != Some(Version::Random)
        || canonical.as_bytes() != message.id.as_bytes()
    {
        return Err(invalid_input("message ID must be a canonical UUIDv4"));
    }
    if message.origin_bid.len() != blendr_identity::BID_LENGTH
        || message.destination_bid.len() != blendr_identity::BID_LENGTH
    {
        return Err(invalid_input("direct messages require full BIDs"));
    }
    if message.envelope.is_empty() || message.envelope.len() > MAX_DIRECT_ENVELOPE_BYTES {
        return Err(invalid_input(
            "direct envelope is empty or exceeds the storage ceiling",
        ));
    }
    positive_time(message.created_at_ms)?;
    if message.expires_at_ms <= message.created_at_ms {
        return Err(invalid_input("expiry must be later than creation"));
    }
    Ok(())
}

/// Compare in SQL to avoid copying an existing envelope merely to deduplicate.
fn duplicate_message(conn: &Connection, message: &DirectMessage) -> Result<bool> {
    let existing: Option<bool> = conn
        .query_row(
            "SELECT visibility = 'direct' AND origin_bid = ?2 AND destination_bid IS ?3
             AND signed_envelope IS ?4 AND body IS ?5 AND created_at_ms = ?6 AND expires_at_ms IS ?7
         FROM messages WHERE message_id = ?1",
            params![
                message.id,
                message.origin_bid,
                message.destination_bid,
                message.envelope,
                message.own_text.as_ref().map(|s| s.as_bytes()),
                message.created_at_ms,
                message.expires_at_ms
            ],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        None => Ok(false),
        Some(true) => Ok(true),
        Some(false) => Err(StorageError::MessageConflict {
            message_id: message.id.clone(),
        }),
    }
}

fn persist_message(
    conn: &Connection,
    message: &DirectMessage,
    owner: &str,
    peer: &str,
    incoming: bool,
    now_ms: i64,
) -> Result<()> {
    // Full BIDs have fixed length, making this deterministic pair unambiguous.
    let conversation = format!("direct:{owner}:{peer}");
    conn.execute(
        "INSERT OR IGNORE INTO conversations (conversation_id, kind, owner_bid, peer_bid, created_at_ms)
         VALUES (?1, 'direct', ?2, ?3, ?4)", params![conversation, owner, peer, now_ms],
    )?;
    conn.execute(
        "INSERT INTO messages (message_id, origin_bid, destination_bid, conversation_id,
             visibility, status, signed_envelope, body, created_at_ms, received_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, 'direct', ?5, ?6, ?7, ?8, ?9, ?10)",
        params![message.id, message.origin_bid, message.destination_bid, conversation,
            if incoming { "stored" } else { "pending" }, message.envelope,
            message.own_text.as_ref().map(|s| s.as_bytes()), message.created_at_ms,
            incoming.then_some(now_ms), message.expires_at_ms],
    )?;
    conn.execute(
        "INSERT INTO seen_messages (message_id, best_jumps, first_seen_ms, last_seen_ms, seen_count)
         VALUES (?1, 0, ?2, ?2, 1)", params![message.id, now_ms],
    )?;
    // Outgoing ledger starts only on actual transfer (there is no queued enum).
    if incoming {
        update_ledger(conn, peer, &message.id, "acknowledged", now_ms)?;
    }
    Ok(())
}

fn require_outgoing(conn: &Connection, peer: &str, message_id: &str) -> Result<()> {
    require_peer(conn, peer)?;
    let owner = owner_bid(conn)?;
    let valid: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1 AND visibility = 'direct'
             AND origin_bid = ?2 AND destination_bid = ?3)",
        params![message_id, owner, peer],
        |r| r.get(0),
    )?;
    if !valid {
        return Err(invalid_input(
            "message is not an outgoing direct message to this peer",
        ));
    }
    Ok(())
}

pub(super) fn update_ledger(
    conn: &Connection,
    peer: &str,
    id: &str,
    state: &str,
    now_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO peer_delivery_ledger (peer_bid, message_id, state, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(peer_bid, message_id) DO UPDATE SET
             state = CASE WHEN peer_delivery_ledger.state = 'acknowledged' THEN 'acknowledged' ELSE excluded.state END,
             updated_at_ms = MAX(peer_delivery_ledger.updated_at_ms, excluded.updated_at_ms)",
        params![peer, id, state, now_ms],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
