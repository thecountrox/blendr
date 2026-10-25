//! Public broadcast posts: durable local feed plus per-peer sync bookkeeping.
//!
//! Broadcasts are explicitly opted-in public content. Both locally authored
//! and received posts retain their signed envelope AND their public plaintext
//! (unlike direct messages, whose incoming plaintext is never persisted).
//! Dedup is `message_id`-anchored exactly like direct messages; per-peer
//! `peer_delivery_ledger` rows drive restart-resumed inventory so a peer is
//! not re-offered posts it already durably acknowledged.

use super::direct::{owner_bid, page_limit, positive_time, require_peer, update_ledger};
use super::{Result, Store, invalid_input};
use rusqlite::{OptionalExtension, params};

/// A public broadcast post as stored: signed wire envelope + public text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastMessage {
    pub id: String,
    /// Full BID of the signing origin (local for authored posts).
    pub origin_bid: String,
    /// Canonical encoded `BroadcastEnvelope`.
    pub envelope: Vec<u8>,
    /// Public plaintext — retained for authored and received posts alike.
    pub text: String,
    /// Author-supplied display name at posting time (from the envelope's
    /// signed origin document; informational only, not identity proof beyond
    /// the signature itself).
    pub origin_name: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// Whether this node authored the post.
    pub outgoing: bool,
}

const BROADCAST_CONVERSATION: &str = "broadcast:feed";

impl Store {
    /// Persist a locally authored broadcast post. The caller must have already
    /// verified `envelope`'s signature and fields (the envelope is stored
    /// verbatim for future forwarding). Returns `false` on an identical
    /// duplicate; a different post under the same ID is a conflict error.
    pub fn publish_broadcast(&mut self, message: &BroadcastMessage, now_ms: i64) -> Result<bool> {
        validate_broadcast(message)?;
        positive_time(now_ms)?;
        let tx = self.conn.transaction()?;
        let owner = owner_bid(&tx)?;
        if message.origin_bid != owner || !message.outgoing {
            return Err(invalid_input(
                "published broadcast must be locally authored",
            ));
        }
        if broadcast_duplicate(&tx, message)? {
            tx.commit()?;
            return Ok(false);
        }
        insert_broadcast(&tx, message, now_ms)?;
        tx.commit()?;
        Ok(true)
    }

    /// Persist an inbound broadcast received from authenticated neighbor
    /// `peer_bid`. Caller must verify signature, expiry, text bound, and that
    /// the origin is not self or blocked. Storage adds: origin must not be
    /// the local owner, the peer must be a known non-blocked pin, and the
    /// message must not be expired. `Ok(false)` on identical redelivery.
    pub fn accept_broadcast(
        &mut self,
        message: &BroadcastMessage,
        peer_bid: &str,
        now_ms: i64,
    ) -> Result<bool> {
        validate_broadcast(message)?;
        positive_time(now_ms)?;
        if message.outgoing {
            return Err(invalid_input(
                "received broadcast must not claim local authorship",
            ));
        }
        if message.expires_at_ms <= now_ms {
            return Err(invalid_input("incoming broadcast has expired"));
        }
        let tx = self.conn.transaction()?;
        let owner = owner_bid(&tx)?;
        if message.origin_bid == owner {
            return Err(invalid_input("incoming broadcast cannot originate locally"));
        }
        require_peer(&tx, peer_bid)?;
        if broadcast_duplicate(&tx, message)? {
            // A redelivery is still a durable reception for this peer.
            update_ledger(&tx, peer_bid, &message.id, "acknowledged", now_ms)?;
            tx.commit()?;
            return Ok(false);
        }
        insert_broadcast(&tx, message, now_ms)?;
        // We durably hold this post: never offer it back to this peer.
        update_ledger(&tx, peer_bid, &message.id, "acknowledged", now_ms)?;
        tx.commit()?;
        Ok(true)
    }

    /// Message IDs eligible to offer `peer_bid`: unexpired broadcast posts
    /// (authored or received, both are reshareable within their signed jump
    /// ceiling) that this peer has not already durably acknowledged.
    /// Oldest-first for deterministic pagination; capped by the negotiated
    /// inventory bound.
    pub fn broadcast_inventory(
        &self,
        peer_bid: &str,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<String>> {
        page_limit(limit)?;
        positive_time(now_ms)?;
        require_peer(&self.conn, peer_bid)?;
        let mut statement = self.conn.prepare(
            "SELECT m.message_id FROM messages m
             WHERE m.visibility = 'broadcast' AND m.expires_at_ms > ?2
                 AND NOT EXISTS (SELECT 1 FROM peer_delivery_ledger l
                     WHERE l.peer_bid = ?1 AND l.message_id = m.message_id
                         AND l.state = 'acknowledged')
             ORDER BY m.created_at_ms ASC, m.message_id ASC LIMIT ?3",
        )?;
        Ok(statement
            .query_map(params![peer_bid, now_ms, limit], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Fetch a stored broadcast for a sync transfer. Only unexpired posts are
    /// offered regardless of the requesting peer's list.
    pub fn broadcast_offer(&self, id: &str, now_ms: i64) -> Result<Option<BroadcastMessage>> {
        positive_time(now_ms)?;
        let mut statement = self.conn.prepare(&broadcast_select(
            "WHERE m.visibility = 'broadcast' AND m.message_id = ?1
                 AND m.expires_at_ms > ?2",
        ))?;
        Ok(statement
            .query_row(params![id, now_ms], broadcast_row)
            .optional()?)
    }

    /// Mark posts the neighbor durably acknowledged this session so they are
    /// excluded from future inventories for that peer. Unknown or non-
    /// broadcast IDs are ignored silently — a misbehaving peer cannot poison
    /// ledger state for messages that were never offered to it.
    pub fn mark_broadcast_acknowledged(
        &mut self,
        peer_bid: &str,
        message_ids: &[String],
        now_ms: i64,
    ) -> Result<u32> {
        positive_time(now_ms)?;
        require_peer(&self.conn, peer_bid)?;
        if message_ids.len() > 4096 {
            return Err(invalid_input("ack list exceeds the inventory bound"));
        }
        let tx = self.conn.transaction()?;
        let mut marked = 0u32;
        for id in message_ids {
            let ours: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM peer_delivery_ledger
                     WHERE peer_bid = ?1 AND message_id = ?2 AND state = 'offered')",
                params![peer_bid, id],
                |r| r.get(0),
            )?;
            if ours {
                update_ledger(&tx, peer_bid, id, "acknowledged", now_ms)?;
                marked += 1;
            }
        }
        tx.commit()?;
        Ok(marked)
    }

    /// Record that `peer_bid` was offered these posts this session (prevents
    /// re-offer on reconnect even before the ack arrives). Bounded list.
    pub fn mark_broadcast_offered(
        &mut self,
        peer_bid: &str,
        message_ids: &[String],
        now_ms: i64,
    ) -> Result<()> {
        positive_time(now_ms)?;
        require_peer(&self.conn, peer_bid)?;
        if message_ids.len() > 4096 {
            return Err(invalid_input("offer list exceeds the inventory bound"));
        }
        let tx = self.conn.transaction()?;
        for id in message_ids {
            update_ledger(&tx, peer_bid, id, "offered", now_ms)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Newest-first public feed page. Includes expired posts — expiry gates
    /// sharing, never personal history.
    pub fn broadcast_feed(&self, limit: u32, offset: u32) -> Result<Vec<BroadcastMessage>> {
        page_limit(limit)?;
        let mut statement = self.conn.prepare(&broadcast_select(
            "WHERE m.visibility = 'broadcast'
             ORDER BY m.created_at_ms DESC, m.message_id ASC LIMIT ?1 OFFSET ?2",
        ))?;
        Ok(statement
            .query_map(params![limit, offset], broadcast_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Whether a broadcast post with this ID is already stored (any origin).
    pub fn has_broadcast(&self, id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?1 AND visibility = 'broadcast')",
            [id],
            |r| r.get(0),
        )?)
    }
}

fn validate_broadcast(message: &BroadcastMessage) -> Result<()> {
    if message.id.len() != 36 {
        return Err(invalid_input("broadcast ID must be a canonical UUIDv4"));
    }
    uuid::Uuid::parse_str(&message.id)
        .map_err(|_| invalid_input("broadcast ID must be a canonical UUIDv4"))?;
    if message.origin_bid.len() != blendr_identity::BID_LENGTH {
        return Err(invalid_input("broadcast origin must be a full BID"));
    }
    if message.envelope.is_empty() || message.envelope.len() > super::MAX_DIRECT_ENVELOPE_BYTES {
        return Err(invalid_input(
            "broadcast envelope is empty or exceeds the storage ceiling",
        ));
    }
    if message.text.is_empty() || message.text.len() > super::MAX_DIRECT_TEXT_BYTES {
        return Err(invalid_input(
            "broadcast text is empty or exceeds the ceiling",
        ));
    }
    positive_time(message.created_at_ms)?;
    if message.expires_at_ms <= message.created_at_ms {
        return Err(invalid_input(
            "broadcast expiry must be later than creation",
        ));
    }
    Ok(())
}

fn broadcast_duplicate(conn: &rusqlite::Connection, message: &BroadcastMessage) -> Result<bool> {
    let existing: Option<bool> = conn
        .query_row(
            "SELECT visibility = 'broadcast' AND origin_bid = ?2 AND signed_envelope IS ?3
                 AND body IS ?4 AND created_at_ms = ?5 AND expires_at_ms = ?6
             FROM messages WHERE message_id = ?1",
            params![
                message.id,
                message.origin_bid,
                message.envelope,
                message.text.as_bytes(),
                message.created_at_ms,
                message.expires_at_ms
            ],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        None => Ok(false),
        Some(true) => Ok(true),
        Some(false) => Err(super::StorageError::MessageConflict {
            message_id: message.id.clone(),
        }),
    }
}

fn insert_broadcast(
    conn: &rusqlite::Connection,
    message: &BroadcastMessage,
    now_ms: i64,
) -> Result<()> {
    let owner = owner_bid(conn)?;
    conn.execute(
        "INSERT OR IGNORE INTO conversations (conversation_id, kind, owner_bid, peer_bid, created_at_ms)
         VALUES (?1, 'broadcast', ?2, NULL, ?3)",
        params![BROADCAST_CONVERSATION, owner, now_ms],
    )?;
    conn.execute(
        "INSERT INTO messages (message_id, origin_bid, destination_bid, conversation_id,
             visibility, status, signed_envelope, body, created_at_ms, received_at_ms, expires_at_ms)
         VALUES (?1, ?2, NULL, ?3, 'broadcast', 'stored', ?4, ?5, ?6, ?7, ?8)",
        params![
            message.id,
            message.origin_bid,
            BROADCAST_CONVERSATION,
            message.envelope,
            message.text.as_bytes(),
            message.created_at_ms,
            if message.outgoing { None } else { Some(now_ms) },
            message.expires_at_ms
        ],
    )?;
    conn.execute(
        "INSERT INTO seen_messages (message_id, best_jumps, first_seen_ms, last_seen_ms, seen_count)
         VALUES (?1, 0, ?2, ?2, 1)",
        params![message.id, now_ms],
    )?;
    Ok(())
}

const BROADCAST_SELECT: &str = "SELECT m.message_id, m.origin_bid, m.signed_envelope, m.body,
     i.display_name, m.created_at_ms, m.expires_at_ms, m.received_at_ms
     FROM messages m LEFT JOIN identities i ON i.bid = m.origin_bid ";

fn broadcast_select(suffix: &str) -> String {
    format!("{BROADCAST_SELECT} {suffix}")
}

fn broadcast_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BroadcastMessage> {
    let text: Vec<u8> = row.get(3)?;
    let received_at_ms: Option<i64> = row.get(7)?;
    let origin_name: Option<String> = row.get(4)?;
    Ok(BroadcastMessage {
        id: row.get(0)?,
        origin_bid: row.get(1)?,
        envelope: row.get(2)?,
        text: String::from_utf8(text).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Blob, Box::new(e))
        })?,
        origin_name: origin_name.unwrap_or_default(),
        created_at_ms: row.get(5)?,
        expires_at_ms: row.get(6)?,
        outgoing: received_at_ms.is_none(),
    })
}
