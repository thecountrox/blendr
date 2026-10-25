//! Authenticated, bounded direct-message exchange over any Blendr transport.
//!
//! Only locally originated addressed envelopes enter outbound turns. Private
//! notes, broadcast data and relay custody are never selected. Incoming text is
//! decrypted to validate it, then discarded; durable incoming history retains
//! only the signed HPKE envelope. History decryption does not enforce delivery
//! TTL, so expiry never erases readable personal history.

use std::time::{SystemTime, UNIX_EPOCH};

use blendr_config::Config;
use blendr_identity::{Identity, IdentityDocument};
use blendr_protocol::{
    Capabilities, Envelope, EnvelopeMetadata, Frame, Receipt, ReceiptKind, SecureSession,
    SessionOptions,
};
use blendr_storage::{DirectMessage, Store, StoredReceipt, TrustStatus};
use blendr_transport::{LinkRole, PeerLink};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum MessagingError {
    #[error("{0}")]
    Policy(&'static str),
    #[error("secure protocol failed: {0}")]
    Protocol(#[from] blendr_protocol::Error),
    #[error("message store operation failed")]
    Storage(#[from] blendr_storage::StorageError),
}

pub type Result<T, E = MessagingError> = std::result::Result<T, E>;

#[derive(Clone)]
pub struct Settings {
    pub capabilities: Capabilities,
    pub blocked_bids: Vec<String>,
    pub ttl_ms: i64,
    pub max_jumps: u8,
    pub direct_enabled: bool,
}

impl Settings {
    pub fn from_config(config: &Config) -> Result<Self> {
        // Config::load validates all integer ranges before these conversions.
        config
            .validate()
            .map_err(|_| MessagingError::Policy("invalid node configuration"))?;
        Ok(Self {
            capabilities: Capabilities {
                max_frame_bytes: config.transport.ble.max_frame_payload_bytes as u32,
                max_text_bytes: config.messaging.max_text_utf8_bytes as u32,
                max_messages: config.messaging.sharing.sync_max_messages_per_session as u32,
                max_bytes: config.messaging.sharing.sync_max_bytes_per_session as u32,
                link_receipt: config.messaging.acknowledgements.link_receipt,
                destination_receipt: config
                    .messaging
                    .acknowledgements
                    .destination_delivery_receipt,
                broadcast_enabled: config.features.broadcast_mode
                    && config.messaging.sharing.broadcast_requires_explicit_opt_in,
                inventory_max_ids: config.messaging.sharing.inventory_max_message_ids as u32,
            },
            blocked_bids: config.security.blocked_bids.clone(),
            ttl_ms: (config.messaging.default_message_ttl_seconds * 1000) as i64,
            max_jumps: config.effective_outgoing_jumps(),
            direct_enabled: config.features.direct_messages,
        })
    }

    pub fn validate_network(&self) -> Result<()> {
        if !self.direct_enabled {
            return Err(MessagingError::Policy(
                "direct messaging is disabled in configuration",
            ));
        }
        if self.capabilities.max_frame_bytes < blendr_protocol::MIN_SECURE_FRAME_BYTES as u32 {
            return Err(MessagingError::Policy(
                "secure sessions require transport.ble.max_frame_payload_bytes >= 1024; use 8192 for the default text limit",
            ));
        }
        Ok(())
    }
}

pub struct Node {
    identity: Identity,
    store: Store,
    settings: Settings,
}

#[derive(Debug)]
pub struct ExchangeReport {
    pub peer: IdentityDocument,
    pub sent: u32,
    pub received: u32,
    pub destination_receipts: u32,
    pub broadcast_sent: u32,
    pub broadcast_received: u32,
}

/// User-visible history projection, deliberately not Debug (contains text).
pub struct HistoryMessage {
    pub id: String,
    pub peer_bid: String,
    pub outgoing: bool,
    pub text: String,
    pub created_at_ms: i64,
    pub status: String,
    pub link_acknowledged: bool,
    pub destination_received: bool,
}

struct Budget {
    messages: u32,
    bytes: usize,
}

impl Budget {
    fn consume(&mut self, bytes: usize) -> Result<()> {
        if self.messages == 0 || bytes > self.bytes {
            return Err(MessagingError::Policy(
                "peer exceeded the negotiated session transfer budget",
            ));
        }
        self.messages -= 1;
        self.bytes -= bytes;
        Ok(())
    }
}

impl Node {
    pub fn new(identity: Identity, store: Store, settings: Settings) -> Result<Self> {
        let (bid, bytes) = store
            .local_identity()?
            .ok_or(MessagingError::Policy("store has no local identity"))?;
        let stored: IdentityDocument = serde_json::from_slice(&bytes)
            .map_err(|_| MessagingError::Policy("stored local identity is malformed"))?;
        if bid != identity.bid() || stored != identity.document() {
            return Err(MessagingError::Policy(
                "keystore and stored identity disagree",
            ));
        }
        Ok(Self {
            identity,
            store,
            settings,
        })
    }

    pub fn bid(&self) -> &str {
        self.identity.bid()
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    fn check_peer(&self, bid: &str) -> Result<()> {
        if bid == self.identity.bid()
            || self
                .settings
                .blocked_bids
                .iter()
                .any(|blocked| blocked == bid)
        {
            return Err(MessagingError::Policy("self or blocked peer rejected"));
        }
        if self
            .store
            .peer(bid)?
            .is_some_and(|peer| peer.trust == TrustStatus::Blocked)
        {
            return Err(MessagingError::Policy("peer is locally blocked"));
        }
        Ok(())
    }

    /// Encrypt and durably queue a direct message without requiring a live link.
    pub fn queue(&mut self, destination: &str, text: &str, now_ms: i64) -> Result<String> {
        self.settings.validate_network()?;
        self.check_peer(destination)?;
        if text.is_empty() || text.len() > self.settings.capabilities.max_text_bytes as usize {
            return Err(MessagingError::Policy(
                "message is empty or exceeds messaging.max_text_utf8_bytes",
            ));
        }
        let peer = self.store.peer(destination)?.ok_or(MessagingError::Policy(
            "unknown recipient; authenticate it with peers --scan first",
        ))?;
        let expires_at_ms =
            now_ms
                .checked_add(self.settings.ttl_ms)
                .ok_or(MessagingError::Policy(
                    "message expiration overflows the clock range",
                ))?;
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = blendr_protocol::seal_message(
            &self.identity,
            &peer.document,
            text,
            EnvelopeMetadata {
                message_id: id.clone(),
                created_at_ms: now_ms,
                expires_at_ms,
                max_jumps: self.settings.max_jumps,
            },
        )?;
        let bytes = envelope.encode();
        if bytes.len()
            > blendr_protocol::max_message_bytes(
                self.settings.capabilities.max_frame_bytes as usize,
            )
        {
            return Err(MessagingError::Policy(
                "encrypted envelope exceeds the configured frame limit; increase transport.ble.max_frame_payload_bytes on both peers",
            ));
        }
        if bytes.len() > self.settings.capabilities.max_bytes as usize {
            return Err(MessagingError::Policy(
                "encrypted envelope exceeds the configured session byte budget",
            ));
        }
        self.store.queue_direct_message(&DirectMessage {
            id: id.clone(),
            origin_bid: self.identity.bid().into(),
            destination_bid: destination.into(),
            envelope: bytes,
            own_text: Some(text.into()),
            created_at_ms: now_ms,
            expires_at_ms,
            status: "pending".into(),
            link_acknowledged: false,
            destination_received: false,
        })?;
        Ok(id)
    }

    /// Authenticate the peer, persist its pin, exchange both directions, close.
    /// The caller supplies an overall deadline; every packet also supports cancellation.
    pub async fn exchange(
        &mut self,
        link: Box<dyn PeerLink>,
        expected_peer: Option<String>,
        cancel: &CancellationToken,
    ) -> Result<ExchangeReport> {
        self.settings.validate_network()?;
        if let Some(bid) = &expected_peer {
            self.check_peer(bid)?;
        }
        let mut session = blendr_protocol::authenticate(
            link,
            &self.identity,
            SessionOptions {
                capabilities: self.settings.capabilities.clone(),
                blocked_bids: self.settings.blocked_bids.clone(),
                expected_peer,
            },
            cancel,
        )
        .await?;
        let result = self.exchange_authenticated(&mut session, cancel).await;
        let closed = session.close().await;
        let report = result?;
        closed?;
        Ok(report)
    }

    async fn exchange_authenticated(
        &mut self,
        session: &mut SecureSession,
        cancel: &CancellationToken,
    ) -> Result<ExchangeReport> {
        self.check_peer(&session.peer().bid)?;
        self.store.remember_peer(session.peer(), now_ms()?)?;
        let peer_limits = session.peer_capabilities();
        let mut budget = Budget {
            messages: self
                .settings
                .capabilities
                .max_messages
                .min(peer_limits.max_messages),
            bytes: self
                .settings
                .capabilities
                .max_bytes
                .min(peer_limits.max_bytes) as usize,
        };
        let mut report = ExchangeReport {
            peer: session.peer().clone(),
            sent: 0,
            received: 0,
            destination_receipts: 0,
            broadcast_sent: 0,
            broadcast_received: 0,
        };
        let broadcast =
            self.settings.capabilities.broadcast_enabled && peer_limits.broadcast_enabled;
        let inventory_ids = self
            .settings
            .capabilities
            .inventory_max_ids
            .min(peer_limits.inventory_max_ids);
        if session.role() == LinkRole::Initiator {
            self.send_turn(session, &mut budget, &mut report, cancel)
                .await?;
            self.receive_turn(session, &mut budget, &mut report, cancel)
                .await?;
            if broadcast {
                self.broadcast_offer_turn(session, &mut budget, inventory_ids, &mut report, cancel)
                    .await?;
                self.broadcast_fetch_turn(session, &mut budget, inventory_ids, &mut report, cancel)
                    .await?;
            }
            session.send(&Frame::Goodbye, cancel).await?;
            expect_goodbye(session, cancel).await?;
            session.send(&Frame::Goodbye, cancel).await?;
            expect_goodbye(session, cancel).await?;
        } else {
            self.receive_turn(session, &mut budget, &mut report, cancel)
                .await?;
            self.send_turn(session, &mut budget, &mut report, cancel)
                .await?;
            if broadcast {
                self.broadcast_fetch_turn(session, &mut budget, inventory_ids, &mut report, cancel)
                    .await?;
                self.broadcast_offer_turn(session, &mut budget, inventory_ids, &mut report, cancel)
                    .await?;
            }
            expect_goodbye(session, cancel).await?;
            session.send(&Frame::Goodbye, cancel).await?;
            expect_goodbye(session, cancel).await?;
            session.send(&Frame::Goodbye, cancel).await?;
            session.wait_for_disconnect(cancel).await?;
        }
        Ok(report)
    }
    async fn send_turn(
        &mut self,
        session: &mut SecureSession,
        budget: &mut Budget,
        report: &mut ExchangeReport,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let peer = session.peer().clone();
        let messages = if budget.messages == 0 || budget.bytes == 0 {
            Vec::new()
        } else {
            self.store.pending_direct_messages(
                &peer.bid,
                now_ms()?,
                budget.messages,
                budget.bytes,
            )?
        };
        for message in messages {
            if message.envelope.len() > session.max_message_bytes() {
                return Err(MessagingError::Policy(
                    "queued envelope exceeds peer's negotiated frame limit",
                ));
            }
            if message.own_text.as_ref().is_some_and(|text| {
                text.len() > session.peer_capabilities().max_text_bytes as usize
            }) {
                return Err(MessagingError::Policy(
                    "queued text exceeds peer's advertised text limit",
                ));
            }
            budget.consume(message.envelope.len())?;
            let envelope = Envelope::decode(&message.envelope, session.max_message_bytes())?;
            session
                .send(&Frame::Message(message.envelope), cancel)
                .await?;
            self.store
                .mark_direct_transferred(&peer.bid, &message.id, now_ms()?)?;
            report.sent += 1;
            if session.peer_capabilities().link_receipt {
                let receipt = match session.recv(cancel).await? {
                    Frame::LinkAck(receipt) if receipt.kind == ReceiptKind::Link => receipt,
                    _ => {
                        return Err(MessagingError::Policy(
                            "expected a link receipt, not destination delivery",
                        ));
                    }
                };
                self.accept_receipt(&peer, &envelope, &receipt)?;
            }
            if session.peer_capabilities().destination_receipt {
                let receipt = match session.recv(cancel).await? {
                    Frame::DestinationReceipt(receipt)
                        if receipt.kind == ReceiptKind::Destination =>
                    {
                        receipt
                    }
                    _ => return Err(MessagingError::Policy("expected a destination receipt")),
                };
                self.accept_receipt(&peer, &envelope, &receipt)?;
                report.destination_receipts += 1;
            }
        }
        session.send(&Frame::TurnEnd, cancel).await?;
        Ok(())
    }

    fn accept_receipt(
        &mut self,
        peer: &IdentityDocument,
        envelope: &Envelope,
        receipt: &Receipt,
    ) -> Result<()> {
        receipt.verify(peer, envelope)?;
        self.store.record_direct_receipt(
            &peer.bid,
            &StoredReceipt {
                id: receipt.id(),
                message_id: receipt.message_id.clone(),
                kind: match receipt.kind {
                    ReceiptKind::Link => blendr_storage::ReceiptKind::Link,
                    ReceiptKind::Destination => blendr_storage::ReceiptKind::Destination,
                },
                signer_bid: receipt.signer_bid.clone(),
                signature: receipt.signature.to_vec(),
                issued_at_ms: receipt.issued_at_ms,
            },
            now_ms()?,
        )?;
        Ok(())
    }

    async fn receive_turn(
        &mut self,
        session: &mut SecureSession,
        budget: &mut Budget,
        report: &mut ExchangeReport,
        cancel: &CancellationToken,
    ) -> Result<()> {
        loop {
            let bytes = match session.recv(cancel).await? {
                Frame::TurnEnd => return Ok(()),
                Frame::Message(bytes) => bytes,
                _ => {
                    return Err(MessagingError::Policy(
                        "unexpected frame during incoming message turn",
                    ));
                }
            };
            budget.consume(bytes.len())?;
            let envelope = Envelope::decode(&bytes, session.max_message_bytes())?;
            let now = now_ms()?;
            if envelope.origin.bid != session.peer().bid
                || envelope.destination_bid != self.identity.bid()
            {
                return Err(MessagingError::Policy(
                    "direct envelope does not bind authenticated sender and local recipient",
                ));
            }
            if envelope.expires_at_ms <= now || envelope.created_at_ms > now.saturating_add(300_000)
            {
                return Err(MessagingError::Policy(
                    "message expired or sender clock is more than five minutes ahead",
                ));
            }
            let _text = Zeroizing::new(blendr_protocol::open_message(
                &self.identity,
                &envelope,
                self.settings.capabilities.max_text_bytes as usize,
            )?);
            let fresh = self.store.accept_direct_message(
                &DirectMessage {
                    id: envelope.message_id.clone(),
                    origin_bid: envelope.origin.bid.clone(),
                    destination_bid: envelope.destination_bid.clone(),
                    envelope: bytes,
                    own_text: None,
                    created_at_ms: envelope.created_at_ms,
                    expires_at_ms: envelope.expires_at_ms,
                    status: "stored".into(),
                    link_acknowledged: false,
                    destination_received: false,
                },
                &session.peer().bid,
                now,
            )?;
            if fresh {
                report.received += 1;
            }
            // Receipt issuance follows durable envelope+dedup commit, never socket receipt alone.
            if self.settings.capabilities.link_receipt {
                let receipt = Receipt::issue(&self.identity, &envelope, ReceiptKind::Link, now)?;
                session.send(&Frame::LinkAck(receipt), cancel).await?;
            }
            if self.settings.capabilities.destination_receipt {
                let receipt =
                    Receipt::issue(&self.identity, &envelope, ReceiptKind::Destination, now)?;
                session
                    .send(&Frame::DestinationReceipt(receipt), cancel)
                    .await?;
            }
        }
    }

    /// Offer-side broadcast sync: advertise unexpired, unacknowledged post IDs
    /// (ledger-backed, so a reconnect does not re-offer acknowledged posts),
    /// serve the requested subset inside the negotiated budget, then apply
    /// the peer's durable-store acknowledgements.
    async fn broadcast_offer_turn(
        &mut self,
        session: &mut SecureSession,
        budget: &mut Budget,
        inventory_ids: u32,
        report: &mut ExchangeReport,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let peer = session.peer().clone();
        let now = now_ms()?;
        let inventory = self
            .store
            .broadcast_inventory(&peer.bid, now, inventory_ids)?;
        let advertised: std::collections::HashSet<String> = inventory.iter().cloned().collect();
        // Persist the offer before sending: a session that dies mid-sync
        // resumes with these IDs already ledger-offered for this peer.
        self.store
            .mark_broadcast_offered(&peer.bid, &inventory, now)?;
        session.send(&Frame::Inventory(inventory), cancel).await?;
        let want = match session.recv(cancel).await? {
            Frame::SyncRequest(ids) => ids,
            _ => {
                return Err(MessagingError::Policy(
                    "expected a broadcast request after inventory",
                ));
            }
        };
        if want.iter().any(|id| !advertised.contains(id)) {
            return Err(MessagingError::Policy(
                "peer requested broadcasts that were never offered",
            ));
        }
        let mut sent = Vec::new();
        for id in &want {
            let Some(post) = self.store.broadcast_offer(id, now)? else {
                continue;
            };
            if post.envelope.len() > session.max_message_bytes() {
                return Err(MessagingError::Policy(
                    "stored broadcast exceeds the negotiated frame limit",
                ));
            }
            if budget.messages == 0 || post.envelope.len() > budget.bytes {
                // Gracefully truncate: remaining requests stay pending for a
                // later session rather than poisoning this one.
                break;
            }
            budget.consume(post.envelope.len())?;
            session
                .send(&Frame::BroadcastMessage(post.envelope), cancel)
                .await?;
            sent.push(post.id);
            report.broadcast_sent += 1;
        }
        session.send(&Frame::SyncEnd, cancel).await?;
        let acked = match session.recv(cancel).await? {
            Frame::BroadcastAck(ids) => ids,
            _ => {
                return Err(MessagingError::Policy(
                    "expected broadcast acknowledgements after sync end",
                ));
            }
        };
        let sent_set: std::collections::HashSet<&String> = sent.iter().collect();
        if acked.iter().any(|id| !sent_set.contains(id)) {
            return Err(MessagingError::Policy(
                "peer acknowledged broadcasts it never received",
            ));
        }
        self.store
            .mark_broadcast_acknowledged(&peer.bid, &acked, now)?;
        Ok(())
    }

    /// Fetch-side broadcast sync: read the peer's inventory, request missing
    /// non-self-authored IDs, verify/persist each envelope as it arrives, and
    /// acknowledge only posts that reached durable storage.
    async fn broadcast_fetch_turn(
        &mut self,
        session: &mut SecureSession,
        budget: &mut Budget,
        inventory_ids: u32,
        report: &mut ExchangeReport,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let peer_bid = session.peer().bid.clone();
        let offered = match session.recv(cancel).await? {
            Frame::Inventory(ids) => ids,
            _ => {
                return Err(MessagingError::Policy(
                    "expected a broadcast inventory to start sync",
                ));
            }
        };
        if offered.len() > inventory_ids as usize {
            return Err(MessagingError::Policy(
                "peer exceeded the negotiated broadcast inventory bound",
            ));
        }
        let mut want = Vec::new();
        for id in offered {
            if want.len() >= budget.messages.min(inventory_ids) as usize {
                break;
            }
            if !self.store.has_broadcast(&id)? {
                want.push(id);
            }
        }
        session.send(&Frame::SyncRequest(want), cancel).await?;
        let text_max = self
            .settings
            .capabilities
            .max_text_bytes
            .min(session.peer_capabilities().max_text_bytes) as usize;
        let mut accepted = Vec::new();
        loop {
            let bytes = match session.recv(cancel).await? {
                Frame::SyncEnd => break,
                Frame::BroadcastMessage(bytes) => bytes,
                _ => {
                    return Err(MessagingError::Policy(
                        "unexpected frame during broadcast sync",
                    ));
                }
            };
            budget.consume(bytes.len())?;
            let now = now_ms()?;
            let envelope = blendr_protocol::BroadcastEnvelope::decode(
                &bytes,
                session.max_message_bytes(),
                text_max,
            )?;
            if envelope.expires_at_ms <= now || envelope.created_at_ms > now.saturating_add(300_000)
            {
                return Err(MessagingError::Policy(
                    "broadcast expired or sender clock is more than five minutes ahead",
                ));
            }
            self.check_peer(&envelope.origin.bid)?;
            let fresh = self.store.accept_broadcast(
                &blendr_storage::BroadcastMessage {
                    id: envelope.message_id.clone(),
                    origin_bid: envelope.origin.bid.clone(),
                    envelope: bytes,
                    text: envelope.text.clone(),
                    origin_name: envelope.origin.display_name.clone(),
                    created_at_ms: envelope.created_at_ms,
                    expires_at_ms: envelope.expires_at_ms,
                    outgoing: false,
                },
                &peer_bid,
                now,
            )?;
            if fresh {
                report.broadcast_received += 1;
            }
            accepted.push(envelope.message_id.clone());
        }
        session.send(&Frame::BroadcastAck(accepted), cancel).await?;
        Ok(())
    }

    /// Explicitly publish a public post: signed, stored to the local feed and
    /// offered to peers at the next authenticated session. Returns the ID.
    pub fn publish(&mut self, text: &str, now_ms: i64) -> Result<String> {
        if !self.settings.capabilities.broadcast_enabled {
            return Err(MessagingError::Policy(
                "broadcast publishing is disabled in configuration",
            ));
        }
        self.settings.validate_network()?;
        if text.is_empty() || text.len() > self.settings.capabilities.max_text_bytes as usize {
            return Err(MessagingError::Policy(
                "post is empty or exceeds messaging.max_text_utf8_bytes",
            ));
        }
        let expires_at_ms =
            now_ms
                .checked_add(self.settings.ttl_ms)
                .ok_or(MessagingError::Policy(
                    "post expiration overflows the clock range",
                ))?;
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = blendr_protocol::seal_broadcast(
            &self.identity,
            text,
            EnvelopeMetadata {
                message_id: id.clone(),
                created_at_ms: now_ms,
                expires_at_ms,
                max_jumps: self.settings.max_jumps,
            },
        )?;
        let bytes = envelope.encode();
        if bytes.len()
            > blendr_protocol::max_message_bytes(
                self.settings.capabilities.max_frame_bytes as usize,
            )
        {
            return Err(MessagingError::Policy(
                "post exceeds the configured frame limit; increase transport.ble.max_frame_payload_bytes",
            ));
        }
        self.store.publish_broadcast(
            &blendr_storage::BroadcastMessage {
                id: id.clone(),
                origin_bid: self.identity.bid().into(),
                envelope: bytes,
                text: text.into(),
                origin_name: self.identity.document().display_name.clone(),
                created_at_ms: now_ms,
                expires_at_ms,
                outgoing: true,
            },
            now_ms,
        )?;
        Ok(id)
    }

    /// Newest-first public feed page (authored and received posts).
    pub fn feed(&self, limit: u32, offset: u32) -> Result<Vec<blendr_storage::BroadcastMessage>> {
        if !(1..=500).contains(&limit) {
            return Err(MessagingError::Policy("feed limit must be 1..=500"));
        }
        self.store.broadcast_feed(limit, offset).map_err(Into::into)
    }

    /// Decrypt bounded history pages; received plaintext is not persisted.
    pub fn history(
        &self,
        peer: Option<&str>,
        search: Option<&str>,
        limit: u32,
    ) -> Result<Vec<HistoryMessage>> {
        if !(1..=500).contains(&limit) {
            return Err(MessagingError::Policy("history limit must be 1..=500"));
        }
        let mut result = Vec::new();
        let mut offset = 0u32;
        loop {
            let page = self.store.direct_messages(peer, 100, offset)?;
            if page.is_empty() {
                break;
            }
            offset = offset
                .checked_add(page.len() as u32)
                .ok_or(MessagingError::Policy("history pagination overflow"))?;
            for row in page {
                let outgoing = row.origin_bid == self.identity.bid();
                let envelope = Envelope::decode(&row.envelope, 65_535)?;
                envelope.verify()?;
                let text = if outgoing {
                    row.own_text.ok_or(MessagingError::Policy(
                        "outgoing history has no retained text",
                    ))?
                } else {
                    // Past configuration changes and TTL expiry must not erase readable history.
                    blendr_protocol::open_message(&self.identity, &envelope, 1 << 20)?
                };
                if search.is_some_and(|query| !literal_search_matches(&text, query)) {
                    continue;
                }
                result.push(HistoryMessage {
                    id: row.id,
                    peer_bid: if outgoing {
                        row.destination_bid
                    } else {
                        row.origin_bid
                    },
                    outgoing,
                    text,
                    created_at_ms: row.created_at_ms,
                    status: row.status,
                    link_acknowledged: row.link_acknowledged,
                    destination_received: row.destination_received,
                });
                if result.len() == limit as usize {
                    return Ok(result);
                }
            }
        }
        Ok(result)
    }
}

fn literal_search_matches(text: &str, query: &str) -> bool {
    // Match SQLite LIKE's ASCII-only folding, but treat '%' and '_' literally.
    query.is_empty()
        || text
            .as_bytes()
            .windows(query.len())
            .any(|window| window.eq_ignore_ascii_case(query.as_bytes()))
}

async fn expect_goodbye(session: &mut SecureSession, cancel: &CancellationToken) -> Result<()> {
    match session.recv(cancel).await? {
        Frame::Goodbye => Ok(()),
        _ => Err(MessagingError::Policy(
            "unexpected frame during session closure",
        )),
    }
}

pub fn now_ms() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MessagingError::Policy("system clock predates Unix epoch"))?;
    i64::try_from(elapsed.as_millis())
        .map_err(|_| MessagingError::Policy("system clock exceeds supported range"))
}
