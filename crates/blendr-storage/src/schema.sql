-- Blendr storage schema, migration 1 (user_version = 1).
--
-- This file is applied transactionally by `Store::migrate`. Every statement is
-- idempotent (`IF NOT EXISTS`) so a committed schema version is never re-applied
-- destructively. Private key material MUST NEVER be stored in this database;
-- it lives only in the encrypted identity keystore (`identity.keystore_path`).
-- Columns here carry public identity documents, public keys, opaque ciphertext,
-- and bookkeeping only.

-- ---------------------------------------------------------------------------
-- identities: one row per known Blendr identity (BID).
-- The row flagged `is_local = 1` is the device's own identity; the partial
-- unique index below enforces the single-owner invariant in the database
-- itself. `document` is the canonical signed identity document JSON
-- (blendr-identity::IdentityDocument serialized); `document_version` and
-- `encryption_epoch` duplicate its version fields so updates can be checked
-- for monotonicity without trusting the JSON body. NO private keys, ever.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identities (
    bid              TEXT PRIMARY KEY,
    is_local         INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    document         BLOB NOT NULL,
    document_version INTEGER NOT NULL CHECK (document_version >= 0),
    encryption_epoch INTEGER NOT NULL CHECK (encryption_epoch >= 0),
    display_name     TEXT NOT NULL,
    created_at_ms    INTEGER NOT NULL,
    updated_at_ms    INTEGER NOT NULL
);

-- At most one identity may be marked as the local owner.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_single_local
    ON identities (is_local) WHERE is_local = 1;

-- ---------------------------------------------------------------------------
-- peers: known remote nodes (trust state, encounter stats).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peers (
    bid              TEXT PRIMARY KEY,
    public_key       BLOB NOT NULL,
    display_name     TEXT NOT NULL DEFAULT '',
    trust_status     TEXT NOT NULL DEFAULT 'unverified'
                     CHECK (trust_status IN ('unverified', 'verified', 'pinned', 'blocked')),
    first_seen_ms    INTEGER NOT NULL,
    last_seen_ms     INTEGER NOT NULL,
    notes            TEXT
);

-- ---------------------------------------------------------------------------
-- conversations: local conversation containers (direct with one peer BID or
-- the broadcast feed). `owner_bid` is always our own local identity.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id  TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('direct', 'broadcast')),
    owner_bid        TEXT NOT NULL REFERENCES identities (bid),
    peer_bid         TEXT,
    title            TEXT NOT NULL DEFAULT '',
    settings_json    TEXT,
    archived         INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    created_at_ms    INTEGER NOT NULL
);

-- ---------------------------------------------------------------------------
-- encounters: ephemeral discovery/session history for diagnostics and future
-- encounter-based routing decisions.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encounters (
    encounter_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_bid         TEXT REFERENCES peers (bid),
    transport        TEXT NOT NULL,
    started_at_ms    INTEGER NOT NULL,
    ended_at_ms      INTEGER,
    diagnostics      TEXT
);

-- ---------------------------------------------------------------------------
-- messages: the node's primary personal history — locally originated private
-- notes and (in later phases) received/sent addressed or broadcast envelopes.
--
-- `message_id` is globally unique and deduplication-anchored: inserting the
-- same ID with identical content is a no-op, inserting different content for
-- an existing ID is a conflict error, never a silent overwrite.
--
-- `visibility = 'private'` + `destination_bid IS NULL` marks a local-only note:
-- such rows are never eligible for advertisement, inventory, or relay.
-- `signed_envelope` holds the full signed wire envelope once protocol support
-- lands; `body` holds plaintext only for locally authored notes (remote
-- addressed messages stay ciphertext-only).
--
-- IMPORTANT: nothing cascades INTO this table from relay_queue. Deleting a
-- message deletes its queue/dedup/ledger bookkeeping, never the reverse —
-- relay queue saturation can never destroy personal history.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    message_id       TEXT PRIMARY KEY,
    origin_bid       TEXT NOT NULL,
    destination_bid  TEXT,
    conversation_id  TEXT REFERENCES conversations (conversation_id),
    visibility       TEXT NOT NULL CHECK (visibility IN ('private', 'direct', 'broadcast')),
    status           TEXT NOT NULL DEFAULT 'stored'
                     CHECK (status IN ('stored', 'pending', 'sent', 'delivered', 'failed')),
    signed_envelope  BLOB,
    body             BLOB,
    created_at_ms    INTEGER NOT NULL,
    received_at_ms   INTEGER,
    expires_at_ms    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON messages (conversation_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_messages_origin
    ON messages (origin_bid, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_messages_local_notes
    ON messages (created_at_ms)
    WHERE visibility = 'private' AND destination_bid IS NULL;

-- ---------------------------------------------------------------------------
-- relay_queue: custody of *other people's* opaque envelopes this node
-- volunteered to carry. Strictly separate from personal history and bounded
-- by config quotas enforced by the caller. `route_state` tracks where the
-- envelope is in its relay lifecycle; `custody` is the node's responsibility
-- state for it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS relay_queue (
    message_id       TEXT PRIMARY KEY REFERENCES messages (message_id)
                     ON DELETE CASCADE,
    route_state      TEXT NOT NULL
                     CHECK (route_state IN ('queued', 'offered', 'in_flight', 'cooldown', 'dropped')),
    custody          TEXT NOT NULL DEFAULT 'carrying'
                     CHECK (custody IN ('carrying', 'handed_off', 'expired', 'dropped')),
    stored_bytes     INTEGER NOT NULL CHECK (stored_bytes >= 0),
    jumps_used       INTEGER NOT NULL CHECK (jumps_used >= 0),
    max_jumps        INTEGER NOT NULL CHECK (max_jumps >= 0),
    queued_at_ms     INTEGER NOT NULL,
    expires_at_ms    INTEGER,
    last_attempt_ms  INTEGER,
    attempt_count    INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_relay_queue_state
    ON relay_queue (route_state, queued_at_ms);

-- ---------------------------------------------------------------------------
-- seen_messages: dedup ledger. `best_jumps` is the smallest known jump count
-- observed for the message; a lower-jump copy may still be worth forwarding.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS seen_messages (
    message_id       TEXT PRIMARY KEY REFERENCES messages (message_id)
                     ON DELETE CASCADE,
    best_jumps       INTEGER NOT NULL CHECK (best_jumps >= 0),
    first_seen_ms    INTEGER NOT NULL,
    last_seen_ms     INTEGER NOT NULL,
    seen_count       INTEGER NOT NULL DEFAULT 1 CHECK (seen_count >= 0)
);

-- ---------------------------------------------------------------------------
-- peer_delivery_ledger: per-(peer, message) sync accounting so a message is
-- never re-offered or re-transferred to a peer that already has it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peer_delivery_ledger (
    peer_bid         TEXT NOT NULL REFERENCES peers (bid),
    message_id       TEXT NOT NULL REFERENCES messages (message_id)
                     ON DELETE CASCADE,
    state            TEXT NOT NULL
                     CHECK (state IN ('offered', 'transferred', 'acknowledged', 'declined')),
    encounter_id     INTEGER REFERENCES encounters (encounter_id),
    updated_at_ms    INTEGER NOT NULL,
    PRIMARY KEY (peer_bid, message_id)
);

-- ---------------------------------------------------------------------------
-- profile_versions: append-only history of signed identity documents per BID
-- (display-name renames and encryption-key epochs). Monotonic `version`.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profile_versions (
    bid              TEXT NOT NULL,
    version          INTEGER NOT NULL CHECK (version >= 0),
    encryption_epoch INTEGER NOT NULL CHECK (encryption_epoch >= 0),
    display_name     TEXT NOT NULL,
    document         BLOB NOT NULL,
    recorded_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (bid, version)
);

-- ---------------------------------------------------------------------------
-- receipts: two deliberately distinct kinds — a `link` receipt acknowledges a
-- single hop's custody-style transfer (the sender may drop its copy to the
-- downstream hop), while a `destination` receipt is signed by the final
-- recipient and is the only proof of end-to-end delivery.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id       TEXT PRIMARY KEY,
    message_id       TEXT NOT NULL REFERENCES messages (message_id)
                     ON DELETE CASCADE,
    kind             TEXT NOT NULL CHECK (kind IN ('link', 'destination')),
    signer_bid       TEXT NOT NULL,
    signature        BLOB NOT NULL,
    jumps_at_signing INTEGER NOT NULL CHECK (jumps_at_signing >= 0),
    issued_at_ms     INTEGER NOT NULL,
    received_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_message
    ON receipts (message_id, kind);
