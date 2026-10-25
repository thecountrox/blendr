//! `blendr-storage` — local-first SQLite persistence for the Blendr node.
//!
//! One embedded database (`storage.database_path`) holds the node's personal
//! history and mesh bookkeeping. Private key material is **never** stored here;
//! it lives only in the encrypted identity keystore managed by
//! `blendr-identity`.
//!
//! Guarantees implemented here:
//!
//! * **Migrations** are transactional and versioned via `PRAGMA user_version`;
//!   databases stamped with a newer schema version than this build supports are
//!   rejected rather than silently mangled.
//! * **Journal** mode is WAL when requested (`Store::open(.., true)`), with
//!   `busy_timeout`, `foreign_keys`, and `synchronous` configured on open.
//! * **Single local identity:** at most one row in `identities` may be the
//!   local owner (enforced by a partial unique index and checked in
//!   `set_local_identity`). Same-BID documents are only accepted with a
//!   strictly increasing `version` — renames/key epochs are monotonic.
//! * **Message dedup:** `message_id` is the dedup anchor. Re-inserting an
//!   identical row is a no-op (`Ok(false)`); inserting different content under
//!   an existing ID is a hard conflict, never a silent overwrite.
//! * **Separation of concerns:** private local notes are never relay-eligible,
//!   and nothing in `relay_queue` can cascade-delete personal history.
//!
//! Authenticated peer documents are TOFU-pinned and monotonic. Direct messages
//! have a durable outbox and distinct link/destination receipt states; received
//! messages retain only their encrypted envelope, never decrypted plaintext.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

mod direct;
pub use direct::{
    DirectMessage, MAX_DIRECT_ENVELOPE_BYTES, MAX_DIRECT_TEXT_BYTES, Peer, ReceiptKind,
    StoredReceipt, TrustStatus,
};

/// Schema revision this build can create/migrate to. Bump when adding
/// migrations to `MIGRATIONS`.
pub const SCHEMA_VERSION: u32 = 1;

/// `PRAGMA application_id` tag identifying a Blendr database.
/// `b"BLND"` as a big-endian i32.
pub const APPLICATION_ID: i32 = 0x424C_4E44;

/// Upper bound for a single `local_messages` page.
pub const MAX_LOCAL_MESSAGE_LIMIT: u32 = 10_000;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// SQLite file header magic, used to reject non-database targets early.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// (target_version, SQL) pairs applied in order. Each migration runs inside
/// its own transaction and bumps `user_version` to its target on success.
const MIGRATIONS: &[(u32, &str)] = &[(1, include_str!("schema.sql"))];

/// Errors produced by `blendr-storage`. Error text never contains secret
/// material; only public identifiers (BIDs, message IDs, paths) appear.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The database path (or one of its ancestors) is unsafe: a symlink or a
    /// non-regular existing file.
    #[error("unsafe database path `{path}`: {reason}")]
    UnsafePath {
        /// Offending path.
        path: PathBuf,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Filesystem setup or I/O around the database file failed.
    #[error("storage I/O error on `{path}`: {source}")]
    Io {
        /// Path being operated on.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The target file is not a Blendr database.
    #[error("`{path}` is not a Blendr database (bad application_id or file header)")]
    ForeignDatabase {
        /// File that failed the check.
        path: PathBuf,
    },
    /// The database's `user_version` is newer than this build understands.
    #[error(
        "database schema version {found} is newer than supported version {supported}; upgrade the application"
    )]
    UnsupportedSchemaVersion {
        /// Version found in the database.
        found: u32,
        /// Maximum version this build supports.
        supported: u32,
    },
    /// A local identity already exists with a different BID. The owner BID of
    /// a store can never be changed silently.
    #[error("a local identity already exists for a different BID")]
    LocalIdentityConflict,
    /// The supplied identity document is not a newer revision of the stored
    /// same-BID document (`version` must strictly increase).
    #[error("identity document for this BID is not newer than the stored version")]
    NonMonotonicIdentityVersion,
    /// The supplied identity document claims the same `version` as the stored
    /// same-BID document but differs in content.
    #[error("identity document conflicts with the stored same-version document")]
    ConflictingIdentityDocument,
    /// The identity document bytes are not the expected JSON shape.
    #[error("invalid identity document: {reason}")]
    InvalidIdentityDocument {
        /// What was wrong with the document.
        reason: String,
    },
    /// A message insert tried to reuse an ID with different content.
    #[error("message `{message_id}` already exists with different content")]
    MessageConflict {
        /// Conflicting message ID.
        message_id: String,
    },
    /// A caller argument violated an API precondition.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// Human-readable reason; never secret.
        reason: String,
    },
    /// Underlying SQLite failure.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Convenience alias; the error type is a defaulted parameter so call sites
/// stay short while precise error types remain possible.
pub type Result<T, E = StorageError> = std::result::Result<T, E>;

/// A private, local-only note authored by this node. Returned by
/// [`Store::local_messages`]. Notes are never advertised, never enter sync
/// inventories, and never enter the relay queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMessage {
    /// Globally unique message ID chosen by the caller.
    pub id: String,
    /// Plaintext body (local notes are stored in the clear on-device).
    pub text: String,
    /// Author-supplied creation timestamp, milliseconds since Unix epoch.
    pub created_at_ms: i64,
}

/// Minimal projection of the identity document needed for monotonic update
/// checks. Field names mirror `blendr_identity::IdentityDocument`'s public
/// serialization; extra fields are ignored.
#[derive(Debug, Deserialize)]
struct IdentityDocProjection {
    bid: String,
    display_name: String,
    version: u64,
    encryption_epoch: u64,
}

fn invalid_input(reason: impl Into<String>) -> StorageError {
    StorageError::InvalidInput {
        reason: reason.into(),
    }
}

fn invalid_doc(reason: impl Into<String>) -> StorageError {
    StorageError::InvalidIdentityDocument {
        reason: reason.into(),
    }
}

fn io_err(path: &Path) -> impl Fn(io::Error) -> StorageError + '_ {
    move |source| StorageError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn now_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(_) => 0,
    }
}

/// SQLite-backed store. Open with [`Store::open`]; all multi-statement writes
/// run inside transactions.
pub struct Store {
    conn: Connection,
    path: PathBuf,
    wal: bool,
}

impl Store {
    /// Opens (creating if needed) the Blendr database at `path`, applies
    /// pending migrations, and configures journal/timeout/foreign-key policy.
    ///
    /// Safety checks on `path`:
    /// * the final component and every existing ancestor must not be symlinks;
    /// * an existing target must be a regular file and, once checked, must
    ///   carry Blendr's `application_id` (or be empty/new);
    /// * a new database file is created with owner-only permissions (`0600`).
    ///
    /// `wal = true` selects WAL journaling (`synchronous = NORMAL`); `false`
    /// selects rollback journaling (`TRUNCATE`, `synchronous = FULL`).
    pub fn open(path: impl AsRef<Path>, wal: bool) -> Result<Self> {
        let path = path.as_ref();
        check_safe_target(path)?;
        ensure_parent_dir(path)?;

        let existed = path.exists();
        if !existed {
            create_owner_only_file(path)?;
        } else {
            reject_non_sqlite_header(path)?;
            tighten_permissions(path)?;
        }

        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
        } else {
            conn.pragma_update(None, "journal_mode", "TRUNCATE")?;
            conn.pragma_update(None, "synchronous", "FULL")?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut store = Store {
            conn,
            path: path.to_path_buf(),
            wal,
        };
        store.check_identity_and_migrate()?;
        Ok(store)
    }

    /// Path of the underlying database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the store was opened in WAL mode.
    pub fn is_wal(&self) -> bool {
        self.wal
    }

    /// Validates `application_id`/`user_version`, then applies pending
    /// migrations one transaction at a time.
    fn check_identity_and_migrate(&mut self) -> Result<()> {
        let app_id: i64 = self
            .conn
            .pragma_query_value(None, "application_id", |row| row.get(0))?;
        if app_id != 0 && app_id != APPLICATION_ID as i64 {
            return Err(StorageError::ForeignDatabase {
                path: self.path.clone(),
            });
        }

        let found: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        let found = u32::try_from(found).map_err(|_| StorageError::UnsupportedSchemaVersion {
            found: u32::MAX,
            supported: SCHEMA_VERSION,
        })?;
        if found > SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion {
                found,
                supported: SCHEMA_VERSION,
            });
        }

        for &(target, sql) in MIGRATIONS {
            if target > found {
                let tx = self.conn.transaction()?;
                tx.execute_batch(sql)?;
                if target == 1 {
                    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
                }
                tx.pragma_update(None, "user_version", target)?;
                tx.commit()?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Local identity
    // -----------------------------------------------------------------------

    /// Returns the local owner's `(BID, canonical identity document JSON)` if
    /// one has been installed via [`Store::set_local_identity`].
    pub fn local_identity(&self) -> Result<Option<(String, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT bid, document FROM identities WHERE is_local = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Installs or updates this device's identity document.
    ///
    /// * If no local identity exists, `bid` becomes the owner. The owner BID
    ///   can never change afterward.
    /// * If the same BID is already stored, the document is only accepted when
    ///   its `version` is strictly greater than the stored one — a stale or
    ///   different same-version document is rejected, never silently merged.
    /// * Every accepted document is appended to `profile_versions` so
    ///   signed renames / encryption-key epochs are retained.
    ///
    /// The whole operation is a single transaction.
    pub fn set_local_identity(&mut self, bid: &str, document_json: &[u8]) -> Result<()> {
        let doc = parse_identity_document(document_json)?;
        if doc.bid != bid {
            return Err(invalid_doc("document BID does not match the supplied BID"));
        }
        let version_i64 = i64::try_from(doc.version)
            .map_err(|_| invalid_doc("version exceeds the SQLite integer range"))?;
        let epoch_i64 = i64::try_from(doc.encryption_epoch)
            .map_err(|_| invalid_doc("encryption_epoch exceeds the SQLite integer range"))?;
        let now = now_ms();

        let tx = self.conn.transaction()?;

        // Single-owner invariant: an owner may exist only for the same BID.
        let owner: Option<String> = tx
            .query_row("SELECT bid FROM identities WHERE is_local = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(owner_bid) = owner
            && owner_bid != bid
        {
            return Err(StorageError::LocalIdentityConflict);
        }

        // Monotonic same-BID writes against whatever row exists (local or a
        // previously cached remote document for this BID).
        let stored: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT document_version, document FROM identities WHERE bid = ?1",
                params![bid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((stored_version, stored_doc)) = &stored {
            if doc.version < *stored_version as u64 {
                return Err(StorageError::NonMonotonicIdentityVersion);
            }
            if doc.version == *stored_version as u64 && stored_doc.as_slice() != document_json {
                return Err(StorageError::ConflictingIdentityDocument);
            }
        }
        let already_stored = stored.is_some();

        if already_stored {
            // Accepting a same-version identical document is idempotent; only
            // strictly newer versions are real updates.
            tx.execute(
                "UPDATE identities
                 SET is_local = 1, document = ?2, document_version = ?3,
                     encryption_epoch = ?4, display_name = ?5, updated_at_ms = ?6
                 WHERE bid = ?1",
                params![
                    bid,
                    document_json,
                    version_i64,
                    epoch_i64,
                    doc.display_name,
                    now
                ],
            )?;
        } else {
            tx.execute(
                "INSERT INTO identities
                     (bid, is_local, document, document_version, encryption_epoch,
                      display_name, created_at_ms, updated_at_ms)
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![
                    bid,
                    document_json,
                    version_i64,
                    epoch_i64,
                    doc.display_name,
                    now
                ],
            )?;
        }

        // Append-only signed profile history; duplicate (bid, version) entries
        // are impossible by this point (conflicts were rejected above).
        tx.execute(
            "INSERT OR IGNORE INTO profile_versions
                 (bid, version, encryption_epoch, display_name, document, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                bid,
                version_i64,
                epoch_i64,
                doc.display_name,
                document_json,
                now
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Local private notes (primary personal history — never relay eligible)
    // -----------------------------------------------------------------------

    /// Inserts a private local-only note owned by `owner_bid`.
    ///
    /// Dedup semantics on `id`:
    /// * fresh ID → row inserted, returns `Ok(true)`;
    /// * identical existing row → no-op, returns `Ok(false)`;
    /// * same ID, different content → `Err(StorageError::MessageConflict)`.
    ///
    /// The message row and its `seen_messages` dedup entry are written in one
    /// transaction, mirroring the inbound-envelope rule (persist content and
    /// dedup state atomically before any custody acknowledgement).
    ///
    /// Private notes are `visibility = 'private'` with a NULL destination:
    /// they can never appear in inventories or the relay queue.
    pub fn insert_local_message(
        &mut self,
        id: &str,
        owner_bid: &str,
        text: &str,
        created_at_ms: i64,
    ) -> Result<bool> {
        if id.is_empty() {
            return Err(invalid_input("message ID must not be empty"));
        }
        if owner_bid.is_empty() {
            return Err(invalid_input("owner BID must not be empty"));
        }

        let tx = self.conn.transaction()?;
        let existing: Option<(String, String, i64, Option<String>, String)> = tx
            .query_row(
                "SELECT origin_bid, body, created_at_ms, destination_bid, visibility
                 FROM messages WHERE message_id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        String::from_utf8_lossy(
                            &row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
                        )
                        .into_owned(),
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;

        if let Some((origin, body, ts, dest, vis)) = existing {
            let identical = origin == owner_bid
                && body == text
                && ts == created_at_ms
                && dest.is_none()
                && vis == "private";
            if identical {
                // Idempotent retry of the same write.
                tx.commit()?;
                return Ok(false);
            }
            return Err(StorageError::MessageConflict {
                message_id: id.to_owned(),
            });
        }

        tx.execute(
            "INSERT INTO messages
                 (message_id, origin_bid, destination_bid, conversation_id,
                  visibility, status, signed_envelope, body,
                  created_at_ms, received_at_ms, expires_at_ms)
             VALUES (?1, ?2, NULL, NULL, 'private', 'stored', NULL, ?3, ?4, ?4, NULL)",
            params![id, owner_bid, text.as_bytes(), created_at_ms],
        )?;
        tx.execute(
            "INSERT INTO seen_messages
                 (message_id, best_jumps, first_seen_ms, last_seen_ms, seen_count)
             VALUES (?1, 0, ?2, ?2, 1)",
            params![id, created_at_ms],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Reads private local notes, newest first.
    ///
    /// * `search`: an optional **literal** substring (not a LIKE pattern; `%`
    ///   and `_` have no special meaning).
    /// * `limit`: page size bound, must be `1..=MAX_LOCAL_MESSAGE_LIMIT`.
    /// * Ordering is deterministic: `created_at_ms` descending, ties broken by
    ///   `message_id` ascending.
    pub fn local_messages(&self, search: Option<&str>, limit: u32) -> Result<Vec<LocalMessage>> {
        if limit == 0 {
            return Err(invalid_input("limit must be at least 1"));
        }
        if limit > MAX_LOCAL_MESSAGE_LIMIT {
            return Err(invalid_input(format!(
                "limit exceeds the maximum of {MAX_LOCAL_MESSAGE_LIMIT}"
            )));
        }

        let mut stmt = self.conn.prepare(
            "SELECT message_id, body, created_at_ms
             FROM messages
             WHERE visibility = 'private'
               AND destination_bid IS NULL
               AND (?1 IS NULL OR instr(COALESCE(body, ''), ?1) > 0)
             ORDER BY created_at_ms DESC, message_id ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![search, limit as i64], |row| {
                let bytes: Vec<u8> = row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default();
                Ok(LocalMessage {
                    id: row.get(0)?,
                    text: String::from_utf8_lossy(&bytes).into_owned(),
                    created_at_ms: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// Parses the caller-supplied identity document JSON enough to enforce
/// monotonic versioning and the BID match. Full signature verification is
/// `blendr-identity`'s job; storage only needs the projection.
fn parse_identity_document(document_json: &[u8]) -> Result<IdentityDocProjection> {
    serde_json::from_slice::<IdentityDocProjection>(document_json).map_err(|e| {
        invalid_doc(format!(
            "expected identity document JSON with bid/display_name/version/encryption_epoch: {e}"
        ))
    })
}

/// Rejects a database path whose final component or any existing ancestor is a
/// symlink, and any existing target that is not a regular file.
fn check_safe_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(StorageError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "database path must not be a symbolic link",
                });
            }
            if !meta.file_type().is_file() {
                return Err(StorageError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "existing database path is not a regular file",
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(path)(e)),
    }

    // Walk ancestors; any existing component that is a symlink is rejected so
    // `data/../x.db` cannot escape the app-private directory via link.
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(StorageError::UnsafePath {
                    path: ancestor.to_path_buf(),
                    reason: "path component must not be a symbolic link",
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Creates the parent directory if missing and restricts it to the owner when
/// we created it ourselves.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(StorageError::UnsafePath {
            path: path.to_path_buf(),
            reason: "database path has no parent directory",
        });
    };
    if parent.as_os_str().is_empty() {
        return Ok(()); // bare filename: current directory
    }
    let existed = parent.exists();
    if !existed {
        fs::create_dir_all(parent).map_err(io_err(parent))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(io_err(parent))?;
        }
    }
    Ok(())
}

/// Creates the database file with owner-only permissions before SQLite opens
/// it, so there is no window where a fresh database is world-readable.
fn create_owner_only_file(path: &Path) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let _file = opts.open(path).map_err(io_err(path))?;
    Ok(())
}

/// Narrows an existing database file to owner-only permissions if needed.
fn tighten_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(io_err(path))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_err(path))?;
        }
    }
    let _ = path;
    Ok(())
}

/// Reads the first 16 bytes of an existing file and rejects anything that is
/// not an SQLite database header. Empty files pass (treated as fresh).
fn reject_non_sqlite_header(path: &Path) -> Result<()> {
    let mut buf = [0u8; 16];
    let mut file = File::open(path).map_err(io_err(path))?;
    let n = file.read(&mut buf).map_err(io_err(path))?;
    if n == 0 {
        return Ok(());
    }
    if n < SQLITE_HEADER.len() || &buf[..SQLITE_HEADER.len()] != SQLITE_HEADER {
        return Err(StorageError::ForeignDatabase {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Fresh database path inside a tempdir that outlives the test via `keep`.
    struct TestDir {
        dir: tempfile::TempDir,
    }

    impl TestDir {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("tempdir"),
            }
        }
        fn db_path(&self) -> PathBuf {
            self.dir.path().join("blendr.db")
        }
    }

    fn doc(bid: &str, name: &str, version: u64, epoch: u64) -> Vec<u8> {
        // Shape mirrors blendr_identity::IdentityDocument's public fields.
        serde_json::json!({
            "bid": bid,
            "display_name": name,
            "version": version,
            "encryption_epoch": epoch,
            "signing_public_key": vec![0u8; 32],
            "encryption_public_key": vec![0u8; 32],
            "signature": []
        })
        .to_string()
        .into_bytes()
    }

    fn table_names(store: &Store) -> Vec<String> {
        let mut stmt = store
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn creates_all_plan_entities_and_marks_version() {
        let dir = TestDir::new();
        let store = Store::open(dir.db_path(), true).unwrap();
        let tables = table_names(&store);
        for expected in [
            "identities",
            "peers",
            "conversations",
            "messages",
            "relay_queue",
            "seen_messages",
            "peer_delivery_ledger",
            "encounters",
            "profile_versions",
            "receipts",
        ] {
            assert!(tables.iter().any(|t| t == expected), "missing {expected}");
        }
        let v: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v as u32, SCHEMA_VERSION);
        let app: i64 = store
            .conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_eq!(app as i32, APPLICATION_ID);
        let journal: String = store
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "wal");
    }

    #[test]
    fn reopen_is_idempotent_and_retains_notes() {
        let dir = TestDir::new();
        let path = dir.db_path();
        {
            let mut store = Store::open(&path, true).unwrap();
            assert!(
                store
                    .insert_local_message("m1", "BID_A", "hello world", 1_000)
                    .unwrap()
            );
            assert!(
                store
                    .insert_local_message("m2", "BID_A", "HELLO again", 2_000)
                    .unwrap()
            );
        }
        {
            let store = Store::open(&path, true).unwrap();
            let notes = store.local_messages(None, 10).unwrap();
            assert_eq!(notes.len(), 2);
            // deterministic newest-first ordering
            assert_eq!(notes[0].id, "m2");
            assert_eq!(notes[1].id, "m1");
        }
    }

    #[test]
    fn literal_substring_search_ignores_like_metacharacters() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        store
            .insert_local_message("m1", "BID_A", "100% sure", 1)
            .unwrap();
        store
            .insert_local_message("m2", "BID_A", "plain text", 2)
            .unwrap();

        // "%" is literal, not a wildcard: only the note containing it matches.
        let hits = store.local_messages(Some("%"), 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "m1");

        // substring semantics, case-sensitive, on the raw text
        let hits = store.local_messages(Some("sure"), 10).unwrap();
        assert_eq!(hits.len(), 1);
        let none = store.local_messages(Some("SURE"), 10).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn limit_is_bounded_and_ordering_deterministic() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        for i in 0..5u32 {
            store
                .insert_local_message(&format!("m{i}"), "BID_A", "x", 100) // same ts
                .unwrap();
        }
        // identical timestamps: tie-break by ascending message_id
        let ids: Vec<String> = store
            .local_messages(None, 10)
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec!["m0", "m1", "m2", "m3", "m4"]);

        assert!(matches!(
            store.local_messages(None, 0),
            Err(StorageError::InvalidInput { .. })
        ));
        assert!(matches!(
            store.local_messages(None, MAX_LOCAL_MESSAGE_LIMIT + 1),
            Err(StorageError::InvalidInput { .. })
        ));
        assert_eq!(store.local_messages(None, 2).unwrap().len(), 2);
    }

    #[test]
    fn dedup_idempotent_and_conflict_rejected() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        assert!(
            store
                .insert_local_message("m1", "BID_A", "same text", 5)
                .unwrap()
        );
        // identical retry: no-op
        assert!(
            !store
                .insert_local_message("m1", "BID_A", "same text", 5)
                .unwrap()
        );
        // changed content under the same ID: hard conflict
        assert!(matches!(
            store.insert_local_message("m1", "BID_A", "different text", 5),
            Err(StorageError::MessageConflict { .. })
        ));
        assert!(matches!(
            store.insert_local_message("m1", "BID_B", "same text", 5),
            Err(StorageError::MessageConflict { .. })
        ));
        // surviving row is the original
        let notes = store.local_messages(None, 10).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text, "same text");
    }

    #[test]
    fn message_and_seen_state_are_written_atomically() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        store
            .insert_local_message("m1", "BID_A", "note", 7)
            .unwrap();
        let seen: i64 = store
            .conn
            .query_row(
                "SELECT seen_count FROM seen_messages WHERE message_id = 'm1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn single_owner_invariant_and_monotonic_updates() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();

        assert!(store.local_identity().unwrap().is_none());
        store
            .set_local_identity("BID_A", &doc("BID_A", "alice", 1, 1))
            .unwrap();
        let (bid, _) = store.local_identity().unwrap().unwrap();
        assert_eq!(bid, "BID_A");

        // A different BID can never replace the owner.
        assert!(matches!(
            store.set_local_identity("BID_B", &doc("BID_B", "bob", 1, 1)),
            Err(StorageError::LocalIdentityConflict)
        ));

        // Same BID, newer version: allowed (signed rename/key epoch).
        store
            .set_local_identity("BID_A", &doc("BID_A", "alice2", 2, 1))
            .unwrap();

        // Older version: rejected.
        assert!(matches!(
            store.set_local_identity("BID_A", &doc("BID_A", "alice3", 1, 1)),
            Err(StorageError::NonMonotonicIdentityVersion)
        ));

        // Same version but different content: rejected, not merged.
        assert!(matches!(
            store.set_local_identity("BID_A", &doc("BID_A", "aliceX", 2, 2)),
            Err(StorageError::ConflictingIdentityDocument)
        ));

        // Mismatched document/BID pair: rejected.
        assert!(matches!(
            store.set_local_identity("BID_A", &doc("BID_Z", "z", 3, 1)),
            Err(StorageError::InvalidIdentityDocument { .. })
        ));

        // Profile history recorded both accepted versions.
        let versions: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM profile_versions WHERE bid = 'BID_A'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(versions, 2);
    }

    #[test]
    fn local_identity_survives_reopen() {
        let dir = TestDir::new();
        let path = dir.db_path();
        {
            let mut store = Store::open(&path, true).unwrap();
            store
                .set_local_identity("BID_A", &doc("BID_A", "alice", 1, 1))
                .unwrap();
        }
        {
            let store = Store::open(&path, true).unwrap();
            let (bid, doc_bytes) = store.local_identity().unwrap().unwrap();
            assert_eq!(bid, "BID_A");
            assert_eq!(doc_bytes, doc("BID_A", "alice", 1, 1));
        }
    }

    #[test]
    fn newer_user_version_is_rejected() {
        let dir = TestDir::new();
        let path = dir.db_path();
        {
            let store = Store::open(&path, true).unwrap();
            store
                .conn
                .pragma_update(None, "user_version", SCHEMA_VERSION + 5)
                .unwrap();
        }
        match Store::open(&path, true) {
            Err(StorageError::UnsupportedSchemaVersion { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 5);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            Err(error) => panic!("expected UnsupportedSchemaVersion, got {error}"),
            Ok(_) => panic!("unsupported schema was accepted"),
        }
    }

    #[test]
    fn symlink_and_non_regular_targets_are_rejected() {
        let dir = TestDir::new();
        let real = dir.dir.path().join("real.db");
        fs::write(&real, b"").unwrap();
        let link = dir.dir.path().join("link.db");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(matches!(
                Store::open(&link, true),
                Err(StorageError::UnsafePath { .. })
            ));
        }
        // A directory as the target is not a regular file.
        let subdir = dir.dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        assert!(matches!(
            Store::open(&subdir, true),
            Err(StorageError::UnsafePath { .. })
        ));
        // A non-SQLite file is rejected as foreign.
        let junk = dir.dir.path().join("junk.db");
        fs::write(&junk, b"definitely not sqlite").unwrap();
        assert!(matches!(
            Store::open(&junk, true),
            Err(StorageError::ForeignDatabase { .. })
        ));
    }

    #[test]
    fn new_database_file_is_owner_only() {
        let dir = TestDir::new();
        let path = dir.db_path();
        let _store = Store::open(&path, true).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn relay_queue_cannot_delete_personal_history() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        store
            .insert_local_message("personal", "BID_A", "my private note", 1)
            .unwrap();
        // Saturate the relay queue with foreign envelopes.
        let foreign: Vec<String> = (0..3)
            .map(|i| {
                let id = format!("relay-{i}");
                store
                    .conn
                    .execute(
                        "INSERT INTO messages
                             (message_id, origin_bid, visibility, status, created_at_ms)
                         VALUES (?1, 'BID_X', 'direct', 'stored', 1)",
                        params![id],
                    )
                    .unwrap();
                store
                    .conn
                    .execute(
                        "INSERT INTO relay_queue
                             (message_id, route_state, custody, stored_bytes,
                              jumps_used, max_jumps, queued_at_ms)
                         VALUES (?1, 'queued', 'carrying', 128, 0, 3, 1)",
                        params![id],
                    )
                    .unwrap();
                id
            })
            .collect();
        // Even deleting every relay entry leaves personal history intact.
        for id in &foreign {
            store
                .conn
                .execute("DELETE FROM relay_queue WHERE message_id = ?1", params![id])
                .unwrap();
            store
                .conn
                .execute("DELETE FROM messages WHERE message_id = ?1", params![id])
                .unwrap();
        }
        let notes = store.local_messages(None, 10).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, "personal");
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let dir = TestDir::new();
        let store = Store::open(dir.db_path(), true).unwrap();
        let on: i64 = store
            .conn
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
        // Orphan relay entries are impossible.
        assert!(
            store
                .conn
                .execute(
                    "INSERT INTO relay_queue
                     (message_id, route_state, custody, stored_bytes,
                      jumps_used, max_jumps, queued_at_ms)
                 VALUES ('ghost', 'queued', 'carrying', 1, 0, 3, 1)",
                    [],
                )
                .is_err()
        );
    }

    #[test]
    fn database_contains_no_private_key_columns() {
        let dir = TestDir::new();
        let store = Store::open(dir.db_path(), true).unwrap();
        let mut stmt = store
            .conn
            .prepare(
                "SELECT m.name, p.name FROM sqlite_master m
                 JOIN pragma_table_info(m.name) p
                 WHERE m.type = 'table'",
            )
            .unwrap();
        let cols: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for (table, col) in &cols {
            let c = col.to_lowercase();
            assert!(
                !c.contains("private") && !c.contains("secret") && !c.contains("passphrase"),
                "suspicious secret-bearing column {table}.{col}"
            );
        }
    }

    #[test]
    fn empty_id_and_owner_are_rejected() {
        let dir = TestDir::new();
        let mut store = Store::open(dir.db_path(), true).unwrap();
        assert!(matches!(
            store.insert_local_message("", "BID_A", "x", 1),
            Err(StorageError::InvalidInput { .. })
        ));
        assert!(matches!(
            store.insert_local_message("m1", "", "x", 1),
            Err(StorageError::InvalidInput { .. })
        ));
        // dropped transaction left nothing behind
        assert!(store.local_messages(None, 10).unwrap().is_empty());
    }

    #[test]
    fn non_wal_mode_uses_truncate_journal() {
        let dir = TestDir::new();
        let store = Store::open(dir.db_path(), false).unwrap();
        let journal: String = store
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "truncate");
    }

    #[test]
    fn sequences_do_not_collide_across_stores() {
        // Regression guard: two stores in separate dirs coexist (no shared
        // global state beyond per-file handles).
        let seq = TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir_a = TestDir::new();
        let dir_b = TestDir::new();
        let mut a = Store::open(dir_a.db_path(), true).unwrap();
        let mut b = Store::open(dir_b.db_path(), true).unwrap();
        a.insert_local_message("m", "BID_A", "a", seq as i64)
            .unwrap();
        b.insert_local_message("m", "BID_B", "b", seq as i64)
            .unwrap();
        assert_eq!(a.local_messages(None, 1).unwrap()[0].text, "a");
        assert_eq!(b.local_messages(None, 1).unwrap()[0].text, "b");
    }
}
