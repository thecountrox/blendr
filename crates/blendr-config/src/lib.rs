//! `blendr-config` — typed `config.json` schema, strict validation, safe path
//! resolution, and atomic settings persistence for the Blendr node.
//!
//! One device = one `config.json`. The schema is intentionally strict:
//! `deny_unknown_fields` on every table, fixed v1 enums, bounded integers, and
//! cross-field policy checks. Invalid input is never silently clamped.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// The only configuration schema revision supported by v1 code.
pub const SUPPORTED_CONFIG_VERSION: u64 = 1;
/// Absolute v1 protocol cap on intermediate relay devices ("jumps").
pub const MAX_JUMPS: u8 = 5;
/// Maximum length of `node.display_name` after normalization (Unicode scalar values).
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Full BID: RFC 4648 Base32 (no padding) of a 32-byte SHA-256 digest = 52 chars.
pub const BID_LENGTH: usize = 52;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors produced while loading, validating, resolving, or saving a config.
///
/// Messages never contain secret material: the JSON schema has no private-key
/// or passphrase fields, and error text only carries field names and
/// non-sensitive values.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("cannot read config file `{path}`: {source}")]
    Read {
        /// File that failed.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The JSON did not match the typed schema (syntax, type, or unknown key).
    #[error("invalid config `{path}`: {message}")]
    Parse {
        /// File that failed to parse.
        path: PathBuf,
        /// Field-qualified message (e.g. `mesh.outgoing.max_jumps: invalid value: integer `-1``).
        message: String,
    },
    /// A semantic/validation rule was violated.
    #[error("invalid config: `{field}`: {message}")]
    Validation {
        /// JSON field path such as `discovery.scan_window_ms`.
        field: String,
        /// Human-readable reason; never secret.
        message: String,
    },
    /// Persisting the config failed.
    #[error("cannot write config file `{path}`: {source}")]
    Write {
        /// Destination that failed.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
}

fn verr(field: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        field: field.into(),
        message: message.into(),
    }
}

/// Filesystem locations derived from a config, anchored to the directory that
/// contains the JSON file (relative paths never resolve against the process
/// working directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPaths {
    /// Root of app-private storage (`node.data_dir`).
    pub data_dir: PathBuf,
    /// Encrypted local private-key store (`identity.keystore_path`).
    pub keystore_path: PathBuf,
    /// SQLite database file (`storage.database_path`).
    pub database_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Schema — mirrors config.json exactly; every table denies unknown keys.
// No private keys, passphrases, or session secrets exist anywhere here.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    display_name: String,
    pub mode: String,
    pub data_dir: String,
    pub start_discoverable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    keystore_path: String,
    pub keystore_backend: String,
    pub display_bid_suffix_chars: u64,
    pub allow_encrypted_backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    enabled: bool,
    pub advertise: bool,
    pub scan: bool,
    pub service_uuid: String,
    pub rotate_discovery_token_seconds: u64,
    pub scan_window_ms: u64,
    pub scan_interval_ms: u64,
    pub peer_stale_after_seconds: u64,
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BleConfig {
    adapter: String,
    pub gatt_service_uuid: String,
    pub gatt_rx_characteristic_uuid: String,
    pub gatt_tx_characteristic_uuid: String,
    pub preferred_mtu: u64,
    pub max_frame_payload_bytes: u64,
    pub reassembly_timeout_ms: u64,
    pub connection_timeout_ms: u64,
    pub max_concurrent_links: u64,
    pub connect_retry_attempts: u64,
    pub connect_retry_backoff_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    preferred: String,
    pub ble: BleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshOutgoing {
    allow_jumps: bool,
    pub max_jumps: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshIncoming {
    accept_relayed_messages: bool,
    pub max_jumps: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRelay {
    enabled: bool,
    pub queue_max_messages: u64,
    pub queue_max_bytes: u64,
    pub max_relay_message_bytes: u64,
    pub forward_batch_max_messages: u64,
    pub max_distinct_peer_copies_per_message: u64,
    pub per_peer_offer_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRouting {
    strategy: String,
    pub deduplicate_by_message_id: bool,
    pub avoid_previous_peer: bool,
    pub reject_expired_messages: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    enabled: bool,
    pub outgoing: MeshOutgoing,
    pub incoming: MeshIncoming,
    pub relay: MeshRelay,
    pub routing: MeshRouting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharingConfig {
    default_visibility: String,
    pub broadcast_requires_explicit_opt_in: bool,
    pub sync_max_messages_per_session: u64,
    pub sync_max_bytes_per_session: u64,
    pub inventory_max_message_ids: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgementsConfig {
    link_receipt: bool,
    pub destination_delivery_receipt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagingConfig {
    max_text_utf8_bytes: u64,
    pub default_message_ttl_seconds: u64,
    pub sharing: SharingConfig,
    pub acknowledgements: AcknowledgementsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    identity_signature: String,
    pub bid_hash: String,
    pub bid_encoding: String,
    pub session_handshake: String,
    pub asynchronous_message_encryption: String,
    pub require_authenticated_sessions: bool,
    pub peer_trust_policy: String,
    pub blocked_bids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    engine: String,
    pub database_path: String,
    pub wal_enabled: bool,
    pub message_history_retention_days: u64,
    pub relay_expiry_cleanup_interval_seconds: u64,
    pub seen_message_id_retention_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    log_level: String,
    pub log_payload_contents: bool,
    pub log_peer_identifiers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeaturesConfig {
    broadcast_mode: bool,
    pub direct_messages: bool,
    match_mode_v2: bool,
    pub wifi_transport: bool,
    pub internet_relay: bool,
}

/// Typed representation of the single `config.json` for a Blendr node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration schema revision; v1 code accepts exactly `1`.
    pub config_version: u64,
    /// Node identity/display and storage root.
    pub node: NodeConfig,
    /// Encrypted keystore location and BID display options.
    pub identity: IdentityConfig,
    /// BLE discovery behavior.
    pub discovery: DiscoveryConfig,
    /// Transport selection and BLE link parameters.
    pub transport: TransportConfig,
    /// Mesh policy: outgoing/incoming jump ceilings, relay custody, routing.
    pub mesh: MeshConfig,
    /// Message limits, sharing defaults, and acknowledgements.
    pub messaging: MessagingConfig,
    /// Fixed interoperable crypto/trust suite and user deny list.
    pub security: SecurityConfig,
    /// SQLite storage location and retention.
    pub storage: StorageConfig,
    /// Logging behavior (privacy-safe defaults; explicit opt-in permitted).
    pub observability: ObservabilityConfig,
    /// Feature flags; v1-forbidden features must stay disabled.
    pub features: FeaturesConfig,
}

impl Config {
    /// Read, parse, normalize, and fully validate a `config.json`.
    ///
    /// Fails on unreadable files, malformed JSON, unknown keys anywhere in the
    /// tree, wrong types, out-of-range values, unsupported versions/suites/
    /// features, and unsafe or colliding paths relative to the file's
    /// directory. Nothing is silently clamped.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut de = serde_json::Deserializer::from_str(&text);
        let mut cfg: Config =
            serde_path_to_error::deserialize(&mut de).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                message: format!("{}: {}", e.path(), e.inner()),
            })?;
        cfg.node.display_name = normalize_display_name(&cfg.node.display_name);
        cfg.validate()?;
        let base = config_base_dir(path)?;
        cfg.check_paths(&base, Some(path))?;
        Ok(cfg)
    }

    /// Validate all semantic rules. `load` already runs this; call it after
    /// mutating a `Config` programmatically or before `save_atomic`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.config_version != SUPPORTED_CONFIG_VERSION {
            return Err(verr(
                "config_version",
                format!(
                    "unsupported revision {}; expected {SUPPORTED_CONFIG_VERSION}",
                    self.config_version
                ),
            ));
        }

        // -- node ------------------------------------------------------------
        check_display_name(&self.node.display_name)?;
        check_enum("node.mode", &self.node.mode, &["broadcast"])?;
        if self.node.data_dir.is_empty() {
            return Err(verr("node.data_dir", "must be a non-empty path"));
        }

        // -- identity ----------------------------------------------------------
        check_enum(
            "identity.keystore_backend",
            &self.identity.keystore_backend,
            &["encrypted_file"],
        )?;
        check_range(
            "identity.display_bid_suffix_chars",
            self.identity.display_bid_suffix_chars,
            1,
            BID_LENGTH as u64,
        )?;
        if self.identity.keystore_path.is_empty() {
            return Err(verr("identity.keystore_path", "must be a non-empty path"));
        }

        // -- discovery ---------------------------------------------------------
        check_uuid("discovery.service_uuid", &self.discovery.service_uuid)?;
        check_range(
            "discovery.rotate_discovery_token_seconds",
            self.discovery.rotate_discovery_token_seconds,
            1,
            86_400,
        )?;
        check_range(
            "discovery.scan_window_ms",
            self.discovery.scan_window_ms,
            1,
            600_000,
        )?;
        check_range(
            "discovery.scan_interval_ms",
            self.discovery.scan_interval_ms,
            1,
            3_600_000,
        )?;
        if self.discovery.scan_window_ms > self.discovery.scan_interval_ms {
            return Err(verr(
                "discovery.scan_window_ms",
                format!(
                    "{}ms exceeds discovery.scan_interval_ms of {}ms",
                    self.discovery.scan_window_ms, self.discovery.scan_interval_ms
                ),
            ));
        }
        check_range(
            "discovery.peer_stale_after_seconds",
            self.discovery.peer_stale_after_seconds,
            1,
            2_592_000,
        )?;

        // -- transport ---------------------------------------------------------
        check_enum("transport.preferred", &self.transport.preferred, &["ble"])?;
        let ble = &self.transport.ble;
        if ble.adapter.is_empty()
            || ble.adapter.len() > 64
            || !ble
                .adapter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(verr(
                "transport.ble.adapter",
                "must be `auto` or an adapter name of 1-64 chars [A-Za-z0-9_.-]",
            ));
        }
        check_uuid("transport.ble.gatt_service_uuid", &ble.gatt_service_uuid)?;
        check_uuid(
            "transport.ble.gatt_rx_characteristic_uuid",
            &ble.gatt_rx_characteristic_uuid,
        )?;
        check_uuid(
            "transport.ble.gatt_tx_characteristic_uuid",
            &ble.gatt_tx_characteristic_uuid,
        )?;
        let uuids = [
            ("discovery.service_uuid", &self.discovery.service_uuid),
            ("transport.ble.gatt_service_uuid", &ble.gatt_service_uuid),
            (
                "transport.ble.gatt_rx_characteristic_uuid",
                &ble.gatt_rx_characteristic_uuid,
            ),
            (
                "transport.ble.gatt_tx_characteristic_uuid",
                &ble.gatt_tx_characteristic_uuid,
            ),
        ];
        // discovery.service_uuid must match the GATT service UUID — a node
        // discovers peers by the same service it hosts.
        if !self
            .discovery
            .service_uuid
            .eq_ignore_ascii_case(&ble.gatt_service_uuid)
        {
            return Err(verr(
                "transport.ble.gatt_service_uuid",
                "must equal discovery.service_uuid so advertising matches the hosted GATT service",
            ));
        }
        // All configured UUIDs except the intentionally-matched service pair
        // must be distinct.
        for i in 0..uuids.len() {
            for j in (i + 1)..uuids.len() {
                if uuids[i].0 == "discovery.service_uuid" || uuids[j].0 == "discovery.service_uuid"
                {
                    continue; // handled above
                }
                if uuids[i].1.eq_ignore_ascii_case(uuids[j].1) {
                    return Err(verr(uuids[j].0, format!("duplicates {}", uuids[i].0)));
                }
            }
        }
        check_range("transport.ble.preferred_mtu", ble.preferred_mtu, 23, 517)?; // ATT MTU range
        check_range(
            "transport.ble.max_frame_payload_bytes",
            ble.max_frame_payload_bytes,
            1,
            65_535,
        )?;
        check_range(
            "transport.ble.reassembly_timeout_ms",
            ble.reassembly_timeout_ms,
            1,
            600_000,
        )?;
        check_range(
            "transport.ble.connection_timeout_ms",
            ble.connection_timeout_ms,
            1,
            600_000,
        )?;
        check_range(
            "transport.ble.max_concurrent_links",
            ble.max_concurrent_links,
            1,
            64,
        )?;
        check_range(
            "transport.ble.connect_retry_attempts",
            ble.connect_retry_attempts,
            0,
            16,
        )?;
        check_range(
            "transport.ble.connect_retry_backoff_ms",
            ble.connect_retry_backoff_ms,
            1,
            60_000,
        )?;

        // -- mesh --------------------------------------------------------------
        check_jumps("mesh.outgoing.max_jumps", self.mesh.outgoing.max_jumps)?;
        check_jumps("mesh.incoming.max_jumps", self.mesh.incoming.max_jumps)?;
        let relay = &self.mesh.relay;
        check_range(
            "mesh.relay.queue_max_messages",
            relay.queue_max_messages,
            1,
            100_000,
        )?;
        check_range(
            "mesh.relay.queue_max_bytes",
            relay.queue_max_bytes,
            1,
            1 << 30,
        )?;
        check_range(
            "mesh.relay.max_relay_message_bytes",
            relay.max_relay_message_bytes,
            1,
            1 << 20,
        )?;
        if relay.max_relay_message_bytes > relay.queue_max_bytes {
            return Err(verr(
                "mesh.relay.max_relay_message_bytes",
                "exceeds mesh.relay.queue_max_bytes; a single message can never fit the queue",
            ));
        }
        check_range(
            "mesh.relay.forward_batch_max_messages",
            relay.forward_batch_max_messages,
            1,
            10_000,
        )?;
        if relay.forward_batch_max_messages > relay.queue_max_messages {
            return Err(verr(
                "mesh.relay.forward_batch_max_messages",
                "exceeds mesh.relay.queue_max_messages",
            ));
        }
        check_range(
            "mesh.relay.max_distinct_peer_copies_per_message",
            relay.max_distinct_peer_copies_per_message,
            1,
            64,
        )?;
        check_range(
            "mesh.relay.per_peer_offer_interval_seconds",
            relay.per_peer_offer_interval_seconds,
            1,
            86_400,
        )?;
        check_enum(
            "mesh.routing.strategy",
            &self.mesh.routing.strategy,
            &["bounded_epidemic"],
        )?;

        // -- messaging ---------------------------------------------------------
        check_range(
            "messaging.max_text_utf8_bytes",
            self.messaging.max_text_utf8_bytes,
            1,
            1 << 20,
        )?;
        check_range(
            "messaging.default_message_ttl_seconds",
            self.messaging.default_message_ttl_seconds,
            1,
            31_536_000,
        )?;
        let sharing = &self.messaging.sharing;
        check_enum(
            "messaging.sharing.default_visibility",
            &sharing.default_visibility,
            &["private"],
        )?;
        if !sharing.broadcast_requires_explicit_opt_in {
            return Err(verr(
                "messaging.sharing.broadcast_requires_explicit_opt_in",
                "must be `true`: publishing to the mesh always requires explicit user opt-in",
            ));
        }
        check_range(
            "messaging.sharing.sync_max_messages_per_session",
            sharing.sync_max_messages_per_session,
            1,
            10_000,
        )?;
        check_range(
            "messaging.sharing.sync_max_bytes_per_session",
            sharing.sync_max_bytes_per_session,
            1,
            1 << 30,
        )?;
        check_range(
            "messaging.sharing.inventory_max_message_ids",
            sharing.inventory_max_message_ids,
            1,
            100_000,
        )?;

        // -- security ----------------------------------------------------------
        let sec = &self.security;
        check_enum(
            "security.identity_signature",
            &sec.identity_signature,
            &["ed25519"],
        )?;
        check_enum("security.bid_hash", &sec.bid_hash, &["sha256"])?;
        check_enum(
            "security.bid_encoding",
            &sec.bid_encoding,
            &["base32_nopad"],
        )?;
        check_enum(
            "security.session_handshake",
            &sec.session_handshake,
            &["noise_xx"],
        )?;
        check_enum(
            "security.asynchronous_message_encryption",
            &sec.asynchronous_message_encryption,
            &["hpke_x25519_hkdf_sha256_chacha20poly1305"],
        )?;
        if !sec.require_authenticated_sessions {
            return Err(verr(
                "security.require_authenticated_sessions",
                "must be `true`: unauthenticated sessions are not permitted in v1",
            ));
        }
        check_enum(
            "security.peer_trust_policy",
            &sec.peer_trust_policy,
            &["tofu_with_manual_verification"],
        )?;
        for (i, bid) in sec.blocked_bids.iter().enumerate() {
            if !is_valid_bid(bid) {
                return Err(verr(
                    format!("security.blocked_bids[{i}]"),
                    "must be a full 52-character canonical Base32 (no-pad, uppercase A-Z2-7, final char A or Q) BID",
                ));
            }
            if sec.blocked_bids[..i].contains(bid) {
                return Err(verr(
                    format!("security.blocked_bids[{i}]"),
                    "duplicate entry",
                ));
            }
        }

        // -- storage -----------------------------------------------------------
        check_enum("storage.engine", &self.storage.engine, &["sqlite"])?;
        if self.storage.database_path.is_empty() {
            return Err(verr("storage.database_path", "must be a non-empty path"));
        }
        check_range(
            "storage.message_history_retention_days",
            self.storage.message_history_retention_days,
            0, // 0 = keep local history until the user deletes it
            36_500,
        )?;
        check_range(
            "storage.relay_expiry_cleanup_interval_seconds",
            self.storage.relay_expiry_cleanup_interval_seconds,
            1,
            86_400,
        )?;
        check_range(
            "storage.seen_message_id_retention_days",
            self.storage.seen_message_id_retention_days,
            1,
            36_500,
        )?;

        // -- observability -----------------------------------------------------
        check_enum(
            "observability.log_level",
            &self.observability.log_level,
            &["error", "warn", "info", "debug", "trace", "off"],
        )?;
        // log_payload_contents / log_peer_identifiers are privacy-safe by
        // default but are legitimate explicit opt-ins — no further constraint.

        // -- features ----------------------------------------------------------
        for (field, enabled) in [
            ("features.match_mode_v2", self.features.match_mode_v2),
            ("features.wifi_transport", self.features.wifi_transport),
            ("features.internet_relay", self.features.internet_relay),
        ] {
            if enabled {
                return Err(verr(
                    field,
                    "must be `false`: this feature is not supported by v1 code",
                ));
            }
        }
        // broadcast_mode / direct_messages are v1 features; either value is valid.

        Ok(())
    }

    /// Effective outgoing jump ceiling: `mesh.enabled &&
    /// mesh.outgoing.allow_jumps ? mesh.outgoing.max_jumps : 0`.
    pub fn effective_outgoing_jumps(&self) -> u8 {
        if self.mesh.enabled && self.mesh.outgoing.allow_jumps {
            self.mesh.outgoing.max_jumps
        } else {
            0
        }
    }

    /// Effective incoming jump ceiling: `mesh.enabled &&
    /// mesh.incoming.accept_relayed_messages ? mesh.incoming.max_jumps : 0`.
    pub fn effective_incoming_jumps(&self) -> u8 {
        if self.mesh.enabled && self.mesh.incoming.accept_relayed_messages {
            self.mesh.incoming.max_jumps
        } else {
            0
        }
    }

    /// Load the config at `config_path` and resolve `data_dir`,
    /// `keystore_path`, and `database_path` relative to the directory that
    /// contains the file — never the process working directory. Two different
    /// config locations therefore resolve fully independently.
    pub fn resolved_paths(config_path: impl AsRef<Path>) -> Result<ResolvedPaths, ConfigError> {
        let path = config_path.as_ref();
        let cfg = Self::load(path)?;
        let base = config_base_dir(path)?;
        cfg.resolve(&base)
    }

    /// Validate and atomically persist this config to `path` using a temporary
    /// file + fsync + rename in the destination directory. The temp file is
    /// created owner-only (`0600`), cleaned up on failure, and the parent
    /// directory is fsynced after rename so the update survives crashes.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        self.validate()?;
        let path = path.as_ref();
        let base = config_base_dir(path)?;
        self.check_paths(&base, Some(path))?;

        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        let dir = match dir {
            Some(d) => d.to_path_buf(),
            None => PathBuf::from("."),
        };
        let name = path
            .file_name()
            .ok_or_else(|| verr("path", "save destination has no file name"))?;
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(
            ".{}.blendr-tmp-{}-{seq}",
            name.to_string_lossy(),
            std::process::id()
        ));

        let body = serde_json::to_vec_pretty(self).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: format!("serialization failed: {e}"),
        })?;

        let result = (|| -> Result<(), io::Error> {
            {
                let mut opts = OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                let mut f = opts.open(&tmp)?;
                f.write_all(&body)?;
                f.write_all(b"\n")?;
                f.sync_all()?;
            }
            fs::rename(&tmp, path)?;
            // fsync the destination directory so the rename itself is durable.
            let d = OpenOptions::new().read(true).open(&dir)?;
            d.sync_all()?;
            Ok(())
        })();

        if let Err(source) = result {
            let _ = fs::remove_file(&tmp); // best-effort cleanup of the temp file
            return Err(ConfigError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
        Ok(())
    }

    /// Resolve the three filesystem paths against `base` and run every safety
    /// check. `config_file` is used for collision detection when available.
    fn resolve(&self, base: &Path) -> Result<ResolvedPaths, ConfigError> {
        let data_dir = join_base(base, Path::new(&self.node.data_dir), "node.data_dir")?;
        let keystore_path = join_base(
            base,
            Path::new(&self.identity.keystore_path),
            "identity.keystore_path",
        )?;
        let database_path = join_base(
            base,
            Path::new(&self.storage.database_path),
            "storage.database_path",
        )?;
        Ok(ResolvedPaths {
            data_dir,
            keystore_path,
            database_path,
        })
    }

    /// Full path safety: resolution, collisions, non-directory parents, and
    /// unsafe symlink targets. Missing intended directories/files are fine —
    /// `blendr init` creates them.
    fn check_paths(&self, base: &Path, config_file: Option<&Path>) -> Result<(), ConfigError> {
        let resolved = self.resolve(base)?;

        check_dir_target("node.data_dir", &resolved.data_dir)?;
        check_file_target("identity.keystore_path", &resolved.keystore_path)?;
        check_file_target("storage.database_path", &resolved.database_path)?;

        // Collisions between the configured paths.
        if resolved.keystore_path == resolved.database_path {
            return Err(verr(
                "storage.database_path",
                "must differ from identity.keystore_path",
            ));
        }
        if resolved.keystore_path == resolved.data_dir {
            return Err(verr(
                "identity.keystore_path",
                "must be a file, not node.data_dir itself",
            ));
        }
        if resolved.database_path == resolved.data_dir {
            return Err(verr(
                "storage.database_path",
                "must be a file, not node.data_dir itself",
            ));
        }

        // Never let the keystore or database collide with the config file.
        if let Some(cfg) = config_file {
            let cfg_norm = normalize_lexical(&absolutize(cfg)?).map_err(|m| verr("config", m))?;
            let cfg_key = fs::canonicalize(&cfg_norm).unwrap_or(cfg_norm);
            for (field, p) in [
                ("identity.keystore_path", &resolved.keystore_path),
                ("storage.database_path", &resolved.database_path),
            ] {
                let key = fs::canonicalize(p).unwrap_or_else(|_| p.clone());
                if key == cfg_key {
                    return Err(verr(field, "collides with the config file itself"));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn check_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConfigError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(verr(
            field,
            format!(
                "unsupported value `{value}`; allowed: {}",
                allowed.join(", ")
            ),
        ))
    }
}

fn check_range(field: &str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(verr(
            field,
            format!("value {value} out of allowed range {min}..={max}"),
        ))
    }
}

fn check_jumps(field: &str, value: u8) -> Result<(), ConfigError> {
    if value > MAX_JUMPS {
        return Err(verr(
            field,
            format!("value {value} out of allowed range 0..={MAX_JUMPS}"),
        ));
    }
    Ok(())
}

fn normalize_display_name(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn check_display_name(name: &str) -> Result<(), ConfigError> {
    if *name != normalize_display_name(name) {
        return Err(verr(
            "node.display_name",
            "must be normalized: trimmed, single-space separated",
        ));
    }
    if name.is_empty() {
        return Err(verr("node.display_name", "must be non-empty"));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(verr(
            "node.display_name",
            format!("exceeds {MAX_DISPLAY_NAME_CHARS} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(verr(
            "node.display_name",
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// Strict UUID syntax check: 8-4-4-4-12 hexadecimal, hyphen-separated.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn check_uuid(field: &str, value: &str) -> Result<(), ConfigError> {
    if is_uuid(value) {
        Ok(())
    } else {
        Err(verr(
            field,
            format!("`{value}` is not a valid UUID (expected 8-4-4-4-12 hexadecimal)"),
        ))
    }
}

/// Canonical full BID: exactly 52 chars of RFC 4648 Base32 without padding
/// (A-Z2-7). A 256-bit SHA-256 digest occupies 51 full groups plus 1 bit, so
/// the final char's low 4 bits are padding and must be zero: only `A` (0) or
/// `Q` (16) are canonical.
fn is_valid_bid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == BID_LENGTH
        && b.iter().all(|c| matches!(c, b'A'..=b'Z' | b'2'..=b'7'))
        && matches!(b[BID_LENGTH - 1], b'A' | b'Q')
}

// ---------------------------------------------------------------------------
// Path resolution and safety
// ---------------------------------------------------------------------------

/// Absolute directory that anchors relative config paths.
fn config_base_dir(config_path: &Path) -> Result<PathBuf, ConfigError> {
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    absolutize(parent)
}

/// Make a path absolute using the process CWD (does not touch the filesystem).
fn absolutize(p: &Path) -> Result<PathBuf, ConfigError> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        let cwd = std::env::current_dir().map_err(|source| ConfigError::Read {
            path: p.to_path_buf(),
            source,
        })?;
        Ok(cwd.join(p))
    }
}

/// Lexically resolve `.` and `..` components without touching the filesystem.
/// `..` may not escape the filesystem root.
fn normalize_lexical(p: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return Err(format!(
                        "path `{}` escapes the filesystem root",
                        p.display()
                    ));
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

fn join_base(base: &Path, p: &Path, field: &str) -> Result<PathBuf, ConfigError> {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    normalize_lexical(&joined).map_err(|m| verr(field, m))
}

/// Inspect an existing path or its nearest existing ancestor.
///
/// Returns the nearest existing ancestor's canonicalized path, or `Ok(None)`
/// if nothing on the chain exists. Rejects broken-symlink targets and
/// non-directory ancestors.
fn nearest_existing_ancestor(path: &Path) -> io::Result<Option<PathBuf>> {
    let mut cur = Some(path);
    while let Some(p) = cur {
        match fs::symlink_metadata(p) {
            Ok(_) => return Ok(Some(fs::canonicalize(p)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => cur = p.parent(),
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// `data_dir` must, if it exists, resolve to a real directory. A symlink is
/// only acceptable when it resolves to a directory; files and broken symlinks
/// are unsafe. Missing directories are fine — init creates them.
fn check_dir_target(field: &str, path: &Path) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                match fs::canonicalize(path) {
                    Ok(target) if target.is_dir() => Ok(()),
                    Ok(_) => Err(verr(
                        field,
                        format!(
                            "`{}` is a symlink to a non-directory target",
                            path.display()
                        ),
                    )),
                    Err(_) => Err(verr(
                        field,
                        format!("`{}` is a dangling symlink", path.display()),
                    )),
                }
            } else if ft.is_dir() {
                Ok(())
            } else {
                Err(verr(
                    field,
                    format!("`{}` exists and is not a directory", path.display()),
                ))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Walk ancestors: the nearest existing ancestor must be a directory
            // (a symlink is fine only if it resolves to one).
            match nearest_existing_ancestor(path) {
                Ok(Some(ancestor)) if ancestor.is_dir() => Ok(()),
                Ok(Some(ancestor)) => Err(verr(
                    field,
                    format!(
                        "`{}` has a non-directory ancestor `{}`",
                        path.display(),
                        ancestor.display()
                    ),
                )),
                Ok(None) => Ok(()),
                Err(e) => Err(verr(
                    field,
                    format!("cannot inspect `{}`: {e}", path.display()),
                )),
            }
        }
        Err(e) => Err(verr(
            field,
            format!("cannot inspect `{}`: {e}", path.display()),
        )),
    }
}

/// A file target (keystore/database) must not be an existing directory, must
/// not be a symlink to anything other than a regular file, and every existing
/// ancestor must be a directory. Missing files/directories are fine.
fn check_file_target(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.file_name().is_none() {
        return Err(verr(
            field,
            format!("`{}` is not a file path", path.display()),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                match fs::canonicalize(path) {
                    Ok(target) if target.is_file() => Ok(()),
                    Ok(_) => Err(verr(
                        field,
                        format!("`{}` is a symlink to a non-file target", path.display()),
                    )),
                    Err(_) => Err(verr(
                        field,
                        format!("`{}` is a dangling symlink", path.display()),
                    )),
                }
            } else if ft.is_dir() {
                Err(verr(
                    field,
                    format!(
                        "`{}` exists and is a directory, expected a file path",
                        path.display()
                    ),
                ))
            } else {
                Ok(())
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => match nearest_existing_ancestor(path) {
            Ok(Some(ancestor)) if ancestor.is_dir() => Ok(()),
            Ok(Some(ancestor)) => Err(verr(
                field,
                format!(
                    "`{}` has a non-directory ancestor `{}`",
                    path.display(),
                    ancestor.display()
                ),
            )),
            Ok(None) => Ok(()),
            Err(e) => Err(verr(
                field,
                format!("cannot inspect `{}`: {e}", path.display()),
            )),
        },
        Err(e) => Err(verr(
            field,
            format!("cannot inspect `{}`: {e}", path.display()),
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests — deterministic behavioral coverage of validation boundaries.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::atomic::AtomicU64;

    const SAMPLE: &str = include_str!("../../../config.json");
    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn sample() -> Value {
        serde_json::from_str(SAMPLE).unwrap()
    }

    /// Set `dotted.path` inside the sample JSON and return the mutated text.
    /// Intermediate missing keys become objects so entirely-new leaf keys
    /// exercise `deny_unknown_fields` too.
    fn mutate(dotted: &str, value: Value) -> String {
        let mut doc = sample();
        let parts: Vec<&str> = dotted.split('.').collect();
        let mut cur = &mut doc;
        for p in &parts[..parts.len() - 1] {
            if !cur.is_object() {
                *cur = json!({});
            }
            cur = &mut cur[*p];
        }
        cur[parts[parts.len() - 1]] = value;
        serde_json::to_string_pretty(&doc).unwrap()
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("blendr-config-test-{}-{seq}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, contents).unwrap();
            p
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn load_str(dir: &TempDir, json: &str) -> Result<Config, ConfigError> {
        let p = dir.write("config.json", json);
        Config::load(p)
    }

    fn err_field(e: &ConfigError) -> String {
        match e {
            ConfigError::Validation { field, .. } => field.clone(),
            ConfigError::Parse { message, .. } => message.clone(),
            other => panic!("unexpected error kind: {other}"),
        }
    }

    // -- happy path -----------------------------------------------------------

    #[test]
    fn sample_loads_and_validates() {
        let dir = TempDir::new();
        let cfg = load_str(&dir, SAMPLE).expect("sample config must load");
        assert_eq!(cfg.config_version, 1);
        assert_eq!(cfg.node.display_name, "alice");
        assert_eq!(cfg.effective_outgoing_jumps(), 3);
        assert_eq!(cfg.effective_incoming_jumps(), 3);
    }

    #[test]
    fn effective_jumps_respect_disabled_switches() {
        let dir = TempDir::new();
        let cfg = load_str(&dir, &mutate("mesh.enabled", json!(false))).unwrap();
        assert_eq!(cfg.effective_outgoing_jumps(), 0);
        assert_eq!(cfg.effective_incoming_jumps(), 0);

        let cfg = load_str(&dir, &mutate("mesh.outgoing.allow_jumps", json!(false))).unwrap();
        assert_eq!(cfg.effective_outgoing_jumps(), 0);
        assert_eq!(cfg.effective_incoming_jumps(), 3);

        let cfg = load_str(
            &dir,
            &mutate("mesh.incoming.accept_relayed_messages", json!(false)),
        )
        .unwrap();
        assert_eq!(cfg.effective_outgoing_jumps(), 3);
        assert_eq!(cfg.effective_incoming_jumps(), 0);
    }

    #[test]
    fn independent_locations_resolve_independently() {
        let dir_a = TempDir::new();
        let dir_b = TempDir::new();
        let path_a = dir_a.write("config.json", SAMPLE);
        let path_b = dir_b.write("config.json", SAMPLE);
        let ra = Config::resolved_paths(&path_a).unwrap();
        let rb = Config::resolved_paths(&path_b).unwrap();
        assert_ne!(ra, rb);
        assert!(
            ra.data_dir
                .starts_with(dir_a.path().canonicalize().unwrap())
        );
        assert!(
            rb.data_dir
                .starts_with(dir_b.path().canonicalize().unwrap())
        );
        assert_eq!(ra.keystore_path, ra.data_dir.join("identity.enc"));
        assert_eq!(rb.database_path, rb.data_dir.join("blendr.sqlite3"));
    }

    // -- jumps ------------------------------------------------------------------

    #[test]
    fn jumps_boundaries() {
        let dir = TempDir::new();
        for field in ["mesh.outgoing.max_jumps", "mesh.incoming.max_jumps"] {
            for ok in [0u8, 5] {
                let json = mutate(field, json!(ok));
                load_str(&dir, &json).unwrap_or_else(|e| panic!("{field}={ok} must load: {e}"));
            }
            for bad in [json!(-1), json!(6), json!(2.5), json!("3"), json!(255)] {
                let e = load_str(&dir, &mutate(field, bad.clone())).unwrap_err();
                assert!(
                    err_field(&e).contains("max_jumps"),
                    "{field}={bad} error must name the field: {e}"
                );
            }
        }
    }

    // -- unknown keys ---------------------------------------------------------

    #[test]
    fn unknown_keys_rejected_everywhere() {
        let dir = TempDir::new();
        for (dotted, val) in [
            ("extra_top_level", json!(true)),
            ("node.extra", json!(1)),
            ("security.unexpected", json!("x")),
            ("mesh.relay.sneaky", json!(0)),
            ("transport.ble.unknown", json!(0)),
        ] {
            let e = load_str(&dir, &mutate(dotted, val)).unwrap_err();
            assert!(matches!(e, ConfigError::Parse { .. }), "{dotted}: {e}");
        }
    }

    #[test]
    fn no_secret_fields_exist() {
        let dir = TempDir::new();
        for (dotted, val) in [
            ("identity.private_key", json!("deadbeef")),
            ("identity.passphrase", json!("hunter2")),
            ("security.session_secret", json!("x")),
        ] {
            let e = load_str(&dir, &mutate(dotted, val)).unwrap_err();
            assert!(matches!(e, ConfigError::Parse { .. }), "{dotted}: {e}");
        }
    }

    // -- version / features -----------------------------------------------------

    #[test]
    fn unsupported_config_version_rejected() {
        let dir = TempDir::new();
        for v in [json!(0), json!(2), json!("1")] {
            load_str(&dir, &mutate("config_version", v)).unwrap_err();
        }
    }

    #[test]
    fn v1_forbidden_features_rejected() {
        let dir = TempDir::new();
        for f in [
            "features.match_mode_v2",
            "features.wifi_transport",
            "features.internet_relay",
        ] {
            let e = load_str(&dir, &mutate(f, json!(true))).unwrap_err();
            assert!(err_field(&e).contains(f), "{f}: {e}");
        }
        // v1 features may be toggled either way.
        load_str(&dir, &mutate("features.broadcast_mode", json!(false))).unwrap();
        load_str(&dir, &mutate("features.direct_messages", json!(false))).unwrap();
    }

    // -- security suite ---------------------------------------------------------

    #[test]
    fn security_suite_is_strict() {
        let dir = TempDir::new();
        for (field, bad) in [
            ("security.identity_signature", json!("rsa4096")),
            ("security.bid_hash", json!("sha1")),
            ("security.bid_encoding", json!("base64")),
            ("security.session_handshake", json!("noise_nk")),
            ("security.peer_trust_policy", json!("open")),
            ("mesh.routing.strategy", json!("flooding")),
            ("messaging.sharing.default_visibility", json!("public")),
            ("storage.engine", json!("postgres")),
            ("node.mode", json!("hidden")),
            ("transport.preferred", json!("wifi")),
            ("identity.keystore_backend", json!("plaintext")),
            ("observability.log_level", json!("chatty")),
        ] {
            let e = load_str(&dir, &mutate(field, bad)).unwrap_err();
            assert!(err_field(&e).contains(field), "{field}: {e}");
        }
        let e = load_str(
            &dir,
            &mutate("security.require_authenticated_sessions", json!(false)),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("require_authenticated_sessions"));
        let e = load_str(
            &dir,
            &mutate(
                "messaging.sharing.broadcast_requires_explicit_opt_in",
                json!(false),
            ),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("broadcast_requires_explicit_opt_in"));
        let e = load_str(
            &dir,
            &mutate(
                "security.asynchronous_message_encryption",
                json!("hpke_p256"),
            ),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("asynchronous_message_encryption"));
    }

    #[test]
    fn privacy_flags_are_explicit_opt_in() {
        let dir = TempDir::new();
        load_str(
            &dir,
            &mutate("observability.log_payload_contents", json!(true)),
        )
        .unwrap();
        load_str(
            &dir,
            &mutate("observability.log_peer_identifiers", json!(true)),
        )
        .unwrap();
    }

    // -- UUIDs ------------------------------------------------------------------

    #[test]
    fn bad_uuids_rejected() {
        let dir = TempDir::new();
        for bad in [
            json!("c2f60001-e7ca-4ac2-b6cd-10d5c0bf000"), // too short
            json!("c2f60001e7ca4ac2b6cd10d5c0bf0001"),    // missing hyphens
            json!("c2f60001-e7ca-4ac2-b6cd-10d5c0bf00zz"), // non-hex
            json!(""),                                    // empty
            json!(42),                                    // wrong type
        ] {
            load_str(
                &dir,
                &mutate("transport.ble.gatt_rx_characteristic_uuid", bad),
            )
            .unwrap_err();
        }
        // Uppercase hex is a valid UUID representation.
        load_str(
            &dir,
            &mutate(
                "transport.ble.gatt_rx_characteristic_uuid",
                json!("C2F60002-E7CA-4AC2-B6CD-10D5C0BF0002"),
            ),
        )
        .unwrap();
    }

    #[test]
    fn service_uuid_must_match_gatt_service() {
        let dir = TempDir::new();
        let e = load_str(
            &dir,
            &mutate(
                "discovery.service_uuid",
                json!("c2f60009-e7ca-4ac2-b6cd-10d5c0bf0009"),
            ),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("gatt_service_uuid"));
    }

    #[test]
    fn duplicate_uuids_rejected() {
        let dir = TempDir::new();
        let e = load_str(
            &dir,
            &mutate(
                "transport.ble.gatt_tx_characteristic_uuid",
                json!("c2f60002-e7ca-4ac2-b6cd-10d5c0bf0001"), // same as rx
            ),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("gatt_tx_characteristic_uuid"));
    }

    // -- blocked BIDs -----------------------------------------------------------

    #[test]
    fn blocked_bids_validated() {
        let dir = TempDir::new();
        // Canonical 256-bit BIDs: 52 chars, final char A or Q.
        for good in ["A".repeat(51) + "A", "A".repeat(51) + "Q"] {
            load_str(
                &dir,
                &mutate("security.blocked_bids", json!([good.clone()])),
            )
            .unwrap();
            // lowercase is not canonical Base32
            load_str(
                &dir,
                &mutate("security.blocked_bids", json!([good.to_lowercase()])),
            )
            .unwrap_err();
        }
        let good = "A".repeat(51) + "A";
        for bad in [
            json!(["A".repeat(51)]),       // too short
            json!(["A".repeat(53)]),       // too long
            json!(["A".repeat(51) + "0"]), // 0 not in base32
            json!(["A".repeat(51) + "2"]), // noncanonical: trailing padding bits set
            json!(["not-a-bid"]),
            json!([good.clone(), good.clone()]), // duplicates
            json!([42]),
        ] {
            load_str(&dir, &mutate("security.blocked_bids", bad)).unwrap_err();
        }
    }

    // -- scan window ------------------------------------------------------------

    #[test]
    fn scan_window_must_not_exceed_interval() {
        let dir = TempDir::new();
        let e = load_str(&dir, &mutate("discovery.scan_window_ms", json!(10_001))).unwrap_err();
        assert!(err_field(&e).contains("scan_window_ms"));
        // Equal is permitted.
        load_str(&dir, &mutate("discovery.scan_window_ms", json!(10_000))).unwrap();
    }

    // -- numeric bounds ---------------------------------------------------------

    #[test]
    fn numerics_bounded_and_positive() {
        let dir = TempDir::new();
        for (field, bads) in [
            (
                "transport.ble.preferred_mtu",
                vec![json!(0), json!(22), json!(518), json!(-1), json!(23.5)],
            ),
            ("mesh.relay.queue_max_messages", vec![json!(0)]),
            ("messaging.default_message_ttl_seconds", vec![json!(0)]),
            (
                "identity.display_bid_suffix_chars",
                vec![json!(0), json!(53)],
            ),
            ("storage.seen_message_id_retention_days", vec![json!(0)]),
            ("discovery.scan_interval_ms", vec![json!(0)]),
        ] {
            for bad in bads {
                let e = load_str(&dir, &mutate(field, bad.clone())).unwrap_err();
                assert!(err_field(&e).contains(field), "{field}={bad}: {e}");
            }
        }
        // Boundary values that must pass.
        load_str(&dir, &mutate("transport.ble.preferred_mtu", json!(23))).unwrap();
        load_str(&dir, &mutate("transport.ble.preferred_mtu", json!(517))).unwrap();
        load_str(
            &dir,
            &mutate("storage.message_history_retention_days", json!(0)),
        )
        .unwrap();
    }

    // -- display name -----------------------------------------------------------

    #[test]
    fn display_name_normalized_and_bounded() {
        let dir = TempDir::new();
        let cfg = load_str(&dir, &mutate("node.display_name", json!("  alice   bob  "))).unwrap();
        assert_eq!(cfg.node.display_name, "alice bob");
        for bad in [
            json!(""),
            json!("   "),
            json!("a".repeat(MAX_DISPLAY_NAME_CHARS + 1)),
            json!("bad\u{0007}name"),
        ] {
            load_str(&dir, &mutate("node.display_name", bad)).unwrap_err();
        }
        load_str(
            &dir,
            &mutate(
                "node.display_name",
                json!("a".repeat(MAX_DISPLAY_NAME_CHARS)),
            ),
        )
        .unwrap();
    }

    // -- paths ------------------------------------------------------------------

    #[test]
    fn non_directory_parents_rejected() {
        let dir = TempDir::new();
        // Make ./data an existing *file* so ./data/identity.enc has a
        // non-directory parent.
        dir.write("data", "not a dir");
        let e = load_str(&dir, SAMPLE).unwrap_err();
        assert!(err_field(&e).contains("keystore_path") || err_field(&e).contains("data_dir"));
    }

    #[test]
    fn directory_collision_rejected() {
        let dir = TempDir::new();
        // database_path points at an existing directory.
        fs::create_dir(dir.path().join("blocker")).unwrap();
        let p = dir.path().join("blocker");
        let e = load_str(
            &dir,
            &mutate("storage.database_path", json!(p.to_string_lossy())),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("database_path"));
    }

    #[test]
    fn same_keystore_and_database_rejected() {
        let dir = TempDir::new();
        let e = load_str(
            &dir,
            &mutate("storage.database_path", json!("./data/identity.enc")),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("database_path"));
    }

    #[test]
    fn keystore_colliding_with_config_file_rejected() {
        let dir = TempDir::new();
        let e = load_str(
            &dir,
            &mutate("identity.keystore_path", json!("./config.json")),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("keystore_path"));
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_symlink_targets_rejected() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        // Symlink keystore → a directory: unsafe.
        let real_dir = dir.path().join("real-dir");
        fs::create_dir(&real_dir).unwrap();
        let link = dir.path().join("link.enc");
        symlink(&real_dir, &link).unwrap();
        let e = load_str(
            &dir,
            &mutate("identity.keystore_path", json!(link.to_string_lossy())),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("keystore_path"));

        // Dangling symlink for data_dir: unsafe.
        let dangle = dir.path().join("dangling");
        symlink(dir.path().join("missing"), &dangle).unwrap();
        let e = load_str(
            &dir,
            &mutate("node.data_dir", json!(dangle.to_string_lossy())),
        )
        .unwrap_err();
        assert!(err_field(&e).contains("data_dir"));

        // Missing intended dirs are fine.
        load_str(&dir, SAMPLE).unwrap();
    }

    // -- atomic save --------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn save_atomic_writes_owner_only_and_reloads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let cfg = load_str(&dir, SAMPLE).unwrap();
        let out = dir.path().join("nested").join("config.json");
        fs::create_dir_all(out.parent().unwrap()).unwrap();
        cfg.save_atomic(&out).unwrap();
        let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "saved config must be owner-only");
        // No stray temp files.
        let leftovers: Vec<_> = fs::read_dir(out.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("blendr-tmp"))
            .collect();
        assert!(leftovers.is_empty());
        // Saved config loads and resolves against its own directory.
        let resolved = Config::resolved_paths(&out).unwrap();
        assert!(
            resolved
                .data_dir
                .starts_with(out.parent().unwrap().canonicalize().unwrap())
        );
    }

    #[test]
    fn save_atomic_validates_before_writing() {
        let dir = TempDir::new();
        let mut cfg = load_str(&dir, SAMPLE).unwrap();
        cfg.mesh.outgoing.max_jumps = 9; // invalid; must not persist
        let out = dir.path().join("out.json");
        assert!(cfg.save_atomic(&out).is_err());
        assert!(!out.exists());
    }
}
