//! blendr — Linux CLI for the Blendr local-first BLE messenger.
//!
//! * `blendr doctor` — config validation + Linux BLE prerequisite checks.
//! * `blendr init` — create data directories, an encrypted keystore, and the
//!   SQLite database without ever overwriting an existing identity. Re-running
//!   on a fully initialized node verifies consistency and is a no-op.
//! * `blendr identity show|rename|export|import` — inspect, rename, and
//!   back up / restore the local identity.
//! * `blendr note` / `blendr inbox` — private local notes and decrypted
//!   direct-message history.
//! * `blendr start|peers|send` — authenticated Noise XX sessions, peer
//!   pinning/trust, and addressed direct messaging over BLE (see `network`).
//!
//! Secrets policy: passphrases are only ever read from the terminal
//! (rpassword) or from `--passphrase-file`/`--backup-passphrase-file` files
//! that must be owner-only regular files. They never appear as command-line
//! values, environment variables, or in error messages.

mod doctor;
mod network;
mod secrets;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use blendr_config::{Config, ConfigError};
use blendr_identity::Identity;
use blendr_storage::Store;
use clap::{Parser, Subcommand};
use serde_json::Value;

/// Exit status used for every runtime failure (identity, keystore, storage,
/// passphrase prompts/files). Never carries secret material.
const EXIT_RUNTIME_ERROR: u8 = 1;
/// Configuration could not be loaded or is invalid (same code as doctor).
const EXIT_CONFIG_ERROR: u8 = 3;
/// Hard cap on `blendr inbox --limit`.
const INBOX_LIMIT_MAX: u32 = 500;
/// Upper bound on candidate note text, applied in addition to the configured
/// `messaging.max_text_utf8_bytes` ceiling.
const MAX_NOTE_BYTES: usize = 64 * 1024;

/// Local-first, authenticated proximity messaging over Bluetooth LE.
#[derive(Parser)]
#[command(name = "blendr", version, about, long_about = None)]
struct Cli {
    /// Path to the Blendr JSON configuration file.
    ///
    /// Relative data paths inside the file are resolved against the
    /// configuration file's directory, not the process working directory.
    #[arg(
        long,
        global = true,
        default_value = "./config.json",
        value_name = "PATH"
    )]
    config: PathBuf,

    /// Read the keystore passphrase from PATH instead of prompting.
    ///
    /// Intended for automation. The file must be a regular file (no symlink),
    /// readable by the owner only (no group/other permission bits), and small.
    /// One trailing newline is stripped. Never pass passphrases as arguments.
    #[arg(long, global = true, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate the configuration and report Linux BLE prerequisites.
    ///
    /// Exit status: 0 = healthy (warnings allowed), 2 = command-line usage
    /// error, 3 = configuration could not be loaded or is invalid,
    /// 4 = required platform/hardware prerequisites are missing.
    Doctor,

    /// Initialize local data directories, the encrypted keystore, and the
    /// SQLite database described by the configuration.
    ///
    /// Never overwrites an existing identity. Re-running verifies that the
    /// keystore and database agree on the same BID and completes any partial
    /// earlier initialization. Exit status: 0 = initialized/already
    /// initialized, 1 = runtime error, 3 = config error.
    Init,

    /// Manage the local Blendr identity (BID).
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    /// Run a foreground authenticated BLE node (Ctrl-C to stop).
    Start {
        /// Stop after SECONDS; otherwise run until interrupted.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        duration: Option<u64>,
        /// Exit after one successful authenticated exchange.
        #[arg(long)]
        once: bool,
    },

    /// List authenticated known peers or manage their pinned identities.
    Peers {
        /// Discover and authenticate nearby nodes before listing stored peers.
        #[arg(long)]
        scan: bool,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        duration: u64,
        #[command(subcommand)]
        action: Option<PeerCommands>,
    },

    /// Encrypt and durably queue a direct message for a known full BID.
    Send {
        #[arg(long, value_name = "BID")]
        to: String,
        /// Message text; command-line text is visible in shell history.
        text: String,
        /// Queue only, without opening Bluetooth.
        #[arg(long)]
        queue_only: bool,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
    },

    /// Store a private local note. Notes are never published, synced, or
    /// relayed; they stay inside the local database.
    Note {
        /// Note text (bounded by messaging.max_text_utf8_bytes).
        text: String,
    },

    /// List private notes and decrypted direct-message history, newest first.
    Inbox {
        /// Literal substring search (ASCII case-insensitive).
        #[arg(long, value_name = "QUERY")]
        search: Option<String>,
        /// Maximum number of notes to list (1..=500).
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=INBOX_LIMIT_MAX as i64))]
        limit: u32,
        /// Only show direct messages with this full BID.
        #[arg(long, value_name = "BID")]
        peer: Option<String>,
        /// Exclude local-only notes.
        #[arg(long)]
        direct: bool,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Mark a peer verified after comparing its signing key out of band.
    Verify {
        bid: String,
        /// Exact 64-hex-character signing key from the other device's identity show.
        #[arg(long)]
        fingerprint: String,
    },
    /// Reject this peer's sessions and outgoing direct messages.
    Block { bid: String },
    /// Remove the local block; manual verification must be repeated.
    Unblock { bid: String },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Show the local identity: handle, full BID, document version, and
    /// public keys. Requires the keystore passphrase.
    Show,

    /// Rename the local identity's display name.
    ///
    /// Signs a new identity document with a monotonically increasing version
    /// (the BID never changes) and atomically updates `node.display_name` in
    /// the configuration. This is also the repair path when the configured
    /// display name and the identity document have drifted apart.
    Rename {
        /// New display name (whitespace is normalized like config.json).
        name: String,
    },

    /// Export the identity to an encrypted backup file.
    ///
    /// Refuses to overwrite an existing file. Requires
    /// `identity.allow_encrypted_backup = true`. A separate backup passphrase
    /// is prompted twice (or read from --backup-passphrase-file).
    Export {
        /// Destination path for the encrypted backup file.
        path: PathBuf,
        /// Read the backup passphrase from PATH instead of prompting
        /// (same owner-only file rules as --passphrase-file).
        #[arg(long, value_name = "PATH")]
        backup_passphrase_file: Option<PathBuf>,
    },

    /// Restore an identity from an encrypted backup file.
    ///
    /// Refuses to run if a keystore already exists at
    /// `identity.keystore_path` — it never overwrites an existing identity.
    /// Prompts for the backup passphrase and for a new local passphrase
    /// (twice). Requires `identity.allow_encrypted_backup = true`.
    Import {
        /// Path of the encrypted backup file produced by `identity export`.
        path: PathBuf,
        /// Read the backup passphrase from PATH instead of prompting.
        #[arg(long, value_name = "PATH")]
        backup_passphrase_file: Option<PathBuf>,
    },
}

/// A command failure that carries its exit code. Error text is always free of
/// secret material by construction (passphrases are never interpolated).
struct Fail {
    code: u8,
    message: String,
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn runtime(message: impl Into<String>) -> Fail {
    Fail {
        code: EXIT_RUNTIME_ERROR,
        message: message.into(),
    }
}

fn config_fail(err: ConfigError) -> Fail {
    Fail {
        code: EXIT_CONFIG_ERROR,
        message: err.to_string(),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Commands::Doctor => return doctor::run(&cli.config),
        Commands::Init => cmd_init(&cli),
        Commands::Identity { ref command } => match command {
            IdentityCommands::Show => cmd_identity_show(&cli),
            IdentityCommands::Rename { name } => cmd_identity_rename(&cli, name),
            IdentityCommands::Export {
                path,
                backup_passphrase_file,
            } => cmd_identity_export(&cli, path, backup_passphrase_file.as_deref()),
            IdentityCommands::Import {
                path,
                backup_passphrase_file,
            } => cmd_identity_import(&cli, path, backup_passphrase_file.as_deref()),
        },
        Commands::Note { ref text } => cmd_note(&cli, text),
        Commands::Start { duration, once } => network::start(&cli, duration, once),
        Commands::Peers {
            scan,
            duration,
            ref action,
        } => network::peers(&cli, scan, duration, action.as_ref()),
        Commands::Send {
            ref to,
            ref text,
            queue_only,
            timeout,
        } => network::send(&cli, to, text, queue_only, timeout),
        Commands::Inbox {
            ref search,
            limit,
            ref peer,
            direct,
        } => network::inbox(&cli, search.as_deref(), limit, peer.as_deref(), direct),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail) => {
            eprintln!("blendr: error: {fail}");
            ExitCode::from(fail.code)
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Load + validate the config and resolve its paths against the config file's
/// directory.
fn load_node(config_path: &Path) -> Result<(Config, blendr_config::ResolvedPaths), Fail> {
    let config = Config::load(config_path).map_err(config_fail)?;
    let paths = Config::resolved_paths(config_path).map_err(config_fail)?;
    Ok((config, paths))
}

/// Serialize a Config to a JSON value so private schema fields can be read the
/// same way `doctor` renders effective settings.
fn config_value(config: &Config) -> Result<Value, Fail> {
    serde_json::to_value(config).map_err(|e| runtime(format!("cannot serialize config: {e}")))
}

/// Read a `dotted.path` inside the serialized config; absence is a hard error
/// because the schema guarantees these keys exist.
fn config_at(config: &Config, path: &str) -> Result<Value, Fail> {
    let value = config_value(config)?;
    let mut cur = &value;
    for key in path.split('.') {
        cur = cur
            .get(key)
            .ok_or_else(|| runtime(format!("config missing `{path}`")))?;
    }
    Ok(cur.clone())
}

fn config_string(config: &Config, path: &str) -> Result<String, Fail> {
    config_at(config, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| runtime(format!("config `{path}` is not a string")))
}

fn config_u64(config: &Config, path: &str) -> Result<u64, Fail> {
    config_at(config, path)?
        .as_u64()
        .ok_or_else(|| runtime(format!("config `{path}` is not an integer")))
}

fn configured_display_name(config: &Config) -> Result<String, Fail> {
    config_string(config, "node.display_name")
}

/// The `name#suffix` handle shown to users; suffix length comes from
/// `identity.display_bid_suffix_chars` and is clamped to the BID length.
fn handle(config: &Config, bid: &str) -> String {
    let suffix_chars = config
        .identity
        .display_bid_suffix_chars
        .min(bid.chars().count() as u64) as usize;
    let start = bid.chars().count().saturating_sub(suffix_chars);
    let suffix: String = bid.chars().skip(start).collect();
    let name = configured_display_name(config).unwrap_or_default();
    format!("{name}#{suffix}")
}

/// Create `dir` (and parents) if needed and enforce owner-only permissions
/// (0700) on private data directories. New directories are created 0700; an
/// existing directory with group/other bits is tightened, and a refusal to
/// tighten (e.g. owned by another user) is a hard error rather than a
/// silently insecure data directory.
fn ensure_private_dir(dir: &Path) -> Result<(), Fail> {
    let mut created = false;
    if !dir.exists() {
        // Best-effort umask-independent path: create then chmod below.
        std::fs::create_dir_all(dir).map_err(|e| {
            runtime(format!(
                "cannot create data directory `{}`: {e}",
                dir.display()
            ))
        })?;
        created = true;
    }
    if !dir.is_dir() {
        return Err(runtime(format!(
            "data path `{}` exists but is not a directory",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)
            .map_err(|e| {
                runtime(format!(
                    "cannot stat data directory `{}`: {e}",
                    dir.display()
                ))
            })?
            .permissions()
            .mode()
            & 0o777;
        if created || mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
                runtime(format!(
                    "data directory `{}` must be owner-only (mode {:o}); cannot tighten \
                     permissions: {e}",
                    dir.display(),
                    mode
                ))
            })?;
        }
    }
    Ok(())
}

/// Create the private directories used by this node: `node.data_dir` plus the
/// parent directories of the keystore and database files (which may live
/// outside `data_dir` when configured independently).
fn ensure_private_dirs(paths: &blendr_config::ResolvedPaths) -> Result<(), Fail> {
    ensure_private_dir(&paths.data_dir)?;
    for file in [&paths.keystore_path, &paths.database_path] {
        if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
            ensure_private_dir(parent)?;
        }
    }
    Ok(())
}

/// Open the SQLite store honoring `storage.wal_enabled`.
fn open_store(config: &Config, paths: &blendr_config::ResolvedPaths) -> Result<Store, Fail> {
    Store::open(&paths.database_path, config.storage.wal_enabled).map_err(|e| {
        runtime(format!(
            "cannot open database `{}`: {e}",
            paths.database_path.display()
        ))
    })
}

/// Load the local identity from the keystore and the store, verify the signed
/// document, reconcile the stored public document, and refuse configuration
/// display-name drift. Shared by every command that operates on an existing
/// node.
fn open_node(
    config: &Config,
    paths: &blendr_config::ResolvedPaths,
    passphrase: &str,
) -> Result<(Identity, Store), Fail> {
    if !paths.keystore_path.exists() {
        return Err(runtime(format!(
            "no keystore at `{}` — run `blendr init` (or `blendr identity import`) first",
            paths.keystore_path.display()
        )));
    }
    let identity = Identity::load(&paths.keystore_path, passphrase)
        .map_err(|e| runtime(format!("cannot unlock keystore: {e}")))?;
    let document = identity.document();
    document
        .verify()
        .map_err(|e| runtime(format!("stored identity document failed verification: {e}")))?;
    reconcile_store(config, paths, &document)?;
    drift_check(config, &document)?;
    let store = open_store(config, paths)?;
    Ok((identity, store))
}

/// Open SQLite and insert/update the stored local identity document. Refuses
/// if the database already owns a different BID.
fn reconcile_store(
    config: &Config,
    paths: &blendr_config::ResolvedPaths,
    document: &blendr_identity::IdentityDocument,
) -> Result<(), Fail> {
    let mut store = open_store(config, paths)?;
    let document_json = serde_json::to_vec(document)
        .map_err(|e| runtime(format!("cannot serialize identity document: {e}")))?;
    store
        .set_local_identity(&document.bid, &document_json)
        .map_err(|e| match e {
            blendr_storage::StorageError::LocalIdentityConflict => runtime(format!(
                "database already owns a different identity; refusing to mix identities \
                 (keystore `{}` vs database `{}`)",
                paths.keystore_path.display(),
                paths.database_path.display()
            )),
            e => runtime(format!(
                "cannot reconcile identity document in database: {e}"
            )),
        })?;
    Ok(())
}

/// Refuse to operate when `node.display_name` and the signed identity
/// document disagree. The explicit repair path is `blendr identity rename`.
fn drift_check(config: &Config, document: &blendr_identity::IdentityDocument) -> Result<(), Fail> {
    let configured = configured_display_name(config)?;
    if configured != document.display_name {
        return Err(runtime(format!(
            "display-name drift: config.json says `{configured}` but the signed identity \
             document says `{}`; run `blendr identity rename \"{configured}\"` (or the desired \
             name) to reconcile",
            document.display_name
        )));
    }
    Ok(())
}

fn unix_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Lowercase hex for public key material printed by `identity show`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(cli: &Cli) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    ensure_private_dirs(&paths)?;
    let store_bid = {
        let store = open_store(&config, &paths)?;
        store
            .local_identity()
            .map_err(|e| runtime(format!("cannot read local identity from database: {e}")))?
            .map(|(bid, _)| bid)
    };
    let keystore_exists = paths.keystore_path.exists();

    match (keystore_exists, store_bid.as_deref()) {
        // A database identity with no keystore is unrecoverable on its own:
        // the private keys are gone, so generating a new identity would
        // silently adopt a new BID while the database still owns the old one.
        // Restoring a backup of the *same* BID via `identity import` is the
        // intended recovery path.
        (false, Some(bid)) => Err(runtime(format!(
            "keystore `{}` is missing but database `{}` already records identity `{bid}`; \
             the private keys are required — restore its backup with `blendr identity import` \
             or point storage at an empty database",
            paths.keystore_path.display(),
            paths.database_path.display()
        ))),
        // Resume a complete or partially-completed initialization: verify the
        // keystore, make sure the database records the same BID's document,
        // and refuse display-name drift.
        (true, _) => {
            let passphrase = secrets::existing_passphrase(
                cli.passphrase_file.as_deref(),
                "keystore passphrase",
            )?;
            let identity = Identity::load(&paths.keystore_path, passphrase.as_str())
                .map_err(|e| runtime(format!("cannot unlock keystore: {e}")))?;
            let document = identity.document();
            document.verify().map_err(|e| {
                runtime(format!("stored identity document failed verification: {e}"))
            })?;
            reconcile_store(&config, &paths, &document)?;
            drift_check(&config, &document)?;
            if store_bid.is_some() {
                println!("blendr already initialized");
            } else {
                println!("blendr initialized (keystore recovered into fresh database)");
            }
            println!("  identity: {}", handle(&config, &document.bid));
            println!("  bid:      {}", document.bid);
            println!("  keystore: {}", paths.keystore_path.display());
            println!("  database: {}", paths.database_path.display());
            Ok(())
        }
        // Fresh initialization: generate keys, write the keystore first (never
        // overwriting), then record the public document in the database.
        (false, None) => {
            let configured = configured_display_name(&config)?;
            let passphrase =
                secrets::new_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
            let identity = Identity::generate(&configured)
                .map_err(|e| runtime(format!("cannot generate identity: {e}")))?;
            identity
                .save_new(&paths.keystore_path, passphrase.as_str())
                .map_err(|e| {
                    runtime(format!(
                        "cannot write keystore `{}` (existing identities are never \
                         overwritten): {e}",
                        paths.keystore_path.display()
                    ))
                })?;
            let document = identity.document();
            document.verify().map_err(|e| {
                runtime(format!("newly generated identity failed verification: {e}"))
            })?;
            reconcile_store(&config, &paths, &document)?;
            println!("blendr initialized");
            println!("  identity: {}", handle(&config, &document.bid));
            println!("  bid:      {}", document.bid);
            println!("  keystore: {}", paths.keystore_path.display());
            println!("  database: {}", paths.database_path.display());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

fn cmd_identity_show(cli: &Cli) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    let passphrase =
        secrets::existing_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
    let (identity, _store) = open_node(&config, &paths, passphrase.as_str())?;
    let document = identity.document();
    println!("identity: {}", handle(&config, &document.bid));
    println!("bid: {}", document.bid);
    println!("display_name: {}", document.display_name);
    println!("version: {}", document.version);
    println!("encryption_epoch: {}", document.encryption_epoch);
    println!("signing_public_key: {}", hex(&document.signing_public_key));
    println!(
        "encryption_public_key: {}",
        hex(&document.encryption_public_key)
    );
    println!("keystore: {}", paths.keystore_path.display());
    println!("database: {}", paths.database_path.display());
    Ok(())
}

fn cmd_identity_rename(cli: &Cli, raw_name: &str) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;

    // Normalize first: both Config::load and Identity::rename collapse
    // whitespace, while Config::validate *requires* the already-normalized
    // form — so the candidate must carry the normalized string.
    let normalized = raw_name.split_whitespace().collect::<Vec<_>>().join(" ");

    // Candidate config with node.display_name replaced; running the real
    // validator gives the same normalization/limits as config.json edits.
    let mut value = config_value(&config)?;
    value["node"]["display_name"] = Value::String(normalized.clone());
    let candidate: Config =
        serde_json::from_value(value).map_err(|e| runtime(format!("invalid display name: {e}")))?;
    candidate
        .validate()
        .map_err(|e| runtime(format!("invalid display name `{normalized}`: {e}")))?;
    let passphrase =
        secrets::existing_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
    if !paths.keystore_path.exists() {
        return Err(runtime(format!(
            "no keystore at `{}` — run `blendr init` first",
            paths.keystore_path.display()
        )));
    }
    let mut identity = Identity::load(&paths.keystore_path, passphrase.as_str())
        .map_err(|e| runtime(format!("cannot unlock keystore: {e}")))?;

    // Reconcile order: update the signed document only if the name actually
    // differs (keeps `rename` idempotent as a drift-repair path), then update
    // config.json atomically, then mirror the document into the database.
    let document = identity.document();
    if document.display_name != normalized {
        identity
            .rename(&normalized)
            .map_err(|e| runtime(format!("cannot rename identity: {e}")))?;
        identity
            .save_update(&paths.keystore_path, passphrase.as_str())
            .map_err(|e| {
                runtime(format!(
                    "cannot update keystore `{}`: {e}",
                    paths.keystore_path.display()
                ))
            })?;
    }
    let document = identity.document();
    document.verify().map_err(|e| {
        runtime(format!(
            "renamed identity document failed verification: {e}"
        ))
    })?;
    candidate.save_atomic(&cli.config).map_err(config_fail)?;
    reconcile_store(&candidate, &paths, &document)?;

    println!("renamed identity to `{normalized}`");
    println!("  bid:      {} (unchanged)", document.bid);
    println!("  version:  {}", document.version);
    Ok(())
}

fn cmd_identity_export(
    cli: &Cli,
    destination: &Path,
    backup_passphrase_file: Option<&Path>,
) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    if !config.identity.allow_encrypted_backup {
        return Err(runtime(
            "identity.allow_encrypted_backup is false; enable it in config.json to export \
             encrypted backups",
        ));
    }
    if destination.exists() {
        return Err(runtime(format!(
            "backup destination `{}` already exists; exports never overwrite — choose a new path",
            destination.display()
        )));
    }
    let passphrase =
        secrets::existing_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
    let (identity, _store) = open_node(&config, &paths, passphrase.as_str())?;
    let backup = secrets::new_passphrase(backup_passphrase_file, "backup passphrase")?;
    identity
        .save_new(destination, backup.as_str())
        .map_err(|e| {
            runtime(format!(
                "cannot write backup `{}` (existing files are never overwritten): {e}",
                destination.display()
            ))
        })?;
    println!(
        "exported encrypted identity backup to `{}`",
        destination.display()
    );
    println!("  bid: {}", identity.document().bid);
    Ok(())
}

fn cmd_identity_import(
    cli: &Cli,
    backup_path: &Path,
    backup_passphrase_file: Option<&Path>,
) -> Result<(), Fail> {
    let (mut config, paths) = load_node(&cli.config)?;
    if !config.identity.allow_encrypted_backup {
        return Err(runtime(
            "identity.allow_encrypted_backup is false; enable it in config.json to import \
             encrypted backups",
        ));
    }
    ensure_private_dirs(&paths)?;

    // A live keystore is an existing identity — import never overwrites it.
    if paths.keystore_path.exists() {
        return Err(runtime(format!(
            "a keystore already exists at `{}`; import never overwrites an existing \
             identity — remove it deliberately first if you really want to replace it",
            paths.keystore_path.display()
        )));
    }

    // A database that already owns a different BID is also an existing
    // identity and refuses the import. The *same* BID means the keystore was
    // lost and this import is restoring it — allowed, with version
    // reconciliation handled below.
    let stored_local = {
        let store = open_store(&config, &paths)?;
        store
            .local_identity()
            .map_err(|e| runtime(format!("cannot read local identity from database: {e}")))?
    };

    let backup = secrets::existing_passphrase(backup_passphrase_file, "backup passphrase")?;
    let mut identity = Identity::load(backup_path, backup.as_str()).map_err(|e| {
        runtime(format!(
            "cannot open backup `{}`: {e}",
            backup_path.display()
        ))
    })?;
    let document = identity.document();
    document
        .verify()
        .map_err(|e| runtime(format!("backup identity document failed verification: {e}")))?;

    if let Some((existing_bid, stored_json)) = &stored_local {
        if *existing_bid != document.bid {
            return Err(runtime(format!(
                "database `{}` already records a different identity (`{existing_bid}`); import \
                 never overwrites an existing identity — point storage at an empty database",
                paths.database_path.display()
            )));
        }
        // Same BID: decode and verify the database's document so version
        // reconciliation below is based on signed, trustworthy state.
        let stored_doc: blendr_identity::IdentityDocument = serde_json::from_slice(stored_json)
            .map_err(|e| {
                runtime(format!(
                    "stored identity document in database is malformed: {e}"
                ))
            })?;
        stored_doc
            .verify()
            .map_err(|e| runtime(format!("stored identity document failed verification: {e}")))?;
        if stored_doc.version == document.version && stored_doc != document {
            return Err(runtime(format!(
                "database already records a different version-{} document for this BID; \
                 refusing to fork identity history",
                document.version
            )));
        }
        if stored_doc.version > document.version {
            // The backup predates the database's newest document (e.g. a
            // rename happened after export). Restoring verbatim would regress
            // the monotonic version chain, so re-sign forward past the stored
            // version — keeping the database's display name — before writing
            // the keystore. Bounded defensively.
            let target = stored_doc.version + 1;
            let mut steps = 0u64;
            while identity.document().version < target {
                identity
                    .rename(&stored_doc.display_name)
                    .map_err(|e| runtime(format!("cannot roll backup forward: {e}")))?;
                steps += 1;
                if steps > 4096 {
                    return Err(runtime(
                        "stored identity version is implausibly far ahead of the backup",
                    ));
                }
            }
            println!(
                "backup predates the database's version {}; re-signed forward to version {}",
                stored_doc.version,
                identity.document().version
            );
        }
        println!("restoring keystore for the identity the database already owns");
    }

    let local = secrets::new_passphrase(cli.passphrase_file.as_deref(), "new keystore passphrase")?;
    identity
        .save_new(&paths.keystore_path, local.as_str())
        .map_err(|e| {
            runtime(format!(
                "cannot write keystore `{}`: {e}",
                paths.keystore_path.display()
            ))
        })?;
    let document = identity.document();
    if configured_display_name(&config)? != document.display_name {
        let mut value = config_value(&config)?;
        value["node"]["display_name"] = Value::String(document.display_name.clone());
        config = serde_json::from_value(value)
            .map_err(|error| runtime(format!("cannot restore display name: {error}")))?;
        config.save_atomic(&cli.config).map_err(|error| {
            runtime(format!(
                "keystore restored but configuration update failed: {error}; \
                 run `blendr identity rename` to reconcile"
            ))
        })?;
    }
    reconcile_store(&config, &paths, &document)?;

    println!("imported identity from `{}`", backup_path.display());
    println!("  bid:      {}", document.bid);
    println!("  keystore: {}", paths.keystore_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// local notes
// ---------------------------------------------------------------------------

fn cmd_note(cli: &Cli, text: &str) -> Result<(), Fail> {
    let (config, paths) = load_node(&cli.config)?;
    let max_bytes =
        (config_u64(&config, "messaging.max_text_utf8_bytes")? as usize).min(MAX_NOTE_BYTES);
    if text.is_empty() {
        return Err(runtime("note text must be non-empty"));
    }
    if text.len() > max_bytes {
        return Err(runtime(format!(
            "note is {} bytes; messaging.max_text_utf8_bytes allows at most {max_bytes}",
            text.len()
        )));
    }
    let passphrase =
        secrets::existing_passphrase(cli.passphrase_file.as_deref(), "keystore passphrase")?;
    let (identity, mut store) = open_node(&config, &paths, passphrase.as_str())?;
    let owner_bid = identity.document().bid;
    let created = unix_ms_now();
    // `insert_local_message` returns Ok(false) when an identical row already
    // exists — that is an idempotent success, not a collision. Only a
    // MessageConflict (same id, different content) needs a fresh id.
    let mut attempts_left = 3u32;
    let mut seq = 0u32;
    loop {
        let id = format!("ln-{created:x}-{:x}-{seq}", std::process::id());
        match store.insert_local_message(&id, &owner_bid, text, created) {
            Ok(fresh) => {
                if fresh {
                    println!("stored private note (never published or relayed)");
                } else {
                    println!("note already stored (idempotent write)");
                }
                return Ok(());
            }
            Err(blendr_storage::StorageError::MessageConflict { .. }) if attempts_left > 0 => {
                attempts_left -= 1;
                seq += 1;
            }
            Err(e) => return Err(runtime(format!("cannot store note: {e}"))),
        }
    }
}
