//! Versioned, passphrase-encrypted keystore for [`Identity`].
//!
//! On-disk layout (format v1):
//!
//! ```text
//! "BLNDKS" || canonical-CBOR header || ciphertext + Poly1305 tag
//! ```
//!
//! The header is a fixed definite-length CBOR array of nine items:
//! `[format_version, kdf_algorithm, argon2_version, m_cost, t_cost, p_cost,
//!   salt, nonce, ciphertext_len]`. Every byte preceding the ciphertext is
//! XChaCha20Poly1305 *associated data*, so tampering with the header — KDF
//! parameters, salt, nonce, or length fields — fails authentication.
//!
//! Fail-closed handling:
//!
//! * All header fields are bounds-checked **before** the Argon2id memory
//!   allocation, so a hostile file cannot force a huge allocation.
//! * The file must be a regular, non-symlink file with owner-only
//!   permissions; the opened inode is re-verified against `fstat` so a
//!   swapped file is rejected.
//! * `save_new` uses `create_new` and never overwrites anything, symlink or
//!   not. `save_update` writes a fresh temp file, fsyncs it, then atomically
//!   renames over the old keystore and fsyncs the parent directory.
//! * Argon2id output, plaintext buffers, and the passphrase-derived key are
//!   wiped via `zeroize`; nothing secret is ever logged or returned in an
//!   error.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version as Argon2Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BID_LENGTH, Identity, IdentityDocument, IdentityError, MAX_DISPLAY_NAME_CHARS, SIGNATURE_LENGTH,
};

/// Magic prefix identifying a Blendr keystore file.
const FILE_MAGIC: &[u8; 6] = b"BLNDKS";
/// The only keystore format version this crate reads or writes.
const FORMAT_VERSION_V1: u16 = 1;
/// Header field value for the only supported KDF.
const KDF_ALGORITHM_ARGON2ID: u8 = 1;
/// Argon2 version selector carried in the header (0x13 == `Version::V0x13`).
const ARGON2_VERSION_V13: u8 = 0x13;

/// Argon2id memory cost for newly written keystores (19 MiB).
/// Together with t=2 and p=1, this matches the argon2 crate defaults.
const WRITE_M_COST: u32 = 19 * 1024;
/// Argon2id time cost for newly written keystores.
const WRITE_T_COST: u32 = 2;
/// Argon2id lane count for newly written keystores.
const WRITE_P_COST: u32 = 1;

/// Bounds enforced on KDF parameters *read* from a header, checked before
/// any allocation. Accepts the local write profile while capping a hostile
/// file at 64 MiB of memory, eight passes, and four lanes.
const MIN_M_COST: u32 = 8;
const MAX_M_COST: u32 = 64 * 1024;
const MIN_T_COST: u32 = 1;
const MAX_T_COST: u32 = 8;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 4;
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;

/// Salt length minted for new keystores.
const SALT_LEN: usize = 16;
/// XChaCha20 nonce length (192 bits).
const NONCE_LEN: usize = 24;
/// AEAD key length derived from the passphrase.
const KEY_LEN: usize = 32;
/// Poly1305 tag length appended to every ciphertext.
const TAG_LEN: usize = 16;

/// Upper bound on the encoded header (magic excluded). The real v1 header is
/// ~100 bytes; anything larger is rejected before it can be used.
const MAX_HEADER_LEN: usize = 512;
/// Upper bound on the decrypted plaintext identity blob.
const MAX_PLAINTEXT_LEN: usize = 32 * 1024;
/// Upper bound on the whole keystore file.
const MAX_FILE_LEN: u64 = (FILE_MAGIC.len() + MAX_HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN) as u64;
/// Smallest structurally possible file: magic + a minimal header + tag.
const MIN_FILE_LEN: u64 = (FILE_MAGIC.len() + 16 + TAG_LEN) as u64;
/// Cap on retained X25519 epochs inside one plaintext blob.
const MAX_EPOCHS: u64 = 64;

/// Domain separator in the plaintext blob's first element.
const PLAINTEXT_DOMAIN: &str = "blendr:keystore:v1";

/// Write a keystore at `path`, failing if anything exists there — file,
/// symlink, or otherwise. The result is a regular 0600 file.
pub(crate) fn save_new(
    identity: &Identity,
    path: &Path,
    passphrase: &str,
) -> Result<(), IdentityError> {
    validate_passphrase(passphrase)?;
    let parent = checked_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let kind = if meta.file_type().is_symlink() {
                "a symlink"
            } else {
                "a file"
            };
            return Err(IdentityError::UnsafePath(format!(
                "`{}` already exists as {kind}; refusing to overwrite",
                path.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(IdentityError::Io(e)),
    }
    let target = real_target(&parent, path)?;
    let bytes = render(identity, passphrase)?;
    let mut file = create_new_file(&target)?;
    if let Err(e) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&target);
        return Err(e.into());
    }
    drop(file);
    enforce_owner_only(&target)?;
    sync_dir(&parent)?;
    Ok(())
}

/// Atomically replace the keystore at `path`. The existing file must unlock
/// with `passphrase` and carry the same BID, proving both authorization and
/// that this update cannot clobber somebody else's identity.
pub(crate) fn save_update(
    identity: &Identity,
    path: &Path,
    passphrase: &str,
) -> Result<(), IdentityError> {
    validate_passphrase(passphrase)?;
    let parent = checked_parent(path)?;
    let existing = load(path, passphrase)?;
    if existing.bid() != identity.bid() {
        return Err(IdentityError::KeystoreIntegrity(
            "existing keystore belongs to a different BID; refusing to overwrite".into(),
        ));
    }
    let target = real_target(&parent, path)?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)?;
    let tmp_path = parent.join(format!(
        "{}.tmp.{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        suffix[0],
        suffix[1],
        suffix[2],
        suffix[3],
        suffix[4],
        suffix[5],
        suffix[6],
        suffix[7],
    ));
    let bytes = render(identity, passphrase)?;
    let mut tmp = create_new_file(&tmp_path)?;
    let written = tmp.write_all(&bytes).and_then(|()| tmp.sync_all());
    if let Err(e) = written {
        drop(tmp);
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    drop(tmp);
    if let Err(e) = enforce_owner_only(&tmp_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    // `rename` is atomic on POSIX; std uses MOVEFILE_REPLACE_EXISTING on
    // Windows, so this replaces the old keystore in one step on both.
    if let Err(e) = fs::rename(&tmp_path, &target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    sync_dir(&parent)?;
    Ok(())
}

/// Unlock and decode the keystore at `path`.
pub(crate) fn load(path: &Path, passphrase: &str) -> Result<Identity, IdentityError> {
    validate_passphrase(passphrase)?;
    let link_meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(IdentityError::NotFound),
        Err(e) => return Err(IdentityError::Io(e)),
    };
    if link_meta.file_type().is_symlink() {
        return Err(IdentityError::UnsafePath(format!(
            "`{}` is a symlink; refusing to follow",
            path.display()
        )));
    }
    if !link_meta.is_file() {
        return Err(IdentityError::UnsafePath(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }
    if link_meta.len() > MAX_FILE_LEN || link_meta.len() < MIN_FILE_LEN {
        return Err(IdentityError::MalformedKeystore(
            "keystore length outside the format bounds".into(),
        ));
    }
    let file = File::open(path)?;
    let file_meta = file.metadata()?;
    // Re-verify what we actually opened: this inode must be the regular,
    // owner-only file we just inspected — a rename/symlink swap between the
    // two syscalls must not let us read an attacker-substituted file.
    if !file_meta.is_file() || !same_file(&link_meta, &file_meta) {
        return Err(IdentityError::UnsafePath(format!(
            "`{}` changed between inspection and open",
            path.display()
        )));
    }
    require_owner_only(&link_meta, path)?;
    require_owner_only(&file_meta, path)?;

    let mut buf = Vec::with_capacity(link_meta.len() as usize);
    (&file).take(MAX_FILE_LEN + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE_LEN {
        return Err(IdentityError::MalformedKeystore(
            "keystore exceeds the maximum file length".into(),
        ));
    }
    decrypt(Zeroizing::new(buf), passphrase)
}

/// Validate the passphrase: non-empty and not whitespace-only.
fn validate_passphrase(passphrase: &str) -> Result<(), IdentityError> {
    if passphrase.trim().is_empty() {
        return Err(IdentityError::InvalidPassphrase);
    }
    Ok(())
}

/// Inspect `path`'s parent directory and return its canonicalized form.
/// The parent must be a real directory (not a symlink, not a FIFO, …) and,
/// on Unix, must not be group-writable nor world-writable without the
/// sticky bit — otherwise a local attacker could swap files under us.
fn checked_parent(path: &Path) -> Result<PathBuf, IdentityError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let meta = match fs::symlink_metadata(parent) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(IdentityError::UnsafePath(format!(
                "parent directory `{}` does not exist",
                parent.display()
            )));
        }
        Err(e) => return Err(IdentityError::Io(e)),
    };
    if !meta.is_dir() {
        return Err(IdentityError::UnsafePath(format!(
            "parent `{}` is not a directory{}",
            parent.display(),
            if meta.file_type().is_symlink() {
                " (symlinks are not allowed)"
            } else {
                ""
            },
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o7777;
        // A sticky world-writable directory (e.g. /tmp) is the conventional
        // exception: the sticky bit prevents file hijacking by other users.
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(IdentityError::UnsafePath(format!(
                "parent directory `{}` is world-writable without the sticky bit",
                parent.display()
            )));
        }
        if mode & 0o020 != 0 {
            return Err(IdentityError::UnsafePath(format!(
                "parent directory `{}` is group-writable",
                parent.display()
            )));
        }
    }
    parent.canonicalize().map_err(IdentityError::Io)
}

/// Join the canonicalized parent with the literal final component so a
/// swapped ancestor directory cannot redirect the write.
fn real_target(parent: &Path, path: &Path) -> Result<PathBuf, IdentityError> {
    let name = path.file_name().ok_or_else(|| {
        IdentityError::UnsafePath(format!("`{}` is not a file path", path.display()))
    })?;
    Ok(parent.join(name))
}

/// Open a fresh file for exclusive creation with owner-only permissions.
fn create_new_file(path: &Path) -> Result<File, IdentityError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => IdentityError::UnsafePath(format!(
            "`{}` already exists; refusing to overwrite",
            path.display()
        )),
        std::io::ErrorKind::NotFound => IdentityError::UnsafePath(format!(
            "parent directory of `{}` does not exist",
            path.display()
        )),
        _ => IdentityError::Io(e),
    })
}

/// Force owner-only permissions on a file we just wrote. `create_new`
/// already requests mode 0600, but an odd filesystem or platform could
/// widen it; this makes the guarantee explicit and fails closed.
fn enforce_owner_only(path: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(IdentityError::Io)?;
    }
    let _ = path;
    Ok(())
}

/// Reject files any group/other principal can read, write, or execute.
fn require_owner_only(meta: &fs::Metadata, path: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 {
            return Err(IdentityError::UnsafePath(format!(
                "`{}` is readable or writable by group/other; expected owner-only (0600)",
                path.display()
            )));
        }
    }
    let _ = (meta, path);
    Ok(())
}

/// On Unix, confirm two metadata blocks describe the same inode.
#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Non-Unix platforms cannot compare inodes through `std`; the symlink and
/// file-type checks above still apply.
#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

/// fsync a directory so a create/rename is durable across power loss.
fn sync_dir(dir: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    let _ = dir;
    Ok(())
}

/// Produce the full on-disk byte stream for `identity` under `passphrase`.
fn render(identity: &Identity, passphrase: &str) -> Result<Vec<u8>, IdentityError> {
    let plaintext = encode_plaintext(identity);
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(IdentityError::MalformedKeystore(
            "identity exceeds the plaintext size bound".into(),
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    let mut key = derive_key(passphrase, WRITE_M_COST, WRITE_T_COST, WRITE_P_COST, &salt)?;

    let header = encode_header(&salt, &nonce, (plaintext.len() + TAG_LEN) as u64);
    let mut file = Vec::with_capacity(FILE_MAGIC.len() + header.len() + plaintext.len() + TAG_LEN);
    file.extend_from_slice(FILE_MAGIC);
    file.extend_from_slice(&header);
    let ciphertext = XChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| IdentityError::InvalidKdfParameters)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &file,
            },
        )
        .map_err(|_| {
            IdentityError::MalformedKeystore("identity plaintext exceeds ciphertext bound".into())
        })?;
    key.zeroize();
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

/// Canonical-CBOR header: a fixed array of nine items, always definite.
fn encode_header(salt: &[u8], nonce: &[u8], ciphertext_len: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    let mut e = minicbor::Encoder::new(&mut buf);
    e.array(9)
        .expect("encoding to Vec is infallible")
        .u16(FORMAT_VERSION_V1)
        .expect("infallible")
        .u8(KDF_ALGORITHM_ARGON2ID)
        .expect("infallible")
        .u8(ARGON2_VERSION_V13)
        .expect("infallible")
        .u32(WRITE_M_COST)
        .expect("infallible")
        .u32(WRITE_T_COST)
        .expect("infallible")
        .u32(WRITE_P_COST)
        .expect("infallible")
        .bytes(salt)
        .expect("infallible")
        .bytes(nonce)
        .expect("infallible")
        .u64(ciphertext_len)
        .expect("infallible");
    buf
}

/// Plaintext blob: `["blendr:keystore:v1", signing_seed, bid, display_name,
/// version, encryption_epoch, signing_public_key, encryption_public_key,
/// signature, [[epoch, secret], ...]]`. Every secret-bearing buffer is
/// wiped on drop.
fn encode_plaintext(identity: &Identity) -> Zeroizing<Vec<u8>> {
    let doc = identity.document();
    let epochs = identity.encryption_secrets();
    let seed = identity.signing_seed();
    let mut buf = Zeroizing::new(Vec::with_capacity(512));
    {
        let target: &mut Vec<u8> = &mut buf;
        let mut e = minicbor::Encoder::new(target);
        e.array(10)
            .expect("encoding to Vec is infallible")
            .str(PLAINTEXT_DOMAIN)
            .expect("infallible")
            .bytes(&*seed)
            .expect("infallible")
            .str(&doc.bid)
            .expect("infallible")
            .str(&doc.display_name)
            .expect("infallible")
            .u64(doc.version)
            .expect("infallible")
            .u64(doc.encryption_epoch)
            .expect("infallible")
            .bytes(&doc.signing_public_key)
            .expect("infallible")
            .bytes(&doc.encryption_public_key)
            .expect("infallible")
            .bytes(&doc.signature)
            .expect("infallible")
            .array(epochs.len() as u64)
            .expect("infallible");
        for (epoch, secret) in &epochs {
            e.array(2)
                .expect("infallible")
                .u64(*epoch)
                .expect("infallible")
                .bytes(&**secret)
                .expect("infallible");
        }
    }
    buf
}

/// Derive the 32-byte AEAD key with bounded, header-supplied Argon2id
/// parameters. Bounds were already enforced by `parse_header`.
fn derive_key(
    passphrase: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, IdentityError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| IdentityError::InvalidKdfParameters)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Argon2Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| IdentityError::InvalidKdfParameters)?;
    Ok(key)
}

/// Header fields extracted for key derivation.
struct ParsedHeader<'a> {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &'a [u8],
    nonce: &'a [u8],
    ciphertext_len: u64,
}

/// Split `buf` into `(header, ciphertext)`, authenticate *format* fields,
/// and bound every attacker-controlled value before it is used.
fn parse_header(buf: &[u8]) -> Result<(ParsedHeader<'_>, usize), IdentityError> {
    let malformed = |m: &str| IdentityError::MalformedKeystore(m.to_string());
    if !buf.starts_with(FILE_MAGIC) {
        return Err(malformed("missing keystore magic"));
    }
    let mut d = minicbor::Decoder::new(&buf[FILE_MAGIC.len()..]);
    if d.array()
        .map_err(|e| malformed(&format!("bad header: {e}")))?
        != Some(9)
    {
        return Err(malformed("header must be a 9-element array"));
    }
    let version = d
        .u16()
        .map_err(|e| malformed(&format!("bad version: {e}")))?;
    if version != FORMAT_VERSION_V1 {
        return Err(malformed("unsupported keystore format version"));
    }
    let kdf = d
        .u8()
        .map_err(|e| malformed(&format!("bad KDF field: {e}")))?;
    let argon2_version = d
        .u8()
        .map_err(|e| malformed(&format!("bad Argon2 field: {e}")))?;
    if kdf != KDF_ALGORITHM_ARGON2ID || argon2_version != ARGON2_VERSION_V13 {
        return Err(IdentityError::InvalidKdfParameters);
    }
    let m_cost = d
        .u32()
        .map_err(|e| malformed(&format!("bad m_cost: {e}")))?;
    let t_cost = d
        .u32()
        .map_err(|e| malformed(&format!("bad t_cost: {e}")))?;
    let p_cost = d
        .u32()
        .map_err(|e| malformed(&format!("bad p_cost: {e}")))?;
    if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        || !(MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        || !(MIN_P_COST..=MAX_P_COST).contains(&p_cost)
        || m_cost < 8 * p_cost
    {
        // Checked *before* Argon2 allocates `m_cost` KiB of memory.
        return Err(IdentityError::InvalidKdfParameters);
    }
    let salt = d
        .bytes()
        .map_err(|e| malformed(&format!("bad salt: {e}")))?;
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(IdentityError::InvalidKdfParameters);
    }
    let nonce = d
        .bytes()
        .map_err(|e| malformed(&format!("bad nonce: {e}")))?;
    if nonce.len() != NONCE_LEN {
        return Err(malformed("nonce must be exactly 24 bytes"));
    }
    let ciphertext_len = d
        .u64()
        .map_err(|e| malformed(&format!("bad length: {e}")))?;
    let header_len = d.position();
    if header_len > MAX_HEADER_LEN {
        return Err(malformed("header exceeds the size bound"));
    }
    if ciphertext_len < TAG_LEN as u64 || ciphertext_len > (MAX_PLAINTEXT_LEN + TAG_LEN) as u64 {
        return Err(malformed("ciphertext length outside the format bounds"));
    }
    Ok((
        ParsedHeader {
            m_cost,
            t_cost,
            p_cost,
            salt,
            nonce,
            ciphertext_len,
        },
        FILE_MAGIC.len() + header_len,
    ))
}

/// Verify the AEAD, then decode and integrity-check the plaintext.
fn decrypt(buf: Zeroizing<Vec<u8>>, passphrase: &str) -> Result<Identity, IdentityError> {
    let (header, aad_len) = parse_header(&buf)?;
    let ciphertext = &buf[aad_len..];
    if ciphertext.len() as u64 != header.ciphertext_len {
        return Err(IdentityError::MalformedKeystore(
            "ciphertext length does not match the header".into(),
        ));
    }
    let key = derive_key(
        passphrase,
        header.m_cost,
        header.t_cost,
        header.p_cost,
        header.salt,
    )?;
    let plaintext = XChaCha20Poly1305::new_from_slice(&*key)
        .map_err(|_| IdentityError::InvalidKdfParameters)?
        .decrypt(
            header
                .nonce
                .try_into()
                .map_err(|_| IdentityError::MalformedKeystore("invalid nonce length".into()))?,
            Payload {
                msg: ciphertext,
                aad: &buf[..aad_len],
            },
        )
        .map_err(|_| IdentityError::DecryptionFailed)?;
    drop(key);
    decode_plaintext(Zeroizing::new(plaintext))
}

/// Strict decode of the plaintext blob. Structure errors after a successful
/// AEAD verify are [`IdentityError::KeystoreIntegrity`], never
/// `DecryptionFailed` — authentication already succeeded.
fn decode_plaintext(buf: Zeroizing<Vec<u8>>) -> Result<Identity, IdentityError> {
    let int = |m: &str| IdentityError::KeystoreIntegrity(m.to_string());
    let mut d = minicbor::Decoder::new(&buf);
    if d.array().map_err(|e| int(&format!("bad plaintext: {e}")))? != Some(10) {
        return Err(int("plaintext must be a 10-element array"));
    }
    if d.str().map_err(|e| int(&format!("bad domain: {e}")))? != PLAINTEXT_DOMAIN {
        return Err(int("unexpected plaintext domain"));
    }
    let seed_bytes = d.bytes().map_err(|e| int(&format!("bad seed: {e}")))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| int("signing seed must be 32 bytes"))?;
    let seed = Zeroizing::new(seed);
    let bid = d.str().map_err(|e| int(&format!("bad BID: {e}")))?;
    if bid.len() != BID_LENGTH || !bid.is_ascii() {
        return Err(int("BID has the wrong shape"));
    }
    let display_name = d.str().map_err(|e| int(&format!("bad name: {e}")))?;
    if display_name.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(int("display name exceeds the length bound"));
    }
    let version = d.u64().map_err(|e| int(&format!("bad version: {e}")))?;
    let encryption_epoch = d.u64().map_err(|e| int(&format!("bad epoch: {e}")))?;
    let spk = d
        .bytes()
        .map_err(|e| int(&format!("bad signing key: {e}")))?;
    let signing_public_key: [u8; 32] = spk
        .try_into()
        .map_err(|_| int("signing public key must be 32 bytes"))?;
    let epk = d
        .bytes()
        .map_err(|e| int(&format!("bad encryption key: {e}")))?;
    let encryption_public_key: [u8; 32] = epk
        .try_into()
        .map_err(|_| int("encryption public key must be 32 bytes"))?;
    let signature = d.bytes().map_err(|e| int(&format!("bad signature: {e}")))?;
    if signature.len() != SIGNATURE_LENGTH {
        return Err(int("document signature must be 64 bytes"));
    }
    let epoch_count = d
        .array()
        .map_err(|e| int(&format!("bad epoch list: {e}")))?
        .ok_or_else(|| int("indefinite epoch list"))?;
    if epoch_count == 0 || epoch_count > MAX_EPOCHS {
        return Err(int("epoch list length outside bounds"));
    }
    let mut secrets = Vec::with_capacity(epoch_count as usize);
    for _ in 0..epoch_count {
        if d.array()
            .map_err(|e| int(&format!("bad epoch entry: {e}")))?
            != Some(2)
        {
            return Err(int("epoch entries must be 2-element arrays"));
        }
        let epoch = d.u64().map_err(|e| int(&format!("bad epoch id: {e}")))?;
        let raw = d
            .bytes()
            .map_err(|e| int(&format!("bad epoch secret: {e}")))?;
        let secret: [u8; 32] = raw
            .try_into()
            .map_err(|_| int("epoch secret must be 32 bytes"))?;
        secrets.push((epoch, Zeroizing::new(secret)));
    }
    if d.position() != buf.len() {
        return Err(int("trailing bytes after keystore plaintext"));
    }
    let document = IdentityDocument {
        bid: bid.to_string(),
        display_name: display_name.to_string(),
        version,
        encryption_epoch,
        signing_public_key,
        encryption_public_key,
        signature: signature.to_vec(),
    };
    // Rebuilds keypairs, re-verifies the document signature, re-derives the
    // BID, and confirms every secret matches its committed public key.
    Identity::from_keystore_parts(*seed, document, secrets)
}
