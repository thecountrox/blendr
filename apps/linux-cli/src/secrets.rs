//! Passphrase acquisition for the CLI.
//!
//! Two sources, never anything else:
//!
//! * interactive terminal prompting via `rpassword` (confirmation enforced for
//!   newly created passphrases);
//! * `--passphrase-file` / `--backup-passphrase-file` for automation. The file
//!   must be a regular file (symlinks refused), readable by its owner only
//!   (no group/other permission bits), and bounded in size. Exactly one
//!   trailing newline (`\n`, optionally preceded by `\r`) is stripped.
//!
//! Passphrases are never accepted as CLI arguments or environment variables,
//! are held in `Zeroizing` buffers, and are never included in error text.

use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use crate::runtime;

/// Largest passphrase file the CLI will read; anything bigger is almost
/// certainly operator error rather than a passphrase.
const MAX_PASSPHRASE_FILE_BYTES: u64 = 4096;
/// Largest passphrase value accepted from any source.
const MAX_PASSPHRASE_BYTES: usize = 1024;

/// Read an *existing* passphrase: from `file` when given, otherwise one
/// interactive prompt.
pub(crate) fn existing_passphrase(
    file: Option<&Path>,
    what: &str,
) -> Result<Zeroizing<String>, crate::Fail> {
    if let Some(path) = file {
        read_passphrase_file(path)
    } else {
        let pass = rpassword::prompt_password(format!("{what}: "))
            .map_err(|e| runtime(format!("cannot read {what} from terminal: {e}")))?;
        finish_passphrase(pass, what)
    }
}

/// Read a *new* passphrase: from `file` when given, otherwise prompted twice
/// with confirmation (mismatch aborts rather than encrypting under a typo).
pub(crate) fn new_passphrase(
    file: Option<&Path>,
    what: &str,
) -> Result<Zeroizing<String>, crate::Fail> {
    if let Some(path) = file {
        return read_passphrase_file(path);
    }
    let first = rpassword::prompt_password(format!("new {what}: "))
        .map_err(|e| runtime(format!("cannot read {what} from terminal: {e}")))?;
    let second = rpassword::prompt_password(format!("confirm {what}: ")).map_err(|e| {
        runtime(format!(
            "cannot read {what} confirmation from terminal: {e}"
        ))
    })?;
    if first != second {
        return Err(runtime(format!(
            "{what} confirmation does not match; aborted"
        )));
    }
    drop(second);
    finish_passphrase(first, what)
}

/// Shared rules for passphrases from any source: non-empty and bounded. The
/// buffer is moved into a `Zeroizing` wrapper so it is scrubbed on drop.
fn finish_passphrase(raw: String, what: &str) -> Result<Zeroizing<String>, crate::Fail> {
    let pass = Zeroizing::new(raw);
    // Matches the keystore contract: non-empty and not whitespace-only.
    if pass.trim().is_empty() {
        return Err(runtime(format!(
            "{what} must be non-empty and not whitespace-only"
        )));
    }
    if pass.len() > MAX_PASSPHRASE_BYTES {
        return Err(runtime(format!(
            "{what} exceeds {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    Ok(pass)
}

/// Strict checks before trusting a passphrase file.
///
/// `symlink_metadata` (not `metadata`) so a symlink is refused outright rather
/// than followed to a real file. The file must be a regular file, bounded in
/// size, and — on Unix — carry no group or other permission bits. Exactly one
/// trailing newline is stripped; the buffer is zeroized on every path.
fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>, crate::Fail> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        runtime(format!(
            "cannot stat passphrase file `{}`: {e}",
            path.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(runtime(format!(
            "passphrase file `{}` is a symbolic link; refusing to follow it",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(runtime(format!(
            "passphrase file `{}` is not a regular file",
            path.display()
        )));
    }
    if meta.len() > MAX_PASSPHRASE_FILE_BYTES {
        return Err(runtime(format!(
            "passphrase file `{}` is larger than {MAX_PASSPHRASE_FILE_BYTES} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(runtime(format!(
                "passphrase file `{}` must be owner-only (e.g. mode 0600); found mode {:o}",
                path.display(),
                mode
            )));
        }
    }

    let mut buf = Zeroizing::new(Vec::new());
    // `take` hard-bounds the read even if the file grows between stat and
    // open; `read_to_end` on the limited reader stops at the cap.
    std::fs::File::open(path)
        .map_err(|e| {
            runtime(format!(
                "cannot open passphrase file `{}`: {e}",
                path.display()
            ))
        })?
        .take(MAX_PASSPHRASE_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            runtime(format!(
                "cannot read passphrase file `{}`: {e}",
                path.display()
            ))
        })?;
    if buf.len() as u64 > MAX_PASSPHRASE_FILE_BYTES {
        return Err(runtime(format!(
            "passphrase file `{}` is larger than {MAX_PASSPHRASE_FILE_BYTES} bytes",
            path.display()
        )));
    }

    // Strip exactly one trailing line terminator: "\r\n" or "\n".
    if buf.ends_with(b"\n") {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }
    let text = std::str::from_utf8(&buf)
        .map_err(|_| {
            runtime(format!(
                "passphrase file `{}` is not valid UTF-8",
                path.display()
            ))
        })?
        .to_owned();
    finish_passphrase(text, "passphrase")
}
