//! Integration tests for `blendr-identity`: deterministic vectors, document
//! verification, transcript-bound proofs, and the encrypted keystore
//! (roundtrip, tamper resistance, wrong passphrase, no-overwrite, atomic
//! update, backup/restore, and fail-closed file-permission handling).

use std::fs;

use blendr_identity::{BID_LENGTH, Identity, IdentityDocument, IdentityError, derive_bid};
use tempfile::TempDir;

/// Passphrase used throughout: clearly not production strength, adequate for
/// exercising the full Argon2id + XChaCha20Poly1305 path.
const PASS: &str = "correct horse battery staple";

/// Deterministic vector material shared with the crate-internal unit tests:
/// Ed25519 seed `0x00..0x1f`, X25519 secret `0x20..0x3f`, name "Vector Node".
const V_PUB: [u8; 32] = [
    0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
    0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
];
const V_EPUB: [u8; 32] = [
    0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
    0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
];
const V_BID: &str = "ATRNDKRAQJ2XY7HGWHWADS3PNFCVYEKUTOGSQIDB645LS5XWGJ6Q";
const V_NAME: &str = "Vector Node";
const V_DOC_SIG: [u8; 64] = [
    0x76, 0x4c, 0x7b, 0xe7, 0x19, 0xc6, 0xab, 0x4b, 0x44, 0x1c, 0xca, 0xc9, 0xc8, 0xd9, 0xea, 0x3f,
    0xe9, 0x0f, 0x81, 0xcd, 0xc3, 0x08, 0xdf, 0x3b, 0x03, 0xbb, 0xfe, 0x8c, 0x14, 0x0b, 0xf3, 0xfc,
    0xd2, 0x4d, 0xd5, 0x69, 0x24, 0x82, 0x42, 0xb6, 0xb3, 0xaa, 0x03, 0x5c, 0x83, 0x4e, 0xe4, 0xd0,
    0xa4, 0x5a, 0xd3, 0x7f, 0x5c, 0xa0, 0xc0, 0x47, 0xde, 0xdd, 0x83, 0x28, 0x40, 0x34, 0x91, 0x03,
];
const V_PROOF_SIG: [u8; 64] = [
    0x96, 0x9d, 0x78, 0xe7, 0xfb, 0x96, 0x48, 0xd2, 0x78, 0xe8, 0x35, 0x3e, 0x19, 0xd8, 0x4d, 0x8f,
    0x04, 0x08, 0x13, 0x3f, 0x9b, 0xf0, 0x1c, 0xe0, 0x1c, 0x88, 0x67, 0xc6, 0x8b, 0xca, 0xbf, 0xe5,
    0xd5, 0x30, 0xa4, 0xf8, 0x06, 0xe7, 0x23, 0xb1, 0x37, 0x50, 0xc0, 0x0c, 0x65, 0x39, 0x0e, 0xe6,
    0x57, 0xab, 0x36, 0x4b, 0x65, 0xc2, 0x14, 0xe4, 0x80, 0xe4, 0x65, 0x84, 0x89, 0xb1, 0x34, 0x05,
];
const V_TRANSCRIPT: [u8; 32] = [0xa5; 32];
const V_INONCE: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const V_RNONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn tmp_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(name)
}

#[test]
fn bid_is_52_char_unpadded_base32() {
    let bid = derive_bid(&V_PUB);
    assert_eq!(bid, V_BID);
    assert_eq!(bid.len(), BID_LENGTH);
    assert!(
        bid.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    );
}

#[test]
fn document_vector_verifies() {
    let doc = IdentityDocument {
        bid: V_BID.to_string(),
        display_name: V_NAME.to_string(),
        version: 1,
        encryption_epoch: 1,
        signing_public_key: V_PUB,
        encryption_public_key: V_EPUB,
        signature: V_DOC_SIG.to_vec(),
    };
    doc.verify()
        .expect("independently computed document verifies");
}

#[test]
fn two_identities_have_distinct_bids() {
    let a = Identity::generate("Alice").unwrap();
    let b = Identity::generate("Alice").unwrap();
    assert_ne!(a.bid(), b.bid());
    assert_ne!(a.document().signature, b.document().signature);
    assert!(a.document().verify().is_ok());
}

#[test]
fn rename_keeps_bid_and_bumps_version() {
    let mut id = Identity::generate("first name").unwrap();
    let bid = id.bid().to_string();
    let doc = id.document();
    assert_eq!(doc.version, 1);
    assert_eq!(doc.display_name, "first name");
    let signing_public_key = doc.signing_public_key;

    id.rename("  second   name  ").unwrap();
    let doc = id.document();
    assert_eq!(doc.display_name, "second name");
    assert_eq!(doc.version, 2);
    assert_eq!(doc.bid, bid);
    assert_eq!(doc.signing_public_key, signing_public_key);
    doc.verify().unwrap();
    assert_eq!(derive_bid(&doc.signing_public_key), bid);
}

#[test]
fn rename_rejects_empty_and_overlong_names() {
    let mut id = Identity::generate("ok").unwrap();
    assert!(matches!(
        id.rename("   "),
        Err(IdentityError::InvalidDisplayName(_))
    ));
    assert!(matches!(
        id.rename(&"x".repeat(65)),
        Err(IdentityError::InvalidDisplayName(_))
    ));
    assert!(Identity::generate("").is_err());
}

#[test]
fn encryption_rotation_retains_old_epochs() {
    let mut id = Identity::generate("rotator").unwrap();
    let first_pub = *id.encryption_public_key();
    assert_eq!(id.document().encryption_epoch, 1);

    id.rotate_encryption_key().unwrap();
    let doc = id.document();
    assert_eq!(doc.encryption_epoch, 2);
    assert_eq!(doc.version, 2);
    assert_ne!(*id.encryption_public_key(), first_pub);
    doc.verify().unwrap();

    // Epoch 1 material remains usable for old ciphertext.
    assert!(id.encryption_secret_for(1).is_some());
    assert!(id.encryption_secret_for(2).is_some());
    assert!(id.encryption_secret_for(3).is_none());
}

#[test]
fn proof_vector_verifies_and_wrong_bindings_fail() {
    // Independently computed Ed25519 signature over the canonical CBOR proof
    // payload for the vector identity.
    let doc = IdentityDocument {
        bid: V_BID.to_string(),
        display_name: V_NAME.to_string(),
        version: 1,
        encryption_epoch: 1,
        signing_public_key: V_PUB,
        encryption_public_key: V_EPUB,
        signature: V_DOC_SIG.to_vec(),
    };
    Identity::verify_proof(
        &doc,
        "initiator",
        &V_TRANSCRIPT,
        &V_INONCE,
        &V_RNONCE,
        &V_PROOF_SIG,
    )
    .expect("independently computed proof verifies");

    for wrong_role in ["responder", "Initiator"] {
        assert!(
            Identity::verify_proof(
                &doc,
                wrong_role,
                &V_TRANSCRIPT,
                &V_INONCE,
                &V_RNONCE,
                &V_PROOF_SIG
            )
            .is_err(),
            "proof must bind the role"
        );
    }
    let mut other_transcript = V_TRANSCRIPT;
    other_transcript[0] ^= 1;
    assert!(
        Identity::verify_proof(
            &doc,
            "initiator",
            &other_transcript,
            &V_INONCE,
            &V_RNONCE,
            &V_PROOF_SIG
        )
        .is_err(),
        "proof must bind the transcript"
    );
    assert!(
        Identity::verify_proof(
            &doc,
            "initiator",
            &V_TRANSCRIPT,
            &V_RNONCE,
            &V_INONCE,
            &V_PROOF_SIG
        )
        .is_err(),
        "proof must bind nonce direction"
    );
}

#[test]
fn generated_identity_proof_roundtrip() {
    let id = Identity::generate("prover").unwrap();
    let transcript = [0x11u8; 32];
    let inonce = [0x22u8; 16];
    let rnonce = [0x33u8; 16];
    let proof = id.prove("responder", &transcript, &inonce, &rnonce);
    assert_eq!(proof.len(), 64);
    Identity::verify_proof(
        &id.document(),
        "responder",
        &transcript,
        &inonce,
        &rnonce,
        &proof,
    )
    .unwrap();
    // A proof signed by a different identity must not verify against ours.
    let other = Identity::generate("impostor").unwrap();
    let forged = other.prove("responder", &transcript, &inonce, &rnonce);
    assert!(
        Identity::verify_proof(
            &id.document(),
            "responder",
            &transcript,
            &inonce,
            &rnonce,
            &forged
        )
        .is_err()
    );
}

#[test]
fn keystore_roundtrip_survives_restart() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");

    let mut id = Identity::generate("restarter").unwrap();
    id.rename("restarter renamed").unwrap();
    id.rotate_encryption_key().unwrap();
    let bid = id.bid().to_string();
    let doc = id.document();
    id.save_new(&path, PASS).unwrap();

    // Simulate a process restart: fresh load from disk only.
    let loaded = Identity::load(&path, PASS).unwrap();
    assert_eq!(loaded.bid(), bid);
    let loaded_doc = loaded.document();
    assert_eq!(loaded_doc, doc);
    assert_eq!(loaded_doc.display_name, "restarter renamed");
    assert_eq!(loaded_doc.encryption_epoch, 2);
    assert!(loaded.encryption_secret_for(1).is_some());
    assert!(loaded.encryption_secret_for(2).is_some());

    // The reloaded identity still produces valid proofs.
    let proof = loaded.prove("initiator", &[7u8; 32], &[8u8; 16], &[9u8; 16]);
    Identity::verify_proof(
        &loaded_doc,
        "initiator",
        &[7u8; 32],
        &[8u8; 16],
        &[9u8; 16],
        &proof,
    )
    .unwrap();
}

#[test]
fn tampered_file_fails_closed() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");
    Identity::generate("integrity")
        .unwrap()
        .save_new(&path, PASS)
        .unwrap();
    let original = fs::read(&path).unwrap();
    assert!(original.len() > 100);
    // Flip a byte inside the ciphertext (last 32 bytes).
    let mut tampered = original.clone();
    let last = tampered.len() - 8;
    tampered[last] ^= 0x01;
    fs::write(&path, &tampered).unwrap();
    assert!(
        Identity::load(&path, PASS).is_err(),
        "ciphertext tamper must be rejected"
    );

    // Flip a byte inside the authenticated header (still inside the file,
    // past the magic) — AAD tampering must break authentication or parsing.
    let mut tampered = original.clone();
    tampered[20] ^= 0x80;
    fs::write(&path, &tampered).unwrap();
    assert!(
        Identity::load(&path, PASS).is_err(),
        "header tamper must be rejected"
    );

    // Wrong magic.
    let mut tampered = original.clone();
    tampered[0] = b'X';
    fs::write(&path, &tampered).unwrap();
    assert!(matches!(
        Identity::load(&path, PASS),
        Err(IdentityError::MalformedKeystore(_))
    ));

    // Truncation.
    fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(Identity::load(&path, PASS).is_err());

    // Restore sanity: the pristine file still loads.
    fs::write(&path, &original).unwrap();
    Identity::load(&path, PASS).unwrap();
}

#[test]
fn inflated_kdf_parameters_are_rejected_before_allocation() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");
    Identity::generate("victim")
        .unwrap()
        .save_new(&path, PASS)
        .unwrap();
    let bytes = fs::read(&path).unwrap();

    // Header layout: "BLNDKS" (6) || CBOR array. m_cost 19456 == 0x4C00 is
    // minimally encoded as `0x19 4C 00`. Locate it and splice in a 5-byte
    // u32 encoding claiming 16 GiB — the bound check must fire before any
    // allocation (and before the AEAD verify it would otherwise fail).
    let needle = [0x19, 0x4c, 0x00];
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("header must contain encoded m_cost");
    let mut tampered = bytes[..pos].to_vec();
    tampered.push(0x1a); // u32 tag
    tampered.extend_from_slice(&0x0040_0000u32.to_be_bytes());
    tampered.extend_from_slice(&bytes[pos + needle.len()..]);
    fs::write(&path, &tampered).unwrap();
    assert!(matches!(
        Identity::load(&path, PASS),
        Err(IdentityError::InvalidKdfParameters)
    ));
}

#[test]
fn save_new_never_overwrites() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");
    Identity::generate("first")
        .unwrap()
        .save_new(&path, PASS)
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Identity::generate("second").unwrap().save_new(&path, PASS),
        Err(IdentityError::UnsafePath(_))
    ));
    // Different passphrase must not matter — existence is refused first.
    assert!(matches!(
        Identity::generate("third")
            .unwrap()
            .save_new(&path, "other"),
        Err(IdentityError::UnsafePath(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    // Original still loads.
    Identity::load(&path, PASS).unwrap();
}

#[test]
fn save_update_rewrites_in_place_and_validates() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");

    let mut id = Identity::generate("mutable").unwrap();
    id.save_new(&path, PASS).unwrap();
    let bid = id.bid().to_string();
    let before = fs::read(&path).unwrap();

    // Wrong passphrase: the pre-flight unlock fails, file untouched.
    assert!(matches!(
        id.save_update(&path, "not it"),
        Err(IdentityError::DecryptionFailed)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);

    // Correct passphrase: atomic rewrite with the renamed document.
    id.rename("mutable v2").unwrap();
    id.save_update(&path, PASS).unwrap();
    let after = fs::read(&path).unwrap();
    assert_ne!(after, before);
    let reloaded = Identity::load(&path, PASS).unwrap();
    assert_eq!(reloaded.bid(), bid);
    assert_eq!(reloaded.document().display_name, "mutable v2");
    assert_eq!(reloaded.document().version, 2);

    // A different identity may not overwrite this keystore.
    let other = Identity::generate("someone else").unwrap();
    assert!(matches!(
        other.save_update(&path, PASS),
        Err(IdentityError::KeystoreIntegrity(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), after);
}

#[test]
fn save_update_requires_existing_keystore() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "absent.ks");
    let id = Identity::generate("orphan").unwrap();
    assert!(matches!(
        id.save_update(&path, PASS),
        Err(IdentityError::NotFound)
    ));
}

#[test]
fn encrypted_backup_exports_and_imports() {
    let dir = TempDir::new().unwrap();
    let keystore = tmp_path(&dir, "live.ks");
    let backup = tmp_path(&dir, "backup.ks");
    let restore_dir = TempDir::new().unwrap();
    let restored_path = tmp_path(&restore_dir, "restored.ks");

    let id = Identity::generate("traveller").unwrap();
    id.save_new(&keystore, PASS).unwrap();
    let bid = id.bid().to_string();

    // Export: a save_new of the same identity under a different passphrase.
    id.save_new(&backup, "backup-only passphrase").unwrap();

    // Import into a fresh location with the backup passphrase.
    let restored = Identity::load(&backup, "backup-only passphrase").unwrap();
    assert_eq!(restored.bid(), bid);
    restored
        .save_new(&restored_path, "new local passphrase")
        .unwrap();
    let reloaded = Identity::load(&restored_path, "new local passphrase").unwrap();
    assert_eq!(reloaded.bid(), bid);
    assert_eq!(reloaded.document(), id.document());
}

#[test]
fn empty_and_whitespace_passphrases_rejected() {
    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");
    let id = Identity::generate("passphrase").unwrap();
    for bad in ["", "   ", "\t\n"] {
        assert!(matches!(
            id.save_new(&path, bad),
            Err(IdentityError::InvalidPassphrase)
        ));
        assert!(matches!(
            Identity::load(&path, bad),
            Err(IdentityError::InvalidPassphrase) | Err(IdentityError::NotFound)
        ));
    }
    assert!(!path.exists(), "invalid passphrases must not create files");
}

#[test]
fn load_missing_and_nonregular_paths() {
    let dir = TempDir::new().unwrap();
    let missing = tmp_path(&dir, "missing.ks");
    assert!(matches!(
        Identity::load(&missing, PASS),
        Err(IdentityError::NotFound)
    ));

    // A directory is not a keystore.
    assert!(matches!(
        Identity::load(dir.path(), PASS),
        Err(IdentityError::UnsafePath(_))
    ));

    // A symlink to a valid keystore is refused.
    let real = tmp_path(&dir, "real.ks");
    Identity::generate("target")
        .unwrap()
        .save_new(&real, PASS)
        .unwrap();
    let link = tmp_path(&dir, "link.ks");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            Identity::load(&link, PASS),
            Err(IdentityError::UnsafePath(_))
        ));
        assert!(matches!(
            Identity::generate("x").unwrap().save_new(&link, PASS),
            Err(IdentityError::UnsafePath(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn world_or_group_readable_keystore_is_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = tmp_path(&dir, "node.ks");
    Identity::generate("perms")
        .unwrap()
        .save_new(&path, PASS)
        .unwrap();

    // Written keystores are owner-only.
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    for loosened in [0o644, 0o660, 0o777] {
        fs::set_permissions(&path, fs::Permissions::from_mode(loosened)).unwrap();
        assert!(
            matches!(
                Identity::load(&path, PASS),
                Err(IdentityError::UnsafePath(_))
            ),
            "mode {loosened:o} must be refused"
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    Identity::load(&path, PASS).unwrap();
}

#[cfg(unix)]
#[test]
fn save_into_missing_or_unsafe_parent_fails() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let id = Identity::generate("wanderer").unwrap();

    // Nonexistent parent directory.
    let bad = tmp_path(&dir, "no/such/dir/node.ks");
    assert!(matches!(
        id.save_new(&bad, PASS),
        Err(IdentityError::UnsafePath(_))
    ));

    // Parent that is a symlink to a real directory.
    let real_dir = tmp_path(&dir, "realdir");
    fs::create_dir(&real_dir).unwrap();
    let link_dir = tmp_path(&dir, "linkdir");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
    assert!(matches!(
        id.save_new(link_dir.join("node.ks"), PASS),
        Err(IdentityError::UnsafePath(_))
    ));

    // World-writable parent without the sticky bit.
    let loose = tmp_path(&dir, "loose");
    fs::create_dir(&loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        id.save_new(loose.join("node.ks"), PASS),
        Err(IdentityError::UnsafePath(_))
    ));
}
