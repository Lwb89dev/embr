//! Behavioural tests of the encrypted vault.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use embr_core::{AccountId, KeySecurity};
use embr_crypto::{EventTemplate, Identity, Limits};
use embr_vault::{Avatar, KdfParams, Vault, VaultError};
use tempfile::TempDir;

/// Fast-but-legal parameters for tests (the OWASP minimum, never the default).
const FAST: KdfParams = KdfParams::MINIMUM;
const PW: &str = "correct horse battery staple";

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault").join("main.embr");
    Fixture { _dir: dir, path }
}

fn new_vault(f: &Fixture) -> Vault {
    Vault::create_with(&f.path, PW, FAST).unwrap()
}

fn tpl(content: &str) -> EventTemplate {
    EventTemplate {
        kind: 1,
        content: content.into(),
        tags: vec![],
        created_at: Some(1_700_000_000),
        pubkey: None,
        id: None,
    }
}

fn assert_err<T: std::fmt::Debug>(
    r: Result<T, VaultError>,
    pred: impl Fn(&VaultError) -> bool,
    what: &str,
) {
    match r {
        Err(e) if pred(&e) => {}
        other => panic!("{what}: unexpected result {other:?}"),
    }
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------------------
// lifecycle and lock state
// ---------------------------------------------------------------------------------------

#[test]
fn create_lock_unlock_cycle() {
    let f = fixture();
    let mut v = new_vault(&f);
    assert!(v.is_unlocked());
    assert!(v.list_accounts().unwrap().is_empty());
    v.lock();
    assert!(!v.is_unlocked());

    assert_err(
        v.unlock("wrong password entirely"),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "wrong pw",
    );
    assert!(!v.is_unlocked());
    v.unlock(PW).unwrap();
    assert!(v.is_unlocked());
    assert_err(
        v.unlock(PW),
        |e| matches!(e, VaultError::AlreadyUnlocked),
        "double unlock",
    );
}

#[test]
fn everything_is_refused_while_locked() {
    let f = fixture();
    let mut v = new_vault(&f);
    let acc = v.add_generated("main").unwrap();
    v.lock();

    let locked = |e: &VaultError| matches!(e, VaultError::Locked);
    assert_err(v.list_accounts(), locked, "list");
    assert_err(v.active_account(), locked, "active");
    assert_err(v.add_generated("x"), locked, "add");
    assert_err(v.import_secret("x", &"11".repeat(32)), locked, "import");
    assert_err(v.set_active(acc.id), locked, "set_active");
    assert_err(v.set_label(acc.id, "n"), locked, "label");
    assert_err(v.remove_account(acc.id), locked, "remove");
    assert_err(
        v.with_identity(acc.id, |i| i.pubkey_hex()),
        locked,
        "with_identity",
    );
    assert_err(v.export_ncryptsec(acc.id, PW, "pw", 16), locked, "export");
    assert_err(v.reveal_nsec(acc.id, PW), locked, "reveal");
    assert_err(
        v.change_password(PW, "another long password"),
        locked,
        "change pw",
    );
    assert_err(
        v.export_backup(&f.path.with_extension("bak")),
        locked,
        "backup",
    );
    assert_err(v.avatar(acc.id), locked, "avatar");
}

#[test]
fn password_policy_is_enforced_in_the_vault_not_the_ui() {
    let f = fixture();
    assert_err(
        Vault::create_with(&f.path, "short", FAST),
        |e| matches!(e, VaultError::PasswordTooShort { .. }),
        "create",
    );
    assert!(
        !f.path.exists(),
        "a rejected create must not leave a file behind"
    );
    let mut v = new_vault(&f);
    assert_err(
        v.change_password(PW, "short"),
        |e| matches!(e, VaultError::PasswordTooShort { .. }),
        "change",
    );
    // Length is counted in characters after NFKC, not bytes.
    let dir = tempfile::tempdir().unwrap();
    assert!(Vault::create_with(dir.path().join("a.embr"), "日本語日本語日本語日", FAST).is_ok());
    assert!(Vault::create_with(dir.path().join("b.embr"), "日本語日本語日本語", FAST).is_err());
}

#[test]
fn passwords_are_nfkc_normalised() {
    let f = fixture();
    let composed = "caf\u{e9}-caf\u{e9}-caf\u{e9}"; // é precomposed
    let decomposed = "cafe\u{301}-cafe\u{301}-cafe\u{301}"; // e + combining acute
    let mut v = Vault::create_with(&f.path, composed, FAST).unwrap();
    v.lock();
    v.unlock(decomposed).unwrap();
}

#[test]
fn create_refuses_to_overwrite_an_existing_vault() {
    let f = fixture();
    let mut v = new_vault(&f);
    v.add_generated("precious").unwrap();
    let before = fs::read(&f.path).unwrap();
    assert_err(
        Vault::create_with(&f.path, "another long password", FAST),
        |e| matches!(e, VaultError::AlreadyExists),
        "overwrite",
    );
    assert_eq!(
        fs::read(&f.path).unwrap(),
        before,
        "existing vault must be untouched"
    );
}

#[test]
fn open_missing_file_is_not_found() {
    let f = fixture();
    assert_err(
        Vault::open(&f.path),
        |e| matches!(e, VaultError::NotFound),
        "open",
    );
}

// ---------------------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------------------

#[test]
fn accounts_persist_across_reopen() {
    let f = fixture();
    let (a, b, c);
    {
        let mut v = new_vault(&f);
        a = v.add_generated("generated").unwrap();
        b = v
            .import_secret(
                "imported",
                "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
            )
            .unwrap();
        let enc = Identity::generate()
            .export_ncryptsec("backup-pw", 16, KeySecurity::Medium)
            .unwrap();
        c = v
            .import_ncryptsec("from backup", &enc, "backup-pw")
            .unwrap();
        v.set_active(b.id).unwrap();
    }
    let mut v = Vault::open(&f.path).unwrap();
    assert!(!v.is_unlocked());
    v.unlock(PW).unwrap();
    let list = v.list_accounts().unwrap();
    assert_eq!(
        list.iter().map(|m| m.label.as_str()).collect::<Vec<_>>(),
        ["generated", "imported", "from backup"]
    );
    assert_eq!(list[0], a);
    assert_eq!(list[1], b);
    assert_eq!(list[2], c);
    assert_eq!(v.active_account().unwrap().unwrap().id, b.id);

    // Security byte semantics.
    assert_eq!(a.key_security, KeySecurity::Medium);
    assert_eq!(b.key_security, KeySecurity::Weak);
    assert_eq!(c.key_security, KeySecurity::Medium);
    // Known NIP-19 pair.
    assert_eq!(
        b.pubkey_hex,
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
    );
    assert_eq!(
        b.npub,
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    );
}

#[test]
fn first_account_becomes_active_and_removal_reassigns() {
    let f = fixture();
    let mut v = new_vault(&f);
    assert!(v.active_account().unwrap().is_none());
    let a = v.add_generated("a").unwrap();
    assert_eq!(v.active_account().unwrap().unwrap().id, a.id);
    let b = v.add_generated("b").unwrap();
    assert_eq!(
        v.active_account().unwrap().unwrap().id,
        a.id,
        "adding must not switch accounts"
    );
    v.set_active(b.id).unwrap();
    v.remove_account(b.id).unwrap();
    assert_eq!(v.active_account().unwrap().unwrap().id, a.id);
    v.remove_account(a.id).unwrap();
    assert!(v.active_account().unwrap().is_none());
    assert!(v.list_accounts().unwrap().is_empty());
    assert_err(
        v.remove_account(a.id),
        |e| matches!(e, VaultError::AccountNotFound),
        "remove twice",
    );
    assert_err(
        v.set_active(AccountId::generate().unwrap()),
        |e| matches!(e, VaultError::AccountNotFound),
        "set_active unknown",
    );
}

#[test]
fn removal_is_persistent_and_forgets_the_key() {
    let f = fixture();
    let mut v = new_vault(&f);
    let keep = v.add_generated("keep").unwrap();
    let gone = v.add_generated("gone").unwrap();
    v.remove_account(gone.id).unwrap();
    drop(v);
    let mut v = Vault::open(&f.path).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(v.list_accounts().unwrap().len(), 1);
    assert_err(
        v.with_identity(gone.id, |_| ()),
        |e| matches!(e, VaultError::AccountNotFound),
        "removed key",
    );
    v.with_identity(keep.id, |_| ()).unwrap();
}

#[test]
fn duplicates_and_invalid_input_are_rejected() {
    let f = fixture();
    let mut v = new_vault(&f);
    let hex = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    v.import_secret("one", hex).unwrap();
    let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    assert_err(
        v.import_secret("dup", nsec),
        |e| matches!(e, VaultError::DuplicateAccount),
        "dup",
    );
    assert_err(
        v.import_secret("bad", "not a key"),
        |e| matches!(e, VaultError::Crypto(_)),
        "bad key",
    );
    assert_err(
        v.import_secret("bad", &"00".repeat(32)),
        |e| matches!(e, VaultError::Crypto(_)),
        "zero key",
    );
    let enc = Identity::generate()
        .export_ncryptsec("right-password", 16, KeySecurity::Unknown)
        .unwrap();
    assert_err(
        v.import_ncryptsec("x", &enc, "wrong"),
        |e| matches!(e, VaultError::Crypto(_)),
        "wrong ncryptsec pw",
    );
    assert_eq!(
        v.list_accounts().unwrap().len(),
        1,
        "failed imports must not add anything"
    );
}

#[test]
fn labels_are_validated() {
    let f = fixture();
    let mut v = new_vault(&f);
    for bad in [
        "",
        "   ",
        &"x".repeat(65),
        "tab\there",
        "new\nline",
        "evil\u{202e}gnp.exe",
        "nul\u{0}",
        "iso\u{2066}late",
    ] {
        assert_err(
            v.add_generated(bad),
            |e| matches!(e, VaultError::InvalidLabel(_)),
            bad,
        );
    }
    assert!(v.list_accounts().unwrap().is_empty());
    let ok = v.add_generated("  Personal 日本語 🔥  ").unwrap();
    assert_eq!(ok.label, "Personal 日本語 🔥", "labels are trimmed");
    assert_err(
        v.set_label(ok.id, "x\u{202e}y"),
        |e| matches!(e, VaultError::InvalidLabel(_)),
        "relabel",
    );
    v.set_label(ok.id, "Renamed").unwrap();
    assert_eq!(v.list_accounts().unwrap()[0].label, "Renamed");
}

#[test]
fn avatars_are_validated_and_persisted() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[0u8; 32]].concat();

    for (mime, data, why) in [
        ("image/png", vec![], "empty"),
        ("image/png", b"GIF89a....".to_vec(), "wrong magic"),
        ("image/svg+xml", b"<svg/>".to_vec(), "svg not allowed"),
        ("text/html", b"<html>".to_vec(), "html not allowed"),
        ("image/png", vec![0x89; 65 * 1024], "too large"),
    ] {
        assert_err(
            v.set_avatar(
                a.id,
                Some(Avatar {
                    mime: mime.into(),
                    data,
                }),
            ),
            |e| matches!(e, VaultError::InvalidAvatar(_)),
            why,
        );
    }
    assert!(!v.list_accounts().unwrap()[0].has_avatar);

    v.set_avatar(
        a.id,
        Some(Avatar {
            mime: "image/png".into(),
            data: png.clone(),
        }),
    )
    .unwrap();
    assert!(v.list_accounts().unwrap()[0].has_avatar);
    drop(v);
    let mut v = Vault::open(&f.path).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(v.avatar(a.id).unwrap().unwrap().data, png);
    v.set_avatar(a.id, None).unwrap();
    assert!(v.avatar(a.id).unwrap().is_none());
}

#[test]
fn account_limit_is_enforced() {
    let f = fixture();
    let mut v = new_vault(&f);
    // Fill quickly with imported deterministic keys (persisting 256 times is fast enough).
    for i in 1..=embr_vault::MAX_ACCOUNTS {
        let mut k = [0u8; 32];
        k[24..].copy_from_slice(&(i as u64).to_be_bytes());
        v.import_secret(&format!("acc {i}"), &hex::encode(k))
            .unwrap();
    }
    assert_err(
        v.add_generated("one too many"),
        |e| matches!(e, VaultError::TooManyAccounts(_)),
        "limit",
    );
}

// ---------------------------------------------------------------------------------------
// using keys without exposing them
// ---------------------------------------------------------------------------------------

#[test]
fn signing_through_the_vault_is_isolated_per_account() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    let b = v.add_generated("b").unwrap();
    let limits = Limits::default();

    let ev_a = v
        .with_identity(a.id, |i| i.sign_event(&tpl("hi"), &limits))
        .unwrap()
        .unwrap();
    let ev_b = v
        .with_identity(b.id, |i| i.sign_event(&tpl("hi"), &limits))
        .unwrap()
        .unwrap();
    assert_eq!(ev_a.pubkey.to_hex(), a.pubkey_hex);
    assert_eq!(ev_b.pubkey.to_hex(), b.pubkey_hex);
    ev_a.verify().unwrap();
    ev_b.verify().unwrap();

    // A template naming account B's pubkey cannot be signed by account A.
    let mut forged = tpl("hi");
    forged.pubkey = Some(b.pubkey_hex.clone());
    let r = v
        .with_identity(a.id, |i| i.sign_event(&forged, &limits))
        .unwrap();
    assert!(r.is_err());

    // NIP-44 between two vault accounts round-trips.
    let ct = v
        .with_identity(a.id, |i| i.nip44_encrypt(&ev_b.pubkey, "secret", &limits))
        .unwrap()
        .unwrap();
    let pt = v
        .with_identity(b.id, |i| i.nip44_decrypt(&ev_a.pubkey, &ct, &limits))
        .unwrap()
        .unwrap();
    assert_eq!(&*pt, "secret");
}

#[test]
fn export_and_reveal_require_the_vault_password() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();

    let wrong = |e: &VaultError| matches!(e, VaultError::WrongPasswordOrCorrupt);
    assert_err(
        v.export_ncryptsec(a.id, "not the vault password", "export-pw", 16),
        wrong,
        "export",
    );
    assert_err(
        v.reveal_nsec(a.id, "not the vault password"),
        wrong,
        "reveal",
    );

    let enc = v.export_ncryptsec(a.id, PW, "export password", 16).unwrap();
    let (back, sec) =
        Identity::from_ncryptsec(&enc, "export password", &Limits::default()).unwrap();
    assert_eq!(back.pubkey_hex(), a.pubkey_hex);
    assert_eq!(
        sec,
        KeySecurity::Medium,
        "generated-in-vault keys export as Medium"
    );

    let nsec = v.reveal_nsec(a.id, PW).unwrap();
    assert_eq!(
        Identity::from_secret_str(&nsec).unwrap().pubkey_hex(),
        a.pubkey_hex
    );

    // Unknown account, even with the right password.
    assert_err(
        v.export_ncryptsec(AccountId::generate().unwrap(), PW, "x", 16),
        |e| matches!(e, VaultError::AccountNotFound),
        "unknown",
    );
}

// ---------------------------------------------------------------------------------------
// nothing sensitive on disk
// ---------------------------------------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn vault_file_leaks_neither_secrets_nor_metadata() {
    let f = fixture();
    let mut v = new_vault(&f);
    let sk_hex = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    let acc = v.import_secret("MY-SECRET-LABEL-12345", nsec).unwrap();
    v.set_avatar(
        acc.id,
        Some(Avatar {
            mime: "image/png".into(),
            data: [b"\x89PNG\r\n\x1a\n".as_slice(), b"AVATAR-MARKER"].concat(),
        }),
    )
    .unwrap();
    let file = fs::read(&f.path).unwrap();

    let raw = hex::decode(sk_hex).unwrap();
    for (needle, what) in [
        (raw.as_slice(), "raw secret bytes"),
        (sk_hex.as_bytes(), "secret hex"),
        (nsec.as_bytes(), "nsec"),
        (acc.pubkey_hex.as_bytes(), "public key hex"),
        (acc.npub.as_bytes(), "npub"),
        (b"MY-SECRET-LABEL-12345".as_slice(), "label"),
        (b"AVATAR-MARKER".as_slice(), "avatar"),
        (PW.as_bytes(), "password"),
    ] {
        assert!(
            !contains(&file, needle),
            "vault file must not contain the {what}"
        );
    }
    // It is plain JSON with only the structural, non-secret header in the clear.
    let text = String::from_utf8(file).unwrap();
    assert!(text.contains("\"magic\": \"embr-vault\""));
    assert!(text.contains("argon2id"));
}

#[test]
fn vault_debug_output_is_harmless() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    let dbg = format!("{v:?}");
    assert!(!dbg.contains(&a.pubkey_hex));
    assert!(dbg.contains("unlocked"));
}

#[cfg(unix)]
#[test]
fn files_and_directories_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let mut v = new_vault(&f);
    v.add_generated("a").unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&f.path), 0o600, "vault file");
    assert_eq!(mode(f.path.parent().unwrap()), 0o700, "vault directory");
    assert!(v.permission_warnings().is_empty());

    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o644)).unwrap();
    let w = v.permission_warnings();
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("chmod 600"));

    // Rewrites keep the file private again (the atomic replace creates a fresh 0600 file).
    v.add_generated("b").unwrap();
    assert_eq!(mode(&f.path), 0o600);
}

#[test]
fn writes_leave_no_temporary_files() {
    let f = fixture();
    let mut v = new_vault(&f);
    for i in 0..5 {
        v.add_generated(&format!("acc{i}")).unwrap();
    }
    v.change_password(PW, "a different long password").unwrap();
    assert_eq!(files_in(f.path.parent().unwrap()), ["main.embr"]);
}

// ---------------------------------------------------------------------------------------
// tampering and hostile files
// ---------------------------------------------------------------------------------------

fn mutate_json(f: &Fixture, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&f.path).unwrap()).unwrap();
    edit(&mut v);
    fs::write(&f.path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn flip_b64_byte(v: &mut serde_json::Value, ptr: &str) {
    use base64::Engine as _;
    let s = v.pointer(ptr).unwrap().as_str().unwrap().to_owned();
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(s).unwrap();
    bytes[0] ^= 0x80;
    *v.pointer_mut(ptr).unwrap() = base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .into();
}

#[test]
fn every_protected_field_is_authenticated() {
    for ptr in [
        "/slots/0/kdf/salt",
        "/slots/0/nonce",
        "/slots/0/wrapped_key",
        "/body/nonce",
        "/body/ciphertext",
    ] {
        let f = fixture();
        let mut v = new_vault(&f);
        v.add_generated("a").unwrap();
        drop(v);
        mutate_json(&f, |j| flip_b64_byte(j, ptr));
        let mut v = Vault::open(&f.path).unwrap();
        assert_err(
            v.unlock(PW),
            |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
            ptr,
        );
        assert!(!v.is_unlocked());
    }
}

#[test]
fn kdf_parameters_are_authenticated_too() {
    // Changing t (still within bounds) must not silently derive another key and "work"; it must
    // fail authentication. (Mutation testing showed this holds because t feeds the KEK itself; the
    // AAD binding in `PasswordSlot::aad` is defence in depth on top of that.)
    let f = fixture();
    new_vault(&f);
    mutate_json(&f, |j| *j.pointer_mut("/slots/0/kdf/t").unwrap() = 3.into());
    let mut v = Vault::open(&f.path).unwrap();
    assert_err(
        v.unlock(PW),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "tampered t",
    );
}

#[test]
fn hostile_kdf_parameters_are_refused_before_any_work() {
    for (field, value) in [
        ("m_kib", serde_json::json!(4_000_000u64)),
        ("m_kib", serde_json::json!(0)),
        ("t", serde_json::json!(1000)),
        ("t", serde_json::json!(0)),
        ("p", serde_json::json!(1000)),
        ("p", serde_json::json!(0)),
    ] {
        let f = fixture();
        new_vault(&f);
        mutate_json(&f, |j| {
            *j.pointer_mut(&format!("/slots/0/kdf/{field}")).unwrap() = value.clone()
        });
        let start = std::time::Instant::now();
        assert_err(
            Vault::open(&f.path),
            |e| matches!(e, VaultError::KdfParams | VaultError::Malformed(_)),
            field,
        );
        assert!(
            start.elapsed().as_secs() < 2,
            "rejection of {field}={value} must be immediate"
        );
    }
}

#[test]
fn malformed_files_are_rejected_cleanly() {
    let f = fixture();
    new_vault(&f);
    let good = fs::read(&f.path).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("garbage", b"\x00\x01\x02 not json".to_vec()),
        ("truncated", good[..good.len() / 2].to_vec()),
        ("json null", b"null".to_vec()),
        ("array", b"[]".to_vec()),
        ("huge garbage", vec![b'{'; 100_000]),
    ];
    for (name, bytes) in cases {
        fs::write(&f.path, bytes).unwrap();
        assert_err(
            Vault::open(&f.path),
            |e| matches!(e, VaultError::Malformed(_)),
            name,
        );
    }
    for (name, edit) in [
        (
            "wrong magic",
            Box::new(|j: &mut serde_json::Value| j["magic"] = "other".into())
                as Box<dyn Fn(&mut serde_json::Value)>,
        ),
        ("unknown top field", Box::new(|j| j["extra"] = 1.into())),
        ("no slots", Box::new(|j| j["slots"] = serde_json::json!([]))),
        (
            "two slots",
            Box::new(|j| {
                let s = j["slots"][0].clone();
                j["slots"].as_array_mut().unwrap().push(s);
            }),
        ),
        (
            "unknown slot type",
            Box::new(|j| j["slots"][0]["type"] = "keyring".into()),
        ),
        (
            "wrong kdf",
            Box::new(|j| j["slots"][0]["kdf"]["alg"] = "pbkdf2".into()),
        ),
        (
            "short salt",
            Box::new(|j| j["slots"][0]["kdf"]["salt"] = "AAAA".into()),
        ),
        (
            "short nonce",
            Box::new(|j| j["body"]["nonce"] = "AAAA".into()),
        ),
        (
            "bad base64",
            Box::new(|j| j["body"]["ciphertext"] = "!!!!".into()),
        ),
    ] {
        fs::write(&f.path, &good).unwrap();
        mutate_json(&f, |j| edit(j));
        assert_err(
            Vault::open(&f.path),
            |e| matches!(e, VaultError::Malformed(_)),
            name,
        );
    }
    fs::write(&f.path, &good).unwrap();
    mutate_json(&f, |j| j["version"] = 2.into());
    assert_err(
        Vault::open(&f.path),
        |e| matches!(e, VaultError::UnsupportedVersion(2)),
        "future version",
    );
}

#[test]
fn oversized_vault_files_are_refused() {
    let f = fixture();
    new_vault(&f);
    let file = fs::OpenOptions::new().write(true).open(&f.path).unwrap();
    file.set_len(33 * 1024 * 1024).unwrap(); // sparse; no real disk use
    assert_err(
        Vault::open(&f.path),
        |e| matches!(e, VaultError::Malformed("file too large")),
        "size",
    );
}

#[test]
fn slots_and_body_cannot_be_mixed_between_vaults() {
    // Same password, same parameters, different vault keys: splicing one vault's body into the
    // other's file must fail authentication.
    let f1 = fixture();
    let f2 = fixture();
    let mut v1 = new_vault(&f1);
    v1.add_generated("one").unwrap();
    let mut v2 = new_vault(&f2);
    v2.add_generated("two").unwrap();
    let body2: serde_json::Value = serde_json::from_slice(&fs::read(&f2.path).unwrap()).unwrap();
    drop((v1, v2));
    mutate_json(&f1, |j| j["body"] = body2["body"].clone());
    let mut v = Vault::open(&f1.path).unwrap();
    assert_err(
        v.unlock(PW),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "spliced body",
    );
}

#[test]
fn a_failed_write_rolls_back_memory_state() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    // Make the target directory unusable: replace the vault file's directory by a file.
    let dir = f.path.parent().unwrap().to_path_buf();
    let moved = dir.with_extension("moved");
    fs::rename(&dir, &moved).unwrap();
    fs::write(&dir, b"i am a file, not a directory").unwrap();

    assert!(v.add_generated("b").is_err());
    assert!(v.set_label(a.id, "renamed").is_err());
    assert!(v.remove_account(a.id).is_err());
    let list = v.list_accounts().unwrap();
    assert_eq!(list.len(), 1, "failed add/remove must be rolled back");
    assert_eq!(list[0].label, "a", "failed rename must be rolled back");
}

// ---------------------------------------------------------------------------------------
// password change
// ---------------------------------------------------------------------------------------

#[test]
fn change_password_rewraps_and_keeps_accounts() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    let before = fs::read(&f.path).unwrap();
    let new_pw = "a completely different passphrase";

    assert_err(
        v.change_password("wrong old password!!", new_pw),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "bad old",
    );
    assert_eq!(
        fs::read(&f.path).unwrap(),
        before,
        "failed change must not touch the file"
    );

    v.change_password(PW, new_pw).unwrap();
    assert_ne!(fs::read(&f.path).unwrap(), before);
    assert_eq!(v.list_accounts().unwrap()[0], a, "still usable immediately");
    drop(v);

    let mut v = Vault::open(&f.path).unwrap();
    assert_err(
        v.unlock(PW),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "old password after change",
    );
    v.unlock(new_pw).unwrap();
    assert_eq!(v.list_accounts().unwrap()[0], a);

    // Documented limitation: a copy made before the change is still opened by the OLD password.
    let backup_dir = tempfile::tempdir().unwrap();
    let old_copy = backup_dir.path().join("old.embr");
    fs::write(&old_copy, &before).unwrap();
    let mut old = Vault::open(&old_copy).unwrap();
    old.unlock(PW).unwrap();
}

#[test]
fn change_password_rotates_salt_and_vault_key() {
    let f = fixture();
    let mut v = new_vault(&f);
    v.add_generated("a").unwrap();
    let j1: serde_json::Value = serde_json::from_slice(&fs::read(&f.path).unwrap()).unwrap();
    v.change_password(PW, PW).unwrap(); // same password, fresh salt and key
    let j2: serde_json::Value = serde_json::from_slice(&fs::read(&f.path).unwrap()).unwrap();
    assert_ne!(j1["slots"][0]["kdf"]["salt"], j2["slots"][0]["kdf"]["salt"]);
    assert_ne!(j1["slots"][0]["wrapped_key"], j2["slots"][0]["wrapped_key"]);
    assert_ne!(j1["body"]["nonce"], j2["body"]["nonce"]);
}

#[test]
fn kdf_parameters_are_reported_and_upgradable() {
    let f = fixture();
    let mut v = new_vault(&f);
    assert_eq!(v.kdf_params().unwrap(), FAST);
    assert!(v.kdf_upgrade_recommended());
    assert_err(
        v.set_kdf_for_new(KdfParams {
            m_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        }),
        |e| matches!(e, VaultError::KdfParams),
        "too weak",
    );
    assert_err(
        v.set_kdf_for_new(KdfParams {
            m_kib: 4_000_000,
            ..FAST
        }),
        |e| matches!(e, VaultError::KdfParams),
        "too strong",
    );
    let stronger = KdfParams {
        m_kib: 32_768,
        t_cost: 3,
        p_cost: 1,
    };
    v.set_kdf_for_new(stronger).unwrap();
    v.change_password(PW, PW).unwrap();
    assert_eq!(v.kdf_params().unwrap(), stronger);
    assert_err(
        Vault::create_with(
            tempfile::tempdir().unwrap().path().join("x.embr"),
            PW,
            KdfParams {
                m_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
        ),
        |e| matches!(e, VaultError::KdfParams),
        "create weak",
    );
}

// ---------------------------------------------------------------------------------------
// backup and recovery
// ---------------------------------------------------------------------------------------

#[test]
fn encrypted_backup_and_restore() {
    let f = fixture();
    let mut v = new_vault(&f);
    let a = v.add_generated("a").unwrap();
    let b = v.import_secret("b", &"22".repeat(32)).unwrap();
    v.set_active(b.id).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("backup.embr");
    v.export_backup(&backup).unwrap();
    assert_err(
        v.export_backup(&backup),
        |e| matches!(e, VaultError::AlreadyExists),
        "no overwrite",
    );

    // The backup is encrypted.
    let bytes = fs::read(&backup).unwrap();
    assert!(!contains(&bytes, &hex::decode("22".repeat(32)).unwrap()));

    // Restore elsewhere.
    let dest = dir.path().join("restored").join("vault.embr");
    assert_err(
        Vault::restore_backup(&backup, "wrong backup password", &dest),
        |e| matches!(e, VaultError::WrongPasswordOrCorrupt),
        "wrong pw",
    );
    assert!(
        !dest.exists(),
        "a failed restore must not create the destination"
    );

    let mut restored = Vault::restore_backup(&backup, PW, &dest).unwrap();
    assert!(restored.is_unlocked());
    assert_eq!(
        restored.list_accounts().unwrap(),
        vec![a.clone(), b.clone()]
    );
    assert_eq!(restored.active_account().unwrap().unwrap().id, b.id);
    assert_err(
        Vault::restore_backup(&backup, PW, &dest),
        |e| matches!(e, VaultError::AlreadyExists),
        "no overwrite on restore",
    );

    // The restored vault is independent and fully functional.
    restored.add_generated("c").unwrap();
    restored.lock();
    let mut reopened = Vault::open(&dest).unwrap();
    reopened.unlock(PW).unwrap();
    assert_eq!(reopened.list_accounts().unwrap().len(), 3);
    // ...and the original is unaffected.
    assert_eq!(v.list_accounts().unwrap().len(), 2);
}

#[test]
fn restoring_a_corrupt_backup_fails_cleanly() {
    let f = fixture();
    let mut v = new_vault(&f);
    v.add_generated("a").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("b.embr");
    v.export_backup(&backup).unwrap();
    let mut bytes = fs::read(&backup).unwrap();
    bytes.truncate(bytes.len() - 40);
    fs::write(&backup, bytes).unwrap();
    let dest = dir.path().join("dest.embr");
    assert!(Vault::restore_backup(&backup, PW, &dest).is_err());
    assert!(!dest.exists());
}

// ---------------------------------------------------------------------------------------
// concurrency / revision
// ---------------------------------------------------------------------------------------

#[test]
fn only_one_creator_wins_a_race() {
    let f = fixture();
    let path = f.path.clone();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p = path.clone();
            std::thread::spawn(move || Vault::create_with(p, PW, FAST).map(|_| ()))
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one create may succeed"
    );
    for r in results.iter().filter(|r| r.is_err()) {
        assert!(
            matches!(r, Err(VaultError::AlreadyExists)),
            "losers must see AlreadyExists, got {r:?}"
        );
    }
    // The surviving file is a valid vault.
    let mut v = Vault::open(&f.path).unwrap();
    v.unlock(PW).unwrap();
}
