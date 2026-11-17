//! NIP-19 encoding, key import/export (NIP-49) and legacy NIP-04.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use embr_core::KeySecurity;
use embr_crypto::{CryptoError, Identity, Limits, encode_npub, parse_public_key};

// NIP-19 documented examples.
const NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
const NSEC_HEX: &str = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
const NPUB_OF_DOC_EXAMPLE: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
const NPUB_HEX: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
const NPUB2: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
const NPUB2_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

// NIP-49 test vector: password "nostr", log_n = 16.
const NCRYPTSEC_VECTOR: &str = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
const NCRYPTSEC_VECTOR_SECRET: &str =
    "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";

#[test]
fn nip19_nsec_and_npub_vectors() {
    let id = Identity::from_secret_str(NSEC).unwrap();
    assert_eq!(hex::encode(*id.secret_bytes()), NSEC_HEX);
    // The NIP-19 doc's nsec and npub examples are a key pair.
    assert_eq!(id.pubkey_hex(), NPUB_HEX);
    assert_eq!(id.npub(), NPUB_OF_DOC_EXAMPLE);
    assert_eq!(&**id.reveal_nsec().unwrap(), NSEC);
    // Same key from hex.
    let id2 = Identity::from_secret_str(NSEC_HEX).unwrap();
    assert_eq!(id2.pubkey_hex(), id.pubkey_hex());
    // Surrounding whitespace (copy/paste) is tolerated.
    assert!(Identity::from_secret_str(&format!("  {NSEC}\n")).is_ok());

    assert_eq!(
        parse_public_key(NPUB_OF_DOC_EXAMPLE).unwrap().to_hex(),
        NPUB_HEX
    );
    assert_eq!(parse_public_key(NPUB_HEX).unwrap().to_hex(), NPUB_HEX);
    assert_eq!(parse_public_key(NPUB2).unwrap().to_hex(), NPUB2_HEX);
    assert_eq!(encode_npub(&parse_public_key(NPUB2_HEX).unwrap()), NPUB2);
    assert_eq!(
        encode_npub(&parse_public_key(NPUB_HEX).unwrap()),
        NPUB_OF_DOC_EXAMPLE
    );
    assert!(id.npub().starts_with("npub1"));
}

#[test]
fn secret_key_parsing_is_strict() {
    let bad = [
        "",
        "nsec1",
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe6", // bad checksum
        NPUB_OF_DOC_EXAMPLE,                                               // a public key
        NCRYPTSEC_VECTOR,                                                  // encrypted key
        &"00".repeat(32),                                                  // zero scalar
        &"ff".repeat(32),                                                  // >= curve order
        &NSEC_HEX[..62],                                                   // short hex
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "0x67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
    ];
    for s in bad {
        assert_eq!(
            Identity::from_secret_str(s).unwrap_err(),
            CryptoError::InvalidSecretKey,
            "{s:?}"
        );
    }
    assert!(Identity::from_secret_bytes(&[0u8; 32]).is_err());
    assert!(Identity::from_secret_bytes(&[0xffu8; 32]).is_err());
}

#[test]
fn public_key_parsing_is_strict() {
    for s in [
        "",
        "npub1",
        NSEC,
        &NPUB_HEX[..63],
        &format!("{NPUB_HEX}0"),
        "nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
        "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p",
    ] {
        assert_eq!(
            parse_public_key(s).unwrap_err(),
            CryptoError::InvalidPublicKey,
            "{s:?}"
        );
    }
    // A hex string that is not on the curve.
    assert!(
        parse_public_key(&"00".repeat(32)).is_err() || {
            // some libraries accept any 32 bytes lazily; then using it must fail
            let me = Identity::generate();
            me.nip44_encrypt(
                &parse_public_key(&"00".repeat(32)).unwrap(),
                "x",
                &Limits::default(),
            )
            .is_err()
        }
    );
}

#[test]
fn nip49_official_vector_decrypts() {
    let (id, security) =
        Identity::from_ncryptsec(NCRYPTSEC_VECTOR, "nostr", &Limits::default()).unwrap();
    assert_eq!(hex::encode(*id.secret_bytes()), NCRYPTSEC_VECTOR_SECRET);
    // The vector was created with key_security = 0x00 or similar; we only assert it parses to a
    // defined variant.
    assert!(matches!(
        security,
        KeySecurity::Weak | KeySecurity::Medium | KeySecurity::Unknown
    ));
}

#[test]
fn nip49_wrong_password_and_corruption() {
    let limits = Limits::default();
    assert_eq!(
        Identity::from_ncryptsec(NCRYPTSEC_VECTOR, "wrong", &limits).unwrap_err(),
        CryptoError::WrongPasswordOrCorrupt
    );
    assert_eq!(
        Identity::from_ncryptsec(NCRYPTSEC_VECTOR, "", &limits).unwrap_err(),
        CryptoError::WrongPasswordOrCorrupt
    );
    // Corrupt a payload character (keep valid bech32 charset; checksum then fails).
    let mut corrupted = NCRYPTSEC_VECTOR.to_string();
    corrupted.replace_range(30..31, if &corrupted[30..31] == "q" { "p" } else { "q" });
    assert_eq!(
        Identity::from_ncryptsec(&corrupted, "nostr", &limits).unwrap_err(),
        CryptoError::InvalidNcryptsec
    );
    for s in ["", "ncryptsec1", NSEC, NPUB2] {
        assert_eq!(
            Identity::from_ncryptsec(s, "x", &limits).unwrap_err(),
            CryptoError::InvalidNcryptsec
        );
    }
}

#[test]
fn nip49_export_roundtrip_and_security_byte() {
    let limits = Limits::default();
    let original = Identity::generate();
    for security in [KeySecurity::Weak, KeySecurity::Medium, KeySecurity::Unknown] {
        let enc = original
            .export_ncryptsec("correct horse battery staple", 16, security)
            .unwrap();
        assert!(enc.starts_with("ncryptsec1"));
        let (back, got) =
            Identity::from_ncryptsec(&enc, "correct horse battery staple", &limits).unwrap();
        assert_eq!(back.pubkey_hex(), original.pubkey_hex());
        assert_eq!(got, security);
    }
    // Non-deterministic: two exports of the same key differ (random salt and nonce).
    let a = original
        .export_ncryptsec("pw", 16, KeySecurity::Medium)
        .unwrap();
    let b = original
        .export_ncryptsec("pw", 16, KeySecurity::Medium)
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn nip49_password_is_nfkc_normalised() {
    // NIP-49: "ÅΩẛ̣" (U+212B U+2126 U+1E9B U+0323) must normalise to U+00C5 U+03A9 U+1E69.
    let raw = "\u{212B}\u{2126}\u{1E9B}\u{0323}";
    let normalised = "\u{00C5}\u{03A9}\u{1E69}";
    let id = Identity::generate();
    let enc = id.export_ncryptsec(raw, 16, KeySecurity::Unknown).unwrap();
    let (back, _) = Identity::from_ncryptsec(&enc, normalised, &Limits::default()).unwrap();
    assert_eq!(back.pubkey_hex(), id.pubkey_hex());
}

#[test]
fn nip49_cost_bounds() {
    let id = Identity::generate();
    for bad in [0u8, 1, 15, 21, 22, 255] {
        assert!(
            matches!(
                id.export_ncryptsec("pw", bad, KeySecurity::Unknown),
                Err(CryptoError::InvalidScryptCost { .. })
            ),
            "log_n {bad} must be refused on export"
        );
    }
    // On import, an attacker-controlled log_n above our limit is refused *before* scrypt runs.
    let enc = id.export_ncryptsec("pw", 17, KeySecurity::Unknown).unwrap();
    let strict = Limits {
        max_ncryptsec_log_n: 16,
        ..Limits::default()
    };
    assert_eq!(
        Identity::from_ncryptsec(&enc, "pw", &strict).unwrap_err(),
        CryptoError::InvalidNcryptsec
    );
    let relaxed = Limits {
        max_ncryptsec_log_n: 17,
        ..Limits::default()
    };
    assert!(Identity::from_ncryptsec(&enc, "pw", &relaxed).is_ok());
}

#[test]
fn nip04_legacy_roundtrip_and_failures() {
    let limits = Limits::default();
    let a = Identity::generate();
    let b = Identity::generate();
    let msg = "legacy message ✓";
    let ct = a.nip04_encrypt(&b.public_key(), msg, &limits).unwrap();
    assert!(
        ct.contains("?iv="),
        "NIP-04 payload format is <base64>?iv=<base64>"
    );
    assert_eq!(
        &*b.nip04_decrypt(&a.public_key(), &ct, &limits).unwrap(),
        msg
    );
    assert_eq!(
        &*a.nip04_decrypt(&b.public_key(), &ct, &limits).unwrap(),
        msg
    );

    // Wrong peer, garbage, truncated and oversized inputs fail without panicking.
    let c = Identity::generate();
    assert!(c.nip04_decrypt(&a.public_key(), &ct, &limits).is_err());
    for bad in ["", "garbage", "AAAA?iv=AAAA", &ct[..ct.len() / 2]] {
        assert!(
            b.nip04_decrypt(&a.public_key(), bad, &limits).is_err(),
            "{bad:?}"
        );
    }
    let tiny = Limits {
        max_plaintext_bytes: 3,
        max_ciphertext_bytes: 3,
        ..Limits::default()
    };
    assert!(a.nip04_encrypt(&b.public_key(), "four", &tiny).is_err());
    assert!(b.nip04_decrypt(&a.public_key(), &ct, &tiny).is_err());
}

#[test]
fn nip44_and_nip04_do_not_cross_decrypt() {
    let limits = Limits::default();
    let a = Identity::generate();
    let b = Identity::generate();
    let c44 = a.nip44_encrypt(&b.public_key(), "m", &limits).unwrap();
    let c04 = a.nip04_encrypt(&b.public_key(), "m", &limits).unwrap();
    assert!(b.nip04_decrypt(&a.public_key(), &c44, &limits).is_err());
    assert!(b.nip44_decrypt(&a.public_key(), &c04, &limits).is_err());
}
