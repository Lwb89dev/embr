//! NIP-44 conformance: the official, checksummed test vectors (paulmillr/nip44, referenced by
//! the NIP text), exercised both against the underlying library and through `embr-crypto`'s
//! public API.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{hex32, load_json};
use embr_crypto::{Identity, Limits, parse_public_key};
use nostr::key::{PublicKey, SecretKey};
use nostr::nips::nip44::v2::{ConversationKey, decrypt_to_bytes, encrypt_to_bytes_with_nonce};
use sha2::{Digest, Sha256};

fn vectors() -> serde_json::Value {
    load_json("nip44.vectors.json")["v2"].clone()
}

#[test]
fn vector_file_matches_checksum_published_in_the_nip() {
    // nostr-protocol/nips 44.md: "269ed0f6…5040  nip44.vectors.json"
    let bytes = std::fs::read(common::vector_path("nip44.vectors.json")).unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        digest,
        "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"
    );
}

#[test]
fn valid_get_conversation_key() {
    let v = vectors();
    let cases = v["valid"]["get_conversation_key"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for c in cases {
        let sk = SecretKey::from_slice(&hex32(c["sec1"].as_str().unwrap())).unwrap();
        let pk = PublicKey::from_hex(c["pub2"].as_str().unwrap()).unwrap();
        let ck = ConversationKey::derive(&sk, &pk).unwrap();
        assert_eq!(
            hex::encode(ck.as_bytes()),
            c["conversation_key"].as_str().unwrap()
        );
    }
}

#[test]
fn valid_encrypt_decrypt_through_public_api() {
    let v = vectors();
    let limits = Limits::default();
    let cases = v["valid"]["encrypt_decrypt"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for c in cases {
        let (sec1, sec2) = (c["sec1"].as_str().unwrap(), c["sec2"].as_str().unwrap());
        let plaintext = c["plaintext"].as_str().unwrap();
        let payload = c["payload"].as_str().unwrap();
        let id1 = Identity::from_secret_bytes(&hex32(sec1)).unwrap();
        let id2 = Identity::from_secret_bytes(&hex32(sec2)).unwrap();

        // Both directions of the ECDH decrypt the official payload.
        let got = id2
            .nip44_decrypt(&id1.public_key(), payload, &limits)
            .unwrap();
        assert_eq!(&*got, plaintext, "sec2 decrypting payload from sec1");
        let got = id1
            .nip44_decrypt(&id2.public_key(), payload, &limits)
            .unwrap();
        assert_eq!(&*got, plaintext, "sec1 decrypting payload from sec2");

        // Library produces the exact official payload for the official nonce (dependency
        // conformance), and our randomised encryption round-trips.
        let ck = ConversationKey::new(hex32(c["conversation_key"].as_str().unwrap()));
        let raw = encrypt_to_bytes_with_nonce(
            &ck,
            plaintext.as_bytes(),
            hex32(c["nonce"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(B64.encode(raw), payload);
        let ours = id1
            .nip44_encrypt(&id2.public_key(), plaintext, &limits)
            .unwrap();
        assert_ne!(
            ours, payload,
            "random nonce must differ from the vector's fixed nonce"
        );
        assert_eq!(
            &*id2
                .nip44_decrypt(&id1.public_key(), &ours, &limits)
                .unwrap(),
            plaintext
        );
    }
}

#[test]
fn valid_long_messages() {
    let v = vectors();
    for c in v["valid"]["encrypt_decrypt_long_msg"].as_array().unwrap() {
        let pattern = c["pattern"].as_str().unwrap();
        let repeat = c["repeat"].as_u64().unwrap() as usize;
        let plaintext = pattern.repeat(repeat);
        assert_eq!(
            hex::encode(Sha256::digest(plaintext.as_bytes())),
            c["plaintext_sha256"].as_str().unwrap()
        );
        let ck = ConversationKey::new(hex32(c["conversation_key"].as_str().unwrap()));
        let raw = encrypt_to_bytes_with_nonce(
            &ck,
            plaintext.as_bytes(),
            hex32(c["nonce"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(B64.encode(&raw).as_bytes())),
            c["payload_sha256"].as_str().unwrap()
        );
        assert_eq!(decrypt_to_bytes(&ck, &raw).unwrap(), plaintext.as_bytes());
    }
}

#[test]
fn invalid_conversation_keys_are_rejected() {
    let v = vectors();
    let cases = v["invalid"]["get_conversation_key"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let note = c["note"].as_str().unwrap();
        let sec1 = hex32(c["sec1"].as_str().unwrap());
        let pub2 = c["pub2"].as_str().unwrap();
        // The failure may legitimately happen at any layer: bad scalar, bad point, or ECDH.
        let Ok(id) = Identity::from_secret_bytes(&sec1) else {
            continue;
        };
        let Ok(pk) = parse_public_key(pub2) else {
            continue;
        };
        assert!(
            id.nip44_encrypt(&pk, "x", &Limits::default()).is_err(),
            "expected failure for: {note}"
        );
    }
}

#[test]
fn invalid_plaintext_lengths_are_rejected_by_our_limits() {
    let v = vectors();
    let id = Identity::generate();
    let peer = Identity::generate().public_key();
    for len in v["invalid"]["encrypt_msg_lengths"].as_array().unwrap() {
        let len = len.as_u64().unwrap() as usize;
        if len > 1_000_000 {
            continue; // do not allocate 10 MB in a unit test; covered by the size limit below
        }
        let plaintext = "a".repeat(len);
        assert!(
            id.nip44_encrypt(&peer, &plaintext, &Limits::default())
                .is_err(),
            "length {len} must be rejected"
        );
    }
    // Boundary: 65535 accepted, 65536 refused by the interop-driven default limit.
    assert!(
        id.nip44_encrypt(&peer, &"a".repeat(65_535), &Limits::default())
            .is_ok()
    );
    assert!(
        id.nip44_encrypt(&peer, &"a".repeat(65_536), &Limits::default())
            .is_err()
    );
}

#[test]
fn invalid_payloads_are_rejected() {
    let v = vectors();
    let cases = v["invalid"]["decrypt"].as_array().unwrap();
    assert!(cases.len() >= 12);
    for c in cases {
        let note = c["note"].as_str().unwrap();
        let ck = ConversationKey::new(hex32(c["conversation_key"].as_str().unwrap()));
        let payload = c["payload"].as_str().unwrap();

        // Spec decode_payload: '#' prefix = non-base64 future format; otherwise base64, then
        // the first byte is the version.
        let result = if payload.starts_with('#') {
            None
        } else {
            B64.decode(payload).ok().and_then(|raw| {
                if raw.first() != Some(&2) {
                    None
                } else {
                    decrypt_to_bytes(&ck, &raw).ok()
                }
            })
        };
        assert!(result.is_none(), "payload must be rejected: {note}");
    }
}

#[test]
fn tampering_is_detected_through_public_api() {
    let limits = Limits::default();
    let a = Identity::generate();
    let b = Identity::generate();
    let payload = a
        .nip44_encrypt(&b.public_key(), "hello nostr", &limits)
        .unwrap();
    let mut raw = B64.decode(&payload).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01; // flip one bit of the MAC
    let tampered = B64.encode(raw);
    assert!(
        b.nip44_decrypt(&a.public_key(), &tampered, &limits)
            .is_err()
    );
    // Wrong peer.
    let c = Identity::generate();
    assert!(b.nip44_decrypt(&c.public_key(), &payload, &limits).is_err());
    // Oversized ciphertext is refused before any work is done.
    let small = Limits {
        max_ciphertext_bytes: 16,
        ..Limits::default()
    };
    assert!(b.nip44_decrypt(&a.public_key(), &payload, &small).is_err());
}
