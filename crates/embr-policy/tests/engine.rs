//! Behavioural tests of the authorization engine.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use embr_core::{AccountId, Operation, Pubkey32};
use embr_policy::*;

const NOW: u64 = 1_700_000_000;
const S1: SessionId = SessionId(1);
const S2: SessionId = SessionId(2);

fn key(n: u8) -> Pubkey32 {
    Pubkey32::from_bytes([n; 32])
}
fn acct(n: u8) -> AccountId {
    AccountId::from_bytes([n; 16])
}
fn sign(client: u8, account: u8, kind: u16) -> Request {
    Request {
        client: key(client),
        account: acct(account),
        op: Operation::SignEvent,
        kind: Some(kind),
        peer: None,
    }
}
fn op(client: u8, account: u8, op: Operation, peer: Option<u8>) -> Request {
    Request {
        client: key(client),
        account: acct(account),
        op,
        kind: None,
        peer: peer.map(key),
    }
}
fn engine() -> Engine {
    let mut e = Engine::new();
    e.pair(key(1), "app one", vec![acct(1), acct(2)], NOW)
        .unwrap();
    e.pair(key(2), "app two", vec![acct(1)], NOW).unwrap();
    e
}
fn exact(r: &Request) -> Scope {
    Scope::exact(r)
}

// ---------------------------------------------------------------------------------------
// default deny
// ---------------------------------------------------------------------------------------

#[test]
fn unknown_blocked_and_unbound_are_refused() {
    let mut e = engine();
    assert_eq!(e.evaluate(&sign(9, 1, 1), S1, NOW), Verdict::NotPaired);
    assert_eq!(
        e.evaluate(&sign(2, 2, 1), S1, NOW),
        Verdict::AccountNotGranted,
        "client 2 is not bound to account 2"
    );
    e.block_client(key(2));
    assert_eq!(e.evaluate(&sign(2, 1, 1), S1, NOW), Verdict::Blocked);
    assert_eq!(
        e.pair(key(2), "back again", vec![acct(1)], NOW),
        Err(PolicyError::Blocked)
    );
    assert!(e.unblock_client(&key(2)));
    e.pair(key(2), "back again", vec![acct(1)], NOW).unwrap();
}

#[test]
fn paired_client_with_no_grants_is_asked_for_everything_but_login() {
    let mut e = engine();
    for o in [
        Operation::SignEvent,
        Operation::Nip44Encrypt,
        Operation::Nip44Decrypt,
        Operation::Nip04Encrypt,
        Operation::Nip04Decrypt,
    ] {
        let r = Request {
            client: key(1),
            account: acct(1),
            op: o,
            kind: (o == Operation::SignEvent).then_some(1),
            peer: None,
        };
        assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Ask, "{o}");
    }
    assert_eq!(
        e.evaluate(&op(1, 1, Operation::GetPublicKey, None), S1, NOW),
        Verdict::Allow { grant: None }
    );
}

#[test]
fn once_choices_store_nothing() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let d = e
        .decide(&r, Choice::AllowOnce, &exact(&r), S1, NOW)
        .unwrap();
    assert_eq!(
        d,
        Decision {
            allow: true,
            grant: None
        }
    );
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Ask);
    let d = e
        .decide(&r, Choice::RejectOnce, &exact(&r), S1, NOW)
        .unwrap();
    assert_eq!(
        d,
        Decision {
            allow: false,
            grant: None
        }
    );
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Ask);
    assert!(e.grants().is_empty());
}

// ---------------------------------------------------------------------------------------
// scoping and isolation
// ---------------------------------------------------------------------------------------

#[test]
fn grants_are_scoped_by_account_client_operation_kind_and_peer() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let d = e
        .decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap();
    let id = d.grant.unwrap();
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Allow { grant: Some(id) });
    assert_eq!(
        e.evaluate(&r, S2, NOW),
        Verdict::Allow { grant: Some(id) },
        "persistent survives sessions"
    );

    assert_eq!(
        e.evaluate(&sign(1, 1, 7), S1, NOW),
        Verdict::Ask,
        "other kind"
    );
    assert_eq!(
        e.evaluate(&sign(1, 2, 1), S1, NOW),
        Verdict::Ask,
        "other account of the same client"
    );
    assert_eq!(
        e.evaluate(&sign(2, 1, 1), S1, NOW),
        Verdict::Ask,
        "other client, same account"
    );
    for o in [
        Operation::Nip44Decrypt,
        Operation::Nip44Encrypt,
        Operation::Nip04Decrypt,
    ] {
        assert_eq!(
            e.evaluate(&op(1, 1, o, Some(5)), S1, NOW),
            Verdict::Ask,
            "a signing grant never covers {o}"
        );
    }
}

#[test]
fn decrypt_grant_is_peer_scoped_and_does_not_imply_signing_or_other_peers() {
    let mut e = engine();
    let r = op(1, 1, Operation::Nip44Decrypt, Some(5));
    e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap();
    assert!(matches!(e.evaluate(&r, S1, NOW), Verdict::Allow { .. }));
    assert_eq!(
        e.evaluate(&op(1, 1, Operation::Nip44Decrypt, Some(6)), S1, NOW),
        Verdict::Ask,
        "other peer"
    );
    assert_eq!(
        e.evaluate(&op(1, 1, Operation::Nip44Decrypt, None), S1, NOW),
        Verdict::Ask,
        "no peer"
    );
    assert_eq!(
        e.evaluate(&sign(1, 1, 1), S1, NOW),
        Verdict::Ask,
        "decrypt grant is not a signing grant"
    );
    assert_eq!(
        e.evaluate(&op(1, 1, Operation::Nip04Decrypt, Some(5)), S1, NOW),
        Verdict::Ask,
        "NIP-04 is separate"
    );
}

// ---------------------------------------------------------------------------------------
// expiry, sessions, usage limits, revocation
// ---------------------------------------------------------------------------------------

#[test]
fn session_grants_end_with_the_session() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    e.decide(&r, Choice::AllowSession, &exact(&r), S1, NOW)
        .unwrap();
    assert!(matches!(e.evaluate(&r, S1, NOW), Verdict::Allow { .. }));
    assert_eq!(
        e.evaluate(&r, S2, NOW),
        Verdict::Ask,
        "another session cannot use it (session fixation)"
    );
    assert_eq!(e.end_session(S1), 1);
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Ask);
}

#[test]
fn time_limited_grants_expire_exactly() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    e.decide(&r, Choice::AllowUntil(NOW + 100), &exact(&r), S1, NOW)
        .unwrap();
    assert!(matches!(
        e.evaluate(&r, S1, NOW + 99),
        Verdict::Allow { .. }
    ));
    assert_eq!(
        e.evaluate(&r, S1, NOW + 100),
        Verdict::Ask,
        "expired at the boundary"
    );
    assert_eq!(e.evaluate(&r, S1, NOW + 10_000), Verdict::Ask);
    assert_eq!(e.purge_expired(NOW + 100), 1);
    assert!(e.grants().is_empty());
    assert_eq!(
        e.decide(&r, Choice::AllowUntil(NOW), &exact(&r), S1, NOW),
        Err(PolicyError::InvalidExpiry)
    );
}

#[test]
fn use_limits_are_consumed_and_then_removed() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let scope = Scope {
        uses: Some(2),
        ..exact(&r)
    };
    e.decide(&r, Choice::AllowPersistent, &scope, S1, NOW)
        .unwrap();
    assert!(matches!(e.evaluate(&r, S1, NOW), Verdict::Allow { .. }));
    assert!(matches!(e.evaluate(&r, S1, NOW), Verdict::Allow { .. }));
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::Ask, "third use");
    assert!(e.grants().is_empty());
    assert_eq!(
        e.decide(
            &r,
            Choice::AllowPersistent,
            &Scope {
                uses: Some(0),
                ..exact(&r)
            },
            S1,
            NOW
        ),
        Err(PolicyError::InvalidUses)
    );
}

#[test]
fn deny_beats_allow_and_always_reject_persists() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap();
    let deny = e
        .decide(&r, Choice::AlwaysReject, &exact(&r), S1, NOW)
        .unwrap();
    assert!(!deny.allow);
    assert_eq!(
        e.evaluate(&r, S1, NOW),
        Verdict::Deny {
            grant: deny.grant.unwrap()
        }
    );
    // A broad deny covers everything for that account/operation, including sensitive kinds.
    let broad = Scope {
        kind: KindScope::Any,
        peer: None,
        uses: None,
    };
    e.decide(&sign(1, 1, 7), Choice::AlwaysReject, &broad, S1, NOW)
        .unwrap();
    assert!(matches!(
        e.evaluate(&sign(1, 1, 14), S1, NOW),
        Verdict::Deny { .. }
    ));
    assert!(matches!(
        e.evaluate(&sign(1, 1, 1059), S1, NOW),
        Verdict::Deny { .. }
    ));
}

#[test]
fn identical_decisions_are_refreshed_not_duplicated() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let a = e
        .decide(&r, Choice::AllowUntil(NOW + 10), &exact(&r), S1, NOW)
        .unwrap()
        .grant
        .unwrap();
    let b = e
        .decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap()
        .grant
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(e.grants().len(), 1);
    assert_eq!(e.grants()[0].expiry, Expiry::Never);
}

#[test]
fn revocation_paths() {
    let mut e = engine();
    let r1 = sign(1, 1, 1);
    let r2 = sign(2, 1, 1);
    let g1 = e
        .decide(&r1, Choice::AllowPersistent, &exact(&r1), S1, NOW)
        .unwrap()
        .grant
        .unwrap();
    e.decide(&r2, Choice::AllowPersistent, &exact(&r2), S1, NOW)
        .unwrap();
    assert!(e.revoke_grant(g1));
    assert!(!e.revoke_grant(g1));
    assert_eq!(e.evaluate(&r1, S1, NOW), Verdict::Ask);
    assert!(matches!(e.evaluate(&r2, S1, NOW), Verdict::Allow { .. }));

    assert!(e.revoke_client(&key(2)));
    assert_eq!(e.evaluate(&r2, S1, NOW), Verdict::NotPaired);
    assert!(e.grants().is_empty(), "a revoked client's grants are gone");
    // Re-pairing starts from zero: old grants do not come back.
    e.pair(key(2), "again", vec![acct(1)], NOW).unwrap();
    assert_eq!(e.evaluate(&r2, S1, NOW), Verdict::Ask);
}

#[test]
fn removing_an_account_removes_its_grants_and_bindings() {
    let mut e = engine();
    let r = sign(1, 2, 1);
    e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap();
    e.remove_account(acct(2));
    assert_eq!(e.evaluate(&r, S1, NOW), Verdict::AccountNotGranted);
    assert!(e.grants().is_empty());
    assert_eq!(e.client(&key(1)).unwrap().accounts, vec![acct(1)]);
}

// ---------------------------------------------------------------------------------------
// stricter defaults for sensitive operations
// ---------------------------------------------------------------------------------------

#[test]
fn direct_message_kinds_cannot_be_remembered_beyond_the_session() {
    let mut e = engine();
    for kind in SENSITIVE_KINDS {
        let r = sign(1, 1, kind);
        for choice in [Choice::AllowPersistent, Choice::AllowUntil(NOW + 60)] {
            assert!(
                matches!(
                    e.decide(&r, choice, &exact(&r), S1, NOW),
                    Err(PolicyError::TooBroad(_))
                ),
                "kind {kind} {choice:?}"
            );
        }
        // Once and Session are fine.
        assert!(
            e.decide(&r, Choice::AllowOnce, &exact(&r), S1, NOW)
                .unwrap()
                .allow
        );
        assert!(
            e.decide(&r, Choice::AllowSession, &exact(&r), S1, NOW)
                .unwrap()
                .allow
        );
        e.end_session(S1);
    }
}

#[test]
fn any_kind_signing_grants_must_expire_and_never_cover_dms() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let any = Scope {
        kind: KindScope::Any,
        peer: None,
        uses: None,
    };
    assert!(matches!(
        e.decide(&r, Choice::AllowPersistent, &any, S1, NOW),
        Err(PolicyError::TooBroad(_))
    ));
    assert!(matches!(
        e.decide(
            &r,
            Choice::AllowUntil(NOW + MAX_BROAD_EXPIRY_SECS + 1),
            &any,
            S1,
            NOW
        ),
        Err(PolicyError::TooBroad(_))
    ));
    e.decide(
        &r,
        Choice::AllowUntil(NOW + MAX_BROAD_EXPIRY_SECS),
        &any,
        S1,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        e.evaluate(&sign(1, 1, 30023), S1, NOW),
        Verdict::Allow { .. }
    ));
    for kind in SENSITIVE_KINDS {
        assert_eq!(
            e.evaluate(&sign(1, 1, kind), S1, NOW),
            Verdict::Ask,
            "an any-kind allow must not cover kind {kind}"
        );
    }
}

#[test]
fn unscoped_decrypt_grants_are_short_lived() {
    let mut e = engine();
    let r = op(1, 1, Operation::Nip44Decrypt, Some(5));
    let no_peer = Scope {
        kind: KindScope::Any,
        peer: None,
        uses: None,
    };
    assert!(matches!(
        e.decide(&r, Choice::AllowPersistent, &no_peer, S1, NOW),
        Err(PolicyError::TooBroad(_))
    ));
    assert!(matches!(
        e.decide(&r, Choice::AllowUntil(NOW + 3601), &no_peer, S1, NOW),
        Err(PolicyError::TooBroad(_))
    ));
    assert!(
        e.decide(&r, Choice::AllowUntil(NOW + 3600), &no_peer, S1, NOW)
            .is_ok()
    );
    assert!(
        e.decide(&r, Choice::AllowSession, &no_peer, S1, NOW)
            .is_ok()
    );
    // Peer-scoped persistent is allowed.
    assert!(
        e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
            .is_ok()
    );
}

#[test]
fn scopes_must_cover_the_request_they_answer() {
    let mut e = engine();
    let r = sign(1, 1, 1);
    let wrong_kind = Scope {
        kind: KindScope::Exact(2),
        peer: None,
        uses: None,
    };
    assert_eq!(
        e.decide(&r, Choice::AllowPersistent, &wrong_kind, S1, NOW),
        Err(PolicyError::ScopeDoesNotCover)
    );
    let wrong_peer = Scope {
        kind: KindScope::Exact(1),
        peer: Some(key(9)),
        uses: None,
    };
    assert_eq!(
        e.decide(&r, Choice::AllowPersistent, &wrong_peer, S1, NOW),
        Err(PolicyError::ScopeDoesNotCover)
    );
    let enc = op(1, 1, Operation::Nip44Encrypt, Some(5));
    let kind_on_encrypt = Scope {
        kind: KindScope::Exact(1),
        peer: None,
        uses: None,
    };
    assert!(matches!(
        e.decide(&enc, Choice::AllowPersistent, &kind_on_encrypt, S1, NOW),
        Err(PolicyError::TooBroad(_))
    ));
    let login = op(1, 1, Operation::GetPublicKey, None);
    assert!(matches!(
        e.decide(
            &login,
            Choice::AllowPersistent,
            &Scope::exact(&login),
            S1,
            NOW
        ),
        Err(PolicyError::TooBroad(_))
    ));
}

#[test]
fn decisions_for_unpaired_or_unbound_requests_are_refused() {
    let mut e = engine();
    let r = sign(9, 1, 1);
    assert_eq!(
        e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW),
        Err(PolicyError::NotPaired)
    );
    let r = sign(2, 2, 1);
    assert_eq!(
        e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW),
        Err(PolicyError::AccountNotGranted)
    );
}

/// Exhaustive invariant: whatever sequence of choices the engine *accepts*, a direct-message kind
/// is never auto-allowed outside the creating session.
#[test]
fn no_accepted_decision_ever_auto_allows_dm_kinds_across_sessions() {
    let choices = [
        Choice::AllowSession,
        Choice::AllowUntil(NOW + 30),
        Choice::AllowUntil(NOW + 3600),
        Choice::AllowUntil(NOW + MAX_BROAD_EXPIRY_SECS),
        Choice::AllowPersistent,
        Choice::AlwaysReject,
    ];
    let kinds = [1u16, 4, 13, 14, 1059, 30023];
    for req_kind in kinds {
        for scope_kind in [KindScope::Any, KindScope::Exact(req_kind)] {
            for choice in choices {
                let mut e = engine();
                let r = sign(1, 1, req_kind);
                let scope = Scope {
                    kind: scope_kind,
                    peer: None,
                    uses: None,
                };
                let Ok(d) = e.decide(&r, choice, &scope, S1, NOW) else {
                    continue;
                };
                if !d.allow {
                    continue;
                }
                for dm in SENSITIVE_KINDS {
                    let v = e.evaluate(&sign(1, 1, dm), S2, NOW);
                    assert!(
                        !matches!(v, Verdict::Allow { .. }),
                        "{choice:?} {scope_kind:?} for kind {req_kind} auto-allowed DM kind {dm} in another session"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// persistence
// ---------------------------------------------------------------------------------------

#[test]
fn persistence_roundtrip_excludes_session_grants_and_expired_ones() {
    let mut e = engine();
    let persistent = sign(1, 1, 1);
    let session = sign(1, 1, 7);
    let timed = sign(1, 1, 9);
    let deny = sign(1, 1, 11);
    e.decide(
        &persistent,
        Choice::AllowPersistent,
        &exact(&persistent),
        S1,
        NOW,
    )
    .unwrap();
    e.decide(&session, Choice::AllowSession, &exact(&session), S1, NOW)
        .unwrap();
    e.decide(
        &timed,
        Choice::AllowUntil(NOW + 50),
        &exact(&timed),
        S1,
        NOW,
    )
    .unwrap();
    e.decide(&deny, Choice::AlwaysReject, &exact(&deny), S1, NOW)
        .unwrap();
    e.block_client(key(7));

    let json = e.to_json();
    let mut back = Engine::from_json(&json, NOW + 10).unwrap();
    assert_eq!(back.clients().len(), 2);
    assert!(back.is_blocked(&key(7)));
    assert!(matches!(
        back.evaluate(&persistent, S1, NOW + 10),
        Verdict::Allow { .. }
    ));
    assert_eq!(
        back.evaluate(&session, S1, NOW + 10),
        Verdict::Ask,
        "session grants are never persisted"
    );
    assert!(matches!(
        back.evaluate(&timed, S1, NOW + 10),
        Verdict::Allow { .. }
    ));
    assert!(matches!(
        back.evaluate(&deny, S1, NOW + 10),
        Verdict::Deny { .. }
    ));

    let later = Engine::from_json(&json, NOW + 51).unwrap();
    assert!(
        later
            .grants()
            .iter()
            .all(|g| g.expiry != Expiry::Until(NOW + 50)),
        "expired grants are dropped on load"
    );

    // New grants after reload get fresh ids.
    let before = back.grants().iter().map(|g| g.id.0).max().unwrap();
    let r = sign(2, 1, 5);
    let id = back
        .decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap()
        .grant
        .unwrap();
    assert!(id.0 > before);
}

#[test]
fn hostile_persisted_data_is_rejected_or_neutralised() {
    for bad in [
        &b""[..],
        b"null",
        b"[]",
        b"{}",
        b"{\"version\":2,\"clients\":[],\"blocked\":[],\"grants\":[],\"next_grant\":0}",
    ] {
        assert!(
            Engine::from_json(bad, NOW).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // Unknown field.
    assert!(
        Engine::from_json(
            br#"{"version":1,"clients":[],"blocked":[],"grants":[],"next_grant":0,"admin":true}"#,
            NOW
        )
        .is_err()
    );

    // A grant for a client that is not paired (e.g. injected by hand) is dropped on load.
    let mut e = engine();
    let r = sign(1, 1, 1);
    e.decide(&r, Choice::AllowPersistent, &exact(&r), S1, NOW)
        .unwrap();
    let mut p = e.persisted();
    p.grants[0].client = key(99);
    let back = Engine::from_persisted(p, NOW).unwrap();
    assert!(back.grants().is_empty());

    // An injected any-kind allow still never covers DM kinds.
    let mut p = e.persisted();
    p.grants[0].kind = KindScope::Any;
    p.grants[0].expiry = Expiry::Never;
    let mut back = Engine::from_persisted(p, NOW).unwrap();
    assert_eq!(back.evaluate(&sign(1, 1, 14), S1, NOW), Verdict::Ask);
    assert!(matches!(
        back.evaluate(&sign(1, 1, 1), S1, NOW),
        Verdict::Allow { .. }
    ));
}

#[test]
fn caps_are_enforced() {
    let mut e = Engine::new();
    for i in 0..MAX_CLIENTS {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&(i as u64).to_be_bytes());
        e.pair(Pubkey32::from_bytes(k), "c", vec![acct(1)], NOW)
            .unwrap();
    }
    assert_eq!(
        e.pair(key(250), "one too many", vec![acct(1)], NOW),
        Err(PolicyError::TooManyClients)
    );
    // Re-pairing an existing client is still fine at the cap.
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&0u64.to_be_bytes());
    e.pair(Pubkey32::from_bytes(k), "renamed", vec![acct(1)], NOW)
        .unwrap();
    // Names are length-capped.
    e.pair(key(251), &"x".repeat(1000), vec![], NOW).ok();
}
