//! Canonical requests: the single, validated representation of what a client asked for.
//!
//! The daemon builds a [`Canonical`] **once**, at submission time. The same stored copy is
//! (1) turned into the preview the user sees, (2) hashed into the digest the user's decision must
//! echo, and (3) executed if approved. Nothing is re-read from the client afterwards, which closes
//! the check-to-use gap: *what you approve is what is signed*.

use embr_core::display::sanitize;
use embr_core::{AccountMeta, Operation, Pubkey32};
use embr_crypto::{EventTemplate, Identity, Limits, PublicKey, parse_public_key};
use embr_ipc::control::{ClientIdent, EventPreview, PendingKind, PendingView};
use embr_ipc::{ErrorCode, RpcError};
use embr_policy::SENSITIVE_KINDS;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A validated request.
#[derive(Debug)]
pub enum Canonical {
    /// A client asks to be paired.
    Pair {
        /// Self-declared label (already sanitised).
        name: String,
        /// Permissions the client wishes for (sanitised, bounded).
        permissions: Vec<String>,
    },
    /// Sign an event.
    Sign {
        /// The validated template.
        template: EventTemplate,
    },
    /// Encrypt for a peer.
    Encrypt {
        /// `Nip44Encrypt` or `Nip04Encrypt`.
        op: Operation,
        /// Peer.
        peer: PublicKey,
        /// Plaintext (zeroised on drop).
        plaintext: Zeroizing<String>,
    },
    /// Decrypt a payload from a peer.
    Decrypt {
        /// `Nip44Decrypt` or `Nip04Decrypt`.
        op: Operation,
        /// Peer.
        peer: PublicKey,
        /// Ciphertext payload.
        payload: String,
    },
}

impl Canonical {
    /// The policy operation (`None` for pairing).
    pub fn operation(&self) -> Option<Operation> {
        match self {
            Canonical::Pair { .. } => None,
            Canonical::Sign { .. } => Some(Operation::SignEvent),
            Canonical::Encrypt { op, .. } | Canonical::Decrypt { op, .. } => Some(*op),
        }
    }

    /// Event kind, for signing.
    pub fn kind(&self) -> Option<u16> {
        match self {
            Canonical::Sign { template } => Some(template.kind),
            _ => None,
        }
    }

    /// Peer for encrypt/decrypt.
    pub fn peer(&self) -> Option<Pubkey32> {
        match self {
            Canonical::Encrypt { peer, .. } | Canonical::Decrypt { peer, .. } => {
                peer.to_hex().parse().ok()
            }
            _ => None,
        }
    }

    /// Builds a signing request: strict template parsing, limits, pubkey consistency.
    pub fn sign(event: Value, account_pubkey: &str, limits: &Limits) -> Result<Self, RpcError> {
        let json = serde_json::to_string(&event)
            .map_err(|_| RpcError::new(ErrorCode::InvalidParams, "event is not valid JSON"))?;
        let template = EventTemplate::from_json(&json, limits)
            .map_err(|e| RpcError::new(ErrorCode::InvalidParams, e.to_string()))?;
        if let Some(pk) = &template.pubkey {
            if !pk.eq_ignore_ascii_case(account_pubkey) {
                return Err(RpcError::new(
                    ErrorCode::InvalidParams,
                    "event pubkey does not match the selected account",
                ));
            }
        }
        Ok(Canonical::Sign { template })
    }

    /// Builds an encrypt/decrypt request.
    pub fn crypto(
        op: Operation,
        peer: &str,
        text: String,
        limits: &Limits,
    ) -> Result<Self, RpcError> {
        let peer = parse_public_key(peer)
            .map_err(|e| RpcError::new(ErrorCode::InvalidParams, e.to_string()))?;
        match op {
            Operation::Nip44Encrypt | Operation::Nip04Encrypt => {
                if text.len() > limits.max_plaintext_bytes {
                    return Err(RpcError::new(
                        ErrorCode::PayloadTooLarge,
                        "plaintext too large",
                    ));
                }
                Ok(Canonical::Encrypt {
                    op,
                    peer,
                    plaintext: Zeroizing::new(text),
                })
            }
            Operation::Nip44Decrypt | Operation::Nip04Decrypt => {
                if text.len() > limits.max_ciphertext_bytes {
                    return Err(RpcError::new(
                        ErrorCode::PayloadTooLarge,
                        "payload too large",
                    ));
                }
                Ok(Canonical::Decrypt {
                    op,
                    peer,
                    payload: text,
                })
            }
            _ => Err(RpcError::new(ErrorCode::Internal, "not a crypto operation")),
        }
    }

    /// SHA-256 over a canonical encoding of the request, bound to client and account.
    pub fn digest(&self, client: &Pubkey32, account: Option<&Pubkey32>) -> String {
        let body = match self {
            Canonical::Pair { name, permissions } => {
                json!({"pair": {"name": name, "permissions": permissions}})
            }
            Canonical::Sign { template } => json!({"sign": template}),
            Canonical::Encrypt {
                op,
                peer,
                plaintext,
            } => {
                json!({"op": op.as_str(), "peer": peer.to_hex(), "plaintext": plaintext.as_str()})
            }
            Canonical::Decrypt { op, peer, payload } => {
                json!({"op": op.as_str(), "peer": peer.to_hex(), "payload": payload})
            }
        };
        let doc = json!({"v": 1, "client": client.to_string(), "account": account.map(ToString::to_string), "body": body});
        hex::encode(Sha256::digest(doc.to_string().as_bytes()))
    }

    /// Builds the approval view the user will see.
    #[allow(clippy::too_many_arguments)]
    pub fn view(
        &self,
        id: u64,
        digest: String,
        client: ClientIdent,
        account: Option<AccountMeta>,
        created_at: u64,
        expires_at: u64,
    ) -> PendingView {
        let mut v = PendingView {
            id,
            digest,
            kind: PendingKind::Operation,
            client,
            account,
            operation: self.operation().map(|o| o.as_str().to_owned()),
            legacy: self.operation().is_some_and(Operation::is_legacy),
            reveals_plaintext: self.operation().is_some_and(Operation::reveals_plaintext),
            event: None,
            peer: self.peer(),
            text_preview: None,
            payload_len: None,
            requested_permissions: Vec::new(),
            created_at,
            expires_at,
        };
        match self {
            Canonical::Pair { permissions, .. } => {
                v.kind = PendingKind::Pair;
                v.requested_permissions = permissions.clone();
            }
            Canonical::Sign { template } => {
                v.event = Some(EventPreview {
                    kind: template.kind,
                    content: sanitize(&template.content, 2000),
                    content_len: template.content.len(),
                    tags: template
                        .tags
                        .iter()
                        .take(50)
                        .map(|t| t.iter().take(8).map(|s| sanitize(s, 200)).collect())
                        .collect(),
                    tags_total: template.tags.len(),
                    created_at: template.created_at,
                    sensitive: SENSITIVE_KINDS.contains(&template.kind),
                });
            }
            Canonical::Encrypt { plaintext, .. } => {
                v.text_preview = Some(sanitize(plaintext, 500));
                v.payload_len = Some(plaintext.len());
            }
            Canonical::Decrypt { payload, .. } => {
                v.payload_len = Some(payload.len());
            }
        }
        v
    }

    /// Executes the request with `identity`. Called only after policy/approval.
    pub fn execute(&self, identity: &Identity, limits: &Limits) -> Result<Value, RpcError> {
        let bad =
            |e: embr_crypto::CryptoError| RpcError::new(ErrorCode::InvalidParams, e.to_string());
        match self {
            Canonical::Pair { .. } => Err(RpcError::new(
                ErrorCode::Internal,
                "pairing is not executable",
            )),
            Canonical::Sign { template } => {
                let event = identity.sign_event(template, limits).map_err(bad)?;
                serde_json::to_value(event)
                    .map_err(|_| RpcError::new(ErrorCode::Internal, "serialise"))
            }
            Canonical::Encrypt {
                op,
                peer,
                plaintext,
            } => {
                let out = if *op == Operation::Nip44Encrypt {
                    identity.nip44_encrypt(peer, plaintext, limits)
                } else {
                    identity.nip04_encrypt(peer, plaintext, limits)
                };
                out.map(Value::String).map_err(bad)
            }
            Canonical::Decrypt { op, peer, payload } => {
                let out = if *op == Operation::Nip44Decrypt {
                    identity.nip44_decrypt(peer, payload, limits)
                } else {
                    identity.nip04_decrypt(peer, payload, limits)
                };
                out.map(|p| Value::String(p.to_string())).map_err(bad)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn client() -> Pubkey32 {
        Pubkey32::from_bytes([1; 32])
    }

    #[test]
    fn digest_changes_with_every_input() {
        let l = Limits::default();
        let acct = Identity::generate().pubkey_hex();
        let a = Canonical::sign(json!({"kind":1,"content":"a","created_at":5}), &acct, &l).unwrap();
        let b = Canonical::sign(json!({"kind":1,"content":"b","created_at":5}), &acct, &l).unwrap();
        let k = Canonical::sign(json!({"kind":2,"content":"a","created_at":5}), &acct, &l).unwrap();
        let acct32: Pubkey32 = acct.parse().unwrap();
        let da = a.digest(&client(), Some(&acct32));
        assert_eq!(da, a.digest(&client(), Some(&acct32)), "deterministic");
        assert_ne!(da, b.digest(&client(), Some(&acct32)), "content");
        assert_ne!(da, k.digest(&client(), Some(&acct32)), "kind");
        assert_ne!(
            da,
            a.digest(&Pubkey32::from_bytes([2; 32]), Some(&acct32)),
            "client"
        );
        assert_ne!(da, a.digest(&client(), None), "account");
    }

    #[test]
    fn sign_rejects_foreign_pubkey_and_bad_templates() {
        let l = Limits::default();
        let me = Identity::generate().pubkey_hex();
        let other = Identity::generate().pubkey_hex();
        assert!(Canonical::sign(json!({"kind":1,"pubkey":other}), &me, &l).is_err());
        assert!(Canonical::sign(json!({"kind":1,"pubkey":me.to_uppercase()}), &me, &l).is_ok());
        assert!(Canonical::sign(json!({"kind":70000}), &me, &l).is_err());
        assert!(Canonical::sign(json!({"kind":1,"sig":"00"}), &me, &l).is_err());
        assert!(Canonical::sign(json!("not an object"), &me, &l).is_err());
    }

    #[test]
    fn view_is_sanitised_and_flags_sensitive_kinds() {
        let l = Limits::default();
        let acct = Identity::generate().pubkey_hex();
        let c = Canonical::sign(
            json!({"kind":14,"content":"hi\u{202e}evil","tags":[["p","x\u{200b}y"]]}),
            &acct,
            &l,
        )
        .unwrap();
        let ident = ClientIdent {
            pubkey: client(),
            name: "n".into(),
            peer: None,
            via: "local".into(),
        };
        let v = c.view(1, "d".into(), ident, None, 0, 1);
        let ev = v.event.unwrap();
        assert!(ev.sensitive);
        assert!(ev.content.contains("⟦U+202E⟧") && !ev.content.contains('\u{202e}'));
        assert!(ev.tags[0][1].contains("⟦U+200B⟧"));
        assert!(!v.reveals_plaintext);
    }

    #[test]
    fn decrypt_views_are_flagged() {
        let l = Limits::default();
        let peer = Identity::generate().pubkey_hex();
        let c = Canonical::crypto(Operation::Nip04Decrypt, &peer, "x".into(), &l).unwrap();
        let ident = ClientIdent {
            pubkey: client(),
            name: "n".into(),
            peer: None,
            via: "local".into(),
        };
        let v = c.view(1, "d".into(), ident, None, 0, 1);
        assert!(v.legacy && v.reveals_plaintext);
        assert!(Canonical::crypto(Operation::Nip44Encrypt, "garbage", "x".into(), &l).is_err());
    }
}
