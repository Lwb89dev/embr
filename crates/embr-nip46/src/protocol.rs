//! NIP-46 messages: JSON-RPC carried in NIP-44-encrypted kind-24133 events.
//!
//! * A **request** is an event from the *client's* key, `p`-tagged with the signer's transport
//!   public key, whose `content` is NIP-44 ciphertext of `{"id","method","params":[strings]}`.
//! * A **response** is an event from the *signer's transport key*, `p`-tagged with the client's
//!   key, whose content is NIP-44 ciphertext of `{"id","result"?,"error"?}`.
//!
//! The transport key is *not* the user's key (NIP-46's "remote-signer-pubkey"). Every inbound
//! event is verified (id and signature) and checked for kind and `p` tag **before** any
//! decryption is attempted.

use embr_crypto::{Event, EventTemplate, Identity, Limits, PublicKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Event kind of NIP-46 messages.
pub const KIND: u16 = 24133;

/// Protocol-level errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    /// The event is not a well-formed NIP-46 message for this signer.
    #[error("not a valid NIP-46 event for this signer")]
    NotForUs,
    /// Id or signature invalid.
    #[error("invalid event signature")]
    BadSignature,
    /// Decryption failed.
    #[error("cannot decrypt")]
    Decrypt,
    /// The decrypted JSON is not a valid request/response.
    #[error("malformed JSON-RPC message")]
    Malformed,
    /// Encryption/signing failed.
    #[error("cannot build the event")]
    Build,
}

/// A JSON-RPC request. Strict: unknown fields are rejected, params must be strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    /// Client-chosen id (echoed in the response).
    pub id: String,
    /// Method name.
    pub method: String,
    /// Positional string parameters.
    #[serde(default)]
    pub params: Vec<String>,
}

/// A JSON-RPC response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse {
    /// Echo of the request id.
    pub id: String,
    /// Result string on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Error text on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Maximum ids length accepted.
pub const MAX_ID: usize = 128;
/// Maximum parameters per request.
pub const MAX_PARAMS: usize = 8;

impl RpcRequest {
    fn validate(self) -> Result<Self, ProtoError> {
        if self.id.is_empty()
            || self.id.len() > MAX_ID
            || self.method.len() > 64
            || self.params.len() > MAX_PARAMS
        {
            return Err(ProtoError::Malformed);
        }
        Ok(self)
    }
}

/// Returns the `p`-tag values of an event.
fn p_tags(event: &Event) -> impl Iterator<Item = &str> {
    event.tags.iter().filter_map(|t| match t.as_slice() {
        [k, v, ..] if k == "p" => Some(v.as_str()),
        _ => None,
    })
}

/// The signer pubkey (hex) an inbound event is addressed to, if it has exactly one `p` tag.
pub fn addressed_to(event: &Event) -> Option<String> {
    let mut it = p_tags(event);
    let first = it.next()?;
    it.next().is_none().then(|| first.to_owned())
}

/// Verifies and opens an inbound request addressed to `signer`. Returns the client public key and
/// the parsed request.
pub fn open_request(
    signer: &Identity,
    event: &Event,
    limits: &Limits,
) -> Result<(PublicKey, RpcRequest), ProtoError> {
    if event.kind.as_u16() != KIND
        || addressed_to(event).as_deref() != Some(signer.pubkey_hex().as_str())
    {
        return Err(ProtoError::NotForUs);
    }
    event.verify().map_err(|_| ProtoError::BadSignature)?;
    let plain: Zeroizing<String> = signer
        .nip44_decrypt(&event.pubkey, &event.content, limits)
        .map_err(|_| ProtoError::Decrypt)?;
    let req: RpcRequest = serde_json::from_str(&plain).map_err(|_| ProtoError::Malformed)?;
    Ok((event.pubkey, req.validate()?))
}

/// Builds a signed response (or any signer→client message) event.
pub fn seal(
    signer: &Identity,
    client: &PublicKey,
    payload: &str,
    created_at: u64,
    limits: &Limits,
) -> Result<Event, ProtoError> {
    let content = signer
        .nip44_encrypt(client, payload, limits)
        .map_err(|_| ProtoError::Build)?;
    let tpl = EventTemplate {
        kind: KIND,
        content,
        tags: vec![vec!["p".into(), client.to_hex()]],
        created_at: Some(created_at),
        pubkey: None,
        id: None,
    };
    signer
        .sign_event(&tpl, limits)
        .map_err(|_| ProtoError::Build)
}

/// Opens a response event addressed to `client` (used by tests and the client side).
pub fn open_response(
    client: &Identity,
    event: &Event,
    limits: &Limits,
) -> Result<RpcResponse, ProtoError> {
    if event.kind.as_u16() != KIND
        || addressed_to(event).as_deref() != Some(client.pubkey_hex().as_str())
    {
        return Err(ProtoError::NotForUs);
    }
    event.verify().map_err(|_| ProtoError::BadSignature)?;
    let plain = client
        .nip44_decrypt(&event.pubkey, &event.content, limits)
        .map_err(|_| ProtoError::Decrypt)?;
    serde_json::from_str(&plain).map_err(|_| ProtoError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn request_event(client: &Identity, signer: &Identity, json: &str) -> Event {
        seal(client, &signer.public_key(), json, NOW, &Limits::default()).unwrap()
    }

    #[test]
    fn request_response_roundtrip() {
        let (client, signer) = (Identity::generate(), Identity::generate());
        let l = Limits::default();
        let ev = request_event(
            &client,
            &signer,
            r#"{"id":"1","method":"get_public_key","params":[]}"#,
        );
        assert_eq!(ev.kind.as_u16(), KIND);
        let (cpk, req) = open_request(&signer, &ev, &l).unwrap();
        assert_eq!(cpk, client.public_key());
        assert_eq!(
            (req.id.as_str(), req.method.as_str(), req.params.len()),
            ("1", "get_public_key", 0)
        );

        let resp = RpcResponse {
            id: "1".into(),
            result: Some("abc".into()),
            error: None,
        };
        let rev = seal(
            &signer,
            &cpk,
            &serde_json::to_string(&resp).unwrap(),
            NOW,
            &l,
        )
        .unwrap();
        assert_eq!(
            rev.pubkey,
            signer.public_key(),
            "responses are signed by the transport key"
        );
        assert_eq!(open_response(&client, &rev, &l).unwrap(), resp);
    }

    #[test]
    fn ciphertext_is_not_readable_by_third_parties_or_relays() {
        let (client, signer, spy) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let ev = request_event(
            &client,
            &signer,
            r#"{"id":"1","method":"ping","params":[]}"#,
        );
        assert!(!ev.content.contains("ping"));
        assert_eq!(
            open_request(&spy, &ev, &Limits::default()),
            Err(ProtoError::NotForUs),
            "not addressed to the spy"
        );
    }

    #[test]
    fn events_for_another_signer_or_with_extra_p_tags_are_refused() {
        let (client, signer, other) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let l = Limits::default();
        let ev = request_event(&client, &other, r#"{"id":"1","method":"ping","params":[]}"#);
        assert_eq!(open_request(&signer, &ev, &l), Err(ProtoError::NotForUs));
        // Two p tags: ambiguous addressing, refused.
        let content = client
            .nip44_encrypt(&signer.public_key(), r#"{"id":"1","method":"ping"}"#, &l)
            .unwrap();
        let tpl = EventTemplate {
            kind: KIND,
            content,
            tags: vec![
                vec!["p".into(), signer.pubkey_hex()],
                vec!["p".into(), other.pubkey_hex()],
            ],
            created_at: Some(NOW),
            pubkey: None,
            id: None,
        };
        let ev = client.sign_event(&tpl, &l).unwrap();
        assert_eq!(open_request(&signer, &ev, &l), Err(ProtoError::NotForUs));
    }

    #[test]
    fn wrong_kind_forged_signature_and_garbage_are_refused_before_or_at_decryption() {
        let (client, signer) = (Identity::generate(), Identity::generate());
        let l = Limits::default();
        let ev = request_event(
            &client,
            &signer,
            r#"{"id":"1","method":"ping","params":[]}"#,
        );
        // Tampered content: signature no longer matches.
        let mut j = serde_json::to_value(&ev).unwrap();
        j["content"] = "AAAA".into();
        let forged: Event = serde_json::from_value(j).unwrap();
        assert_eq!(
            open_request(&signer, &forged, &l),
            Err(ProtoError::BadSignature)
        );
        // Valid signature, content that is not NIP-44.
        let tpl = EventTemplate {
            kind: KIND,
            content: "not encrypted".into(),
            tags: vec![vec!["p".into(), signer.pubkey_hex()]],
            created_at: Some(NOW),
            pubkey: None,
            id: None,
        };
        let ev = client.sign_event(&tpl, &l).unwrap();
        assert_eq!(open_request(&signer, &ev, &l), Err(ProtoError::Decrypt));
        // Another kind.
        let tpl = EventTemplate {
            kind: 1,
            content: String::new(),
            tags: vec![vec!["p".into(), signer.pubkey_hex()]],
            created_at: Some(NOW),
            pubkey: None,
            id: None,
        };
        let ev = client.sign_event(&tpl, &l).unwrap();
        assert_eq!(open_request(&signer, &ev, &l), Err(ProtoError::NotForUs));
    }

    #[test]
    fn rpc_messages_are_strict() {
        let (client, signer) = (Identity::generate(), Identity::generate());
        let l = Limits::default();
        for bad in [
            r#"{"id":"1","method":"ping","params":[1]}"#,
            r#"{"id":"1","method":"ping","extra":true}"#,
            r#"{"method":"ping"}"#,
            r#"{"id":"","method":"ping"}"#,
            r#"[]"#,
            r#"{"id":"1","method":"ping","params":["a","b","c","d","e","f","g","h","i"]}"#,
        ] {
            let ev = request_event(&client, &signer, bad);
            assert_eq!(
                open_request(&signer, &ev, &l),
                Err(ProtoError::Malformed),
                "{bad}"
            );
        }
    }
}
