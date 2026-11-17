//! Message shapes of the client API. All incoming types use `deny_unknown_fields`: nothing the
//! user was not shown can ride along in a request.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ErrorCode, RpcError};

/// Methods of the client API, in the order advertised in the handshake.
pub const METHODS: [&str; 11] = [
    "connect",
    "get_public_key",
    "list_accounts",
    "sign_event",
    "nip44_encrypt",
    "nip44_decrypt",
    "nip04_encrypt",
    "nip04_decrypt",
    "ping",
    "cancel",
    "revoke_self",
];

/// First line sent by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    /// Protocol major version marker (always the protocol version).
    pub embr: u32,
    /// Product name.
    pub name: String,
    /// Daemon version.
    pub version: String,
    /// Supported protocol versions.
    pub protocol: Vec<u32>,
    /// Supported methods.
    pub methods: Vec<String>,
    /// Fresh per-connection nonce (64 hex characters).
    pub nonce: String,
}

/// Client's reply to the [`ServerHello`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    /// The hello body.
    pub hello: HelloBody,
}

/// Body of a [`ClientHello`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloBody {
    /// Protocol version the client speaks.
    pub protocol: u32,
    /// Who the client claims to be.
    pub client: ClientInfo,
    /// Proof of possession of the client key: a signed event, see [`crate::auth`].
    pub proof: Value,
}

/// Client identity: a self-declared label and the public key that is its real identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInfo {
    /// Self-declared label (untrusted).
    pub name: String,
    /// Client public key, 64 hex characters.
    pub pubkey: String,
}

/// Server's answer to a [`ClientHello`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloReply {
    /// `true` if the handshake succeeded.
    pub ok: bool,
    /// Opaque session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Whether the client key is paired; `None` while the vault is locked (unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<bool>,
    /// Whether the vault is currently locked.
    #[serde(default)]
    pub locked: bool,
    /// Error, if `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A request line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Client-chosen id, unique within the session.
    pub id: String,
    /// Method name.
    pub method: String,
    /// Parameters (object); defaults to `{}`.
    #[serde(default = "empty_object")]
    pub params: Value,
    /// Optional per-request timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

/// A response line. Both `result` and `error` are always present (one of them `null`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// Echo of the request id.
    pub id: String,
    /// Result on success.
    pub result: Option<Value>,
    /// Error on failure.
    pub error: Option<RpcError>,
}

impl Response {
    /// A success response.
    pub fn ok(id: impl Into<String>, result: Value) -> Self {
        Self {
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    /// An error response.
    pub fn err(id: impl Into<String>, error: RpcError) -> Self {
        Self {
            id: id.into(),
            result: None,
            error: Some(error),
        }
    }

    /// Converts into a `Result`, as a client wants it.
    pub fn into_result(self) -> Result<Value, RpcError> {
        match (self.result, self.error) {
            (_, Some(e)) => Err(e),
            (Some(v), None) => Ok(v),
            (None, None) => Ok(Value::Null),
        }
    }
}

/// Validates a request id: 1–64 printable ASCII characters.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= crate::MAX_ID_LEN
        && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

// ---- typed parameters ------------------------------------------------------------------

/// `connect`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectParams {
    /// Permissions the client would like (a request, never a grant): `"sign_event:1"`, `"nip44_encrypt"`, …
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Optional label overriding the hello's name (untrusted).
    #[serde(default)]
    pub label: Option<String>,
}

/// Methods taking only an optional account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountParams {
    /// Account as hex pubkey or `npub1…`; defaults to the client's default account.
    #[serde(default)]
    pub account: Option<String>,
}

/// `sign_event`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignEventParams {
    /// Account selector.
    #[serde(default)]
    pub account: Option<String>,
    /// The unsigned event (`kind`, `content`, `tags`, `created_at?`).
    pub event: Value,
}

/// `nip44_encrypt` / `nip04_encrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptParams {
    /// Account selector.
    #[serde(default)]
    pub account: Option<String>,
    /// Peer public key (hex or `npub1…`).
    pub peer: String,
    /// Text to encrypt.
    pub plaintext: String,
}

/// `nip44_decrypt` / `nip04_decrypt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptParams {
    /// Account selector.
    #[serde(default)]
    pub account: Option<String>,
    /// Peer public key (hex or `npub1…`).
    pub peer: String,
    /// Ciphertext payload.
    pub payload: String,
}

/// `cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelParams {
    /// Id of the pending request to withdraw.
    pub id: String,
}

/// Parses typed params, mapping failures to `invalid_params`.
///
/// `params` must be a JSON **object**. (serde would also build a struct from an array of
/// positional values; accepting that would make the accepted syntax ambiguous.)
pub fn parse_params<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    if !params.is_object() {
        return Err(RpcError::new(
            ErrorCode::InvalidParams,
            "params must be a JSON object",
        ));
    }
    serde_json::from_value(params)
        .map_err(|e| RpcError::new(ErrorCode::InvalidParams, format!("bad parameters: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_and_strictness() {
        let r: Request = serde_json::from_str(r#"{"id":"1","method":"ping"}"#).unwrap();
        assert_eq!(r.params, serde_json::json!({}));
        assert!(
            serde_json::from_str::<Request>(r#"{"id":"1","method":"ping","extra":1}"#).is_err()
        );
        assert!(serde_json::from_str::<Request>(r#"{"method":"ping"}"#).is_err());
        assert!(
            serde_json::from_str::<Request>(r#"{"id":1,"method":"ping"}"#).is_err(),
            "numeric ids are not accepted"
        );
    }

    #[test]
    fn id_validation() {
        assert!(valid_id("1"));
        assert!(valid_id("req-7_a.b"));
        assert!(!valid_id(""));
        assert!(!valid_id(&"x".repeat(65)));
        assert!(!valid_id("has space"));
        assert!(!valid_id("tab\t"));
        assert!(!valid_id("ünï"));
    }

    #[test]
    fn response_always_has_both_fields() {
        let ok = serde_json::to_string(&Response::ok("1", serde_json::json!("pong"))).unwrap();
        assert_eq!(ok, r#"{"id":"1","result":"pong","error":null}"#);
        let err =
            serde_json::to_string(&Response::err("2", RpcError::new(ErrorCode::Denied, "no")))
                .unwrap();
        assert!(
            err.starts_with(r#"{"id":"2","result":null,"error":{"code":5,"name":"denied""#),
            "{err}"
        );
    }

    #[test]
    fn params_reject_unknown_and_missing_fields() {
        assert!(
            parse_params::<EncryptParams>(serde_json::json!({"peer":"x","plaintext":"y"})).is_ok()
        );
        assert!(parse_params::<EncryptParams>(serde_json::json!({"peer":"x"})).is_err());
        assert!(
            parse_params::<EncryptParams>(
                serde_json::json!({"peer":"x","plaintext":"y","admin":true})
            )
            .is_err()
        );
        assert!(parse_params::<AccountParams>(serde_json::json!([])).is_err());
    }
}
