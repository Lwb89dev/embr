//! The client of the local signer API (`docs/LOCAL_SIGNER_API.md`).

use std::io::BufReader;
use std::path::PathBuf;
use std::time::Duration;

use embr_crypto::{Event, Identity};
use embr_ipc::codec::{read_line, write_line};
use embr_ipc::{
    ClientHello, ClientInfo, HelloBody, HelloReply, MAX_LINE_BYTES, PROTOCOL_VERSION, Request,
    Response, ServerHello, auth,
};
use serde_json::{Value, json};

use crate::ClientError;

#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
type Stream = std::fs::File;

/// Options for [`SignerClient::connect`].
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// Endpoint to use; defaults to the per-user signer socket (`EMBR_SIGNER_SOCKET` honoured).
    pub endpoint: Option<PathBuf>,
    /// Your app's self-declared name, shown to the user flagged as *unverified*.
    pub client_name: String,
    /// Socket read timeout. `None` waits indefinitely (the signer has its own request timeouts).
    pub read_timeout: Option<Duration>,
}

impl ConnectOptions {
    /// Defaults with the given app name.
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            endpoint: None,
            client_name: client_name.into(),
            read_timeout: None,
        }
    }
}

/// Result of [`SignerClient::pair`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairInfo {
    /// Whether the client is paired.
    pub paired: bool,
    /// The account's public key (hex) it was bound to.
    pub account: String,
}

/// A connected, authenticated session with the signer. Requests are sequential; for concurrent
/// requests open several connections.
pub struct SignerClient {
    reader: BufReader<Stream>,
    writer: Stream,
    next_id: u64,
    /// Opaque session id assigned by the signer.
    pub session: String,
    /// Whether the client key is paired (`None` if the vault is locked and the signer cannot tell).
    pub paired: Option<bool>,
    /// Whether the vault was locked at connection time.
    pub locked: bool,
    /// Signer version.
    pub server_version: String,
}

impl std::fmt::Debug for SignerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerClient")
            .field("session", &self.session)
            .field("paired", &self.paired)
            .finish()
    }
}

impl SignerClient {
    /// Connects, performs the handshake and proves possession of `identity` (the client key).
    pub fn connect(identity: &Identity, opts: ConnectOptions) -> Result<Self, ClientError> {
        #[cfg(not(unix))]
        {
            let _ = (identity, opts);
            Err(ClientError::Unsupported)
        }
        #[cfg(unix)]
        {
            let path = opts
                .endpoint
                .clone()
                .unwrap_or_else(embr_platform::paths::signer_socket);
            if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                // Refuse to talk to a socket in a directory someone else could have prepared.
                embr_platform::paths::verify_private_dir(dir).map_err(ClientError::Connect)?;
            }
            let stream = Stream::connect(&path).map_err(ClientError::Connect)?;
            stream.set_read_timeout(opts.read_timeout)?;
            Self::handshake(stream, identity, &opts.client_name)
        }
    }

    /// Runs the handshake over an already-connected stream (used by tests and launchers that pass
    /// a pre-connected descriptor).
    #[cfg(unix)]
    pub fn handshake(stream: Stream, identity: &Identity, name: &str) -> Result<Self, ClientError> {
        let writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let mut writer = writer;

        let line = read_line(&mut reader, MAX_LINE_BYTES)?
            .ok_or_else(|| ClientError::Protocol("signer closed the connection".into()))?;
        let hello: ServerHello = serde_json::from_str(&line)
            .map_err(|_| ClientError::Protocol("bad server hello".into()))?;
        if !hello.protocol.contains(&PROTOCOL_VERSION) {
            return Err(ClientError::Protocol(format!(
                "signer speaks protocol {:?}, this SDK speaks {PROTOCOL_VERSION}",
                hello.protocol
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let proof = auth::make_proof(identity, &hello.nonce, now)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        let reply = ClientHello {
            hello: HelloBody {
                protocol: PROTOCOL_VERSION,
                client: ClientInfo {
                    name: name.to_owned(),
                    pubkey: identity.pubkey_hex(),
                },
                proof,
            },
        };
        write_line(&mut writer, &reply, MAX_LINE_BYTES)?;
        let line = read_line(&mut reader, MAX_LINE_BYTES)?
            .ok_or_else(|| ClientError::Protocol("signer closed the connection".into()))?;
        let ok: HelloReply = serde_json::from_str(&line)
            .map_err(|_| ClientError::Protocol("bad hello reply".into()))?;
        if !ok.ok {
            return Err(match ok.error {
                Some(e) => ClientError::Rpc(e),
                None => ClientError::Protocol("handshake refused".into()),
            });
        }
        Ok(Self {
            reader,
            writer,
            next_id: 1,
            session: ok.session.unwrap_or_default(),
            paired: ok.paired,
            locked: ok.locked,
            server_version: hello.version,
        })
    }

    /// Sends one request and waits for its response.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        self.call_with_timeout(method, params, None)
    }

    /// Like [`SignerClient::call`] with a per-request timeout (milliseconds) the signer enforces.
    pub fn call_with_timeout(
        &mut self,
        method: &str,
        params: Value,
        timeout_ms: Option<u64>,
    ) -> Result<Value, ClientError> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let req = Request {
            id: id.clone(),
            method: method.to_owned(),
            params,
            timeout_ms,
        };
        write_line(&mut self.writer, &req, MAX_LINE_BYTES)?;
        let resp = self.read_response()?;
        if resp.id != id {
            return Err(ClientError::Protocol(format!(
                "response id {:?} does not match request {id:?}",
                resp.id
            )));
        }
        Ok(resp.into_result()?)
    }

    /// Sends a raw line (for protocol tests and advanced use).
    pub fn send_raw(&mut self, line: &str) -> Result<(), ClientError> {
        use std::io::Write;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    /// Reads one response line.
    pub fn read_response(&mut self) -> Result<Response, ClientError> {
        let line = read_line(&mut self.reader, MAX_LINE_BYTES)?
            .ok_or_else(|| ClientError::Protocol("signer closed the connection".into()))?;
        serde_json::from_str(&line).map_err(|_| ClientError::Protocol("bad response".into()))
    }

    /// Liveness check.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        self.call("ping", json!({})).map(|_| ())
    }

    /// Requests pairing (`connect`). The first time, the user approves this app inside Embr.
    pub fn pair(
        &mut self,
        permissions: &[&str],
        label: Option<&str>,
    ) -> Result<PairInfo, ClientError> {
        let v = self.call(
            "connect",
            json!({"permissions": permissions, "label": label}),
        )?;
        let paired = v.get("paired").and_then(Value::as_bool).unwrap_or(false);
        let account = v
            .get("account")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.paired = Some(paired);
        Ok(PairInfo { paired, account })
    }

    /// Returns the public key (hex) of the account — "log in". Triggers pairing for a new client.
    pub fn get_public_key(&mut self, account: Option<&str>) -> Result<String, ClientError> {
        let v = self.call("get_public_key", json!({"account": account}))?;
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| ClientError::Protocol("expected a string".into()))
    }

    /// Accounts this client may use.
    pub fn list_accounts(&mut self) -> Result<Vec<Value>, ClientError> {
        match self.call("list_accounts", json!({}))? {
            Value::Array(a) => Ok(a),
            _ => Err(ClientError::Protocol("expected an array".into())),
        }
    }

    /// Signs an unsigned event (`kind`, `content`, `tags`, `created_at?`).
    pub fn sign_event(
        &mut self,
        event: &Value,
        account: Option<&str>,
    ) -> Result<Event, ClientError> {
        let v = self.call("sign_event", json!({"account": account, "event": event}))?;
        serde_json::from_value(v)
            .map_err(|_| ClientError::Protocol("signer returned a malformed event".into()))
    }

    /// NIP-44 encryption (preferred).
    pub fn nip44_encrypt(
        &mut self,
        peer: &str,
        plaintext: &str,
        account: Option<&str>,
    ) -> Result<String, ClientError> {
        self.string_call(
            "nip44_encrypt",
            json!({"account": account, "peer": peer, "plaintext": plaintext}),
        )
    }

    /// NIP-44 decryption. Returns private plaintext: the user must approve (separate permission).
    pub fn nip44_decrypt(
        &mut self,
        peer: &str,
        payload: &str,
        account: Option<&str>,
    ) -> Result<String, ClientError> {
        self.string_call(
            "nip44_decrypt",
            json!({"account": account, "peer": peer, "payload": payload}),
        )
    }

    /// **Legacy** NIP-04 encryption.
    pub fn nip04_encrypt(
        &mut self,
        peer: &str,
        plaintext: &str,
        account: Option<&str>,
    ) -> Result<String, ClientError> {
        self.string_call(
            "nip04_encrypt",
            json!({"account": account, "peer": peer, "plaintext": plaintext}),
        )
    }

    /// **Legacy** NIP-04 decryption.
    pub fn nip04_decrypt(
        &mut self,
        peer: &str,
        payload: &str,
        account: Option<&str>,
    ) -> Result<String, ClientError> {
        self.string_call(
            "nip04_decrypt",
            json!({"account": account, "peer": peer, "payload": payload}),
        )
    }

    /// Forgets this client's pairing in the signer.
    pub fn revoke_self(&mut self) -> Result<(), ClientError> {
        self.call("revoke_self", json!({})).map(|_| ())
    }

    fn string_call(&mut self, method: &str, params: Value) -> Result<String, ClientError> {
        let v = self.call(method, params)?;
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| ClientError::Protocol("expected a string".into()))
    }
}
