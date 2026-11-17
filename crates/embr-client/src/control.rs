//! Client of the privileged **control channel** (used by `embrctl` and the GUI).
//!
//! Notifications (`pending_added`, `locked`, …) can arrive between responses; they are queued and
//! returned by [`ControlClient::next_event`].

use std::collections::VecDeque;
use std::io::BufReader;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use embr_ipc::codec::{read_line, write_line};
use embr_ipc::control::{
    ControlEvent, ControlHello, DecideParams, DecisionWire, PendingView, ScopeWire, StatusView,
};
use embr_ipc::{MAX_LINE_BYTES, Request, Response};
use serde_json::{Value, json};

use crate::ClientError;

type Stream = crate::transport::Stream;

/// A connection to the control channel.
pub struct ControlClient {
    reader: BufReader<Stream>,
    writer: Stream,
    next_id: u64,
    events: VecDeque<ControlEvent>,
    /// The hello the daemon sent on connect (includes a status snapshot).
    pub hello: ControlHello,
    /// Control token obtained by unlocking/creating/authenticating; keep it in memory only.
    pub token: Option<String>,
}

impl ControlClient {
    /// Connects to `endpoint` (default: the per-user control socket).
    pub fn connect(endpoint: Option<PathBuf>) -> Result<Self, ClientError> {
        let path = endpoint.unwrap_or_else(embr_platform::paths::control_socket);
        let stream = crate::transport::connect(&path)?;
        let writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let line = read_line(&mut reader, MAX_LINE_BYTES)?
            .ok_or_else(|| ClientError::Protocol("daemon closed the connection".into()))?;
        let hello: ControlHello = serde_json::from_str(&line)
            .map_err(|_| ClientError::Protocol("bad control hello".into()))?;
        Ok(Self {
            reader,
            writer,
            next_id: 1,
            events: VecDeque::new(),
            hello,
            token: None,
        })
    }

    /// Sets the read timeout of the underlying socket.
    #[cfg(unix)]
    pub fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.reader.get_ref().set_read_timeout(t)
    }

    /// Sends a request and waits for its response, queueing any events that arrive meanwhile.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let req = Request {
            id: id.clone(),
            method: method.to_owned(),
            params,
            timeout_ms: None,
        };
        write_line(&mut self.writer, &req, MAX_LINE_BYTES)?;
        loop {
            let line = read_line(&mut self.reader, MAX_LINE_BYTES)?
                .ok_or_else(|| ClientError::Protocol("daemon closed the connection".into()))?;
            let v: Value = serde_json::from_str(&line)
                .map_err(|_| ClientError::Protocol("bad line".into()))?;
            if v.get("event").is_some() {
                if let Ok(ev) = serde_json::from_value::<ControlEvent>(v) {
                    self.events.push_back(ev);
                }
                continue;
            }
            let resp: Response = serde_json::from_value(v)
                .map_err(|_| ClientError::Protocol("bad response".into()))?;
            if resp.id != id {
                return Err(ClientError::Protocol("response id mismatch".into()));
            }
            return Ok(resp.into_result()?);
        }
    }

    /// The next notification: a queued one, or the next line from the daemon (blocking, subject to
    /// the read timeout). `Ok(None)` on timeout.
    pub fn next_event(&mut self) -> Result<Option<ControlEvent>, ClientError> {
        if let Some(e) = self.events.pop_front() {
            return Ok(Some(e));
        }
        match read_line(&mut self.reader, MAX_LINE_BYTES) {
            Ok(Some(line)) => {
                let v: Value = serde_json::from_str(&line)
                    .map_err(|_| ClientError::Protocol("bad line".into()))?;
                Ok(serde_json::from_value::<ControlEvent>(v).ok())
            }
            Ok(None) => Err(ClientError::Protocol("daemon closed the connection".into())),
            Err(embr_ipc::codec::CodecError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn token_call(&mut self, method: &str, params: Value) -> Result<String, ClientError> {
        let v = self.call(method, params)?;
        let t = v
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::Protocol("no token in reply".into()))?
            .to_owned();
        self.token = Some(t.clone());
        Ok(t)
    }

    /// Unlocks the vault (or re-authenticates if it is already unlocked). Returns the token.
    pub fn unlock(&mut self, password: &str) -> Result<String, ClientError> {
        self.token_call("unlock", json!({"password": password}))
    }

    /// Creates the vault and unlocks it. Returns the token.
    pub fn create_vault(&mut self, password: &str) -> Result<String, ClientError> {
        self.token_call("create_vault", json!({"password": password}))
    }

    /// Authenticates this connection with a previously issued token.
    pub fn authenticate(&mut self, token: &str) -> Result<(), ClientError> {
        self.call("auth", json!({"token": token})).map(|_| ())?;
        self.token = Some(token.to_owned());
        Ok(())
    }

    /// Daemon status.
    pub fn status(&mut self) -> Result<StatusView, ClientError> {
        let v = self.call("status", json!({}))?;
        serde_json::from_value(v).map_err(|_| ClientError::Protocol("bad status".into()))
    }

    /// Pending approval requests.
    pub fn pending(&mut self) -> Result<Vec<PendingView>, ClientError> {
        let v = self.call("list_pending", json!({}))?;
        serde_json::from_value(v).map_err(|_| ClientError::Protocol("bad pending list".into()))
    }

    /// Answers a pending request. `view` is the request the user actually looked at (its digest is
    /// echoed so a different request can never be approved by mistake).
    pub fn decide(
        &mut self,
        view: &PendingView,
        decision: DecisionWire,
        scope: Option<ScopeWire>,
    ) -> Result<Value, ClientError> {
        let params = DecideParams {
            id: view.id,
            digest: view.digest.clone(),
            decision,
            scope,
        };
        self.call(
            "decide",
            serde_json::to_value(params).map_err(|e| ClientError::Crypto(e.to_string()))?,
        )
    }

    /// Starts receiving notifications.
    pub fn subscribe(&mut self) -> Result<(), ClientError> {
        self.call("subscribe", json!({})).map(|_| ())
    }
}
