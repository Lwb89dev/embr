//! The authorization engine. See the crate documentation for the model.

use std::collections::BTreeSet;

use embr_core::{AccountId, Operation, Pubkey32};
use serde::{Deserialize, Serialize};

/// Event kinds whose signatures/plaintexts are direct messages or their envelopes (NIP-04 DMs,
/// NIP-59 seal, NIP-17 chat message, NIP-59 gift wrap). Signing them can never be *remembered*
/// by an allow grant — each one needs the user's attention (lesson from Omostrich).
pub const SENSITIVE_KINDS: [u16; 4] = [4, 13, 14, 1059];

/// Longest validity of a broad (any-kind) signing grant: 24 hours.
pub const MAX_BROAD_EXPIRY_SECS: u64 = 24 * 60 * 60;
/// Longest validity of a decrypt grant that is not restricted to one peer: 1 hour.
pub const MAX_UNSCOPED_DECRYPT_SECS: u64 = 60 * 60;
/// Maximum number of paired clients.
pub const MAX_CLIENTS: usize = 256;
/// Maximum number of stored grants.
pub const MAX_GRANTS: usize = 4096;
const MAX_NAME_CHARS: usize = 64;

/// Identifier of a connection/session. Session-scoped grants die with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub u64);

/// Identifier of a stored grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantId(pub u64);

/// Allow or deny.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Permit without asking.
    Allow,
    /// Refuse without asking.
    Deny,
}

/// Which event kinds a grant covers (meaningful for `sign_event` only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindScope {
    /// Every kind — except, for *allow* grants, the [`SENSITIVE_KINDS`].
    Any,
    /// Exactly this kind.
    Exact(u16),
}

/// When a grant stops applying.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expiry {
    /// Until the session (connection) that created it ends. Never persisted.
    Session(SessionId),
    /// Until this Unix time (seconds).
    Until(u64),
    /// Until revoked.
    Never,
}

/// One stored allow/deny rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Identifier.
    pub id: GrantId,
    /// Client the rule applies to.
    pub client: Pubkey32,
    /// Account the rule applies to.
    pub account: AccountId,
    /// Operation covered.
    pub op: Operation,
    /// Kinds covered.
    pub kind: KindScope,
    /// If set, only requests naming exactly this peer (encrypt/decrypt recipient/sender).
    pub peer: Option<Pubkey32>,
    /// Allow or deny.
    pub effect: Effect,
    /// Validity.
    pub expiry: Expiry,
    /// Remaining uses, if limited.
    pub uses_left: Option<u32>,
    /// Creation time (Unix seconds).
    pub created_at: u64,
}

/// A paired client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRecord {
    /// The client's public key (its identity).
    pub key: Pubkey32,
    /// Self-declared label — untrusted, shown flagged as such.
    pub name: String,
    /// Accounts this client may use; the first is its default.
    pub accounts: Vec<AccountId>,
    /// Pairing time.
    pub created_at: u64,
    /// Last request time.
    pub last_seen: u64,
}

/// What is being asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// Requesting client.
    pub client: Pubkey32,
    /// Target account (already resolved).
    pub account: AccountId,
    /// Operation.
    pub op: Operation,
    /// Event kind (for `sign_event`).
    pub kind: Option<u16>,
    /// Peer public key (for encrypt/decrypt).
    pub peer: Option<Pubkey32>,
}

/// Result of [`Engine::evaluate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed. `grant` is `None` for implicit allows (`get_public_key` of a bound account).
    Allow {
        /// The deciding grant, if any.
        grant: Option<GrantId>,
    },
    /// A stored deny rule applies.
    Deny {
        /// The deciding grant.
        grant: GrantId,
    },
    /// No rule: ask the user. **Never** an implicit allow.
    Ask,
    /// The client key is unknown.
    NotPaired,
    /// The client key was blocked by the user.
    Blocked,
    /// The client is paired, but not for this account.
    AccountNotGranted,
}

/// The user's answer to a prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Allow this request only; nothing is stored.
    AllowOnce,
    /// Allow matching requests until the client's session ends.
    AllowSession,
    /// Allow matching requests until the given Unix time.
    AllowUntil(u64),
    /// Allow matching requests until revoked (narrow scopes only).
    AllowPersistent,
    /// Reject this request only.
    RejectOnce,
    /// Reject matching requests from now on.
    AlwaysReject,
}

/// Scope of a remembered decision. Ignored for the `…Once` choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// Kinds covered.
    pub kind: KindScope,
    /// Restrict to one peer.
    pub peer: Option<Pubkey32>,
    /// Limit the number of uses.
    pub uses: Option<u32>,
}

impl Scope {
    /// The narrowest scope that covers `req`: its exact kind and peer.
    pub fn exact(req: &Request) -> Self {
        Self {
            kind: req.kind.map_or(KindScope::Any, KindScope::Exact),
            peer: req.peer,
            uses: None,
        }
    }
}

/// Outcome of [`Engine::decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Whether the *current* request may proceed.
    pub allow: bool,
    /// The grant that was created or refreshed, if the choice was remembered.
    pub grant: Option<GrantId>,
}

/// Errors from engine operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Unknown client.
    #[error("client is not paired")]
    NotPaired,
    /// Blocked client.
    #[error("client is blocked")]
    Blocked,
    /// The client is not bound to this account.
    #[error("account is not granted to this client")]
    AccountNotGranted,
    /// The choice is broader than allowed for this operation.
    #[error("refused: {0}")]
    TooBroad(&'static str),
    /// The scope does not cover the request it answers.
    #[error("the scope does not cover the request")]
    ScopeDoesNotCover,
    /// Expiry in the past.
    #[error("expiry is in the past")]
    InvalidExpiry,
    /// `uses` is zero.
    #[error("use limit must be at least 1")]
    InvalidUses,
    /// Too many grants stored.
    #[error("too many stored permissions")]
    TooManyGrants,
    /// Too many paired clients.
    #[error("too many paired clients")]
    TooManyClients,
    /// Persisted data failed validation.
    #[error("invalid stored policy: {0}")]
    InvalidPersisted(&'static str),
}

/// The part of the engine that is stored (inside the vault).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persisted {
    /// Format version.
    pub version: u32,
    /// Paired clients.
    pub clients: Vec<ClientRecord>,
    /// Blocked client keys.
    pub blocked: Vec<Pubkey32>,
    /// Non-session grants.
    pub grants: Vec<Grant>,
    /// Next grant id.
    pub next_grant: u64,
}

/// The authorization engine. See the crate docs.
#[derive(Debug, Default)]
pub struct Engine {
    clients: Vec<ClientRecord>,
    blocked: BTreeSet<Pubkey32>,
    grants: Vec<Grant>,
    next_grant: u64,
}

impl Engine {
    /// An empty engine: nothing paired, nothing granted.
    pub fn new() -> Self {
        Self::default()
    }

    // ===== pairing ======================================================================

    /// Pairs (or updates) a client bound to `accounts`. The first account is the default.
    pub fn pair(
        &mut self,
        key: Pubkey32,
        name: &str,
        accounts: Vec<AccountId>,
        now: u64,
    ) -> Result<(), PolicyError> {
        if self.blocked.contains(&key) {
            return Err(PolicyError::Blocked);
        }
        let name: String = name.chars().take(MAX_NAME_CHARS).collect();
        if let Some(c) = self.clients.iter_mut().find(|c| c.key == key) {
            c.name = name;
            c.accounts = accounts;
            c.last_seen = now;
            return Ok(());
        }
        if self.clients.len() >= MAX_CLIENTS {
            return Err(PolicyError::TooManyClients);
        }
        self.clients.push(ClientRecord {
            key,
            name,
            accounts,
            created_at: now,
            last_seen: now,
        });
        Ok(())
    }

    /// Records activity of a client.
    pub fn touch(&mut self, key: &Pubkey32, now: u64) {
        if let Some(c) = self.clients.iter_mut().find(|c| &c.key == key) {
            c.last_seen = now;
        }
    }

    /// A paired client, if known.
    pub fn client(&self, key: &Pubkey32) -> Option<&ClientRecord> {
        self.clients.iter().find(|c| &c.key == key)
    }

    /// All paired clients.
    pub fn clients(&self) -> &[ClientRecord] {
        &self.clients
    }

    /// `true` if the key was blocked.
    pub fn is_blocked(&self, key: &Pubkey32) -> bool {
        self.blocked.contains(key)
    }

    /// Forgets a client and all its grants (it may pair again).
    pub fn revoke_client(&mut self, key: &Pubkey32) -> bool {
        let before = self.clients.len();
        self.clients.retain(|c| &c.key != key);
        self.grants.retain(|g| &g.client != key);
        self.clients.len() != before
    }

    /// Forgets a client, its grants, and refuses it from now on ("always reject").
    pub fn block_client(&mut self, key: Pubkey32) {
        self.revoke_client(&key);
        self.blocked.insert(key);
    }

    /// Lifts a block.
    pub fn unblock_client(&mut self, key: &Pubkey32) -> bool {
        self.blocked.remove(key)
    }

    /// Removes an account everywhere (call when an account is deleted from the vault).
    pub fn remove_account(&mut self, account: AccountId) {
        self.grants.retain(|g| g.account != account);
        for c in &mut self.clients {
            c.accounts.retain(|a| *a != account);
        }
    }

    // ===== evaluation ===================================================================

    /// Decides what to do with `req` from the client's `session`. Consumes one use of a
    /// use-limited grant. Default-deny: no matching allow ⇒ [`Verdict::Ask`].
    pub fn evaluate(&mut self, req: &Request, session: SessionId, now: u64) -> Verdict {
        if self.blocked.contains(&req.client) {
            return Verdict::Blocked;
        }
        let Some(client) = self.clients.iter().find(|c| c.key == req.client) else {
            return Verdict::NotPaired;
        };
        if !client.accounts.contains(&req.account) {
            return Verdict::AccountNotGranted;
        }
        if req.op == Operation::GetPublicKey {
            return Verdict::Allow { grant: None };
        }

        let matching: Vec<usize> = self
            .grants
            .iter()
            .enumerate()
            .filter(|(_, g)| grant_matches(g, req, session, now))
            .map(|(i, _)| i)
            .collect();

        // A deny always beats an allow.
        if let Some(&i) = matching
            .iter()
            .find(|&&i| self.grants.get(i).is_some_and(|g| g.effect == Effect::Deny))
        {
            if let Some(g) = self.grants.get(i) {
                return Verdict::Deny { grant: g.id };
            }
        }
        if let Some(&i) = matching.first() {
            if let Some(g) = self.grants.get_mut(i) {
                let id = g.id;
                if let Some(n) = g.uses_left.as_mut() {
                    *n = n.saturating_sub(1);
                }
                if g.uses_left == Some(0) {
                    self.grants.remove(i);
                }
                return Verdict::Allow { grant: Some(id) };
            }
        }
        Verdict::Ask
    }

    // ===== decisions ====================================================================

    /// Checks that `choice`/`scope` is acceptable for `req` without changing anything.
    ///
    /// Rules (the "stricter defaults for sensitive operations" of the design):
    /// * the scope must cover the request it answers, and only `sign_event` has kinds;
    /// * signing kinds in [`SENSITIVE_KINDS`] (DMs, seals, gift wraps) can only be allowed *once* or
    ///   for the *session*;
    /// * an any-kind signing grant must expire (session, or ≤ 24 h) — never persistent;
    /// * decrypt grants not restricted to one peer: session, or ≤ 1 h;
    /// * every remembered allow needs a valid, future expiry and a non-zero use count.
    pub fn validate_choice(
        &self,
        req: &Request,
        choice: Choice,
        scope: &Scope,
        now: u64,
    ) -> Result<(), PolicyError> {
        if matches!(choice, Choice::AllowOnce | Choice::RejectOnce) {
            return Ok(());
        }
        match (req.op, scope.kind) {
            (Operation::SignEvent, KindScope::Exact(k)) if req.kind != Some(k) => {
                return Err(PolicyError::ScopeDoesNotCover);
            }
            (op, KindScope::Exact(_)) if op != Operation::SignEvent => {
                return Err(PolicyError::TooBroad("kinds only apply to sign_event"));
            }
            _ => {}
        }
        if let Some(p) = scope.peer {
            if req.peer != Some(p) {
                return Err(PolicyError::ScopeDoesNotCover);
            }
        }
        if scope.uses == Some(0) {
            return Err(PolicyError::InvalidUses);
        }
        if choice == Choice::AlwaysReject {
            return Ok(());
        }
        if req.op == Operation::GetPublicKey {
            return Err(PolicyError::TooBroad(
                "get_public_key is implicit for paired clients",
            ));
        }
        if let Choice::AllowUntil(t) = choice {
            if t <= now {
                return Err(PolicyError::InvalidExpiry);
            }
        }
        let remaining = match choice {
            Choice::AllowUntil(t) => Some(t.saturating_sub(now)),
            _ => None,
        };
        let session_only = choice == Choice::AllowSession;

        if req.op == Operation::SignEvent {
            let sensitive = match scope.kind {
                KindScope::Exact(k) => SENSITIVE_KINDS.contains(&k),
                KindScope::Any => false,
            };
            if sensitive && !session_only {
                return Err(PolicyError::TooBroad(
                    "direct-message kinds (4, 13, 14, 1059) can only be allowed once or for the session",
                ));
            }
            if scope.kind == KindScope::Any {
                match choice {
                    Choice::AllowPersistent => {
                        return Err(PolicyError::TooBroad(
                            "a persistent signing permission must name one event kind",
                        ));
                    }
                    Choice::AllowUntil(_) if remaining > Some(MAX_BROAD_EXPIRY_SECS) => {
                        return Err(PolicyError::TooBroad(
                            "an any-kind signing permission may last at most 24 hours",
                        ));
                    }
                    _ => {}
                }
            }
        }
        if req.op.reveals_plaintext() && scope.peer.is_none() && !session_only {
            match choice {
                Choice::AllowUntil(_) if remaining <= Some(MAX_UNSCOPED_DECRYPT_SECS) => {}
                _ => {
                    return Err(PolicyError::TooBroad(
                        "a decrypt permission not limited to one peer may last at most 1 hour",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Applies the user's answer: validates it, stores a grant if it is to be remembered, and says
    /// whether the current request may proceed.
    pub fn decide(
        &mut self,
        req: &Request,
        choice: Choice,
        scope: &Scope,
        session: SessionId,
        now: u64,
    ) -> Result<Decision, PolicyError> {
        if self.blocked.contains(&req.client) {
            return Err(PolicyError::Blocked);
        }
        let client = self.client(&req.client).ok_or(PolicyError::NotPaired)?;
        if !client.accounts.contains(&req.account) {
            return Err(PolicyError::AccountNotGranted);
        }
        self.validate_choice(req, choice, scope, now)?;

        let (effect, expiry) = match choice {
            Choice::AllowOnce => {
                return Ok(Decision {
                    allow: true,
                    grant: None,
                });
            }
            Choice::RejectOnce => {
                return Ok(Decision {
                    allow: false,
                    grant: None,
                });
            }
            Choice::AllowSession => (Effect::Allow, Expiry::Session(session)),
            Choice::AllowUntil(t) => (Effect::Allow, Expiry::Until(t)),
            Choice::AllowPersistent => (Effect::Allow, Expiry::Never),
            Choice::AlwaysReject => (Effect::Deny, Expiry::Never),
        };
        self.purge_expired(now);

        // Refresh an identical rule instead of piling up duplicates.
        if let Some(g) = self.grants.iter_mut().find(|g| {
            g.client == req.client
                && g.account == req.account
                && g.op == req.op
                && g.kind == scope.kind
                && g.peer == scope.peer
                && g.effect == effect
        }) {
            g.expiry = expiry;
            g.uses_left = scope.uses;
            return Ok(Decision {
                allow: effect == Effect::Allow,
                grant: Some(g.id),
            });
        }
        if self.grants.len() >= MAX_GRANTS {
            return Err(PolicyError::TooManyGrants);
        }
        let id = GrantId(self.next_grant);
        self.next_grant += 1;
        self.grants.push(Grant {
            id,
            client: req.client,
            account: req.account,
            op: req.op,
            kind: scope.kind,
            peer: scope.peer,
            effect,
            expiry,
            uses_left: scope.uses,
            created_at: now,
        });
        Ok(Decision {
            allow: effect == Effect::Allow,
            grant: Some(id),
        })
    }

    // ===== maintenance ==================================================================

    /// All stored grants.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Revokes one grant.
    pub fn revoke_grant(&mut self, id: GrantId) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.id != id);
        self.grants.len() != before
    }

    /// Drops all grants tied to a finished session. Returns how many were removed.
    pub fn end_session(&mut self, session: SessionId) -> usize {
        let before = self.grants.len();
        self.grants.retain(|g| g.expiry != Expiry::Session(session));
        before - self.grants.len()
    }

    /// Drops expired time-limited grants. Returns how many were removed.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|g| !matches!(g.expiry, Expiry::Until(t) if t <= now));
        before - self.grants.len()
    }

    // ===== persistence ==================================================================

    /// The persistent part (session grants are excluded).
    pub fn persisted(&self) -> Persisted {
        Persisted {
            version: 1,
            clients: self.clients.clone(),
            blocked: self.blocked.iter().copied().collect(),
            grants: self
                .grants
                .iter()
                .filter(|g| !matches!(g.expiry, Expiry::Session(_)))
                .cloned()
                .collect(),
            next_grant: self.next_grant,
        }
    }

    /// Rebuilds an engine from stored data, validating it and dropping expired grants and grants
    /// that reference unknown clients.
    pub fn from_persisted(p: Persisted, now: u64) -> Result<Self, PolicyError> {
        if p.version != 1 {
            return Err(PolicyError::InvalidPersisted("unsupported version"));
        }
        if p.clients.len() > MAX_CLIENTS || p.grants.len() > MAX_GRANTS {
            return Err(PolicyError::InvalidPersisted("too many entries"));
        }
        let mut e = Engine {
            clients: p.clients,
            blocked: p.blocked.into_iter().collect(),
            grants: Vec::new(),
            next_grant: p.next_grant,
        };
        for g in p.grants {
            if matches!(g.expiry, Expiry::Session(_)) || g.uses_left == Some(0) {
                continue;
            }
            if matches!(g.expiry, Expiry::Until(t) if t <= now) {
                continue;
            }
            if !e.clients.iter().any(|c| c.key == g.client) {
                continue;
            }
            if g.id.0 >= e.next_grant {
                e.next_grant = g.id.0 + 1;
            }
            e.grants.push(g);
        }
        Ok(e)
    }

    /// Serialises the persistent part as JSON.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.persisted()).unwrap_or_default()
    }

    /// Parses [`Engine::to_json`] output.
    pub fn from_json(bytes: &[u8], now: u64) -> Result<Self, PolicyError> {
        let p: Persisted = serde_json::from_slice(bytes)
            .map_err(|_| PolicyError::InvalidPersisted("not valid policy JSON"))?;
        Self::from_persisted(p, now)
    }
}

fn grant_matches(g: &Grant, req: &Request, session: SessionId, now: u64) -> bool {
    if g.client != req.client || g.account != req.account || g.op != req.op {
        return false;
    }
    match g.expiry {
        Expiry::Session(s) if s != session => return false,
        Expiry::Until(t) if t <= now => return false,
        _ => {}
    }
    if g.peer.is_some() && g.peer != req.peer {
        return false;
    }
    match g.kind {
        KindScope::Exact(k) => req.kind == Some(k),
        // An any-kind *allow* never covers the sensitive kinds, even if one slipped into storage.
        KindScope::Any => {
            g.effect == Effect::Deny || !req.kind.is_some_and(|k| SENSITIVE_KINDS.contains(&k))
        }
    }
}
