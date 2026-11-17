//! `bunker://` and `nostrconnect://` connection URIs (NIP-46), with strict validation.
//!
//! Everything here is attacker-influenced text (a URI pasted from a web page, a QR code…), so:
//! public keys must be exactly 64 hex characters, relay URLs must be `wss://` (or `ws://` to a
//! loopback host, for local testing), counts and lengths are bounded, and unknown parameters are
//! ignored rather than interpreted.

use embr_core::Pubkey32;
use url::{Host, Url};

/// Maximum relays accepted in one URI.
pub const MAX_RELAYS: usize = 8;
/// Maximum length of a relay URL.
pub const MAX_RELAY_URL: usize = 256;
/// Maximum length of a connection secret.
pub const MAX_SECRET: usize = 128;
/// Maximum number of requested permissions.
pub const MAX_PERMS: usize = 64;

/// URI parsing errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UriError {
    /// Not a valid URL or wrong scheme.
    #[error("not a valid {0}:// URI")]
    Scheme(&'static str),
    /// The public key is not 64 hex characters.
    #[error("invalid public key")]
    Pubkey,
    /// A relay URL is not acceptable.
    #[error("invalid relay URL: {0}")]
    Relay(String),
    /// Too many relays.
    #[error("too many relays (maximum {MAX_RELAYS})")]
    TooManyRelays,
    /// A required parameter is missing.
    #[error("missing required parameter `{0}`")]
    Missing(&'static str),
    /// A parameter is too long or malformed.
    #[error("parameter `{0}` is invalid")]
    Invalid(&'static str),
}

/// Validates a relay URL: `wss://host[:port][/path]`, or `ws://` to localhost / a loopback IP.
/// Returns the normalised URL string.
pub fn validate_relay(raw: &str) -> Result<String, UriError> {
    let bad = |why: &str| {
        UriError::Relay(format!(
            "{why}: {}",
            raw.chars().take(60).collect::<String>()
        ))
    };
    if raw.len() > MAX_RELAY_URL {
        return Err(bad("too long"));
    }
    // The URL parser silently strips leading/trailing control characters and percent-encodes the
    // rest, which would let hidden characters through. Refuse them (found by fuzzing).
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad("control characters and spaces are not allowed"));
    }
    let u = Url::parse(raw).map_err(|_| bad("not a URL"))?;
    if u.username() != "" || u.password().is_some() || u.fragment().is_some() {
        return Err(bad("credentials and fragments are not allowed"));
    }
    let loopback = match u.host().ok_or_else(|| bad("no host"))? {
        Host::Domain(d) => {
            let ok_label = |l: &str| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            };
            if d.len() > 253 || !d.split('.').all(ok_label) {
                return Err(bad("invalid host name"));
            }
            d == "localhost"
        }
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    };
    match u.scheme() {
        "wss" => {}
        "ws" if loopback => {}
        "ws" => return Err(bad("plain ws:// is only allowed for localhost; use wss://")),
        _ => return Err(bad("scheme must be wss://")),
    }
    let normalised = u.to_string();
    // The *normalised* form is what gets stored and re-validated later: bound it too.
    if normalised.len() > MAX_RELAY_URL {
        return Err(bad("too long once normalised"));
    }
    Ok(normalised)
}

fn relays_from(url: &Url) -> Result<Vec<String>, UriError> {
    let mut out = Vec::new();
    for (k, v) in url.query_pairs() {
        if k == "relay" {
            if out.len() >= MAX_RELAYS {
                return Err(UriError::TooManyRelays);
            }
            let r = validate_relay(&v)?;
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    Ok(out)
}

fn pubkey_from_host(url: &Url) -> Result<Pubkey32, UriError> {
    url.host_str()
        .ok_or(UriError::Pubkey)?
        .parse::<Pubkey32>()
        .map_err(|_| UriError::Pubkey)
}

/// `bunker://<remote-signer-pubkey>?relay=…&secret=…` — created by the signer, pasted into a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BunkerUri {
    /// The signer's transport public key.
    pub signer: Pubkey32,
    /// Relays to use.
    pub relays: Vec<String>,
    /// Single-use connection secret.
    pub secret: Option<String>,
}

impl BunkerUri {
    /// Parses a `bunker://` URI.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let url = Url::parse(s.trim()).map_err(|_| UriError::Scheme("bunker"))?;
        if url.scheme() != "bunker" {
            return Err(UriError::Scheme("bunker"));
        }
        let signer = pubkey_from_host(&url)?;
        let relays = relays_from(&url)?;
        let secret = url
            .query_pairs()
            .find(|(k, _)| k == "secret")
            .map(|(_, v)| v.into_owned());
        if secret.as_ref().is_some_and(|s| s.len() > MAX_SECRET) {
            return Err(UriError::Invalid("secret"));
        }
        Ok(Self {
            signer,
            relays,
            secret,
        })
    }

    /// Renders the URI (relays and secret are percent-encoded).
    pub fn render(&self) -> String {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        for r in &self.relays {
            q.append_pair("relay", r);
        }
        if let Some(s) = &self.secret {
            q.append_pair("secret", s);
        }
        format!("bunker://{}?{}", self.signer, q.finish())
    }
}

/// `nostrconnect://<client-pubkey>?relay=…&secret=…&perms=…&name=…` — created by the client,
/// imported into the signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrConnectUri {
    /// The client's public key (its identity).
    pub client: Pubkey32,
    /// Relays the client listens on.
    pub relays: Vec<String>,
    /// Secret the signer must echo in its `connect` response (required by NIP-46).
    pub secret: String,
    /// Requested permissions (`method[:param]`), a wish and never a grant.
    pub perms: Vec<String>,
    /// Self-declared name (untrusted).
    pub name: Option<String>,
    /// Self-declared URL (untrusted).
    pub url: Option<String>,
}

impl NostrConnectUri {
    /// Parses a `nostrconnect://` URI.
    pub fn parse(s: &str) -> Result<Self, UriError> {
        let url = Url::parse(s.trim()).map_err(|_| UriError::Scheme("nostrconnect"))?;
        if url.scheme() != "nostrconnect" {
            return Err(UriError::Scheme("nostrconnect"));
        }
        let client = pubkey_from_host(&url)?;
        let relays = relays_from(&url)?;
        if relays.is_empty() {
            return Err(UriError::Missing("relay"));
        }
        let get = |k: &str| {
            url.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
        };
        let secret = get("secret").ok_or(UriError::Missing("secret"))?;
        if secret.is_empty() || secret.len() > MAX_SECRET {
            return Err(UriError::Invalid("secret"));
        }
        let perms: Vec<String> = get("perms")
            .map(|p| {
                p.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if perms.len() > MAX_PERMS || perms.iter().any(|p| p.len() > 64) {
            return Err(UriError::Invalid("perms"));
        }
        let bounded = |v: Option<String>, k: &'static str, max: usize| match v {
            Some(x) if x.chars().count() > max => Err(UriError::Invalid(k)),
            other => Ok(other),
        };
        Ok(Self {
            client,
            relays,
            secret,
            perms,
            name: bounded(get("name"), "name", 64)?,
            url: bounded(get("url"), "url", 256)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const PK: &str = "83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5";

    #[test]
    fn bunker_roundtrip() {
        let u = BunkerUri {
            signer: PK.parse().unwrap(),
            relays: vec![
                "wss://relay.example.com/".into(),
                "ws://127.0.0.1:7777/".into(),
            ],
            secret: Some("s3cr3t value&=".into()),
        };
        let text = u.render();
        assert!(text.starts_with(&format!("bunker://{PK}?")), "{text}");
        assert_eq!(BunkerUri::parse(&text).unwrap(), u);
    }

    #[test]
    fn bunker_spec_example_parses() {
        let u = BunkerUri::parse(&format!("bunker://{PK}?relay=wss%3A%2F%2Frelay1.example.com&relay=wss://relay2.example.com&secret=abc")).unwrap();
        assert_eq!(u.relays.len(), 2);
        assert_eq!(u.secret.as_deref(), Some("abc"));
    }

    #[test]
    fn nostrconnect_with_perms_and_metadata() {
        let u = NostrConnectUri::parse(&format!(
            "nostrconnect://{PK}?relay=wss%3A%2F%2Frelay1.example.com&secret=0s8j2djs&perms=nip44_encrypt%2Cnip44_decrypt%2Csign_event%3A13&name=My+App&url=https%3A%2F%2Fapp.example"
        ))
        .unwrap();
        assert_eq!(u.client.to_string(), PK);
        assert_eq!(u.perms, ["nip44_encrypt", "nip44_decrypt", "sign_event:13"]);
        assert_eq!(u.name.as_deref(), Some("My App"));
        assert_eq!(u.secret, "0s8j2djs");
    }

    #[test]
    fn hostile_uris_are_rejected() {
        let ok_relay = "relay=wss://r.example";
        for bad in [
            "".to_string(),
            "http://example.com".to_string(),
            "bunker://notahexkey?relay=wss://r.example".to_string(),
            format!("bunker://{}?{ok_relay}", &PK[..62]),
            format!("bunker://{PK}?relay=ws://evil.example"), // plaintext to a non-loopback host
            format!("bunker://{PK}?relay=https://r.example"), // wrong scheme
            format!("bunker://{PK}?relay=wss://user:pw@r.example"), // credentials
            format!("bunker://{PK}?relay=wss://r.example/%23frag"),
            format!(
                "bunker://{PK}?relay={}",
                "wss://x.example/".to_string() + &"a".repeat(300)
            ),
            format!("bunker://{PK}?secret={}", "s".repeat(200)),
            format!(
                "bunker://{PK}?{}",
                (0..9)
                    .map(|i| format!("relay=wss://r{i}.example"))
                    .collect::<Vec<_>>()
                    .join("&")
            ),
        ] {
            assert!(BunkerUri::parse(&bad).is_err(), "should reject {bad:.80}");
        }
        for bad in [
            format!("nostrconnect://{PK}?secret=x"),   // no relay
            format!("nostrconnect://{PK}?{ok_relay}"), // no secret (required by NIP-46)
            format!("nostrconnect://{PK}?{ok_relay}&secret="),
            format!(
                "nostrconnect://{PK}?{ok_relay}&secret=x&name={}",
                "n".repeat(65)
            ),
            format!("bunker://{PK}?{ok_relay}&secret=x"), // wrong scheme for this parser
        ] {
            assert!(
                NostrConnectUri::parse(&bad).is_err(),
                "should reject {bad:.80}"
            );
        }
    }

    /// Found by fuzzing (`nip46_uri`): control characters were stripped/encoded by the URL parser, the
    /// normalised result exceeded the length limit and no longer re-validated.
    #[test]
    fn fuzz_regression_normalised_relays_are_always_revalidatable() {
        let crash = "\u{1}wss:.z1/.\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0;\n:.\u{11}";
        assert!(validate_relay(crash).is_err());
        for bad in [
            "wss://.z1/",
            "wss://a..b/",
            "wss://-a.example/",
            "wss://a-.example/",
            "wss://exa mple.com",
            "wss://example.com/\u{7f}",
            "\twss://example.com",
            "wss://example.com\n",
            "wss://a_b.example/",
        ] {
            assert!(validate_relay(bad).is_err(), "{bad:?}");
        }
        for good in [
            "wss://relay.example.com",
            "wss://relay.example.com:8443/path?x=1",
            "ws://localhost:7777",
            "ws://127.0.0.1:7777/",
            "ws://[::1]:9",
        ] {
            let n = validate_relay(good).unwrap_or_else(|e| panic!("{good}: {e}"));
            assert_eq!(validate_relay(&n).unwrap(), n, "idempotent: {good}");
        }
    }

    #[test]
    fn relay_validation() {
        assert!(validate_relay("wss://relay.damus.io").is_ok());
        assert!(validate_relay("ws://localhost:8080").is_ok());
        assert!(validate_relay("ws://[::1]:8080").is_ok());
        assert!(validate_relay("ws://127.0.0.1:1").is_ok());
        assert!(
            validate_relay("ws://192.168.1.5").is_err(),
            "LAN is not loopback"
        );
        assert!(validate_relay("ws://relay.example").is_err());
        assert!(validate_relay("wss://").is_err());
    }
}
