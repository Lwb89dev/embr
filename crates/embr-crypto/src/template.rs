//! Event templates (what a client asks the signer to sign) and the limits applied to them.

use serde::{Deserialize, Serialize};

use crate::CryptoError;

/// Resource and structure limits applied to every untrusted input.
///
/// The defaults are conservative but generous enough for real-world clients (long-form notes,
/// large NIP-51 lists). They bound memory and CPU spent on a single request; they are not a
/// substitute for the rate limiting done by the IPC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of the raw JSON text of an event template.
    pub max_template_bytes: usize,
    /// Maximum size of `content`.
    pub max_content_bytes: usize,
    /// Maximum number of tags.
    pub max_tags: usize,
    /// Maximum number of elements in a single tag.
    pub max_tag_items: usize,
    /// Maximum size of a single tag element.
    pub max_tag_item_bytes: usize,
    /// Maximum size of a NIP-44 / NIP-04 payload accepted for decryption.
    pub max_ciphertext_bytes: usize,
    /// Maximum size of a plaintext accepted for encryption.
    ///
    /// Defaults to 65 535 bytes, the largest plaintext accepted by the original NIP-44 v2 rules.
    /// The current NIP-44 text allows up to 2^32-1 bytes (extended length prefix) and recent
    /// implementations (e.g. nostr-tools 2.26.1, rust-nostr) accept it, but the checksummed
    /// reference test vectors still list 65 536 as invalid, so older recipients' clients may
    /// reject larger messages. See `docs/RESEARCH.md` (§ spec inconsistencies).
    pub max_plaintext_bytes: usize,
    /// Allow C0 control characters (U+0000–U+001F) other than `\b \f \n \r \t` in `content` and tags.
    ///
    /// Default `false`. NIP-01 says such characters are serialised "verbatim" when computing the
    /// event id, but JSON-based implementations (`nostr-tools`, `rust-nostr`, `serde_json`, ...)
    /// escape them as `\u00XX`, so the **id of such an event is computed differently by different
    /// verifiers**. A signer must not produce signatures whose validity depends on the verifier;
    /// see `docs/RESEARCH.md` (§ spec inconsistencies).
    pub allow_ambiguous_control_chars: bool,
    /// Highest scrypt `log_n` accepted when *importing* an `ncryptsec` (memory = 128·2^log_n·8 B).
    pub max_ncryptsec_log_n: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_template_bytes: 1024 * 1024,
            max_content_bytes: 512 * 1024,
            max_tags: 5_000,
            max_tag_items: 64,
            max_tag_item_bytes: 16 * 1024,
            max_ciphertext_bytes: 1024 * 1024,
            max_plaintext_bytes: 65_535,
            allow_ambiguous_control_chars: false,
            max_ncryptsec_log_n: 20,
        }
    }
}

/// An unsigned event as submitted by a client.
///
/// Accepted JSON fields: `kind` (required, 0–65535), `content`, `tags`, `created_at`, and – for
/// compatibility with clients that send a full unsigned event – `pubkey` and `id`.
///
/// * `pubkey`, if present, **must** equal the public key of the signing identity.
/// * `id`, if present, **must** equal the id computed from the other fields.
/// * `sig` is **rejected** (unknown field): a template is by definition unsigned.
/// * Any other unknown field is rejected, so that nothing the user was not shown can be smuggled
///   into a signing request.
///
/// Omitted `content` defaults to `""`, omitted `tags` to `[]`, omitted `created_at` to "now".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventTemplate {
    /// Event kind.
    pub kind: u16,
    /// Event content.
    #[serde(default)]
    pub content: String,
    /// Event tags (each tag is a non-empty list of strings).
    #[serde(default)]
    pub tags: Vec<Vec<String>>,
    /// Creation time, Unix seconds. `None` means "now at signing time".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    /// Optional claimed author; must match the signing identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    /// Optional claimed event id; must match the computed id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl EventTemplate {
    /// Parses and validates a template from JSON text.
    pub fn from_json(json: &str, limits: &Limits) -> Result<Self, CryptoError> {
        if json.len() > limits.max_template_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "event template size",
                limit: limits.max_template_bytes,
            });
        }
        let tpl: EventTemplate =
            serde_json::from_str(json).map_err(|e| CryptoError::InvalidEvent(e.to_string()))?;
        tpl.validate(limits)?;
        Ok(tpl)
    }

    /// Checks structural validity and limits. Called by [`Self::from_json`] and again by
    /// [`crate::Identity::sign_event`], so a hand-built template is validated too.
    pub fn validate(&self, limits: &Limits) -> Result<(), CryptoError> {
        if self.content.len() > limits.max_content_bytes {
            return Err(CryptoError::LimitExceeded {
                what: "event content",
                limit: limits.max_content_bytes,
            });
        }
        if !limits.allow_ambiguous_control_chars
            && (has_ambiguous_control(&self.content)
                || self
                    .tags
                    .iter()
                    .flatten()
                    .any(|item| has_ambiguous_control(item)))
        {
            return Err(CryptoError::InvalidEvent(
                "contains control characters whose NIP-01 serialization is ambiguous".into(),
            ));
        }
        if self.tags.len() > limits.max_tags {
            return Err(CryptoError::LimitExceeded {
                what: "tag count",
                limit: limits.max_tags,
            });
        }
        for tag in &self.tags {
            if tag.is_empty() {
                return Err(CryptoError::InvalidEvent("empty tag".into()));
            }
            if tag.len() > limits.max_tag_items {
                return Err(CryptoError::LimitExceeded {
                    what: "tag length",
                    limit: limits.max_tag_items,
                });
            }
            if tag
                .iter()
                .any(|item| item.len() > limits.max_tag_item_bytes)
            {
                return Err(CryptoError::LimitExceeded {
                    what: "tag element size",
                    limit: limits.max_tag_item_bytes,
                });
            }
        }
        if let Some(pk) = &self.pubkey {
            if !is_hex32(pk) {
                return Err(CryptoError::InvalidEvent(
                    "pubkey must be 64 hex characters".into(),
                ));
            }
        }
        if let Some(id) = &self.id {
            if !is_hex32(id) {
                return Err(CryptoError::InvalidEvent(
                    "id must be 64 hex characters".into(),
                ));
            }
        }
        Ok(())
    }
}

/// `true` if `s` contains a C0 control character that implementations serialise differently.
/// `\b \f \n \r \t` have a universally agreed escape and are fine.
fn has_ambiguous_control(s: &str) -> bool {
    s.chars()
        .any(|c| c < '\u{20}' && !matches!(c, '\u{08}' | '\u{09}' | '\u{0a}' | '\u{0c}' | '\u{0d}'))
}

fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
