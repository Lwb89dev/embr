//! Validation of user-supplied account metadata.

use crate::VaultError;

/// Maximum label length in Unicode scalar values.
pub const MAX_LABEL_CHARS: usize = 64;
/// Maximum avatar size in bytes.
pub const MAX_AVATAR_BYTES: usize = 64 * 1024;

/// Validates and normalises (trims) an account label.
///
/// Control characters and bidirectional-override characters are refused: a label is shown inside
/// approval prompts, so it must not be able to reorder or hide neighbouring text.
pub(crate) fn label(raw: &str) -> Result<String, VaultError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(VaultError::InvalidLabel("empty"));
    }
    if s.chars().count() > MAX_LABEL_CHARS {
        return Err(VaultError::InvalidLabel("too long"));
    }
    if s.chars().any(|c| c.is_control() || is_bidi_control(c)) {
        return Err(VaultError::InvalidLabel(
            "contains control or bidirectional-override characters",
        ));
    }
    Ok(s.to_owned())
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Checks an avatar's size and magic bytes (PNG, JPEG or WebP). It does **not** decode the image;
/// whoever renders it must treat the bytes as untrusted.
pub(crate) fn avatar(mime: &str, data: &[u8]) -> Result<(), VaultError> {
    if data.is_empty() {
        return Err(VaultError::InvalidAvatar("empty"));
    }
    if data.len() > MAX_AVATAR_BYTES {
        return Err(VaultError::InvalidAvatar("too large"));
    }
    let ok = match mime {
        "image/png" => data.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => data.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/webp" => data.get(0..4) == Some(b"RIFF") && data.get(8..12) == Some(b"WEBP"),
        _ => return Err(VaultError::InvalidAvatar("unsupported type")),
    };
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidAvatar("content does not match its type"))
    }
}
