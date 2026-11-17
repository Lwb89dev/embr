//! Safe rendering of untrusted text (event content, tags, labels, client names) for approval
//! prompts and logs.
//!
//! The goal is that **what the user sees cannot hide or reorder what is really there**:
//! control characters, bidirectional overrides/isolates and invisible/zero-width characters are
//! replaced by a visible `⟦U+XXXX⟧` marker; newlines and tabs become `↵` and `⇥`; the result is
//! truncated with an explicit count of what was cut. The output is plain text: UIs must not
//! interpret it as markup or linkify it.

/// Characters that are visually invisible or change text direction.
fn is_deceptive(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                       // soft hyphen
        | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'        // zero-width space/joiners, LRM, RLM
        | '\u{202A}'..='\u{202E}'        // bidi embeddings / overrides
        | '\u{2060}'..='\u{2064}'        // word joiner, invisible operators
        | '\u{2066}'..='\u{2069}'        // bidi isolates
        | '\u{FEFF}'                     // BOM / zero-width no-break space
        | '\u{FFF9}'..='\u{FFFB}'        // interlinear annotation
        | '\u{E0000}'..='\u{E007F}'      // tag characters
    )
}

/// Renders `input` safely, showing at most `max_chars` input characters.
pub fn sanitize(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars.saturating_mul(2)));
    let mut shown = 0usize;
    let mut total = 0usize;
    for c in input.chars() {
        total += 1;
        if shown >= max_chars {
            continue;
        }
        shown += 1;
        match c {
            '\n' => out.push('↵'),
            '\t' => out.push('⇥'),
            c if c.is_control() || is_deceptive(c) => {
                out.push_str(&format!("⟦U+{:04X}⟧", c as u32));
            }
            c => out.push(c),
        }
    }
    if total > shown {
        out.push_str(&format!("… (+{} more characters)", total - shown));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(sanitize("hello 日本語 🔥", 100), "hello 日本語 🔥");
    }

    #[test]
    fn deceptive_characters_become_visible() {
        let s = sanitize("evil\u{202e}gnp.exe\u{200b}\u{0}\u{7f}", 100);
        assert_eq!(s, "evil⟦U+202E⟧gnp.exe⟦U+200B⟧⟦U+0000⟧⟦U+007F⟧");
        assert!(s.chars().all(|c| !is_deceptive(c) && !c.is_control()));
    }

    #[test]
    fn whitespace_is_made_explicit() {
        assert_eq!(sanitize("a\nb\tc", 100), "a↵b⇥c");
    }

    #[test]
    fn long_input_is_truncated_with_a_count() {
        assert_eq!(sanitize("abcdef", 3), "abc… (+3 more characters)");
        assert_eq!(sanitize("abc", 3), "abc");
        assert_eq!(sanitize("", 3), "");
    }
}
