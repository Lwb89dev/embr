//! Desktop notifications. They carry **metadata only** (who, which operation, which kind): never
//! event content, plaintext or keys, because notification daemons log and display them.

use embr_core::display::sanitize;

/// freedesktop notification servers render a small HTML subset in the body (`<b>`, `<a href>`…), and
/// the app name is chosen by the (untrusted) requesting app, so markup characters must be escaped or
/// an app could put a link or bold text into a message that looks like it comes from Embr. macOS
/// and Windows notifications are plain text, where escaping would show the entities literally.
fn for_body(text: &str) -> String {
    if cfg!(all(unix, not(target_os = "macos"))) {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    } else {
        text.to_owned()
    }
}

/// The notification text for a request. Pure, so it can be tested without a notification daemon.
fn body(client: &str, operation: Option<&str>, kind: Option<u16>) -> String {
    let what = match (operation, kind) {
        (Some("sign_event"), Some(k)) => format!("sign a kind-{k} event"),
        (Some(op), _) => op.replace('_', " "),
        (None, _) => "connect to your signer".to_owned(),
    };
    for_body(&format!(
        "{} (unverified) wants to {what}.",
        sanitize(client, 40)
    ))
}

/// "An app is waiting for your decision."
pub fn approval_needed(client: &str, operation: Option<&str>, kind: Option<u16>) {
    let body = body(client, operation, kind);
    // Notification daemons can block on D-Bus: never do it on the UI thread.
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .appname("Embr")
            .summary("Approval needed")
            .body(&body)
            .icon("dialog-password")
            .show();
    });
}

/// "N requests are waiting." — sent by the tray helper, which knows only a count.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn pending_waiting(pending: usize) {
    let body = crate::tray::notification_body(pending);
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .appname("Embr")
            .summary("Approval needed")
            .body(&body)
            .icon("dialog-password")
            .show();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_names_the_app_as_unverified_and_the_action() {
        let b = body("OUTKAST", Some("sign_event"), Some(1));
        assert!(
            b.contains("OUTKAST (unverified)") && b.contains("kind-1"),
            "{b}"
        );
        assert!(body("x", None, None).contains("connect to your signer"));
        assert!(body("x", Some("nip44_decrypt"), None).contains("nip44 decrypt"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn an_app_cannot_inject_markup_into_a_notification() {
        let b = body(r#"<a href="x">E</a> & <b>y</b>"#, None, None);
        assert!(!b.contains('<') && !b.contains('>'), "{b}");
        assert!(b.contains("&lt;a href") && b.contains("&amp;"), "{b}");
    }

    #[test]
    fn a_long_name_is_cut_and_never_carries_message_content() {
        let b = body(&"A".repeat(500), Some("sign_event"), Some(1));
        assert!(b.len() < 120, "{} bytes", b.len());
    }
}
