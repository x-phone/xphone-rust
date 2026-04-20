//! Parser for `application/dialog-info+xml` (RFC 4235).
//!
//! Extracts extension state from the `<dialog>` elements in a dialog-info XML body.
//! Used by the BLF (Busy Lamp Field) subscription to derive [`ExtensionState`].

use quick_xml::events::Event;
use quick_xml::Reader;
use tracing::debug;

use crate::types::ExtensionState;

/// Parses a dialog-info+xml body and returns the derived [`ExtensionState`].
///
/// Mapping rules (RFC 4235 section 4.1.6):
/// - No `<dialog>` elements → `Available` (no active dialogs)
/// - Any `<state>confirmed</state>` → `OnThePhone`
/// - Any `<state>early</state>` or `<state>trying</state>` → `Ringing`
/// - All `<state>terminated</state>` → `Available` (all dialogs ended)
/// - Parse error or empty → `Unknown`
pub fn parse_dialog_info(xml: &str) -> ExtensionState {
    let states = parse_dialog_states(xml);
    if states.is_empty() {
        // No dialog elements found.
        // If the XML was valid dialog-info with zero dialogs, that means available.
        // If the XML was garbage, return Unknown.
        if xml.contains("dialog-info") {
            return ExtensionState::Available;
        }
        return ExtensionState::Unknown;
    }

    // Priority: confirmed > early/trying > terminated
    let mut has_confirmed = false;
    let mut has_early = false;
    let mut all_terminated = true;

    for state in &states {
        match state.as_str() {
            "confirmed" => {
                has_confirmed = true;
                all_terminated = false;
            }
            "early" | "trying" => {
                has_early = true;
                all_terminated = false;
            }
            "terminated" => {}
            _ => {
                all_terminated = false;
            }
        }
    }

    if has_confirmed {
        ExtensionState::OnThePhone
    } else if has_early {
        ExtensionState::Ringing
    } else if all_terminated {
        ExtensionState::Available
    } else {
        ExtensionState::Unknown
    }
}

/// Parses the raw dialog state strings from the XML.
///
/// Returns a `Vec` of state values found inside `<state>` elements that are
/// children of `<dialog>` elements (e.g. `["confirmed", "early"]`).
pub fn parse_dialog_states(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut states = Vec::new();
    let mut in_dialog = false;
    let mut in_state = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = local_name.as_ref();
                if name == b"dialog" {
                    in_dialog = true;
                } else if name == b"state" && in_dialog {
                    in_state = true;
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let name = local_name.as_ref();
                if name == b"dialog" {
                    in_dialog = false;
                } else if name == b"state" {
                    in_state = false;
                }
            }
            Ok(Event::Text(e)) if in_state => match e.unescape() {
                Ok(text) => states.push(text.trim().to_lowercase()),
                Err(err) => {
                    debug!(error = %err, "dialog-info: failed to unescape state text");
                }
            },
            Ok(Event::Eof) => break,
            Err(err) => {
                debug!(error = %err, "dialog-info: XML parse error");
                break;
            }
            _ => {}
        }
    }

    states
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_DIALOG_INFO: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
</dialog-info>"#;

    const CONFIRMED: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="abc123" direction="initiator">
    <state>confirmed</state>
  </dialog>
</dialog-info>"#;

    const EARLY: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="abc123" direction="recipient">
    <state>early</state>
  </dialog>
</dialog-info>"#;

    const TRYING: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="abc123">
    <state>trying</state>
  </dialog>
</dialog-info>"#;

    const TERMINATED: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="abc123">
    <state>terminated</state>
  </dialog>
</dialog-info>"#;

    const MIXED_EARLY_CONFIRMED: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="2" state="full" entity="sip:1001@pbx.local">
  <dialog id="d1">
    <state>early</state>
  </dialog>
  <dialog id="d2">
    <state>confirmed</state>
  </dialog>
</dialog-info>"#;

    const MULTIPLE_TERMINATED: &str = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="3" state="full" entity="sip:1001@pbx.local">
  <dialog id="d1">
    <state>terminated</state>
  </dialog>
  <dialog id="d2">
    <state>terminated</state>
  </dialog>
</dialog-info>"#;

    #[test]
    fn no_dialogs_is_available() {
        assert_eq!(
            parse_dialog_info(EMPTY_DIALOG_INFO),
            ExtensionState::Available
        );
    }

    #[test]
    fn confirmed_is_on_the_phone() {
        assert_eq!(parse_dialog_info(CONFIRMED), ExtensionState::OnThePhone);
    }

    #[test]
    fn early_is_ringing() {
        assert_eq!(parse_dialog_info(EARLY), ExtensionState::Ringing);
    }

    #[test]
    fn trying_is_ringing() {
        assert_eq!(parse_dialog_info(TRYING), ExtensionState::Ringing);
    }

    #[test]
    fn confirmed_wins_over_early() {
        assert_eq!(
            parse_dialog_info(MIXED_EARLY_CONFIRMED),
            ExtensionState::OnThePhone
        );
    }

    #[test]
    fn all_terminated_is_available() {
        assert_eq!(parse_dialog_info(TERMINATED), ExtensionState::Available);
        assert_eq!(
            parse_dialog_info(MULTIPLE_TERMINATED),
            ExtensionState::Available
        );
    }

    #[test]
    fn empty_string_is_unknown() {
        assert_eq!(parse_dialog_info(""), ExtensionState::Unknown);
    }

    #[test]
    fn malformed_xml_is_unknown() {
        assert_eq!(parse_dialog_info("<broken"), ExtensionState::Unknown);
        assert_eq!(parse_dialog_info("not xml at all"), ExtensionState::Unknown);
    }

    #[test]
    fn namespaced_elements() {
        // Some servers use namespace prefixes.
        let xml = r#"<?xml version="1.0"?>
<di:dialog-info xmlns:di="urn:ietf:params:xml:ns:dialog-info"
                version="1" state="full" entity="sip:1001@pbx.local">
  <di:dialog id="a1">
    <di:state>confirmed</di:state>
  </di:dialog>
</di:dialog-info>"#;
        assert_eq!(parse_dialog_info(xml), ExtensionState::OnThePhone);
    }

    #[test]
    fn parse_dialog_states_returns_all() {
        let states = parse_dialog_states(MIXED_EARLY_CONFIRMED);
        assert_eq!(states.len(), 2);
        assert!(states.contains(&"early".to_string()));
        assert!(states.contains(&"confirmed".to_string()));
    }

    #[test]
    fn case_insensitive_state() {
        let xml = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="a1">
    <state>Confirmed</state>
  </dialog>
</dialog-info>"#;
        assert_eq!(parse_dialog_info(xml), ExtensionState::OnThePhone);
    }

    #[test]
    fn whitespace_in_state_text() {
        let xml = r#"<?xml version="1.0"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
             version="1" state="full" entity="sip:1001@pbx.local">
  <dialog id="a1">
    <state>  early  </state>
  </dialog>
</dialog-info>"#;
        assert_eq!(parse_dialog_info(xml), ExtensionState::Ringing);
    }
}
