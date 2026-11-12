//! Strict direct-gateway challenge envelopes. This parser never evaluates
//! JavaScript or repairs malformed XML/HTML. No response text enters errors.

use super::{xml, GpError, Session, MAX_XML};
use std::{fmt::Write, sync::Arc};
use url::Url;
use zeroize::Zeroizing;

pub(super) const MAX_SECRET: usize = 8192;
const MAX_PROMPT: usize = 2048;
pub(super) const MAX_ROUNDS: u8 = 4;

/// A credential POST either finishes login or requires a fresh, explicit answer.
/// Deliberately not Debug or Clone: challenges are one-use secret capabilities.
pub enum LoginProgress {
    Session(Session),
    Challenge(LoginChallenge),
}

/// Bound to the originating authentication client (including its clones).
/// The original password is never retained here. Dropping this value abandons
/// continuation locally; no remote challenge revocation protocol is assumed.
pub struct LoginChallenge {
    pub(super) user: String,
    pub(super) computer: String,
    pub(super) input_str: Zeroizing<String>,
    pub(super) origin: Url,
    pub(super) authentication: Arc<()>,
    pub(super) prompt: String,
    pub(super) round: u8,
}

impl LoginChallenge {
    /// Untrusted gateway text, escaped for a single-line terminal display.
    /// Callers must add their own fixed local prefix and must not log it.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn round(&self) -> u8 {
        self.round
    }
}

pub(super) struct Fields {
    pub input_str: Zeroizing<String>,
    pub prompt: String,
}

fn invalid() -> GpError {
    GpError::Protocol("invalid authentication challenge")
}

fn bounded_fields(input_str: Zeroizing<String>, prompt: &str) -> Result<Fields, GpError> {
    if input_str.is_empty() || input_str.len() > MAX_SECRET {
        return Err(invalid());
    }
    let mut rendered = String::new();
    for ch in prompt.chars() {
        if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(&mut rendered, "\\u{{{:04x}}}", u32::from(ch)).map_err(|_| invalid())?;
        } else {
            rendered.push(ch);
        }
        if rendered.len() > MAX_PROMPT {
            return Err(invalid());
        }
    }
    if rendered.is_empty() {
        return Err(invalid());
    }
    Ok(Fields {
        input_str,
        prompt: rendered,
    })
}

fn plain_element(node: roxmltree::Node<'_, '_>) -> Result<(), GpError> {
    if !node.is_element()
        || node.tag_name().namespace().is_some()
        || node.attributes().len() != 0
        || node.namespaces().len() != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn text_only<'a>(node: roxmltree::Node<'a, 'a>) -> Result<&'a str, GpError> {
    plain_element(node)?;
    if node.children().any(|child| !child.is_text()) || node.children().count() > 1 {
        return Err(invalid());
    }
    Ok(node.text().unwrap_or(""))
}

fn element_children<'a>(
    node: roxmltree::Node<'a, 'a>,
) -> Result<Vec<roxmltree::Node<'a, 'a>>, GpError> {
    plain_element(node)?;
    let mut elements = Vec::new();
    for child in node.children() {
        if child.is_element() {
            elements.push(child);
        } else if !child.is_text() || !child.text().unwrap_or("").trim().is_empty() {
            return Err(invalid());
        }
    }
    Ok(elements)
}

/// None means this is another XML response (e.g. JNLP), whose existing parser
/// must still validate it. Malformed recognized envelopes never fall back.
pub(super) fn parse(body: &str) -> Result<Option<Fields>, GpError> {
    if body.len() > MAX_XML {
        return Err(invalid());
    }
    let body = body.trim();
    if !body.starts_with('<') {
        return javascript(body).map(Some);
    }
    let doc = xml(body)?;
    let root = doc.root_element();
    if matches!(root.tag_name().name(), "challenge" | "html")
        && doc.root().children().any(|child| {
            child != root && (!child.is_text() || !child.text().unwrap_or("").trim().is_empty())
        })
    {
        return Err(invalid());
    }
    match root.tag_name().name() {
        "challenge" => {
            let mut state = None;
            let mut prompt = None;
            let mut user_seen = false;
            for child in element_children(root)? {
                let value = text_only(child)?;
                match child.tag_name().name() {
                    "inputstr" if state.is_none() => state = Some(value),
                    "respmsg" if prompt.is_none() => prompt = Some(value),
                    // Some gateways include a user label; it cannot replace the
                    // original caller's account on continuation.
                    "user" if !user_seen && value.len() <= MAX_SECRET => user_seen = true,
                    _ => return Err(invalid()),
                }
            }
            bounded_fields(
                Zeroizing::new(state.ok_or_else(invalid)?.to_owned()),
                prompt.ok_or_else(invalid)?,
            )
            .map(Some)
        }
        "html" => {
            let children = element_children(root)?;
            let body = match children.as_slice() {
                [body] if body.has_tag_name("body") => *body,
                [head, body] if head.has_tag_name("head") && body.has_tag_name("body") => {
                    if !text_only(*head)?.trim().is_empty() {
                        return Err(invalid());
                    }
                    *body
                }
                _ => return Err(invalid()),
            };
            javascript(text_only(body)?).map(Some)
        }
        _ => Ok(None),
    }
}

fn whitespace(input: &str) -> &str {
    input.trim_start_matches([' ', '\t', '\r', '\n'])
}

fn assignment(input: &mut &str, name: &str) -> Result<Zeroizing<String>, GpError> {
    let rest = whitespace(input).strip_prefix(name).ok_or_else(invalid)?;
    let rest = whitespace(rest).strip_prefix('=').ok_or_else(invalid)?;
    let rest = whitespace(rest);
    if !rest.starts_with('"') {
        return Err(invalid());
    }
    // Deserialize exactly one JSON string, then require the semicolon. JSON
    // rejects raw controls, JS-only escapes and expressions without executing.
    let mut decoder = serde_json::Deserializer::from_str(rest).into_iter::<String>();
    let value = Zeroizing::new(decoder.next().ok_or_else(invalid)?.map_err(|_| invalid())?);
    *input = whitespace(&rest[decoder.byte_offset()..])
        .strip_prefix(';')
        .ok_or_else(invalid)?;
    Ok(value)
}

fn javascript(mut body: &str) -> Result<Fields, GpError> {
    let status = assignment(&mut body, "var respStatus")?;
    let prompt = assignment(&mut body, "var respMsg")?;
    let state = assignment(&mut body, "thisForm.inputStr.value")?;
    if !whitespace(body).is_empty() {
        return Err(invalid());
    }
    match status.as_str() {
        "Challenge" => bounded_fields(state, &prompt),
        "Error" => Err(GpError::Authentication),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js(state: &str, prompt: &str) -> String {
        format!(
            "var respStatus = \"Challenge\";\nvar respMsg = {};\nthisForm.inputStr.value = {};\n",
            serde_json::to_string(prompt).unwrap(),
            serde_json::to_string(state).unwrap()
        )
    }

    #[test]
    fn three_strict_envelopes_preserve_opaque_state_and_ignore_user_label() {
        let state = "  a&+%/\"雪\t  ";
        let xml = "<challenge><user>different-account</user><respmsg>Code &amp; PIN</respmsg><inputstr>  a&amp;+%/\"雪&#9;  </inputstr></challenge>";
        let script = js(state, "Code & PIN");
        let escaped = script
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        for body in [
            xml.to_owned(),
            script,
            format!("<html><head></head><body>{escaped}</body></html>"),
        ] {
            let parsed = parse(&body).unwrap().unwrap();
            assert_eq!(&*parsed.input_str, state);
            assert_eq!(parsed.prompt, "Code & PIN");
        }
        assert!(parse("<jnlp><application-desc/></jnlp>").unwrap().is_none());
    }

    #[test]
    fn terminal_controls_bidi_and_line_breaks_are_escaped_before_bound() {
        let parsed = parse(&js(
            "state",
            "Code\x1b[2J\r\n\x07\u{0085}\u{061c}\u{202e}\u{2066}\u{2028}结束",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(parsed.prompt, "Code\\u{001b}[2J\\u{000d}\\u{000a}\\u{0007}\\u{0085}\\u{061c}\\u{202e}\\u{2066}\\u{2028}结束");
        assert!(!parsed.prompt.chars().any(char::is_control));
        assert!(parse(&js("state", &"x".repeat(MAX_PROMPT))).is_ok());
        assert!(parse(&js("state", &"x".repeat(MAX_PROMPT + 1))).is_err());
        assert!(parse(&js("state", &"\x1b".repeat(MAX_PROMPT / 8 + 1))).is_err());
        assert!(parse(&js("state", &"雪".repeat(MAX_PROMPT / 3 + 1))).is_err());
    }

    #[test]
    fn opaque_state_empty_or_oversize_fails_without_truncation() {
        let max = "s".repeat(MAX_SECRET);
        assert_eq!(
            parse(&js(&max, "Code")).unwrap().unwrap().input_str.len(),
            MAX_SECRET
        );
        for state in [String::new(), "s".repeat(MAX_SECRET + 1)] {
            assert!(parse(&js(&state, "Code")).is_err());
            assert!(parse(&format!(
                "<challenge><inputstr>{state}</inputstr><respmsg>Code</respmsg></challenge>"
            ))
            .is_err());
        }
        assert!(parse(&js("state", "")).is_err());
        assert!(parse(&" ".repeat(MAX_XML + 1)).is_err());
    }

    #[test]
    fn malformed_duplicate_unknown_and_ambiguous_xml_are_rejected() {
        let valid = "<challenge><inputstr>s</inputstr><respmsg>Code</respmsg></challenge>";
        for body in [
            valid.replace("<inputstr>s</inputstr>", ""),
            valid.replace("<respmsg>Code</respmsg>", ""),
            valid.replace("</challenge>", "<inputstr>other</inputstr></challenge>"),
            valid.replace("</challenge>", "<respmsg>other</respmsg></challenge>"),
            valid.replace("</challenge>", "<user>a</user><user>b</user></challenge>"),
            valid.replace("</challenge>", "<unknown/></challenge>"),
            valid.replace("Code", "A<hidden/>B"),
            valid.replace("Code", "A<!-- split -->B"),
            valid.replace("Code", "A<?pi value?>B"),
            valid.replace("Code", "literal & invalid"),
            valid.replace("<inputstr>", "<inputstr x='1'>"),
            valid.replace("<challenge>", "<challenge xmlns='urn:other'>"),
            valid.replace("<challenge>", "<challenge xmlns:x='urn:other'>"),
            format!("{valid}<challenge/>"),
            format!("<!DOCTYPE challenge [<!ENTITY injected 'state'>]>{valid}"),
            format!("<!-- unused -->{valid}"),
            "<challenge><inputstr>state".to_owned(),
        ] {
            assert!(parse(&body).is_err());
        }
    }

    #[test]
    fn javascript_is_fixed_assignments_not_expressions_or_recovery() {
        let valid = js("opaque", "Code");
        for body in [
            valid.replace("Challenge", "ChallengeExtra"),
            valid.replace("Challenge", "Other"),
            valid.replace("var respMsg", "var other"),
            valid.replace("thisForm.inputStr.value", "thisForm.inputstr.value"),
            valid.replace("\"Code\"", "\"Code\" + \"suffix\""),
            valid.replace("\"Code\"", "'Code'"),
            valid.replace("\"Code\"", "\"line\nline\""),
            valid.replace("\"Code\"", "\"bad\\'escape\""),
            valid.replace("\"Code\"", "\"bad\\uD800\""),
            valid.replace("\"Code\"", "prompt()"),
            valid.replace(';', ""),
            format!("{valid}var respMsg = \"again\";"),
            format!("{valid}alert(1);"),
            format!("/*comment*/{valid}"),
        ] {
            assert!(parse(&body).is_err());
        }
        assert!(matches!(
            parse(&valid.replace("Challenge", "Error")),
            Err(GpError::Authentication)
        ));
        // Even an Error envelope is not a license to ignore trailing code.
        assert!(matches!(
            parse(&format!("{}alert(1);", valid.replace("Challenge", "Error"))),
            Err(GpError::Protocol(_))
        ));
    }

    #[test]
    fn html_cannot_hide_script_tags_attributes_or_extra_nodes() {
        let valid = format!("<html><head/><body>{}</body></html>", js("s", "Code"));
        assert!(parse(&valid).is_ok());
        for body in [
            valid.replace("<body>", "<body onload='run()'>"),
            valid.replace("<head/>", "<head><script/></head>"),
            valid
                .replace("<body>", "<body><script>")
                .replace("</body>", "</script></body>"),
            valid.replace("</body>", "</body><body/>"),
            valid.replace("</body>", "<!-- split --></body>"),
            valid.replace("<head/>", "<head>unexpected</head>"),
            valid.replace("</html>", "</html>trailing"),
        ] {
            assert!(parse(&body).is_err());
        }
    }
}
