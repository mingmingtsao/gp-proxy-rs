//! Explicit, gateway-bound session-file loading through the shared secret reader.
use crate::{gp::Session, secret_file};
use serde::{Deserialize, Deserializer};
use std::{net::Ipv4Addr, path::Path};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFile {
    gateway: String,
    user: String,
    #[serde(deserialize_with = "deserialize_secret")]
    authcookie: Zeroizing<String>,
    #[serde(default)]
    portal: String,
    #[serde(default)]
    domain: String,
    computer: String,
    #[serde(default)]
    preferred_ip: Option<Ipv4Addr>,
}

fn deserialize_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub fn read(path: &Path, gateway: &str) -> Result<Session, Box<dyn std::error::Error>> {
    let source = secret_file::read(path)?;
    parse(&source, gateway)
}

/// Explicit IPC import: validate the gateway binding before returning the
/// zeroizing source. No cookie is written to a new file or exposed through Debug.
pub fn read_for_transfer(
    path: &Path,
    gateway: &str,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let source = secret_file::read(path)?;
    drop(parse(&source, gateway)?);
    Ok(source)
}

pub(crate) fn parse(source: &str, gateway: &str) -> Result<Session, Box<dyn std::error::Error>> {
    let mut parsed: SessionFile =
        serde_json::from_str(source).map_err(|_| "invalid session JSON (contents redacted)")?;
    let stored_gateway = url::Url::parse(&parsed.gateway)
        .map_err(|_| "invalid session gateway (contents redacted)")?;
    let configured_gateway =
        url::Url::parse(gateway).map_err(|_| "invalid configured gateway (contents redacted)")?;
    if stored_gateway != configured_gateway {
        return Err(
            "session file gateway does not match configured gateway; refusing to send credentials"
                .into(),
        );
    }
    Ok(Session::new(
        parsed.user,
        std::mem::take(&mut *parsed.authcookie),
        parsed.portal,
        parsed.domain,
        parsed.computer,
        parsed.preferred_ip,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = r#"{"gateway":"https://vpn.example.test:7777/","user":"test-user","authcookie":"synthetic-cookie-31513","computer":"test-host"}"#;

    #[test]
    fn valid_session_retains_gateway_binding_and_optional_defaults() {
        let session = parse(SOURCE, "https://vpn.example.test:7777").unwrap();
        assert_eq!(session.user, "test-user");
        assert_eq!(session.computer, "test-host");
        assert!(session.portal.is_empty() && session.domain.is_empty());
        assert_eq!(session.preferred_ip, None);
        assert!(!format!("{session:?}").contains("31513"));
        assert!(parse(SOURCE, "https://different.example.test:7777").is_err());
        let extended = SOURCE.replace(
            "\"computer\":\"test-host\"",
            "\"computer\":\"test-host\",\"portal\":\"test-portal\",\"domain\":\"test-domain\",\"preferred_ip\":\"10.23.4.5\"",
        );
        let session = parse(&extended, "https://vpn.example.test:7777").unwrap();
        assert_eq!(session.portal, "test-portal");
        assert_eq!(session.domain, "test-domain");
        assert_eq!(session.preferred_ip, Some(Ipv4Addr::new(10, 23, 4, 5)));
    }

    #[test]
    fn malformed_ambiguous_or_invalid_session_fields_remain_errors_without_secret_text() {
        for source in [
            SOURCE.replace("\"test-user\"", "\"test-user\",\"user\":\"duplicate\""),
            SOURCE.replace("\"test-host\"", "\"test-host\",\"unknown\":\"31513\""),
            SOURCE.replace("synthetic-cookie-31513", ""),
            SOURCE.replace("test-host", "bad\\n31513"),
            SOURCE.replace("https://vpn.example.test:7777/", "bad gateway 31513"),
            "{\"authcookie\":\"31513\",\"user\": []}".into(),
        ] {
            let error = parse(&source, "https://vpn.example.test:7777").unwrap_err();
            assert!(!error.to_string().contains("31513"));
        }
    }
}
