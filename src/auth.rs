//! Nonsecret, immutable-by-ownership authentication destinations. A portal
//! credential and a direct-gateway credential are different capabilities even
//! when both endpoints happen to have the same HTTPS origin.
use serde::{Deserialize, Serialize};
use std::io;
use url::Url;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthBinding {
    Direct { gateway: String },
    Portal { portal: String, gateway: String },
}

impl AuthBinding {
    pub fn direct(gateway: &str) -> io::Result<Self> {
        Ok(Self::Direct {
            gateway: origin(gateway)?,
        })
    }

    pub fn via_portal(portal: &str, gateway: &str) -> io::Result<Self> {
        Ok(Self::Portal {
            portal: origin(portal)?,
            gateway: origin(gateway)?,
        })
    }

    pub fn gateway(&self) -> &str {
        match self {
            Self::Direct { gateway } | Self::Portal { gateway, .. } => gateway,
        }
    }

    pub fn portal_origin(&self) -> Option<&str> {
        match self {
            Self::Direct { .. } => None,
            Self::Portal { portal, .. } => Some(portal),
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        self.canonical().map(|_| ())
    }

    /// Compare validated origins and the authentication role, never just a
    /// hostname. Invalid inputs cannot match themselves.
    pub fn matches(&self, other: &Self) -> bool {
        match (self.canonical(), other.canonical()) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }

    fn canonical(&self) -> io::Result<Self> {
        match self {
            Self::Direct { gateway } => Self::direct(gateway),
            Self::Portal { portal, gateway } => Self::via_portal(portal, gateway),
        }
    }
}

fn origin(source: &str) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid authentication origin");
    // url normalizes some whitespace/control characters. Refuse them before
    // parsing so identity displays and wire comparisons share one meaning.
    if source.is_empty()
        || source.len() > 2048
        || source.contains('\\')
        || source.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid());
    }
    let (scheme, remainder) = source.split_once("://").ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("https")
        || remainder.contains('@')
        || remainder
            .find('/')
            .is_some_and(|slash| &remainder[slash..] != "/")
    {
        return Err(invalid());
    }
    let url = Url::parse(source).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err(invalid());
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_normalization_does_not_erase_role_or_port() {
        let direct = AuthBinding::direct("https://VPN.EXAMPLE:443/").unwrap();
        assert!(direct.matches(&AuthBinding::direct("https://vpn.example").unwrap()));
        let portal = AuthBinding::via_portal("https://vpn.example", "https://vpn.example").unwrap();
        assert!(!portal.matches(&direct));
        assert!(!portal.matches(
            &AuthBinding::via_portal("https://vpn.example:444", "https://vpn.example").unwrap()
        ));
        assert!(!portal.matches(
            &AuthBinding::via_portal("https://vpn.example", "https://vpn.example:444").unwrap()
        ));
    }

    #[test]
    fn untrusted_bindings_require_complete_mode_and_valid_origins() {
        for value in [
            r#"{"gateway":"https://vpn.example"}"#,
            r#"{"mode":"portal","gateway":"https://vpn.example"}"#,
            r#"{"mode":"direct","gateway":"https://vpn.example","portal":"https://vpn.example"}"#,
            r#"{"mode":"direct","gateway":"https://vpn.example","gateway":"https://other.example"}"#,
        ] {
            assert!(serde_json::from_str::<AuthBinding>(value).is_err());
        }
        for origin in [
            "http://vpn.example",
            "https://vpn.example:0",
            "https://user@vpn.example",
            "https://vpn.example/path",
            "https://vpn.example?secret=1",
            "https://vpn.example#x",
            "https://vpn.example/x/..",
            "https://vpn.example/%2e",
            "https://@vpn.example",
            "https://vpn.exa\nmple",
            " https://vpn.example",
            "https://vpn.example\\path",
        ] {
            let bad = AuthBinding::Direct {
                gateway: origin.into(),
            };
            assert!(bad.validate().is_err());
            assert!(!bad.matches(&bad));
            assert!(!bad.validate().unwrap_err().to_string().contains(origin));
        }
    }
}
