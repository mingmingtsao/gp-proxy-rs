//! Explicit, literal credential-file loading, without shell execution or process
//! environment mutation. This intentionally supports a small dotenv subset:
//! `KEY=value`, optional `export`, whole-line `#` comments, and matching outer
//! single/double quotes. Values are never interpolated or escape-decoded; inline
//! `#`, `$`, `=`, and backslashes are literal. Quote values to preserve edge spaces.
use std::{fmt, io, path::Path};
use url::Url;
use zeroize::Zeroizing;

const MAX_FILE_BYTES: usize = crate::secret_file::MAX_BYTES;
const MAX_CREDENTIAL_BYTES: usize = 8192;

pub struct Credentials {
    pub user: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub gateway: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("gateway", &"[REDACTED]")
            .finish()
    }
}

impl Credentials {
    pub fn read(path: &Path) -> io::Result<Self> {
        let source = crate::secret_file::read(path)?;
        Self::parse(&source)
    }

    fn parse(source: &str) -> io::Result<Self> {
        let (user, password, origin) = parse_fields(source, "GP_GATEWAY")?;
        let gateway = normalize_origin(&origin)?;
        Ok(Self {
            user,
            password,
            gateway,
        })
    }
}

pub struct PortalCredentials {
    pub user: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub portal: String,
}

impl fmt::Debug for PortalCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortalCredentials")
            .field("user", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("portal", &"[REDACTED]")
            .finish()
    }
}

impl PortalCredentials {
    pub fn read(path: &Path) -> io::Result<Self> {
        let source = crate::secret_file::read(path)?;
        Self::parse(&source)
    }

    fn parse(source: &str) -> io::Result<Self> {
        let (user, password, origin) = parse_fields(source, "GP_PORTAL")?;
        let portal = normalize_origin(&origin)?;
        Ok(Self {
            user,
            password,
            portal,
        })
    }
}

fn parse_fields(
    source: &str,
    origin_key: &str,
) -> io::Result<(Zeroizing<String>, Zeroizing<String>, Zeroizing<String>)> {
    if source.len() > MAX_FILE_BYTES {
        return Err(invalid("credential file exceeds 64 KiB limit"));
    }
    let mut user = None;
    let mut password = None;
    let mut gateway = None;
    for raw_line in source.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with([' ', '\t']) {
                line = rest.trim_start();
            }
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("invalid credential assignment"))?;
        let slot = match key.trim() {
            "GP_USER" => &mut user,
            "GP_PASSWORD" => &mut password,
            key if key == origin_key => &mut gateway,
            _ => return Err(invalid("unsupported key in credential file")),
        };
        if slot.is_some() {
            return Err(invalid("duplicate key in credential file"));
        }
        let value = literal_value(value)?;
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(invalid(
                "credential value is empty, too long, or contains control characters",
            ));
        }
        *slot = Some(Zeroizing::new(value.to_owned()));
    }
    let user = user.ok_or_else(|| invalid("credential file requires GP_USER"))?;
    let password = password.ok_or_else(|| invalid("credential file requires GP_PASSWORD"))?;
    let raw_gateway =
        gateway.ok_or_else(|| invalid("credential file requires its role-specific origin key"))?;
    Ok((user, password, raw_gateway))
}

fn literal_value(value: &str) -> io::Result<&str> {
    let value = value.trim();
    if let Some(quote @ (b'\'' | b'"')) = value.as_bytes().first().copied() {
        if value.len() < 2 || value.as_bytes().last() != Some(&quote) {
            return Err(invalid("unmatched quote in credential value"));
        }
        return Ok(&value[1..value.len() - 1]);
    }
    Ok(value)
}

fn normalize_origin(raw: &str) -> io::Result<String> {
    if raw.len() > 2048
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
        || raw.contains('\\')
    {
        return Err(invalid("invalid credential HTTPS origin"));
    }
    let origin = Zeroizing::new(if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    });
    let authority_and_path = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| invalid("invalid credential HTTPS origin"))?;
    if authority_and_path
        .find('/')
        .is_some_and(|index| &authority_and_path[index..] != "/")
    {
        return Err(invalid("credential origin cannot contain a path"));
    }
    let gateway = Url::parse(&origin).map_err(|_| invalid("invalid credential HTTPS origin"))?;
    if gateway.scheme() != "https"
        || gateway.host_str().is_none()
        || !gateway.username().is_empty()
        || gateway.password().is_some()
        || gateway.path() != "/"
        || gateway.query().is_some()
        || gateway.fragment().is_some()
        || gateway.port_or_known_default() == Some(0)
    {
        return Err(invalid(
            "credential origin must be an HTTPS origin without credentials, path, query or fragment",
        ));
    }
    Ok(gateway.origin().ascii_serialization())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, io::Write, path::PathBuf};

    const SYNTHETIC: &str =
        "GP_USER=test-user\nGP_PASSWORD=test-password\nGP_GATEWAY=vpn.example.test:7777\n";

    struct SyntheticFile(PathBuf);

    impl SyntheticFile {
        fn create(source: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "gp-proxy-synthetic-credentials-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path).unwrap();
            file.write_all(source).unwrap();
            Self(path)
        }
    }

    impl Drop for SyntheticFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn portal_credentials_are_a_distinct_role_and_never_supply_a_gateway() {
        let source = "GP_USER=synthetic-user\nGP_PASSWORD='synthetic-secret'\nGP_PORTAL=portal.example.test:7443\n";
        let credentials = PortalCredentials::parse(source).unwrap();
        assert_eq!(credentials.portal, "https://portal.example.test:7443");
        assert_eq!(&*credentials.password, "synthetic-secret");
        assert!(Credentials::parse(source).is_err());
        assert!(PortalCredentials::parse(SYNTHETIC).is_err());
        for bad in [
            source.replace("GP_PORTAL=", "GP_GATEWAY="),
            format!("{source}GP_GATEWAY=vpn.example.test\n"),
            format!("{source}GP_PORTAL=another.example.test\n"),
            source.replace(
                "portal.example.test:7443",
                "https://portal.example.test/x/..",
            ),
            source.replace(
                "portal.example.test:7443",
                "https://user:secret@portal.example.test",
            ),
        ] {
            assert!(PortalCredentials::parse(&bad).is_err());
        }
        let debug = format!("{credentials:?}");
        assert_eq!(debug.matches("[REDACTED]").count(), 3);
        assert!(!debug.contains("synthetic") && !debug.contains("example"));
    }

    #[test]
    fn parses_given_shape_and_normalizes_https_gateway() {
        let credentials = Credentials::parse(SYNTHETIC).unwrap();
        assert_eq!(&*credentials.user, "test-user");
        assert_eq!(&*credentials.password, "test-password");
        assert_eq!(credentials.gateway, "https://vpn.example.test:7777");
    }

    #[test]
    fn values_are_literal_and_quotes_preserve_edge_spaces() {
        let credentials = Credentials::parse(
            "# test fixture\r\n export GP_USER = ' test user '\r\nGP_PASSWORD=\" ${HOME}#a=b\\n`id`$(id) \"\r\nGP_GATEWAY='https://vpn.example.test:7777/'\r\n"
        ).unwrap();
        assert_eq!(&*credentials.user, " test user ");
        assert_eq!(&*credentials.password, " ${HOME}#a=b\\n`id`$(id) ");
        let credentials =
            Credentials::parse(&SYNTHETIC.replace("test-password", "a#b=$HOME\\literal")).unwrap();
        assert_eq!(&*credentials.password, "a#b=$HOME\\literal");
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_malformed_entries() {
        for source in [
            "GP_USER=x\nGP_PASSWORD=y",
            "GP_USER=x\nGP_PASSWORD=y\nGP_GATEWAY=vpn.example.test\nGP_USER=z",
            "GP_USER=x\nGP_PASSWORD=y\nGP_GATEWAY=vpn.example.test\nGP_TYPO=z",
            "GP_USER=x\nGP_PASSWORD='unclosed\nGP_GATEWAY=vpn.example.test",
            "GP_USER=x\nGP_PASSWORD=\nGP_GATEWAY=vpn.example.test",
            "GP_USER=x\nGP_PASSWORD=x\ty\nGP_GATEWAY=vpn.example.test",
            "source some-file",
        ] {
            assert!(Credentials::parse(source).is_err());
        }
    }

    #[test]
    fn rejects_unsafe_gateway_origins_without_echoing_input() {
        for gateway in [
            "http://vpn.example.test:7777",
            "https://user:secret@vpn.example.test",
            "vpn.example.test/path",
            "vpn.example.test?auth=secret",
            "vpn.example.test#secret",
            "vpn.example.test:0",
            "vpn.example.test:invalid",
            "vpn.example.test\\path",
            "https://vpn.example.test/../path",
            "https://vpn.example.test/x/..",
            "vpn.example.test secret",
        ] {
            let source = SYNTHETIC.replace("vpn.example.test:7777", gateway);
            let result = Credentials::parse(&source);
            // URL normalization can erase a path: explicit path syntax is never allowed.
            assert!(result.is_err());
            let error = result.err().unwrap();
            assert!(!error.to_string().contains("secret"));
            assert!(!error.to_string().contains(gateway));
        }
    }

    #[test]
    fn all_debug_fields_are_redacted() {
        let credentials = Credentials::parse(SYNTHETIC).unwrap();
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("test-user"));
        assert!(!debug.contains("test-password"));
        assert!(!debug.contains("vpn.example.test"));
        assert_eq!(debug.matches("[REDACTED]").count(), 3);
    }

    #[test]
    fn reads_only_the_explicit_private_synthetic_file() {
        let file = SyntheticFile::create(SYNTHETIC.as_bytes());
        let credentials = Credentials::read(&file.0).unwrap();
        assert_eq!(&*credentials.password, "test-password");
    }

    #[test]
    fn rejects_oversize_and_non_utf8_files() {
        for source in [vec![b'a'; MAX_FILE_BYTES + 1], vec![0xff, 0xfe]] {
            let file = SyntheticFile::create(&source);
            assert!(Credentials::read(&file.0).is_err());
        }
        assert!(Credentials::parse(&"a".repeat(MAX_FILE_BYTES + 1)).is_err());
        assert!(Credentials::read(&std::env::temp_dir()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_readable_files() {
        use std::os::unix::fs::PermissionsExt;
        let file = SyntheticFile::create(SYNTHETIC.as_bytes());
        std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            Credentials::read(&file.0).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
