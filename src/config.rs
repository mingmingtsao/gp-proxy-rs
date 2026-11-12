use serde::Deserialize;
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub gateway: String,
    /// Explicit portal origin; credentials never change the selected gateway.
    pub portal: Option<String>,
    /// Independent portal trust roots; never reused for the gateway.
    pub portal_ca_file: Option<PathBuf>,
    pub http_listen: SocketAddr,
    pub socks_listen: SocketAddr,
    pub domains: Vec<String>,
    pub networks: Vec<ipnet::IpNet>,
    /// Relative paths are resolved beside the selected configuration file.
    pub ca_file: Option<PathBuf>,
    pub max_connections: usize,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub reconnect_max_secs: u64,
    /// Local check schedule for direct gateway mode; not a portal-provided value.
    pub hip_check_interval_secs: u64,
    pub trust_gateway_routes: bool,
    /// Relative paths are resolved beside the selected configuration file.
    /// Omitted paths default to that file with a `.pac-history.json` extension.
    pub pac_history_file: Option<PathBuf>,
    /// Runtime writer capability; never read from TOML or used as egress authority.
    #[serde(skip)]
    pub pac_history: Option<Arc<crate::pac_history::PacHistory>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway: String::new(),
            portal: None,
            portal_ca_file: None,
            http_listen: "127.0.0.1:8080".parse().unwrap(),
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            domains: vec![],
            networks: vec![],
            ca_file: None,
            max_connections: 128,
            connect_timeout_secs: 15,
            idle_timeout_secs: 300,
            reconnect_max_secs: 60,
            hip_check_interval_secs: 3540,
            trust_gateway_routes: false,
            pac_history_file: None,
            pac_history: None,
        }
    }
}

impl Config {
    pub fn read(path: &Path) -> io::Result<Self> {
        Self::read_with_gateway(path, None)
    }

    /// An explicitly selected credential file takes precedence over the TOML gateway.
    pub fn read_with_gateway(path: &Path, gateway: Option<&str>) -> io::Result<Self> {
        let mut config = Self::read_fields(path)?;
        if let Some(gateway) = gateway {
            if config.portal.is_some() {
                return Err(invalid(
                    "gateway credential overrides are forbidden in portal mode",
                ));
            }
            config.gateway = gateway.to_owned();
        }
        config.validate()?;
        Ok(config)
    }

    /// Check the nonsecret mode before the caller opens a direct credential file.
    /// The configuration is read exactly once; only direct mode permits an override.
    pub fn read_with_gateway_provider(
        path: &Path,
        provider: impl FnOnce() -> io::Result<String>,
    ) -> io::Result<Self> {
        let mut config = Self::read_fields(path)?;
        if config.portal.is_some() {
            return Err(invalid(
                "--env-file is forbidden in portal mode; use --portal-env-file",
            ));
        }
        config.gateway = provider()?;
        config.validate()?;
        Ok(config)
    }

    fn read_fields(path: &Path) -> io::Result<Self> {
        let bytes =
            crate::local_file::read(path, crate::local_file::Access::Public).map_err(|error| {
                io::Error::new(error.kind(), format!("configuration file: {error}"))
            })?;
        let source =
            std::str::from_utf8(&bytes).map_err(|_| invalid("configuration must be UTF-8 TOML"))?;
        let mut config: Self = toml::from_str(source)
            .map_err(|_| invalid("invalid configuration TOML; check field names and types"))?;
        // Keep file-relative inputs beside the selected path, even when the
        // selected config is a deployment symlink to a different directory.
        config.ca_file = config.ca_file.map(|ca| {
            if ca.is_absolute() {
                ca
            } else {
                path.parent().unwrap_or(Path::new(".")).join(ca)
            }
        });
        config.portal_ca_file = config.portal_ca_file.map(|ca| {
            if ca.is_absolute() {
                ca
            } else {
                path.parent().unwrap_or(Path::new(".")).join(ca)
            }
        });
        config.pac_history_file = Some(match config.pac_history_file {
            Some(ref history) if history.is_absolute() => history.clone(),
            Some(ref history) => path.parent().unwrap_or(Path::new(".")).join(history),
            None => path.with_extension("pac-history.json"),
        });
        Ok(config)
    }

    pub fn auth_binding(&self) -> io::Result<crate::auth::AuthBinding> {
        match &self.portal {
            Some(portal) => crate::auth::AuthBinding::via_portal(portal, &self.gateway),
            None => crate::auth::AuthBinding::direct(&self.gateway),
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        self.auth_binding()?;
        if self.portal.is_none() && self.portal_ca_file.is_some() {
            return Err(invalid("portal_ca_file requires an explicit portal"));
        }
        for listen in [self.http_listen, self.socks_listen] {
            if !listen.ip().is_loopback() || listen.port() == 0 {
                return Err(invalid(
                    "proxy listeners must use loopback IPs and nonzero ports",
                ));
            }
        }
        if self.http_listen == self.socks_listen {
            return Err(invalid("HTTP and SOCKS listeners must differ"));
        }
        if !(1..=4096).contains(&self.max_connections) {
            return Err(invalid("max_connections must be 1..=4096"));
        }
        if !(1..=120).contains(&self.connect_timeout_secs) {
            return Err(invalid("connect_timeout_secs must be 1..=120"));
        }
        if !(1..=86400).contains(&self.idle_timeout_secs) {
            return Err(invalid("idle_timeout_secs must be 1..=86400"));
        }
        if !(1..=600).contains(&self.reconnect_max_secs) {
            return Err(invalid("reconnect_max_secs must be 1..=600"));
        }
        if !(60..=3600).contains(&self.hip_check_interval_secs) {
            return Err(invalid("hip_check_interval_secs must be 60..=3600"));
        }
        if self.domains.len() > 1024 || self.networks.len() > 1024 {
            return Err(invalid("too many policy entries"));
        }
        if self.domains.is_empty() && self.networks.is_empty() && !self.trust_gateway_routes {
            return Err(invalid(
                "configure authorized domains/networks or explicitly trust gateway routes",
            ));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Config {
        Config {
            gateway: "https://vpn.example.com".into(),
            domains: vec!["corp.example.com".into()],
            ..Config::default()
        }
    }
    #[test]
    fn refuses_remote_listeners_and_credentials_in_gateway() {
        let mut c = good();
        assert!(c.validate().is_ok());
        c.http_listen = "0.0.0.0:8080".parse().unwrap();
        assert!(c.validate().is_err());
        c = good();
        c.gateway = "https://user:secret@vpn.example.com".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn portal_identity_and_roots_are_independent_of_the_gateway() {
        let mut config = good();
        config.portal_ca_file = Some("portal.pem".into());
        assert!(config.validate().is_err());
        config.portal = Some("https://vpn.example.com:7443".into());
        assert!(config.validate().is_ok());
        let binding = config.auth_binding().unwrap();
        assert_eq!(
            binding.portal_origin(),
            Some("https://vpn.example.com:7443")
        );
        assert_eq!(binding.gateway(), "https://vpn.example.com");
        assert!(!binding.matches(&crate::auth::AuthBinding::direct(binding.gateway()).unwrap()));
        for bad in [
            "http://portal.example.test",
            "https://portal.example.test/x/..",
            "https://user:secret@portal.example.test",
        ] {
            config.portal = Some(bad.into());
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn portal_configuration_rejects_direct_provider_before_opening_credentials() {
        let directory =
            std::env::temp_dir().join(format!("gp-config-portal-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("config.toml");
        std::fs::write(&path, "gateway='https://vpn.example.test'\nportal='https://portal.example.test'\nportal_ca_file='portal.pem'\nca_file='gateway.pem'\ndomains=['corp.example.test']\n").unwrap();
        let called = std::cell::Cell::new(false);
        let result = Config::read_with_gateway_provider(&path, || {
            called.set(true);
            Ok("https://override.example.test".into())
        });
        assert!(result.is_err());
        assert!(!called.get());
        assert!(Config::read_with_gateway(&path, Some("https://override.example.test")).is_err());
        let loaded = Config::read(&path).unwrap();
        assert_eq!(loaded.ca_file, Some(directory.join("gateway.pem")));
        assert_eq!(loaded.portal_ca_file, Some(directory.join("portal.pem")));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_unknown_settings() {
        assert!(toml::from_str::<Config>("allow_direct = true").is_err());
    }

    #[test]
    fn hip_interval_has_a_safe_default_and_bounded_override() {
        assert_eq!(good().hip_check_interval_secs, 3540);
        for interval in [0, 59, 3601, u64::MAX] {
            let mut config = good();
            config.hip_check_interval_secs = interval;
            assert!(config.validate().is_err());
        }
        for interval in [60, 3540, 3600] {
            let mut config = good();
            config.hip_check_interval_secs = interval;
            assert!(config.validate().is_ok());
        }
    }
}
