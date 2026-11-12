//! Small, credential-free declaration of the contracts needed by a manager.
//!
//! A compatible declaration is not executable authenticity or proof that an
//! arbitrary candidate is safe. The manager must first verify its candidate's
//! ownership and pinned release identity, then verify the actual started service.
//! Package versions alone cannot distinguish incompatible historical previews.

use serde::{Deserialize, Serialize};
use std::io;

/// Includes any surrounding JSON whitespace and the emitted final newline.
pub const MAX_CAPABILITIES_BYTES: usize = 1024;
const MAX_VERSION_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub schema: u8,
    pub control: u8,
    pub status: u8,
    pub log_store: u8,
    pub managed_contract: u8,
    pub managed_available: bool,
    /// Bounded diagnostic label. Compatibility is decided by the contract IDs.
    pub version: String,
}

impl Capabilities {
    /// Does not read configuration, credentials, environment, or filesystem.
    pub fn current() -> Self {
        Self {
            schema: 1,
            control: 5,
            status: 2,
            log_store: 1,
            managed_contract: 3,
            managed_available: cfg!(target_os = "macos"),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// One JSON object and one newline, with a fixed field order and no prose.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_CAPABILITIES_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }

    /// Accept one bounded declaration from a management-capable candidate.
    /// A structurally valid declaration with managed_available=false is refused.
    /// The caller must separately cap captured child output before buffering it.
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_CAPABILITIES_BYTES {
            return Err(invalid());
        }
        let capabilities: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        capabilities.validate_for_management()?;
        Ok(capabilities)
    }

    /// Validate an emitted declaration, including an honest unsupported platform.
    pub fn validate(&self) -> io::Result<()> {
        if self.schema != 1
            || self.control != 5
            || self.status != 2
            || self.log_store != 1
            || self.managed_contract != 3
            || self.version.is_empty()
            || self.version.len() > MAX_VERSION_BYTES
            || !self
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn validate_for_management(&self) -> io::Result<()> {
        self.validate()?;
        if !self.managed_available {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "candidate management is unavailable on its platform",
            ));
        }
        Ok(())
    }
}

/// Public identity of one admitted managed runtime, never an authentication secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedIdentity {
    pub installation: [u8; 16],
    pub generation: u64,
    pub release: [u8; 32],
}

impl ManagedIdentity {
    pub fn validate(&self) -> io::Result<()> {
        if self.generation == 0
            || self.installation.iter().all(|byte| *byte == 0)
            || self.release.iter().all(|byte| *byte == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed instance identity is invalid",
            ));
        }
        Ok(())
    }
}

fn invalid() -> io::Error {
    // Do not echo arbitrary candidate output or a serde error into diagnostics.
    io::Error::new(
        io::ErrorKind::InvalidData,
        "candidate management capabilities are invalid or incompatible",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPATIBLE: &[u8] = br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0"}"#;

    #[test]
    fn fixed_output_and_package_version_independent_compatibility() {
        let expected = format!(
            "{{\"schema\":1,\"control\":5,\"status\":2,\"log_store\":1,\"managed_contract\":3,\"managed_available\":{},\"version\":\"{}\"}}\n",
            cfg!(target_os = "macos"),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            Capabilities::current().encode().unwrap(),
            expected.as_bytes()
        );
        let remote = br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"9.4.1-alpha.2+review"}"#;
        assert_eq!(
            Capabilities::parse(remote).unwrap().version,
            "9.4.1-alpha.2+review"
        );
        assert_eq!(Capabilities::parse(COMPATIBLE).unwrap().version, "0.1.0");
        for old_output in [
            b"gp-proxy 0.1.0\n".as_slice(),
            br#"{"schema":1,"control":4,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0"}"#,
            br#"{"version":"0.1.0"}"#,
            br#"{"schema":1,"control":5,"status":2,"log_store":1,"version":"0.1.0"}"#,
        ] {
            assert!(Capabilities::parse(old_output).is_err());
        }
    }

    #[test]
    fn unsupported_platform_can_declare_itself_but_is_not_a_managed_candidate() {
        let current = Capabilities::current();
        assert_eq!(current.managed_available, cfg!(target_os = "macos"));
        let emitted = current.encode().unwrap();
        #[cfg(target_os = "macos")]
        assert!(Capabilities::parse(&emitted).is_ok());
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            Capabilities::parse(&emitted).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let mut unsupported = current;
        unsupported.managed_available = false;
        let output = unsupported.encode().unwrap();
        assert!(unsupported.validate().is_ok());
        assert_eq!(
            Capabilities::parse(&output).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn every_contract_is_required_and_must_match() {
        for field in [
            "schema",
            "control",
            "status",
            "log_store",
            "managed_contract",
            "managed_available",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(COMPATIBLE).unwrap();
            value[field] = serde_json::json!(99);
            assert!(Capabilities::parse(&serde_json::to_vec(&value).unwrap()).is_err());
            value.as_object_mut().unwrap().remove(field);
            assert!(Capabilities::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = Capabilities::current();
        value.managed_contract = 0;
        assert!(
            value.encode().is_err(),
            "local callers cannot encode a mismatched contract"
        );
        value.managed_contract = 2;
        assert!(
            value.encode().is_err(),
            "runtime without incarnation history is incompatible"
        );
        value.managed_contract = 1;
        assert!(
            value.encode().is_err(),
            "legacy deployment format is incompatible"
        );
    }

    #[test]
    fn ambiguous_output_unknown_fields_and_unsafe_labels_are_rejected() {
        for bytes in [
            br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0","extra":true}"#.as_slice(),
            br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0","version":"0.1.0"}"#,
            br#"{"schema":1,"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0"}"#,
            br#"{"schema":1,"control":true,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0"}"#,
            br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0\u001b[31m"}"#,
            br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":""}"#,
            b"\xff",
            b"[]",
        ] {
            let error = Capabilities::parse(bytes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "candidate management capabilities are invalid or incompatible");
        }
        let mut repeated = COMPATIBLE.to_vec();
        repeated.extend_from_slice(COMPATIBLE);
        assert!(Capabilities::parse(&repeated).is_err());
    }

    #[test]
    fn document_and_version_bounds_include_whitespace() {
        let mut at_limit = COMPATIBLE.to_vec();
        at_limit.resize(MAX_CAPABILITIES_BYTES, b' ');
        assert!(Capabilities::parse(&at_limit).is_ok());
        at_limit.push(b'\n');
        assert!(Capabilities::parse(&at_limit).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(COMPATIBLE).unwrap();
        value["version"] = serde_json::json!("a".repeat(MAX_VERSION_BYTES));
        assert!(Capabilities::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["version"] = serde_json::json!("a".repeat(MAX_VERSION_BYTES + 1));
        assert!(Capabilities::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn managed_identity_requires_exact_shapes_and_nonzero_fields() {
        let valid = ManagedIdentity {
            installation: [1; 16],
            generation: 1,
            release: [2; 32],
        };
        assert!(valid.validate().is_ok());
        for invalid in [
            ManagedIdentity {
                installation: [0; 16],
                ..valid
            },
            ManagedIdentity {
                generation: 0,
                ..valid
            },
            ManagedIdentity {
                release: [0; 32],
                ..valid
            },
        ] {
            assert_eq!(
                invalid.validate().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut value = serde_json::to_value(valid).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ManagedIdentity>(value).is_err());
        let mut value = serde_json::to_value(valid).unwrap();
        value["installation"] = serde_json::json!([1]);
        assert!(serde_json::from_value::<ManagedIdentity>(value).is_err());
        let mut value = serde_json::to_value(valid).unwrap();
        value["release"] = serde_json::json!([2]);
        assert!(serde_json::from_value::<ManagedIdentity>(value).is_err());
    }
}
