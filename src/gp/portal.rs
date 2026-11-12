//! Explicit password/challenge portal authentication for a fixed gateway.
//! This minimal profile uses protocol observations, not copied reference code.
//! It neither installs portal policy nor falls back to forwarding a password.

use super::{challenge, client::client_os, xml, GatewayClient, GpError, ResumptionPolicy};
use std::{collections::HashSet, sync::Arc};
use url::Url;
use zeroize::Zeroizing;

const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_POLICY_NODES: usize = 4096;
const MAX_GATEWAYS: usize = 128;
const MAX_PRIORITIES: usize = 64;

pub enum PortalProgress {
    Cookies(PortalCookies),
    Challenge(PortalChallenge),
}

/// One-use, origin- and authentication-client-bound portal continuation. A
/// distinct type prevents gateway/portal endpoint substitution, even on one host.
/// No original password is retained; no Debug, Clone or serialization is offered.
///
/// A portal challenge cannot be submitted to the gateway endpoint:
/// ```compile_fail
/// fn wrong_endpoint(client: &gp_proxy::gp::GatewayClient, challenge: gp_proxy::gp::PortalChallenge) {
///     let _ = client.answer_challenge(challenge, zeroize::Zeroizing::new("answer".into()));
/// }
/// ```
/// Nor can a direct-gateway challenge be submitted to the portal:
/// ```compile_fail
/// fn wrong_endpoint(client: &gp_proxy::gp::PortalClient, challenge: gp_proxy::gp::LoginChallenge) {
///     let _ = client.answer_challenge(challenge, zeroize::Zeroizing::new("answer".into()));
/// }
/// ```
pub struct PortalChallenge {
    user: String,
    computer: String,
    input_str: Zeroizing<String>,
    portal: Url,
    gateway: Url,
    authentication: Arc<()>,
    prompt: String,
    round: u8,
}

impl PortalChallenge {
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn round(&self) -> u8 {
        self.round
    }
}

/// Opaque bearer credentials, consumed once by the fixed gateway. Dropping them
/// clears local secrets; no remote portal-cookie revocation endpoint is assumed.
pub struct PortalCookies {
    pub(super) user: String,
    pub(super) computer: String,
    pub(super) portal: Url,
    pub(super) gateway: Url,
    pub(super) user_cookie: Zeroizing<String>,
    pub(super) prelogon_cookie: Option<Zeroizing<String>>,
}

#[derive(Clone)]
pub struct PortalClient {
    // Reuse the bounded HTTPS transport only. Login endpoints stay explicit here.
    transport: GatewayClient,
    gateway: Url,
    authentication: Arc<()>,
}

pub(super) fn cookie_password() -> Result<&'static str, GpError> {
    match std::env::consts::OS {
        "macos" => Ok(""),
        "linux" => Ok("SAMLPASS"),
        // Other OS profiles have not been established by the pinned evidence.
        _ => Err(GpError::UnsupportedAuthentication),
    }
}

fn validate_origin(origin: &Url) -> Result<(), GpError> {
    if origin.as_str().len() > 2048
        || origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
        || origin.port_or_known_default() == Some(0)
    {
        return Err(GpError::Protocol(
            "portal authentication requires fixed HTTPS origins",
        ));
    }
    Ok(())
}

fn login_input(user: &str, secret: &str, computer: &str) -> Result<(), GpError> {
    for (value, limit) in [
        (user, challenge::MAX_SECRET),
        (secret, challenge::MAX_SECRET),
        (computer, 255),
    ] {
        if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
            return Err(GpError::Protocol("invalid portal authentication input"));
        }
    }
    Ok(())
}

impl PortalClient {
    /// Construct without network access. The portal and gateway remain fixed;
    /// supplied TLS trust is never augmented by a portal policy response.
    pub fn new(
        portal: Url,
        fixed_gateway: Url,
        tls: Arc<rustls::ClientConfig>,
        policy: ResumptionPolicy,
    ) -> Result<Self, GpError> {
        validate_origin(&portal)?;
        validate_origin(&fixed_gateway)?;
        cookie_password()?;
        Ok(Self {
            transport: GatewayClient::new(portal, tls, policy)?,
            gateway: fixed_gateway,
            authentication: Arc::new(()),
        })
    }

    pub fn origin(&self) -> &Url {
        self.transport.gateway()
    }
    pub fn fixed_gateway(&self) -> &Url {
        &self.gateway
    }

    pub(crate) fn for_authentication(&self) -> Self {
        Self {
            transport: self.transport.for_authentication(),
            gateway: self.gateway.clone(),
            authentication: Arc::new(()),
        }
    }

    /// Read-only discovery; SAML and other authentication modes are not silently
    /// converted into password authentication by this portal profile.
    pub async fn prelogin(&self) -> Result<(), GpError> {
        let path = format!(
            "/global-protect/prelogin.esp?tmp=tmp&clientVer=4100&clientos={}",
            client_os()
        );
        let response = self.transport.post_guarded(&path, &[], || Ok(())).await?;
        parse_prelogin(&response)
    }

    pub async fn begin_login(
        &self,
        user: &str,
        password: &str,
        computer: &str,
    ) -> Result<PortalProgress, GpError> {
        self.begin_login_guarded(user, password, computer, || Ok(()))
            .await
    }

    pub(crate) async fn begin_login_guarded(
        &self,
        user: &str,
        password: &str,
        computer: &str,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<PortalProgress, GpError> {
        login_input(user, password, computer)?;
        self.login_post(user, password, computer, None, 1, before_write)
            .await
    }

    pub async fn answer_challenge(
        &self,
        continuation: PortalChallenge,
        answer: Zeroizing<String>,
    ) -> Result<PortalProgress, GpError> {
        self.answer_challenge_guarded(continuation, answer, || Ok(()))
            .await
    }

    pub(crate) async fn answer_challenge_guarded(
        &self,
        continuation: PortalChallenge,
        answer: Zeroizing<String>,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<PortalProgress, GpError> {
        if continuation.portal != *self.origin()
            || continuation.gateway != self.gateway
            || !Arc::ptr_eq(&continuation.authentication, &self.authentication)
        {
            return Err(GpError::Protocol("portal challenge client mismatch"));
        }
        login_input(&continuation.user, &answer, &continuation.computer)?;
        self.login_post(
            &continuation.user,
            &answer,
            &continuation.computer,
            Some(&continuation.input_str),
            continuation.round + 1,
            before_write,
        )
        .await
    }

    async fn login_post(
        &self,
        user: &str,
        secret: &str,
        computer: &str,
        input_str: Option<&str>,
        round: u8,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<PortalProgress, GpError> {
        let mut fields = vec![
            ("jnlpReady", "jnlpReady"),
            ("ok", "Login"),
            ("direct", "yes"),
            ("clientVer", "4100"),
            ("prot", "https:"),
            ("internal", "no"),
            ("clientos", client_os()),
            ("os-version", std::env::consts::OS),
            ("ipv6-support", "no"),
            ("server", self.origin().host_str().unwrap_or_default()),
            ("computer", computer),
            ("user", user),
            ("passwd", secret),
        ];
        if let Some(state) = input_str {
            fields.push(("inputStr", state));
        }
        let response = self
            .transport
            .post_guarded("/global-protect/getconfig.esp", &fields, before_write)
            .await?;
        if let Some(fields) = challenge::parse(&response)? {
            if round > challenge::MAX_ROUNDS {
                return Err(GpError::Protocol("portal challenge round limit exceeded"));
            }
            return Ok(PortalProgress::Challenge(PortalChallenge {
                user: user.to_owned(),
                computer: computer.to_owned(),
                input_str: fields.input_str,
                portal: self.origin().clone(),
                gateway: self.gateway.clone(),
                authentication: self.authentication.clone(),
                prompt: fields.prompt,
                round,
            }));
        }
        let cookies = parse_policy(&response, &self.gateway)?;
        Ok(PortalProgress::Cookies(PortalCookies {
            user: user.to_owned(),
            computer: computer.to_owned(),
            portal: self.origin().clone(),
            gateway: self.gateway.clone(),
            user_cookie: cookies.user,
            prelogon_cookie: cookies.prelogon,
        }))
    }
}

struct PolicyCookies {
    user: Zeroizing<String>,
    prelogon: Option<Zeroizing<String>>,
}

fn invalid() -> GpError {
    GpError::Protocol("invalid portal policy")
}

fn parse_prelogin(body: &str) -> Result<(), GpError> {
    if body.len() > 64 * 1024 {
        return Err(invalid());
    }
    let doc = xml(body)?;
    let root = doc.root_element();
    if !root.has_tag_name("prelogin-response") {
        return Err(GpError::Authentication);
    }
    let fields = unique(
        root,
        &[
            "status",
            "authentication-message",
            "username-label",
            "password-label",
            "region",
            "ccusername",
            "autosubmit",
            "msg",
            "newmsg",
            "panos-version",
            "saml-request",
            "saml-auth-method",
        ],
    )?;
    let mut success = false;
    for field in fields {
        let value = scalar(field)?;
        if value.len() > 8192 {
            return Err(invalid());
        }
        match field.tag_name().name() {
            "status" => success = value.trim() == "Success",
            "saml-request" | "saml-auth-method" => return Err(GpError::UnsupportedAuthentication),
            "ccusername" if !value.is_empty() => return Err(GpError::UnsupportedAuthentication),
            "autosubmit" if !matches!(value.trim(), "" | "false" | "no") => {
                return Err(GpError::UnsupportedAuthentication)
            }
            _ => (),
        }
    }
    if !success {
        return Err(GpError::Authentication);
    }
    Ok(())
}

fn plain(node: roxmltree::Node<'_, '_>) -> Result<(), GpError> {
    if !node.is_element()
        || node.tag_name().namespace().is_some()
        || node.namespaces().len() != 0
        || node.attributes().len() != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn children<'a>(node: roxmltree::Node<'a, 'a>) -> Result<Vec<roxmltree::Node<'a, 'a>>, GpError> {
    let mut result = Vec::new();
    for child in node.children() {
        if child.is_element() {
            result.push(child);
        } else if !child.is_text() || !child.text().unwrap_or_default().trim().is_empty() {
            return Err(invalid());
        }
    }
    Ok(result)
}

fn scalar<'a>(node: roxmltree::Node<'a, 'a>) -> Result<&'a str, GpError> {
    plain(node)?;
    if node.children().any(|node| !node.is_text()) || node.children().count() > 1 {
        return Err(invalid());
    }
    Ok(node.text().unwrap_or_default())
}

fn unique<'a>(
    node: roxmltree::Node<'a, 'a>,
    allowed: &[&str],
) -> Result<Vec<roxmltree::Node<'a, 'a>>, GpError> {
    plain(node)?;
    let nodes = children(node)?;
    let mut seen = HashSet::new();
    for child in &nodes {
        if !allowed.contains(&child.tag_name().name()) || !seen.insert(child.tag_name().name()) {
            return Err(invalid());
        }
    }
    Ok(nodes)
}

fn cookie(node: roxmltree::Node<'_, '_>) -> Result<Option<Zeroizing<String>>, GpError> {
    let value = scalar(node)?;
    if value.len() > challenge::MAX_SECRET || value.chars().any(char::is_control) {
        return Err(invalid());
    }
    if value.trim().is_empty() || matches!(value.trim(), "empty" | "(null)") {
        return Ok(None);
    }
    Ok(Some(Zeroizing::new(value.to_owned())))
}

fn authority(value: &str) -> Result<Url, GpError> {
    if value.is_empty()
        || value.len() > 2048
        || !value.is_ascii()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || "/\\@?#%".contains(ch))
    {
        return Err(invalid());
    }
    let origin = Url::parse(&format!("https://{value}")).map_err(|_| invalid())?;
    validate_origin(&origin)?;
    let canonical = &origin[url::Position::BeforeHost..url::Position::AfterPort];
    // Permit DNS case and the conventional explicit default port, not alternate
    // numeric-IP spellings, escaped authorities or arbitrary URL interpretation.
    if !(value.eq_ignore_ascii_case(canonical)
        || origin.port_or_known_default() == Some(443)
            && value.eq_ignore_ascii_case(&format!("{canonical}:443")))
    {
        return Err(invalid());
    }
    Ok(origin)
}

fn named_entry<'a>(node: roxmltree::Node<'a, 'a>) -> Result<&'a str, GpError> {
    if !node.has_tag_name("entry")
        || node.tag_name().namespace().is_some()
        || node.namespaces().len() != 0
        || node.attributes().len() != 1
    {
        return Err(invalid());
    }
    node.attribute("name").ok_or_else(invalid)
}

fn priorities(node: roxmltree::Node<'_, '_>) -> Result<(), GpError> {
    plain(node)?;
    let entries = children(node)?;
    if entries.len() > MAX_PRIORITIES {
        return Err(invalid());
    }
    let mut regions = HashSet::new();
    for entry in entries {
        let region = named_entry(entry)?;
        if region.is_empty()
            || region.len() > 64
            || region.chars().any(char::is_control)
            || !regions.insert(region)
        {
            return Err(invalid());
        }
        let fields = children(entry)?;
        if fields.len() != 1 || !fields[0].has_tag_name("priority") {
            return Err(invalid());
        }
        let priority = scalar(fields[0])?.trim();
        if priority.is_empty()
            || !priority.bytes().all(|byte| byte.is_ascii_digit())
            || priority.parse::<u16>().is_err()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn gateways(node: roxmltree::Node<'_, '_>, expected: &Url) -> Result<(), GpError> {
    let fields = unique(node, &["external", "internal"])?;
    let external = fields
        .iter()
        .find(|node| node.has_tag_name("external"))
        .ok_or_else(invalid)?;
    let fields = unique(*external, &["list"])?;
    let list = fields.first().ok_or_else(invalid)?;
    plain(*list)?;
    let entries = children(*list)?;
    if entries.is_empty() || entries.len() > MAX_GATEWAYS {
        return Err(invalid());
    }
    let mut origins = HashSet::new();
    let mut found = false;
    for entry in entries {
        let origin = authority(named_entry(entry)?)?;
        if !origins.insert(origin.as_str().to_owned()) {
            return Err(invalid());
        }
        found |= origin == *expected;
        let mut seen = HashSet::new();
        for field in children(entry)? {
            if !seen.insert(field.tag_name().name()) {
                return Err(invalid());
            }
            match field.tag_name().name() {
                "description" => {
                    if scalar(field)?.len() > 2048 {
                        return Err(invalid());
                    }
                }
                "priority-rule" => priorities(field)?,
                _ => return Err(invalid()),
            }
        }
    }
    if !found {
        return Err(GpError::ConfigurationRejected);
    }
    Ok(())
}

fn parse_policy(body: &str, gateway: &Url) -> Result<PolicyCookies, GpError> {
    if body.len() > MAX_POLICY_BYTES {
        return Err(invalid());
    }
    let doc = xml(body)?;
    let root = doc.root_element();
    if !root.has_tag_name("policy") {
        return Err(GpError::Authentication);
    }
    if doc.descendants().count() > MAX_POLICY_NODES
        || doc.descendants().any(|node| {
            node.is_comment()
                || node.is_pi()
                || (node.is_element()
                    && (node.tag_name().namespace().is_some() || node.namespaces().len() != 0))
        })
    {
        return Err(invalid());
    }
    let fields = unique(
        root,
        &[
            "gateways",
            "has-config",
            "portal-userauthcookie",
            "portal-prelogonuserauthcookie",
            // Explicitly ignored, never installed, executed or used to augment trust.
            "version",
            "portal-name",
            "hip-collection",
            "root-ca",
            "welcome-page",
            "help-page",
            "help-page-2",
            "internal-host-detection",
            "connect-method",
            "max-internal-gateway-connection-attempts",
        ],
    )?;
    let mut user = None;
    let mut prelogon = None;
    let mut matched = false;
    for field in fields {
        match field.tag_name().name() {
            "gateways" => {
                gateways(field, gateway)?;
                matched = true;
            }
            "has-config" => match scalar(field)?.trim() {
                "yes" => (),
                "no" => return Err(GpError::ConfigurationRejected),
                _ => return Err(invalid()),
            },
            "portal-userauthcookie" => user = cookie(field)?,
            "portal-prelogonuserauthcookie" => prelogon = cookie(field)?,
            _ => (),
        }
    }
    if !matched {
        return Err(GpError::ConfigurationRejected);
    }
    Ok(PolicyCookies {
        user: user.ok_or(GpError::UnsupportedAuthentication)?,
        prelogon,
    })
}

#[cfg(test)]
#[path = "portal_tests.rs"]
mod tests;
