use super::{
    challenge, child_text, parse_config, scalar_text, secret_buffer::SecretBuffer, xml, GpError,
    LoginChallenge, LoginProgress, TunnelConfig, MAX_XML,
};
use rustls::client::ClientSessionStore;
use std::{fmt, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use url::Url;
use zeroize::Zeroizing;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADERS: usize = 16 * 1024;
pub type TlsTunnel = TlsStream<TcpStream>;

/// Report freshness/request status, not a HIP compliance or access decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HipStatus {
    NotRequested,
    ReportRequested,
}

pub(super) fn client_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "Mac",
        "windows" => "Windows",
        _ => "Linux",
    }
}

#[derive(Clone)]
pub struct Session {
    pub user: String,
    auth_cookie: Zeroizing<String>,
    pub portal: String,
    pub domain: String,
    pub computer: String,
    pub preferred_ip: Option<Ipv4Addr>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(
        user: String,
        auth_cookie: String,
        portal: String,
        domain: String,
        computer: String,
        preferred_ip: Option<Ipv4Addr>,
    ) -> Result<Self, GpError> {
        let auth_cookie = Zeroizing::new(auth_cookie);
        for field in [&user, &*auth_cookie, &portal, &domain, &computer] {
            if field.len() > 8192 || field.chars().any(char::is_control) {
                return Err(GpError::Protocol("invalid session credential field"));
            }
        }
        if user.is_empty() || auth_cookie.is_empty() || computer.is_empty() {
            return Err(GpError::Protocol("missing session credential field"));
        }
        Ok(Self {
            user,
            auth_cookie,
            portal,
            domain,
            computer,
            preferred_ip,
        })
    }

    fn fields(&self) -> Vec<(&str, &str)> {
        vec![
            ("user", &self.user),
            ("authcookie", &self.auth_cookie),
            ("portal", &self.portal),
            ("domain", &self.domain),
            ("computer", &self.computer),
        ]
    }
}

/// Parses native gateway JNLP login responses. Portal discovery and interactive
/// challenges are deliberately not interpreted as a successful gateway session.
pub fn parse_login(body: &str, computer: &str) -> Result<Session, GpError> {
    let doc = xml(body).map_err(|_| GpError::UnsupportedAuthentication)?;
    let root = doc.root_element();
    if !root.has_tag_name("jnlp") {
        return Err(GpError::Authentication);
    }
    let descriptions: Vec<_> = root
        .children()
        .filter(|n| n.has_tag_name("application-desc"))
        .collect();
    if descriptions.len() != 1 {
        return Err(GpError::Protocol("ambiguous login response"));
    }
    let args: Vec<_> = descriptions[0]
        .children()
        .filter(|n| n.is_element())
        .map(|n| {
            if !n.has_tag_name("argument") {
                return Err(GpError::Protocol("unexpected login response field"));
            }
            let value = scalar_text(n)?.trim();
            // Values in this XML are themselves URL-encoded by some gateways.
            let mut decoded =
                super::form::decode_argument(if value == "(null)" { "" } else { value })?;
            if matches!(decoded.as_str(), "(null)" | "-1") {
                decoded.clear();
            }
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args.len() < 15 || args[12].as_str() != "tunnel" || args[14].as_str() != "4100" {
        return Err(GpError::Protocol("unsupported gateway login protocol"));
    }
    let preferred_ip = args
        .get(15)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|_| GpError::Protocol("invalid preferred IPv4 address"))
        })
        .transpose()?;
    Session::new(
        args[4].to_string(),
        args[1].to_string(),
        args[3].to_string(),
        args[7].to_string(),
        computer.to_owned(),
        preferred_ip,
    )
}

#[derive(Clone)]
pub struct GatewayClient {
    gateway: Url,
    tls: Arc<rustls::ClientConfig>,
    resumption: ResumptionPolicy,
    // Clones share one authentication capability and TLS cache. A new lifecycle
    // gets a distinct identity even when its origin and trust are unchanged.
    authentication: Arc<()>,
}

/// Explicit transport policy; opaque `ClientConfig::resumption` cannot safely
/// be cloned into an independent cache while preserving its TLS 1.2 settings.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ResumptionPolicy {
    Disabled,
    Memory {
        tls12: rustls::client::Tls12Resumption,
    },
}

impl ResumptionPolicy {
    fn fresh_config(self, template: &rustls::ClientConfig) -> Arc<rustls::ClientConfig> {
        let mut config = template.clone();
        config.resumption = match self {
            Self::Disabled => rustls::client::Resumption::disabled(),
            Self::Memory {
                tls12: rustls::client::Tls12Resumption::Disabled,
            } => {
                // rustls 0.23.46 still reads/stores session IDs with an ordinary
                // memory store in this mode. Enforce the explicit policy at the
                // store boundary, while retaining bounded TLS 1.3 tickets.
                rustls::client::Resumption::store(Arc::new(Tls13OnlySessions(
                    rustls::client::ClientSessionMemoryCache::new(8),
                )))
                .tls12_resumption(rustls::client::Tls12Resumption::Disabled)
            }
            // A GatewayClient has one immutable origin. Keep up to eight
            // tickets (and rustls's single TLS 1.2 session) for its server name.
            Self::Memory { tls12 } => {
                rustls::client::Resumption::in_memory_sessions(8).tls12_resumption(tls12)
            }
        };
        Arc::new(config)
    }
}

struct Tls13OnlySessions(rustls::client::ClientSessionMemoryCache);

impl fmt::Debug for Tls13OnlySessions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tls13OnlySessions")
            .finish_non_exhaustive()
    }
}

impl ClientSessionStore for Tls13OnlySessions {
    fn set_kx_hint(&self, name: rustls::pki_types::ServerName<'static>, group: rustls::NamedGroup) {
        self.0.set_kx_hint(name, group);
    }
    fn kx_hint(&self, name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.0.kx_hint(name)
    }
    fn set_tls12_session(
        &self,
        _: rustls::pki_types::ServerName<'static>,
        _: rustls::client::Tls12ClientSessionValue,
    ) {
        // Do not retain the TLS 1.2 master secret or ticket.
    }
    fn tls12_session(
        &self,
        _: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _: &rustls::pki_types::ServerName<'static>) {}
    fn insert_tls13_ticket(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.0.insert_tls13_ticket(name, value);
    }
    fn take_tls13_ticket(
        &self,
        name: &rustls::pki_types::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.0.take_tls13_ticket(name)
    }
}

impl GatewayClient {
    pub(crate) fn gateway(&self) -> &Url {
        &self.gateway
    }

    /// `tls` must enforce normal certificate chain and hostname validation.
    /// The caller selects the crypto provider and resumption policy explicitly.
    /// The supplied configuration's resumption field is replaced with a fresh
    /// origin-local cache under that policy; its other TLS settings are kept.
    /// Clones share this cache, but separately constructed clients never do.
    pub fn new(
        gateway: Url,
        tls: Arc<rustls::ClientConfig>,
        resumption: ResumptionPolicy,
    ) -> Result<Self, GpError> {
        if gateway.scheme() != "https"
            || gateway.host_str().is_none()
            || !gateway.username().is_empty()
            || gateway.password().is_some()
            || gateway.query().is_some()
            || gateway.fragment().is_some()
            || !matches!(gateway.path(), "" | "/")
        {
            return Err(GpError::Protocol(
                "gateway must be an HTTPS origin without credentials or path",
            ));
        }
        Ok(Self {
            gateway,
            tls: resumption.fresh_config(&tls),
            resumption,
            authentication: Arc::new(()),
        })
    }

    /// Start an independent authentication lifecycle without changing trust,
    /// origin, algorithms or the explicitly selected resumption policy.
    pub(crate) fn for_authentication(&self) -> Self {
        Self {
            gateway: self.gateway.clone(),
            tls: self.resumption.fresh_config(&self.tls),
            resumption: self.resumption,
            authentication: Arc::new(()),
        }
    }

    async fn tls_connect(&self) -> Result<TlsTunnel, GpError> {
        let host = self
            .gateway
            .host()
            .ok_or(GpError::Protocol("missing gateway host"))?
            .to_string();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = self.gateway.port_or_known_default().unwrap_or(443);
        let addresses = super::bootstrap::resolve(host, port).await?;
        // Numeric addresses avoid a second, implicit Tokio blocking lookup.
        // The original hostname remains the TLS certificate/SNI identity.
        let tcp = TcpStream::connect(addresses.as_slice()).await?;
        tcp.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| GpError::Protocol("invalid gateway TLS name"))?;
        Ok(TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await?)
    }

    async fn post(
        &self,
        path: &str,
        fields: &[(&str, &str)],
    ) -> Result<Zeroizing<String>, GpError> {
        self.post_guarded(path, fields, || Ok(())).await
    }

    pub(super) async fn post_guarded(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<Zeroizing<String>, GpError> {
        timeout(IO_TIMEOUT, async {
            let body = super::form::encode(fields)?;
            let authority = &self.gateway[url::Position::BeforeHost..url::Position::AfterPort];
            let request = Zeroizing::new(format!(
                "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: PAN GlobalProtect\r\nAccept-Encoding: identity\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), *body
            ));
            let mut tls = self.tls_connect().await?;
            // TLS may have consumed most of the admission budget or outlived
            // cancellation. Recheck immediately before the first HTTP write.
            // This synchronous check and the write are not an atomic operation:
            // once writing begins the owner must finish bounded cookie cleanup.
            before_write()?;
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;
            let bytes = read_http_body(&mut tls).await?;
            let text = std::str::from_utf8(&bytes).map_err(|_| GpError::Protocol("non-UTF8 gateway response"))?;
            Ok(Zeroizing::new(text.to_owned()))
        }).await.map_err(|_| GpError::Timeout)?
    }

    /// Noninteractive convenience login. Never guesses or automatically answers
    /// a challenge; interactive callers use prelogin/begin_login explicitly.
    pub async fn login(
        &self,
        user: &str,
        password: &str,
        computer: &str,
    ) -> Result<Session, GpError> {
        validate_login_input(user, password, computer)?;
        self.prelogin().await?;
        match self.begin_login(user, password, computer).await? {
            LoginProgress::Session(session) => Ok(session),
            LoginProgress::Challenge(_) => Err(GpError::UnsupportedAuthentication),
        }
    }

    /// Read-only authentication discovery. No password or challenge answer is
    /// submitted. The service may cancel this phase before starting login.
    pub async fn prelogin(&self) -> Result<(), GpError> {
        let prelogin_path = format!(
            "/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos={}",
            client_os()
        );
        let prelogin = self.post(&prelogin_path, &[]).await?;
        let doc = xml(&prelogin)?;
        let root = doc.root_element();
        if !root.has_tag_name("prelogin-response") || child_text(root, "status")? != Some("Success")
        {
            return Err(GpError::Authentication);
        }
        if child_text(root, "saml-request")?.is_some() {
            return Err(GpError::UnsupportedAuthentication);
        }
        Ok(())
    }

    /// Submit the supplied initial secret exactly once, after caller prelogin.
    /// No prelogin, retry, redirect or automatic challenge answer occurs here.
    pub async fn begin_login(
        &self,
        user: &str,
        password: &str,
        computer: &str,
    ) -> Result<LoginProgress, GpError> {
        self.begin_login_guarded(user, password, computer, || Ok(()))
            .await
    }

    pub(crate) async fn begin_login_guarded(
        &self,
        user: &str,
        password: &str,
        computer: &str,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<LoginProgress, GpError> {
        validate_login_input(user, password, computer)?;
        self.login_post(user, password, computer, None, 1, before_write)
            .await
    }

    /// Consume this authentication client's challenge and a fresh answer. The
    /// opaque gateway state is retained exactly and sent only as `inputStr`.
    pub async fn answer_challenge(
        &self,
        continuation: LoginChallenge,
        answer: Zeroizing<String>,
    ) -> Result<LoginProgress, GpError> {
        self.answer_challenge_guarded(continuation, answer, || Ok(()))
            .await
    }

    pub(crate) async fn answer_challenge_guarded(
        &self,
        continuation: LoginChallenge,
        answer: Zeroizing<String>,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<LoginProgress, GpError> {
        if continuation.origin != self.gateway
            || !Arc::ptr_eq(&continuation.authentication, &self.authentication)
        {
            return Err(GpError::Protocol(
                "authentication challenge client mismatch",
            ));
        }
        if answer.is_empty()
            || answer.len() > challenge::MAX_SECRET
            || answer.chars().any(char::is_control)
        {
            return Err(GpError::Protocol("invalid authentication challenge answer"));
        }
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
    ) -> Result<LoginProgress, GpError> {
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
            ("server", self.gateway.host_str().unwrap_or_default()),
            ("computer", computer),
            ("user", user),
            ("passwd", secret),
        ];
        if let Some(state) = input_str {
            fields.push(("inputStr", state));
        }
        let response = self
            .post_guarded("/ssl-vpn/login.esp", &fields, before_write)
            .await?;
        match challenge::parse(&response)? {
            Some(fields) => {
                if round > challenge::MAX_ROUNDS {
                    return Err(GpError::Protocol(
                        "authentication challenge round limit exceeded",
                    ));
                }
                Ok(LoginProgress::Challenge(LoginChallenge {
                    user: user.to_owned(),
                    computer: computer.to_owned(),
                    input_str: fields.input_str,
                    prompt: fields.prompt,
                    origin: self.gateway.clone(),
                    authentication: self.authentication.clone(),
                    round,
                }))
            }
            None => parse_login(&response, computer).map(LoginProgress::Session),
        }
    }

    /// Consume portal credentials only for this fixed gateway and the explicitly
    /// expected portal. Never retains or retries the portal password.
    pub async fn login_with_portal_cookies(
        &self,
        cookies: super::PortalCookies,
        expected_portal: &Url,
    ) -> Result<Session, GpError> {
        self.login_with_portal_cookies_guarded(cookies, expected_portal, || Ok(()))
            .await
    }

    pub(crate) async fn login_with_portal_cookies_guarded(
        &self,
        cookies: super::PortalCookies,
        expected_portal: &Url,
        before_write: impl FnOnce() -> Result<(), GpError> + Send,
    ) -> Result<Session, GpError> {
        if cookies.gateway != self.gateway || cookies.portal != *expected_portal {
            return Err(GpError::Protocol("portal cookie origin mismatch"));
        }
        let fields = [
            ("jnlpReady", "jnlpReady"),
            ("ok", "Login"),
            ("direct", "yes"),
            ("clientVer", "4100"),
            ("prot", "https:"),
            ("internal", "no"),
            ("clientos", client_os()),
            ("os-version", std::env::consts::OS),
            ("ipv6-support", "no"),
            ("server", self.gateway.host_str().unwrap_or_default()),
            ("computer", cookies.computer.as_str()),
            ("user", cookies.user.as_str()),
            ("passwd", super::portal::cookie_password()?),
            ("portal-userauthcookie", cookies.user_cookie.as_str()),
            (
                "portal-prelogonuserauthcookie",
                cookies
                    .prelogon_cookie
                    .as_deref()
                    .map(|value| value.as_str())
                    .unwrap_or("empty"),
            ),
            ("prelogin-cookie", ""),
            ("token", ""),
        ];
        let response = self
            .post_guarded("/ssl-vpn/login.esp", &fields, before_write)
            .await?;
        if challenge::parse(&response)?.is_some() {
            return Err(GpError::UnsupportedAuthentication);
        }
        parse_login(&response, &cookies.computer)
    }

    pub async fn get_config(&self, session: &Session) -> Result<TunnelConfig, GpError> {
        // Start before the request: a buffered response consumed after suspend
        // must not restart the server's remaining lifetime on resume.
        let anchor = crate::lease::Sample::now();
        let preferred = session.preferred_ip.map(|x| x.to_string());
        let mut fields = session.fields();
        fields.extend([
            ("client-type", "1"),
            ("protocol-version", "p1"),
            ("app-version", env!("CARGO_PKG_VERSION")),
            ("internal", "no"),
            ("ipv6-support", "no"),
            ("clientos", client_os()),
            ("os-version", std::env::consts::OS),
        ]);
        if let Some(ip) = &preferred {
            fields.push(("preferred-ip", ip));
        }
        let mut config = parse_config(&self.post("/ssl-vpn/getconfig.esp", &fields).await?)?;
        config.received_at = anchor.monotonic;
        config.received_wall = anchor.wall;
        Ok(config)
    }

    /// An empty-report fingerprint announces that no HIP report is available.
    /// The response requests report data; it does not itself authorize/deny access.
    pub async fn check_hip(
        &self,
        session: &Session,
        config: &TunnelConfig,
    ) -> Result<HipStatus, GpError> {
        let address = config.address.to_string();
        let mut fields = session.fields();
        fields.extend([
            ("client-role", "global-protect-full"),
            ("client-ip", address.as_str()),
            ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ]);
        let response = self.post("/ssl-vpn/hipreportcheck.esp", &fields).await?;
        parse_hip_response(&response)
    }

    pub async fn connect_tunnel(
        &self,
        session: &Session,
        config: &TunnelConfig,
    ) -> Result<TlsTunnel, GpError> {
        if !super::config::valid_tunnel_path(&config.ssl_tunnel_path) {
            return Err(GpError::Protocol("unsafe SSL tunnel path"));
        }
        // Always query HIP state and reject malformed/error responses. A report
        // request is not a denial: normal tunnel and per-flow policy remain the
        // gateway's decision. No report or compliance claim is fabricated.
        if self.check_hip(session, config).await? == HipStatus::ReportRequested {
            tracing::warn!("gateway requested HIP report; no report submitted, access remains subject to gateway policy");
        }
        timeout(IO_TIMEOUT, async {
            let query = super::form::encode(&[
                ("user", session.user.as_str()),
                ("authcookie", session.auth_cookie.as_str()),
            ])?;
            let request = super::form::tunnel_request(&config.ssl_tunnel_path, &query)?;
            let mut tls = self.tls_connect().await?;
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;
            let mut start = [0; 12];
            tls.read_exact(&mut start).await?;
            verify_tunnel_start(&start)?;
            Ok(tls)
        })
        .await
        .map_err(|_| GpError::Timeout)?
    }

    pub async fn logout(&self, session: &Session) -> Result<(), GpError> {
        let mut fields = session.fields();
        fields.push(("os-version", std::env::consts::OS));
        let response = self.post("/ssl-vpn/logout.esp", &fields).await?;
        let doc = xml(&response)?;
        let root = doc.root_element();
        if root.has_tag_name("response") && root.attribute("status") == Some("success") {
            Ok(())
        } else {
            Err(GpError::Protocol("gateway did not confirm logout"))
        }
    }
}

fn validate_login_input(user: &str, password: &str, computer: &str) -> Result<(), GpError> {
    if user.is_empty()
        || user.len() > challenge::MAX_SECRET
        || password.len() > challenge::MAX_SECRET
        || computer.is_empty()
        || computer.len() > 255
    {
        return Err(GpError::Protocol("invalid login input"));
    }
    Ok(())
}

fn verify_tunnel_start(start: &[u8; 12]) -> Result<(), GpError> {
    if start == b"START_TUNNEL" {
        return Ok(());
    }
    if (start.starts_with(b"HTTP/1.1 ") || start.starts_with(b"HTTP/1.0 "))
        && start[9..].iter().all(u8::is_ascii_digit)
    {
        let status = u16::from(start[9] - b'0') * 100
            + u16::from(start[10] - b'0') * 10
            + u16::from(start[11] - b'0');
        // The tunnel endpoint also uses 502 to reject an invalid session cookie.
        return match status {
            401 | 403 | 502 | 512 => Err(GpError::Authentication),
            513 => Err(GpError::UnsupportedAuthentication),
            _ => Err(GpError::HttpStatus(status)),
        };
    }
    Err(GpError::Protocol("invalid tunnel start marker"))
}

fn parse_hip_response(body: &str) -> Result<HipStatus, GpError> {
    let doc = xml(body)?;
    let root = doc.root_element();
    if !root.has_tag_name("response") || root.attribute("status").is_some_and(|s| s != "success") {
        return Err(GpError::Protocol("invalid HIP check response"));
    }
    if root
        .children()
        .filter(|n| n.has_tag_name("hip-report-needed"))
        .count()
        != 1
    {
        return Err(GpError::Protocol("ambiguous HIP report request"));
    }
    match child_text(root, "hip-report-needed")? {
        Some("no") => Ok(HipStatus::NotRequested),
        Some("yes") => Ok(HipStatus::ReportRequested),
        _ => Err(GpError::Protocol("invalid HIP report request")),
    }
}

async fn bounded_line<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<SecretBuffer, GpError> {
    let mut line = SecretBuffer::new(limit)?;
    while line.len() < limit {
        let offset = line.len();
        line.push(0)?;
        reader
            .read_exact(&mut line.initialized_mut()[offset..offset + 1])
            .await?;
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(GpError::Protocol("HTTP line exceeds limit"))
}

async fn read_http_body<R: AsyncRead + Unpin>(reader: &mut R) -> Result<SecretBuffer, GpError> {
    let status_line = bounded_line(reader, MAX_HEADERS).await?;
    let line =
        std::str::from_utf8(&status_line).map_err(|_| GpError::Protocol("invalid HTTP status"))?;
    let mut parts = line.split_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(GpError::Protocol("invalid HTTP version"));
    }
    let status: u16 = parts
        .next()
        .ok_or(GpError::Protocol("missing HTTP status"))?
        .parse()
        .map_err(|_| GpError::Protocol("invalid HTTP status"))?;
    // PAN also uses proprietary 512/513 status codes for expired cookies and
    // client-certificate requirements. Retrying these as generic 5xx is futile.
    if matches!(status, 401 | 403 | 512) {
        return Err(GpError::Authentication);
    }
    if status == 513 {
        return Err(GpError::UnsupportedAuthentication);
    }
    if status != 200 {
        return Err(GpError::HttpStatus(status));
    }
    let mut total = status_line.len();
    let mut length = None;
    let mut chunked = false;
    loop {
        let line = bounded_line(reader, MAX_HEADERS.saturating_sub(total)).await?;
        total += line.len();
        if &*line == b"\r\n" {
            break;
        }
        let line =
            std::str::from_utf8(&line).map_err(|_| GpError::Protocol("invalid HTTP header"))?;
        let (name, value) = line
            .trim_end()
            .split_once(':')
            .ok_or(GpError::Protocol("invalid HTTP header"))?;
        if name.starts_with(char::is_whitespace) {
            return Err(GpError::Protocol("folded HTTP header"));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(GpError::Protocol("duplicate Content-Length"));
            }
            let n: usize = value
                .parse()
                .map_err(|_| GpError::Protocol("invalid Content-Length"))?;
            if n > MAX_XML {
                return Err(GpError::Protocol("HTTP body exceeds limit"));
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(GpError::Protocol("unsupported Transfer-Encoding"));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(GpError::Protocol("unsupported Content-Encoding"));
        }
    }
    if chunked && length.is_some() {
        return Err(GpError::Protocol("ambiguous HTTP body framing"));
    }
    // Allocate before accepting any body byte. Keep all storage initialized
    // and fixed: malformed framing and cancellation wipe partial data too,
    // and no growing Vec can leave earlier plaintext allocations behind.
    let capacity = if chunked {
        MAX_XML
    } else {
        length.unwrap_or(MAX_XML + 1)
    };
    let mut body = SecretBuffer::new(capacity)?;
    if chunked {
        let mut chunks = 0;
        loop {
            chunks += 1;
            if chunks > 16384 {
                return Err(GpError::Protocol("too many HTTP chunks"));
            }
            let size_line = bounded_line(reader, 128).await?;
            let size = std::str::from_utf8(&size_line)
                .map_err(|_| GpError::Protocol("invalid chunk length"))?
                .split(';')
                .next()
                .unwrap_or_default()
                .trim();
            let n = usize::from_str_radix(size, 16)
                .map_err(|_| GpError::Protocol("invalid chunk length"))?;
            if n == 0 {
                // Trailers are unnecessary for this protocol, but consume with a bound.
                let mut trailer_size = 0;
                loop {
                    let trailer = bounded_line(reader, MAX_HEADERS - trailer_size).await?;
                    trailer_size += trailer.len();
                    if &*trailer == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            if n > MAX_XML - body.len() {
                return Err(GpError::Protocol("HTTP body exceeds limit"));
            }
            let start = body.len();
            body.set_len(start + n)?;
            reader
                .read_exact(&mut body.initialized_mut()[start..start + n])
                .await?;
            let mut end = SecretBuffer::new(2)?;
            reader.read_exact(end.initialized_mut()).await?;
            end.set_len(2)?;
            if &*end != b"\r\n" {
                return Err(GpError::Protocol("invalid HTTP chunk terminator"));
            }
        }
    } else if let Some(n) = length {
        body.set_len(n)?;
        reader.read_exact(body.initialized_mut()).await?;
    } else {
        loop {
            let filled = body.len();
            let count = reader.read(&mut body.initialized_mut()[filled..]).await?;
            body.set_len(filled + count)?;
            if body.len() > MAX_XML {
                return Err(GpError::Protocol("HTTP body exceeds limit"));
            }
            if count == 0 {
                break;
            }
        }
    }
    Ok(body)
}

#[cfg(test)]
#[path = "challenge_tests.rs"]
mod challenge_tests;

#[cfg(test)]
#[path = "http_memory_tests.rs"]
mod http_memory_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proprietary_gateway_auth_rejections_are_not_transient_server_errors() {
        let expired = "HTTP/1.1 512 Rejected\r\n";
        assert!(matches!(
            read_http_body(&mut expired.as_bytes()).await,
            Err(GpError::Authentication)
        ));
        let certificate_required = "HTTP/1.1 513 Rejected\r\n";
        assert!(matches!(
            read_http_body(&mut certificate_required.as_bytes()).await,
            Err(GpError::UnsupportedAuthentication)
        ));
        let unavailable = "HTTP/1.1 503 Unavailable\r\n";
        assert!(matches!(
            read_http_body(&mut unavailable.as_bytes()).await,
            Err(GpError::HttpStatus(503))
        ));
    }

    #[test]
    fn tunnel_start_distinguishes_cookie_rejection_from_service_failure() {
        assert!(verify_tunnel_start(b"START_TUNNEL").is_ok());
        assert!(matches!(
            verify_tunnel_start(b"HTTP/1.1 502"),
            Err(GpError::Authentication)
        ));
        assert!(matches!(
            verify_tunnel_start(b"HTTP/1.1 503"),
            Err(GpError::HttpStatus(503))
        ));
        assert!(matches!(
            verify_tunnel_start(b"HTTP/1.0 513"),
            Err(GpError::UnsupportedAuthentication)
        ));
        assert!(matches!(
            verify_tunnel_start(b"HTTP/1.1 xyz"),
            Err(GpError::Protocol(_))
        ));
        assert!(matches!(
            verify_tunnel_start(b"<html>broken"),
            Err(GpError::Protocol(_))
        ));
    }

    pub(super) fn mock_tls_configs(
        version: &'static rustls::SupportedProtocolVersion,
    ) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        let certs = CertificateDer::pem_slice_iter(include_bytes!("testdata/localhost-cert.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("testdata/localhost-key.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        (Arc::new(client), Arc::new(server))
    }

    #[tokio::test]
    async fn native_tls_gateway_configuration_hip_and_framed_tunnel() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            for report_requested in [false, true] {
                native_tls_gateway_with_version(version, report_requested).await;
            }
        }
    }

    async fn native_tls_gateway_with_version(
        version: &'static rustls::SupportedProtocolVersion,
        report_requested: bool,
    ) {
        timeout(Duration::from_secs(10), async {
            let (client_tls, server_tls) = mock_tls_configs(version);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let gateway = Url::parse(&format!("https://localhost:{}", listener.local_addr().unwrap().port())).unwrap();
            let (anchor_tx, anchor_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut anchor_tx = Some(anchor_tx);
                let acceptor = tokio_rustls::TlsAcceptor::from(server_tls);
                for step in 0..5 {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut tls = acceptor.accept(tcp).await.unwrap();
                    let first = bounded_line(&mut tls, MAX_HEADERS).await.unwrap();
                    let mut length = 0;
                    loop {
                        let line = bounded_line(&mut tls, MAX_HEADERS).await.unwrap();
                        if &*line == b"\r\n" { break; }
                        let line = std::str::from_utf8(&line).unwrap();
                        if let Some(value) = line.strip_prefix("Content-Length: ") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                    let mut body = vec![0; length];
                    tls.read_exact(&mut body).await.unwrap();
                    if step == 4 {
                        assert!(first.starts_with(b"GET /ssl-tunnel-connect.sslvpn?user=test-user&authcookie=test-cookie "));
                        for byte in b"START_TUNNEL" { tls.write_all(&[*byte]).await.unwrap(); }
                        tls.flush().await.unwrap();
                        let mut packet = vec![0; 20]; packet[0] = 0x45; packet[3] = 20;
                        super::super::write_frame(&mut tls, &super::super::Frame::Ip(packet), 1400).await.unwrap();
                        assert_eq!(super::super::read_frame(&mut tls, 1400).await.unwrap(), super::super::Frame::Keepalive);
                    } else {
                        if step != 0 { assert!(!body.is_empty()); }
                        let response = if step == 0 {
                            assert!(first.starts_with(b"POST /ssl-vpn/prelogin.esp?"));
                            "<prelogin-response><status>Success</status></prelogin-response>"
                        } else if step == 1 {
                            assert!(first.starts_with(b"POST /ssl-vpn/login.esp "));
                            assert!(std::str::from_utf8(&body).unwrap().contains("passwd=secret%26password"));
                            "<jnlp><application-desc><argument/><argument>test-cookie</argument><argument/><argument>gateway</argument><argument>test-user</argument><argument>LDAP-auth</argument><argument>vsys1</argument><argument>domain</argument><argument/><argument/><argument/><argument/><argument>tunnel</argument><argument>-1</argument><argument>4100</argument><argument>10.0.0.2</argument></application-desc></jnlp>"
                        } else if step == 2 {
                            assert!(first.starts_with(b"POST /ssl-vpn/getconfig.esp "));
                            anchor_tx.take().unwrap().send(crate::lease::Sample::now()).unwrap();
                            assert!(std::str::from_utf8(&body).unwrap().contains(&format!("app-version={}", env!("CARGO_PKG_VERSION"))));
                            "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.0.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><dns><member>10.0.0.53</member></dns></response>"
                        } else {
                            assert!(first.starts_with(b"POST /ssl-vpn/hipreportcheck.esp "));
                            if report_requested { "<response status='success'><hip-report-needed>yes</hip-report-needed></response>" }
                            else { "<response status='success'><hip-report-needed>no</hip-report-needed></response>" }
                        };
                        tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
                    }
                    tls.shutdown().await.unwrap();
                }
            });
            let client = GatewayClient::new(gateway, client_tls,
crate::gp::ResumptionPolicy::Memory { tls12: rustls::client::Tls12Resumption::SessionIdOrTickets },
).unwrap();
            let session = client.login("test-user", "secret&password", "test-computer").await.unwrap();
            let config = client.get_config(&session).await.unwrap();
            // The anchor must precede the server receiving the request, not
            // merely precede config parsing after its response is consumed.
            let request_received = anchor_rx.await.unwrap();
            assert!(config.received_at <= request_received.monotonic);
            assert!(config.received_wall <= request_received.wall);
            let mut tunnel = client.connect_tunnel(&session, &config).await.unwrap();
            assert!(matches!(super::super::read_frame(&mut tunnel, 1400).await.unwrap(), super::super::Frame::Ip(_)));
            super::super::write_frame(&mut tunnel, &super::super::Frame::Keepalive, 1400).await.unwrap();
            server.await.unwrap();
        }).await.unwrap();
    }

    #[test]
    fn hip_report_request_is_not_a_compliance_verdict_and_errors_still_fail() {
        assert_eq!(
            parse_hip_response("<response><hip-report-needed>yes</hip-report-needed></response>")
                .unwrap(),
            HipStatus::ReportRequested
        );
        for body in [
            "<response status='error'><hip-report-needed>no</hip-report-needed></response>",
            "<response><hip-report-needed>yes</hip-report-needed><hip-report-needed>no</hip-report-needed></response>",
            "<response><hip-report-needed>unknown</hip-report-needed></response>",
            "<response><hip-report-needed>no<hidden/>yes</hip-report-needed></response>",
            "<response><hip-report-needed>no<!--split-->yes</hip-report-needed></response>",
            "<response/>",
        ] { assert!(parse_hip_response(body).is_err()); }
    }

    #[tokio::test]
    async fn tls_rejects_wrong_gateway_hostname() {
        timeout(Duration::from_secs(10), async {
            let (client_tls, server_tls) = mock_tls_configs(&rustls::version::TLS13);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            // Fixture only authorizes DNS:localhost, not the IP literal.
            let gateway =
                Url::parse(&format!("https://{}", listener.local_addr().unwrap())).unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                assert!(tokio_rustls::TlsAcceptor::from(server_tls)
                    .accept(tcp)
                    .await
                    .is_err());
            });
            let client = GatewayClient::new(
                gateway,
                client_tls,
                crate::gp::ResumptionPolicy::Memory {
                    tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
                },
            )
            .unwrap();
            let session = Session::new(
                "test".into(),
                "cookie".into(),
                "gateway".into(),
                "domain".into(),
                "computer".into(),
                None,
            )
            .unwrap();
            assert!(matches!(
                client.get_config(&session).await,
                Err(GpError::Io(_))
            ));
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn login_is_decoded_and_debug_redacts_credentials() {
        let args = [
            "",
            "secret-cookie",
            "",
            "gateway",
            "user%40example",
            "LDAP-auth",
            "vsys1",
            "%28empty_domain%29",
            "",
            "",
            "",
            "",
            "tunnel",
            "-1",
            "4100",
            "10.0.0.2",
        ];
        let body = format!(
            "<jnlp><application-desc>{}</application-desc></jnlp>",
            args.iter()
                .map(|a| format!("<argument>{a}</argument>"))
                .collect::<String>()
        );
        let session = parse_login(&body, "test-computer").unwrap();
        assert_eq!(session.user, "user@example");
        assert_eq!(session.domain, "(empty_domain)");
        assert!(!format!("{session:?}").contains("secret-cookie"));
        assert!(
            parse_login(&body.replace("<argument>10.0.0.2</argument>", ""), "test")
                .unwrap()
                .preferred_ip
                .is_none()
        );
        assert!(parse_login(&body.replace("10.0.0.2", "-1"), "test")
            .unwrap()
            .preferred_ip
            .is_none());
        assert!(parse_login(&body.replace("<argument>tunnel", "<argument>web"), "test").is_err());
    }

    #[tokio::test]
    async fn http_body_handles_fragmented_chunks_and_rejects_ambiguity() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let (mut tx, mut rx) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            tx.write_all(response).await.unwrap();
        });
        assert_eq!(&*read_http_body(&mut rx).await.unwrap(), b"abcde");
        task.await.unwrap();
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: https://attacker.test\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
        ] {
            assert!(read_http_body(&mut response.as_bytes()).await.is_err());
        }
    }
}
