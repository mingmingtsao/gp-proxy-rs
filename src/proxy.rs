//! Loopback-only application proxies. The connector is the sole egress path.
use crate::policy::{normalize_host, Policy};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Bytes, Frame, Incoming},
    header, Request as HttpRequest, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};

const MAX_HEADER: usize = 32 * 1024;
const MAX_HEADERS: usize = 128;
// Business streams never retain these permits. This leaves bounded capacity
// for PAC/status even when every application slot is occupied.
const MAX_HTTP_HANDSHAKES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn new(host: &str, port: u16) -> io::Result<Self> {
        if port == 0 {
            return Err(invalid("zero destination port"));
        }
        Ok(Self {
            host: normalize_host(host)?,
            port,
        })
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;
pub type ConnectFuture<'a> = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'a>>;
pub trait Connector: Send + Sync {
    fn connect(&self, target: Target) -> ConnectFuture<'_>;
    fn status(&self) -> crate::status::Snapshot {
        crate::status::Snapshot::default()
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub http_addr: SocketAddr,
    pub socks_addr: SocketAddr,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:8080".parse().unwrap(),
            socks_addr: "127.0.0.1:1080".parse().unwrap(),
            max_connections: 256,
            handshake_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

pub struct ProxyServer {
    http: TcpListener,
    socks: TcpListener,
    config: ProxyConfig,
}

impl ProxyServer {
    pub async fn bind(mut config: ProxyConfig) -> io::Result<Self> {
        if !config.http_addr.ip().is_loopback() || !config.socks_addr.ip().is_loopback() {
            return Err(invalid("proxy listeners must bind loopback addresses"));
        }
        if !(1..=4096).contains(&config.max_connections)
            || config.handshake_timeout.is_zero()
            || config.idle_timeout.is_zero()
        {
            return Err(invalid(
                "proxy connections must be 1..=4096 and timeouts nonzero",
            ));
        }
        let http = TcpListener::bind(config.http_addr).await?;
        let socks = TcpListener::bind(config.socks_addr).await?;
        config.http_addr = http.local_addr()?;
        config.socks_addr = socks.local_addr()?;
        Ok(Self {
            http,
            socks,
            config,
        })
    }

    pub fn local_addrs(&self) -> (SocketAddr, SocketAddr) {
        (self.config.http_addr, self.config.socks_addr)
    }

    pub async fn serve(
        self,
        connector: Arc<dyn Connector>,
        policy: watch::Receiver<Arc<Policy>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let permits = Arc::new(Semaphore::new(self.config.max_connections));
        let http_handshakes = Arc::new(Semaphore::new(MAX_HTTP_HANDSHAKES));
        let max_tasks = self.config.max_connections + MAX_HTTP_HANDSHAKES;
        let mut tasks = JoinSet::new();
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            // Completed tasks release permits before JoinSet collects their
            // results. Drain them before another accept, otherwise short local
            // requests could accumulate completion records without a bound.
            while tasks.try_join_next().is_some() {}
            tokio::select! {
                changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { break Ok(()); } }
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.http.accept(), if tasks.len() < max_tasks => {
                    let (stream, _) = match accepted { Ok(v) => v, Err(e) => break Err(e) };
                    if let Ok(handshake) = http_handshakes.clone().try_acquire_owned() {
                        let connector = connector.clone(); let policy = policy.clone(); let config = self.config.clone(); let business = permits.clone();
                        tasks.spawn(async move { if let Err(error) = handle_http(stream, connector, policy, config, business, handshake).await { tracing::debug!(%error, "HTTP proxy connection ended"); } });
                    }
                }
                accepted = self.socks.accept(), if tasks.len() < max_tasks => {
                    let (stream, _) = match accepted { Ok(v) => v, Err(e) => break Err(e) };
                    if let Ok(permit) = permits.clone().try_acquire_owned() {
                        let connector = connector.clone(); let policy = policy.clone(); let config = self.config.clone();
                        tasks.spawn(async move { let _permit = permit; if let Err(error) = handle_socks(stream, connector, policy, config).await { tracing::debug!(%error, "SOCKS proxy connection ended"); } });
                    }
                }
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

pub async fn run(
    config: ProxyConfig,
    connector: Arc<dyn Connector>,
    policy: watch::Receiver<Arc<Policy>>,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    ProxyServer::bind(config)
        .await?
        .serve(connector, policy, shutdown)
        .await
}

async fn handle_http(
    mut client: TcpStream,
    connector: Arc<dyn Connector>,
    policy: watch::Receiver<Arc<Policy>>,
    config: ProxyConfig,
    business: Arc<Semaphore>,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()> {
    let parsed = timeout(config.handshake_timeout, read_request(&mut client)).await;
    let request = match parsed {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => {
            return http_error(&mut client, 400, "Bad Request").await;
        }
        Err(_) => {
            return http_error(&mut client, 408, "Request Timeout").await;
        }
    };
    let policy = policy.borrow().clone();
    if let Some(endpoint) = request.local_endpoint {
        if !local_pac_host(&request.host_header, config.http_addr) {
            return http_error(&mut client, 403, "Forbidden").await;
        }
        let (content_type, body) = match endpoint {
            LocalEndpoint::Pac => (
                "application/x-ns-proxy-autoconfig",
                policy.pac(config.http_addr),
            ),
            LocalEndpoint::Status => (
                "application/json",
                serde_json::to_string(&connector.status()).map_err(io::Error::other)?,
            ),
        };
        return timeout(config.handshake_timeout, client.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())).await.map_err(|_| timed_out())?;
    }
    let target = request
        .target
        .as_ref()
        .ok_or_else(|| invalid("missing destination"))?;
    if !policy.allows(target) {
        return http_error(&mut client, 403, "Forbidden").await;
    }
    let Ok(_business) = business.try_acquire_owned() else {
        return http_error(&mut client, 503, "Proxy Capacity Reached").await;
    };
    // No await between admission and releasing the header slot: an admitted
    // slow dial/upload/CONNECT must not consume management capacity.
    drop(handshake);
    let upstream = timeout(config.handshake_timeout, connector.connect(target.clone())).await;
    let upstream = match upstream {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
            return http_error(&mut client, 403, "Forbidden").await;
        }
        _ => return http_error(&mut client, 502, "Tunnel Unavailable").await,
    };
    if request.connect {
        timeout(
            config.handshake_timeout,
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        )
        .await
        .map_err(|_| timed_out())??;
        relay_with_idle(client, upstream, request.extra, config.idle_timeout).await
    } else {
        let mut prefix = request.forward_header;
        prefix.extend_from_slice(&request.extra);
        forward_http_with_idle(client, upstream, prefix, config.idle_timeout).await
    }
}

#[derive(Clone, Copy)]
enum LocalEndpoint {
    Pac,
    Status,
}

struct Request {
    target: Option<Target>,
    connect: bool,
    local_endpoint: Option<LocalEndpoint>,
    host_header: String,
    forward_header: Vec<u8>,
    extra: Vec<u8>,
}

async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Request> {
    let mut bytes = Vec::with_capacity(2048);
    loop {
        if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            return parse_request(&bytes[..end + 4], bytes[end + 4..].to_vec());
        }
        if bytes.len() >= MAX_HEADER {
            return Err(invalid("request header too large"));
        }
        let mut chunk = [0u8; 2048];
        let remaining = (MAX_HEADER - bytes.len()).min(chunk.len());
        let count = reader.read(&mut chunk[..remaining]).await?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

fn parse_request(bytes: &[u8], extra: Vec<u8>) -> io::Result<Request> {
    if !bytes.is_ascii()
        || bytes
            .iter()
            .any(|b| *b < 32 && !matches!(*b, b'\r' | b'\n' | b'\t'))
        || bytes.contains(&127)
    {
        return Err(invalid("invalid header character"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid headers"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("missing request line"))?;
    if request_line.contains(['\r', '\n', '\t']) {
        return Err(invalid("invalid request line"));
    }
    for line in lines {
        if line.contains(['\r', '\n']) || line.starts_with([' ', '\t']) {
            return Err(invalid("obsolete or invalid header folding"));
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(bytes) {
        Ok(httparse::Status::Complete(n)) if n == bytes.len() => {}
        _ => return Err(invalid("invalid HTTP request")),
    }
    if parsed.version != Some(1) {
        return Err(invalid("HTTP/1.1 is required"));
    }
    let method = parsed.method.ok_or_else(|| invalid("missing method"))?;
    let path = parsed.path.ok_or_else(|| invalid("missing target"))?;
    let mut host = None;
    let mut length = None;
    let mut chunked = false;
    let mut expect_continue = false;
    let mut connection_tokens = Vec::new();
    for header in parsed.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| invalid("invalid header"))?
            .trim();
        if header.name.eq_ignore_ascii_case("host") {
            if host.replace(value).is_some() {
                return Err(invalid("duplicate Host"));
            }
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || length.is_some() {
                return Err(invalid("ambiguous Content-Length"));
            }
            length = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| invalid("invalid Content-Length"))?,
            );
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(invalid("unsupported or ambiguous transfer coding"));
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("expect") {
            if expect_continue || !value.eq_ignore_ascii_case("100-continue") {
                return Err(invalid("unsupported expectation"));
            }
            expect_continue = true;
        } else if header.name.eq_ignore_ascii_case("upgrade") {
            return Err(invalid("unsupported request framing or upgrade"));
        } else if header.name.eq_ignore_ascii_case("connection") {
            for token in value.split(',') {
                let token = token.trim().to_ascii_lowercase();
                if token.is_empty()
                    || !token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || matches!(
                        token.as_str(),
                        "host" | "content-length" | "transfer-encoding" | "expect"
                    )
                {
                    return Err(invalid("invalid Connection header"));
                }
                connection_tokens.push(token);
            }
        }
    }
    if chunked && length.is_some() {
        return Err(invalid("ambiguous HTTP message framing"));
    }
    let host_header = host.ok_or_else(|| invalid("missing Host"))?.to_string();
    let connect = method == "CONNECT";
    let local_endpoint = match (method, path) {
        ("GET", path) if is_local_pac_path(path) => Some(LocalEndpoint::Pac),
        ("GET", "/status") => Some(LocalEndpoint::Status),
        _ => None,
    };
    if local_endpoint.is_some() {
        if length.unwrap_or(0) != 0 || chunked || expect_continue || !extra.is_empty() {
            return Err(invalid("unexpected local endpoint body or pipeline"));
        }
        return Ok(Request {
            target: None,
            connect: false,
            local_endpoint,
            host_header,
            forward_header: vec![],
            extra,
        });
    }
    let (target, origin_path) = if connect {
        if length.unwrap_or(0) != 0 || chunked || expect_continue {
            return Err(invalid("CONNECT body is not supported"));
        }
        (parse_authority(path, None)?, String::new())
    } else {
        // Absolute-form only; URLs with userinfo/fragments or unusual authority
        // syntax are rejected before URL normalization can reinterpret them.
        let authority_path = path
            .strip_prefix("http://")
            .ok_or_else(|| invalid("absolute http URI required"))?;
        let end = authority_path
            .find(['/', '?', '#'])
            .unwrap_or(authority_path.len());
        let authority = &authority_path[..end];
        if path.contains(['\\', '#']) {
            return Err(invalid("invalid HTTP URI"));
        }
        let target = parse_authority(authority, Some(80))?;
        let rest = &authority_path[end..];
        let origin = if rest.is_empty() {
            "/".to_string()
        } else if rest.starts_with('?') {
            format!("/{rest}")
        } else {
            rest.to_string()
        };
        (target, origin)
    };
    let host_target = parse_authority(&host_header, if connect { None } else { Some(80) })?;
    if host_target != target {
        return Err(invalid("Host does not match request target"));
    }
    let mut forward = Vec::new();
    if !connect {
        forward.extend_from_slice(format!("{method} {origin_path} HTTP/1.1\r\n").as_bytes());
        for header in parsed.headers.iter() {
            let name = header.name.to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "connection"
                    | "proxy-connection"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "keep-alive"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
            ) || connection_tokens.contains(&name)
            {
                continue;
            }
            forward.extend_from_slice(header.name.as_bytes());
            forward.extend_from_slice(b": ");
            forward.extend_from_slice(header.value);
            forward.extend_from_slice(b"\r\n");
        }
        if chunked {
            forward.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        forward.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    Ok(Request {
        target: Some(target),
        connect,
        local_endpoint: None,
        host_header,
        forward_header: forward,
        extra,
    })
}

fn is_local_pac_path(path: &str) -> bool {
    path == "/proxy.pac"
        || path.strip_prefix("/proxy.pac?gpv=").is_some_and(|version| {
            version.len() == 32
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> io::Result<Target> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| invalid("invalid IPv6 authority"))?;
        let host = &rest[..end];
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(invalid("invalid IPv6 address"));
        }
        let trailing = &rest[end + 1..];
        let port = if trailing.is_empty() {
            default_port.ok_or_else(|| invalid("port required"))?
        } else {
            parse_port(
                trailing
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("invalid authority"))?,
            )?
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err(invalid("IPv6 must use brackets"));
        }
        (host, parse_port(port)?)
    } else {
        (
            authority,
            default_port.ok_or_else(|| invalid("port required"))?,
        )
    };
    Target::new(host, port)
}

fn parse_port(port: &str) -> io::Result<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid port"));
    }
    let port = port.parse().map_err(|_| invalid("invalid port"))?;
    if port == 0 {
        return Err(invalid("zero port"));
    }
    Ok(port)
}

fn local_pac_host(host: &str, listener: SocketAddr) -> bool {
    parse_authority(host, Some(80)).is_ok_and(|target| {
        target.port == listener.port()
            && (target.host == listener.ip().to_string() || target.host == "localhost")
    })
}

async fn http_error<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: u16,
    reason: &str,
) -> io::Result<()> {
    let body = format!("{reason}\n");
    timeout(Duration::from_secs(2), stream.write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())).await.map_err(|_| timed_out())?
}

async fn handle_socks(
    mut client: TcpStream,
    connector: Arc<dyn Connector>,
    policy: watch::Receiver<Arc<Policy>>,
    config: ProxyConfig,
) -> io::Result<()> {
    let target = match timeout(config.handshake_timeout, socks_handshake(&mut client)).await {
        Ok(Ok(target)) => target,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(timed_out()),
    };
    let policy = policy.borrow().clone();
    if !policy.allows(&target) {
        return socks_reply(&mut client, 2).await;
    }
    let upstream = timeout(config.handshake_timeout, connector.connect(target)).await;
    match upstream {
        Ok(Ok(upstream)) => {
            socks_reply(&mut client, 0).await?;
            relay_with_idle(client, upstream, vec![], config.idle_timeout).await
        }
        Ok(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
            socks_reply(&mut client, 2).await
        }
        _ => socks_reply(&mut client, 1).await,
    }
}

async fn socks_handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<Target> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(invalid("invalid SOCKS greeting"));
    }
    let mut methods = vec![0; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        return Err(invalid("no supported SOCKS authentication"));
    }
    stream.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        socks_reply(stream, 1).await?;
        return Err(invalid("invalid SOCKS header"));
    }
    if header[1] != 1 {
        socks_reply(stream, 7).await?;
        return Err(invalid("SOCKS supports CONNECT only"));
    }
    let host = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| invalid("invalid SOCKS hostname"))?
        }
        _ => {
            socks_reply(stream, 8).await?;
            return Err(invalid("unsupported SOCKS address type"));
        }
    };
    let port = stream.read_u16().await?;
    match Target::new(&host, port) {
        Ok(target) => Ok(target),
        Err(e) => {
            socks_reply(stream, 8).await?;
            Err(e)
        }
    }
}

async fn socks_reply<S: AsyncWrite + Unpin>(stream: &mut S, status: u8) -> io::Result<()> {
    timeout(
        Duration::from_secs(2),
        stream.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0]),
    )
    .await
    .map_err(|_| timed_out())?
}

struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}
impl Activity {
    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}
struct Tracked<S> {
    stream: S,
    activity: Arc<Activity>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            if buf.filled().len() > before {
                self.activity.touch();
            }
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            if *n != 0 {
                self.activity.touch();
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn monitor_idle<F: Future<Output = io::Result<()>>>(
    work: F,
    activity: Arc<Activity>,
    idle: Duration,
) -> io::Result<()> {
    tokio::pin!(work);
    loop {
        let last = activity.start + Duration::from_millis(activity.last_ms.load(Ordering::Relaxed));
        tokio::select! {
            result = &mut work => return result,
            _ = tokio::time::sleep_until(last + idle) => {
                let last = activity.start + Duration::from_millis(activity.last_ms.load(Ordering::Relaxed));
                if last.elapsed() >= idle { return Err(timed_out()); }
            }
        }
    }
}

async fn relay_with_idle<C: AsyncRead + AsyncWrite + Unpin>(
    client: C,
    upstream: BoxStream,
    early: Vec<u8>,
    idle: Duration,
) -> io::Result<()> {
    let activity = Arc::new(Activity {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let mut client = Tracked {
        stream: client,
        activity: activity.clone(),
    };
    let mut upstream = Tracked {
        stream: upstream,
        activity: activity.clone(),
    };
    monitor_idle(
        async {
            upstream.write_all(&early).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .map(|_| ())
        },
        activity,
        idle,
    )
    .await
}

/// A strict preflight validates authority, policy, and request ambiguity before
/// dialing. Hyper then owns HTTP framing, including chunks and early responses;
/// it receives only sanitized headers and the already authorized VPN stream.
async fn forward_http_with_idle<C: AsyncRead + AsyncWrite + Unpin>(
    client: C,
    upstream: BoxStream,
    prefix: Vec<u8>,
    idle: Duration,
) -> io::Result<()> {
    let activity = Arc::new(Activity {
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let client = Tracked {
        stream: Prefixed {
            prefix: io::Cursor::new(prefix),
            stream: client,
        },
        activity: activity.clone(),
    };
    let upstream = Tracked {
        stream: upstream,
        activity: activity.clone(),
    };
    monitor_idle(
        async {
            let (sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(MAX_HEADER)
                .max_header_size(MAX_HEADER)
                .max_headers(MAX_HEADERS)
                .handshake(TokioIo::new(upstream))
                .await
                .map_err(|_| invalid("upstream HTTP handshake failed"))?;
            let sender = std::sync::Mutex::new(Some(sender));
            let service = hyper::service::service_fn(move |request: HttpRequest<Incoming>| {
                let sender = sender.lock().unwrap().take();
                async move {
                    let Some(mut sender) = sender else {
                        return Ok::<_, std::convert::Infallible>(gateway_error());
                    };
                    let (mut parts, body) = request.into_parts();
                    // The local server generates 100 Continue when the upstream
                    // client polls the upload body. Do not negotiate it twice.
                    parts.headers.remove(header::EXPECT);
                    parts.headers.remove(header::TRANSFER_ENCODING);
                    let upload = Arc::new(std::sync::Mutex::new(Some(body)));
                    let request = HttpRequest::from_parts(parts, UploadBody(upload.clone()));
                    let result = sender.send_request(request).await;
                    // A final response can precede the upload. Drop the downstream
                    // request body now so its server can close the read side; do
                    // not wait forever for a client that stopped after a rejection.
                    upload.lock().unwrap().take();
                    let response = match result {
                        Ok(mut response)
                            if response.status() != StatusCode::SWITCHING_PROTOCOLS =>
                        {
                            if sanitize_response(response.headers_mut()).is_err() {
                                gateway_error()
                            } else {
                                let (parts, body) = response.into_parts();
                                Response::from_parts(parts, without_trailers(body))
                            }
                        }
                        _ => gateway_error(),
                    };
                    Ok(response)
                }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(false)
                .half_close(true)
                .max_buf_size(MAX_HEADER)
                .max_header_size(MAX_HEADER)
                .max_headers(MAX_HEADERS)
                .header_read_timeout(None);
            let server = builder.serve_connection(TokioIo::new(client), service);
            tokio::pin!(server, connection);
            // Own both futures directly: timeout/cancellation drops both transports,
            // with no spawned connection task surviving a proxy request.
            let result = tokio::select! {
                result = &mut server => result,
                _ = &mut connection => server.await,
            };
            result.map_err(|_| invalid("invalid or incomplete HTTP exchange"))
        },
        activity,
        idle,
    )
    .await
}

type HttpBody = UnsyncBoxBody<Bytes, hyper::Error>;

struct UploadBody(Arc<std::sync::Mutex<Option<Incoming>>>);
impl hyper::body::Body for UploadBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let mut body = self.0.lock().unwrap();
        match body.as_mut() {
            Some(body) => Pin::new(body).poll_frame(cx).map(|frame| {
                frame.map(|frame| {
                    frame.map(|frame| Frame::data(frame.into_data().unwrap_or_default()))
                })
            }),
            // The response is already in flight. Do not fabricate an EOF for a
            // partially sent Content-Length body (which would abort reading the
            // response). The owning connection closes after its response ends.
            None => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        use hyper::body::Body;
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(Body::is_end_stream)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        use hyper::body::Body;
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .map_or_else(hyper::body::SizeHint::default, Body::size_hint)
    }
}

fn without_trailers(body: Incoming) -> HttpBody {
    // Do not promote trailers into headers or forward proxy credentials and
    // framing fields hidden in trailers. Content stays streamed and bounded.
    body.map_frame(|frame| Frame::data(frame.into_data().unwrap_or_default()))
        .boxed_unsync()
}

fn gateway_error() -> Response<HttpBody> {
    let body = Full::new(Bytes::from_static(b"Tunnel Unavailable\n"))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    response
}

fn sanitize_response(headers: &mut header::HeaderMap) -> io::Result<()> {
    let mut coding = headers.get_all(header::TRANSFER_ENCODING).iter();
    if let Some(value) = coding.next() {
        // Hyper decodes chunk framing, not arbitrary transfer compression, and
        // preserves the original fields. Never relabel encoded bytes or let a
        // conflicting Content-Length govern the downstream response.
        if headers.contains_key(header::CONTENT_LENGTH)
            || coding.next().is_some()
            || !value
                .to_str()
                .is_ok_and(|v| v.trim().eq_ignore_ascii_case("chunked"))
        {
            return Err(invalid("unsupported or ambiguous response transfer coding"));
        }
    }
    let mut named = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for token in value
            .to_str()
            .map_err(|_| invalid("invalid response Connection"))?
            .split(',')
        {
            let name = header::HeaderName::from_bytes(token.trim().as_bytes())
                .map_err(|_| invalid("invalid response Connection"))?;
            if matches!(name.as_str(), "content-length" | "transfer-encoding") {
                return Err(invalid("response Connection alters framing"));
            }
            named.push(name);
        }
    }
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    headers.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    Ok(())
}

struct Prefixed<S> {
    prefix: io::Cursor<Vec<u8>>,
    stream: S,
}
impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = self.prefix.position() as usize;
        if start < self.prefix.get_ref().len() {
            let count = buf.remaining().min(self.prefix.get_ref().len() - start);
            buf.put_slice(&self.prefix.get_ref()[start..start + count]);
            self.prefix.set_position((start + count) as u64);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn timed_out() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, Mutex};

    fn parse(raw: &str) -> io::Result<Request> {
        parse_request(raw.as_bytes(), vec![])
    }

    #[test]
    fn rejects_ambiguous_http_and_smuggling_inputs() {
        for raw in [
            "GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET http://corp.example/ HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
            "GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nHost: corp.example\r\n\r\n",
            "GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nConnection: content-length\r\n\r\n",
            "GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\n X-Obsolete: value\r\n\r\n",
            "GET http://user:pass@corp.example/ HTTP/1.1\r\nHost: corp.example\r\n\r\n",
            "GET http://corp.example/#fragment HTTP/1.1\r\nHost: corp.example\r\n\r\n",
            "GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\nInjected: x\r\n\r\n",
            "CONNECT corp.example:443 HTTP/1.1\r\nHost: corp.example:443\r\nContent-Length: 1\r\n\r\n",
            "POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nTransfer-Encoding: chunked\r\nConnection: transfer-encoding\r\n\r\n",
            "POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nExpect: something-else\r\n\r\n",
        ] {
            assert!(parse(raw).is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn strips_proxy_secrets_and_hop_headers_and_preserves_target_auth() {
        let request = parse("POST http://corp.example:8081/a?b=c HTTP/1.1\r\nHost: corp.example:8081\r\nContent-Length: 3\r\nProxy-Authorization: Basic secret\r\nAuthorization: Bearer target\r\nConnection: x-private, keep-alive\r\nX-Private: discard\r\nKeep-Alive: 30\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
        let header = String::from_utf8(request.forward_header).unwrap();
        assert!(header.starts_with("POST /a?b=c HTTP/1.1\r\n"));
        assert!(!header.to_lowercase().contains("proxy-"));
        assert!(!header.contains("secret"));
        assert!(!header.contains("discard"));
        assert!(header.contains("Authorization: Bearer target\r\n"));
        assert!(header.ends_with("Connection: close\r\n\r\n"));
        assert!(header.contains("Content-Length: 3\r\n"));
    }

    #[test]
    fn authority_parser_rejects_ambiguous_addresses() {
        assert_eq!(
            parse_authority("[2001:db8::1]:443", None).unwrap(),
            Target::new("2001:db8::1", 443).unwrap()
        );
        for invalid in [
            "127.1:80",
            "0127.0.0.1:80",
            "example:0",
            "example:+80",
            "example:65536",
            "2001:db8::1",
            "user@example:80",
            "example:80/path",
            "[::1]evil:80",
        ] {
            assert!(
                parse_authority(invalid, None).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn status_endpoint_accepts_only_unambiguous_bodyless_origin_get() {
        assert!(matches!(
            parse("GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
                .unwrap()
                .local_endpoint,
            Some(LocalEndpoint::Status)
        ));
        for raw in [
            "POST /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET /status?x=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET //status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nHost: localhost:8080\r\n\r\n",
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 1\r\n\r\n",
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\n\r\n",
        ] {
            assert!(parse(raw).is_err(), "accepted {raw:?}");
        }
        let header = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
        assert!(parse_request(header, b"unexpected body".to_vec()).is_err());
        let absolute =
            parse("GET http://127.0.0.1:8080/status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
                .unwrap();
        assert!(absolute.local_endpoint.is_none());
        let listener = "127.0.0.1:8080".parse().unwrap();
        assert!(local_pac_host("127.0.0.1:8080", listener));
        assert!(local_pac_host("localhost:8080", listener));
        for host in [
            "corp.example:8080",
            "127.0.0.1:80",
            "127.0.0.2:8080",
            "localhost.attacker:8080",
            "user@localhost:8080",
            "127.1:8080",
        ] {
            assert!(!local_pac_host(host, listener));
        }
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Echo,
        Http,
        Fail,
        Denied,
    }
    struct MockConnector {
        calls: AtomicUsize,
        mode: Mode,
        received: Arc<Mutex<Vec<u8>>>,
    }
    impl Connector for MockConnector {
        fn connect(&self, _target: Target) -> ConnectFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mode = self.mode;
            let received = self.received.clone();
            Box::pin(async move {
                if matches!(mode, Mode::Fail) {
                    return Err(io::Error::from(io::ErrorKind::NotConnected));
                }
                if matches!(mode, Mode::Denied) {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                let (client, mut peer) = tokio::io::duplex(65536);
                tokio::spawn(async move {
                    match mode {
                        Mode::Echo => {
                            let (mut r, mut w) = tokio::io::split(peer);
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                        }
                        Mode::Http => {
                            let mut bytes = vec![];
                            while !bytes.ends_with(b"\r\n\r\n") {
                                bytes.push(peer.read_u8().await.unwrap());
                            }
                            let text = String::from_utf8(bytes.clone()).unwrap();
                            let length = text
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(str::to_owned)
                                })
                                .unwrap()
                                .parse::<usize>()
                                .unwrap();
                            let mut body = vec![0; length];
                            peer.read_exact(&mut body).await.unwrap();
                            bytes.extend_from_slice(&body);
                            *received.lock().unwrap() = bytes;
                            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                        }
                        Mode::Fail | Mode::Denied => unreachable!(),
                    }
                });
                Ok(Box::new(client) as BoxStream)
            })
        }
    }

    async fn start(
        mode: Mode,
    ) -> (
        SocketAddr,
        SocketAddr,
        Arc<MockConnector>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        start_with_limit(mode, ProxyConfig::default().max_connections).await
    }

    async fn start_with_limit(
        mode: Mode,
        max_connections: usize,
    ) -> (
        SocketAddr,
        SocketAddr,
        Arc<MockConnector>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let config = ProxyConfig {
            http_addr: "127.0.0.1:0".parse().unwrap(),
            socks_addr: "127.0.0.1:0".parse().unwrap(),
            handshake_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(3),
            max_connections,
        };
        let server = ProxyServer::bind(config).await.unwrap();
        let (http, socks) = server.local_addrs();
        let connector = Arc::new(MockConnector {
            calls: AtomicUsize::new(0),
            mode,
            received: Arc::new(Mutex::new(vec![])),
        });
        let policy = Arc::new(Policy::new(vec!["corp.example".into()], vec![]).unwrap());
        let (shutdown, receiver) = watch::channel(false);
        let (_, policy_receiver) = watch::channel(policy);
        let task = tokio::spawn(server.serve(connector.clone(), policy_receiver, receiver));
        (http, socks, connector, shutdown, task)
    }

    async fn finish(shutdown: watch::Sender<bool>, task: tokio::task::JoinHandle<io::Result<()>>) {
        shutdown.send(true).unwrap();
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn connect_preserves_pipelined_tls_bytes() {
        let (http, _, connector, shutdown, task) = start(Mode::Echo).await;
        let mut client = TcpStream::connect(http).await.unwrap();
        client.write_all(b"CONNECT corp.example:443 HTTP/1.1\r\nHost: corp.example:443\r\n\r\nearly TLS bytes").await.unwrap();
        let mut expected =
            vec![0; b"HTTP/1.1 200 Connection Established\r\n\r\nearly TLS bytes".len()];
        timeout(Duration::from_secs(2), client.read_exact(&mut expected))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            expected,
            b"HTTP/1.1 200 Connection Established\r\n\r\nearly TLS bytes"
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn ordinary_http_forwards_only_one_framed_request() {
        let (http, _, connector, shutdown, task) = start(Mode::Http).await;
        let mut client = TcpStream::connect(http).await.unwrap();
        client.write_all(b"POST http://corp.example/a HTTP/1.1\r\nHost: corp.example\r\nContent-Length: 3\r\nProxy-Authorization: secret\r\n\r\nabcGET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n").await.unwrap();
        let mut response = vec![];
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"));
        let sent = connector.received.lock().unwrap().clone();
        assert!(sent.ends_with(b"\r\n\r\nabc"));
        assert!(!String::from_utf8(sent).unwrap().contains("evil.example"));
        finish(shutdown, task).await;
    }

    async fn wire_header<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < MAX_HEADER);
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    }

    // Deliberately independent from Hyper: inspect its wire output and enforce
    // the endpoint's framing boundary, rather than echoing decoded library types.
    async fn wire_chunks<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut body = Vec::new();
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                assert!(line.len() < 128);
                line.push(stream.read_u8().await.unwrap());
            }
            let length =
                usize::from_str_radix(std::str::from_utf8(&line[..line.len() - 2]).unwrap(), 16)
                    .unwrap();
            assert!(body.len() + length <= 65536);
            if length == 0 {
                assert_eq!(stream.read_u16().await.unwrap(), 0x0d0a);
                return body;
            }
            let start = body.len();
            body.resize(start + length, 0);
            stream.read_exact(&mut body[start..]).await.unwrap();
            assert_eq!(stream.read_u16().await.unwrap(), 0x0d0a);
        }
    }

    #[tokio::test]
    async fn streams_chunked_expect_continue_and_strips_trailers_and_second_messages() {
        timeout(Duration::from_secs(3), async {
            let request = parse("POST http://corp.example/upload HTTP/1.1\r\nHost: corp.example\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nTrailer: Proxy-Authorization\r\n\r\n").unwrap();
            let (client, mut app) = tokio::io::duplex(1024);
            let (upstream, mut origin) = tokio::io::duplex(1024);
            let proxy = tokio::spawn(forward_http_with_idle(client, Box::new(upstream), request.forward_header, Duration::from_secs(2)));
            let origin = tokio::spawn(async move {
                let header = String::from_utf8(wire_header(&mut origin).await).unwrap();
                assert!(header.starts_with("POST /upload HTTP/1.1\r\n"));
                assert!(header.contains("transfer-encoding: chunked"));
                assert!(!header.contains("expect:"));
                assert!(!header.contains("trailer:"));
                assert_eq!(wire_chunks(&mut origin).await, b"abcde");
                origin.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-private\r\nX-Private: hidden\r\nTrailer: Proxy-Authenticate\r\n\r\n2\r\nok\r\n0\r\nProxy-Authenticate: secret\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nevil!").await.unwrap();
                let mut remaining = Vec::new();
                origin.read_to_end(&mut remaining).await.unwrap();
                assert!(remaining.is_empty());
            });
            let interim = wire_header(&mut app).await;
            assert!(interim.starts_with(b"HTTP/1.1 100 Continue\r\n"));
            for part in [b"3\r\na".as_slice(), b"bc\r\n2\r\nde\r\n", b"0\r\nProxy-Authorization: secret\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: evil.example\r\n\r\n"] {
                app.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
            let response = String::from_utf8(wire_header(&mut app).await).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(!response.to_lowercase().contains("x-private"));
            assert!(!response.to_lowercase().contains("trailer:"));
            assert_eq!(wire_chunks(&mut app).await, b"ok");
            let mut remaining = Vec::new();
            app.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
            proxy.await.unwrap().unwrap();
            origin.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn early_final_response_does_not_wait_for_unsent_upload() {
        timeout(Duration::from_secs(3), async {
            for length in [0, 32768] {
                let request = parse("POST http://corp.example/upload HTTP/1.1\r\nHost: corp.example\r\nContent-Length: 100000\r\n\r\n").unwrap();
                let (client, mut app) = tokio::io::duplex(1024);
                let (upstream, mut origin) = tokio::io::duplex(1024);
                let proxy = tokio::spawn(forward_http_with_idle(client, Box::new(upstream), request.forward_header, Duration::from_secs(30)));
                wire_header(&mut origin).await;
                let origin = tokio::spawn(async move {
                    origin.write_all(format!("HTTP/1.1 413 Content Too Large\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    for _ in 0..length / 512 {
                        origin.write_all(&[b'x'; 512]).await.unwrap();
                        tokio::task::yield_now().await;
                    }
                });
                let header = wire_header(&mut app).await;
                assert!(header.starts_with(b"HTTP/1.1 413"));
                let mut response = Vec::new();
                app.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, vec![b'x'; length]);
                proxy.await.unwrap().unwrap();
                origin.await.unwrap();
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn response_transfer_coding_cannot_relabel_or_truncate_content() {
        timeout(Duration::from_secs(3), async {
            for headers in [
                "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
                "Transfer-Encoding: gzip, chunked\r\n",
                "Transfer-Encoding: gzip\r\n",
            ] {
                let request = parse("GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\n\r\n").unwrap();
                let (client, mut app) = tokio::io::duplex(1024);
                let (upstream, mut origin) = tokio::io::duplex(1024);
                let proxy = tokio::spawn(forward_http_with_idle(client, Box::new(upstream), request.forward_header, Duration::from_secs(30)));
                wire_header(&mut origin).await;
                origin.write_all(format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n4\r\nevil\r\n0\r\n\r\n").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                app.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 502"));
                assert!(!String::from_utf8_lossy(&response).contains("evil"));
                proxy.await.unwrap().unwrap();
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn malformed_chunks_cannot_be_forwarded_as_another_request() {
        timeout(Duration::from_secs(2), async {
            let request = parse("POST http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
            let (client, mut app) = tokio::io::duplex(1024);
            let (upstream, mut origin) = tokio::io::duplex(1024);
            let proxy = tokio::spawn(forward_http_with_idle(client, Box::new(upstream), request.forward_header, Duration::from_secs(10)));
            app.write_all(b"z\r\nGET /smuggled HTTP/1.1\r\nHost: evil.example\r\n\r\n").await.unwrap();
            let mut sent = Vec::new();
            origin.read_to_end(&mut sent).await.unwrap();
            assert!(!String::from_utf8_lossy(&sent).contains("smuggled"));
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            assert!(!response.starts_with(b"HTTP/1.1 200"));
            let _ = proxy.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn oversized_origin_headers_produce_bounded_gateway_error() {
        timeout(Duration::from_secs(2), async {
            let request =
                parse("GET http://corp.example/ HTTP/1.1\r\nHost: corp.example\r\n\r\n").unwrap();
            let (client, mut app) = tokio::io::duplex(1024);
            let (upstream, mut origin) = tokio::io::duplex(1024);
            let proxy = tokio::spawn(forward_http_with_idle(
                client,
                Box::new(upstream),
                request.forward_header,
                Duration::from_secs(10),
            ));
            wire_header(&mut origin).await;
            let origin = tokio::spawn(async move {
                let mut bytes = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
                bytes.extend_from_slice(&vec![b'x'; MAX_HEADER]);
                bytes.extend_from_slice(b"\r\n\r\n");
                let _ = origin.write_all(&bytes).await;
            });
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 502"));
            assert!(response.len() < 1024);
            proxy.await.unwrap().unwrap();
            origin.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unauthorized_and_offline_requests_do_not_connect_elsewhere() {
        let (http, _, connector, shutdown, task) = start(Mode::Fail).await;
        for (host, status) in [("public.example", "403"), ("corp.example", "502")] {
            let mut client = TcpStream::connect(http).await.unwrap();
            client
                .write_all(
                    format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
        }
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn current_connector_denial_is_distinct_from_an_offline_tunnel() {
        // PAC/history may still classify a revoked target. The current
        // connector's authorization remains authoritative and reports policy
        // denial, instead of pretending that a healthy VPN is offline.
        let (http, socks, connector, shutdown, task) = start(Mode::Denied).await;
        let mut client = TcpStream::connect(http).await.unwrap();
        client
            .write_all(b"CONNECT corp.example:443 HTTP/1.1\r\nHost: corp.example:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(2), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 403"));
        let mut client = TcpStream::connect(socks).await.unwrap();
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, 12];
        request.extend_from_slice(b"corp.example");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0; 12];
        timeout(Duration::from_secs(2), client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        assert_eq!(response[3], 2);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 2);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn socks_domain_connect_and_udp_rejection() {
        let (_, socks, connector, shutdown, task) = start(Mode::Echo).await;
        let mut client = TcpStream::connect(socks).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 12];
        request.extend_from_slice(b"corp.example");
        request.extend_from_slice(&443_u16.to_be_bytes());
        request.extend_from_slice(b"early");
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 15];
        timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[1], 0);
        assert_eq!(&reply[10..], b"early");
        let mut unsupported = TcpStream::connect(socks).await.unwrap();
        unsupported.write_all(&[5, 1, 0, 5, 3, 0, 1]).await.unwrap();
        let mut reply = [0; 12];
        unsupported.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[3], 7);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn serves_local_pac_without_opening_tunnel_connection() {
        let (http, _, connector, shutdown, task) = start(Mode::Fail).await;
        let mut client = TcpStream::connect(http).await.unwrap();
        client
            .write_all(format!("GET /proxy.pac HTTP/1.1\r\nHost: {http}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.contains("FindProxyForURL"));
        assert!(!response.contains("; DIRECT"));
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn versioned_local_pac_is_strict_and_never_opens_egress() {
        timeout(Duration::from_secs(5), async {
            let (http, _, connector, shutdown, task) = start(Mode::Fail).await;
            let valid = "/proxy.pac?gpv=0123456789abcdef0123456789abcdef";
            for (method, target, host, headers, expected) in [
                ("GET", valid, http.to_string(), "", 200),
                (
                    "GET",
                    "/proxy.pac?gpv=00000000000000000000000000000000",
                    http.to_string(),
                    "",
                    200,
                ),
                ("GET", "/proxy.pac?gpv=", http.to_string(), "", 400),
                (
                    "GET",
                    "/proxy.pac?gpv=0123456789abcdef0123456789abcde",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?gpv=0123456789abcdef0123456789abcdef0",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?gpv=0123456789abcdef0123456789abcdeF",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?gpv=0123456789abcdef0123456789abcdef&x=1",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?gpv=0123456789abcdef0123456789abcdef&gpv=0",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?%67pv=0123456789abcdef0123456789abcdef",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/proxy.pac?gpv=%30123456789abcdef0123456789abcdef",
                    http.to_string(),
                    "",
                    400,
                ),
                (
                    "GET",
                    "/status?gpv=0123456789abcdef0123456789abcdef",
                    http.to_string(),
                    "",
                    400,
                ),
                ("POST", valid, http.to_string(), "", 400),
                ("GET", valid, "corp.example".to_string(), "", 403),
                ("GET", valid, http.to_string(), "Content-Length: 1\r\n", 400),
                (
                    "GET",
                    valid,
                    http.to_string(),
                    "Transfer-Encoding: chunked\r\n",
                    400,
                ),
            ] {
                let mut client = TcpStream::connect(http).await.unwrap();
                client
                    .write_all(
                        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut response = String::new();
                client.read_to_string(&mut response).await.unwrap();
                assert!(
                    response.starts_with(&format!("HTTP/1.1 {expected} ")),
                    "{target}: {response}"
                );
                assert_eq!(response.contains("FindProxyForURL"), expected == 200);
            }
            assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
            finish(shutdown, task).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_business_capacity_preserves_pac_and_status_without_extra_egress() {
        timeout(Duration::from_secs(10), async {
            for hold_socks in [false, true] {
                let (http, socks, connector, shutdown, task) =
                    start_with_limit(Mode::Echo, 1).await;
                let mut held = TcpStream::connect(if hold_socks { socks } else { http })
                    .await
                    .unwrap();
                if hold_socks {
                    held.write_all(&[5, 1, 0]).await.unwrap();
                    let mut method = [0; 2];
                    held.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 0]);
                    let mut request = vec![5, 1, 0, 3, 12];
                    request.extend_from_slice(b"corp.example");
                    request.extend_from_slice(&443u16.to_be_bytes());
                    held.write_all(&request).await.unwrap();
                    let mut reply = [0; 10];
                    held.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply[1], 0);
                } else {
                    held.write_all(
                        b"CONNECT corp.example:443 HTTP/1.1\r\nHost: corp.example:443\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    assert!(wire_header(&mut held).await.starts_with(b"HTTP/1.1 200"));
                }
                assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
                // A healthy full proxy must still serve PAC and diagnostics.
                crate::status::query(http)
                    .await
                    .expect("business saturation must not starve status");
                for (request, expected) in [
                    (
                        format!("GET /proxy.pac HTTP/1.1\r\nHost: {http}\r\n\r\n"),
                        "HTTP/1.1 200",
                    ),
                    (
                        "CONNECT corp.example:443 HTTP/1.1\r\nHost: corp.example:443\r\n\r\n"
                            .into(),
                        "HTTP/1.1 503",
                    ),
                ] {
                    let mut client = TcpStream::connect(http).await.unwrap();
                    client.write_all(request.as_bytes()).await.unwrap();
                    let mut response = String::new();
                    client.read_to_string(&mut response).await.unwrap();
                    assert!(response.starts_with(expected), "{response}");
                    if expected.ends_with("200") {
                        assert!(response.contains("PROXY"));
                        assert!(!response.contains("; DIRECT"));
                    }
                }
                assert_eq!(
                    connector.calls.load(Ordering::SeqCst),
                    1,
                    "management reserve must not admit extra business connections"
                );
                held.write_all(b"still-live").await.unwrap();
                let mut echo = [0; 10];
                held.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"still-live");
                finish(shutdown, task).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn status_is_local_no_store_and_never_opens_egress() {
        let (http, _, connector, shutdown, task) = start(Mode::Fail).await;
        for (host, expected) in [
            (http.to_string(), "HTTP/1.1 200"),
            (format!("attacker.example:{}", http.port()), "HTTP/1.1 403"),
        ] {
            let mut client = TcpStream::connect(http).await.unwrap();
            client
                .write_all(format!("GET /status HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(expected));
            if expected.ends_with("200") {
                assert!(response.contains("Content-Type: application/json\r\n"));
                assert!(response.contains("Cache-Control: no-store\r\n"));
                assert!(!response
                    .to_ascii_lowercase()
                    .contains("access-control-allow-origin"));
                let snapshot: crate::status::Snapshot =
                    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(snapshot, crate::status::Snapshot::default());
            }
        }
        assert_eq!(
            crate::status::query(http).await.unwrap().phase,
            crate::status::Phase::Unknown
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        finish(shutdown, task).await;
    }

    #[tokio::test]
    async fn refuses_public_listener_binding() {
        let config = ProxyConfig {
            http_addr: "0.0.0.0:0".parse().unwrap(),
            ..ProxyConfig::default()
        };
        assert!(ProxyServer::bind(config).await.is_err());
        for max_connections in [0, 4097, usize::MAX] {
            let config = ProxyConfig {
                max_connections,
                ..ProxyConfig::default()
            };
            assert_eq!(
                ProxyServer::bind(config).await.err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test]
    async fn bounds_header_memory_before_connecting() {
        let (mut client, mut reader) = tokio::io::duplex(MAX_HEADER + 1);
        client.write_all(&vec![b'x'; MAX_HEADER + 1]).await.unwrap();
        assert_eq!(
            read_request(&mut reader).await.err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test(start_paused = true)]
    async fn one_way_traffic_keeps_the_relay_alive() {
        let (client, mut application) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(relay_with_idle(
            client,
            Box::new(upstream),
            vec![],
            Duration::from_secs(5),
        ));
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(4)).await;
            application.write_all(b"x").await.unwrap();
            let mut byte = [0];
            server.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [b'x']);
            assert!(!task.is_finished());
        }
        drop(application);
        drop(server);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_relay_times_out_and_closes_peer() {
        let (client, mut application) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(64);
        let task = tokio::spawn(relay_with_idle(
            client,
            Box::new(upstream),
            vec![],
            Duration::from_secs(5),
        ));
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let mut byte = [0];
        assert_eq!(application.read(&mut byte).await.unwrap(), 0);
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }
}
