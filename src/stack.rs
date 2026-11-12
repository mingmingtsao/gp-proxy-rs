//! An IP-only userspace network stack. No host network interfaces or destination sockets.
//!
//! A stack belongs to exactly one VPN session. Cancelling that session closes all
//! application streams; a new session must create a new stack and handle.

use std::{
    collections::VecDeque,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot, Notify},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const PACKET_QUEUE: usize = 64;
const STREAM_BUFFER: usize = 32 * 1024;
const TCP_BUFFER: usize = 64 * 1024;
const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_PORT: u16 = 49152;

/// Coherent resource counters for one VPN generation. Queue gauges cover the
/// stack device, not caller-owned transport channels. Byte counters count whole
/// IP packets, including headers and retransmissions. Capacity is a buffer
/// budget, not a measurement of process RSS or allocator overhead.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct StackStats {
    pub active_tcp: usize,
    pub pending_tcp: usize,
    pub active_udp: usize,
    pub time_wait: usize,
    pub socket_count: usize,
    pub command_queue: usize,
    pub incoming_queue: usize,
    pub outgoing_queue: usize,
    pub tcp_buffer_capacity_bytes: usize,
    pub peak_active_tcp: usize,
    pub peak_active_udp: usize,
    pub peak_time_wait: usize,
    pub peak_socket_count: usize,
    pub peak_command_queue: usize,
    pub peak_incoming_queue: usize,
    pub peak_outgoing_queue: usize,
    pub peak_tcp_buffer_capacity_bytes: usize,
    pub tcp_connect_requests: u64,
    pub tcp_connects_established: u64,
    pub tcp_admission_rejections: u64,
    pub tcp_flows_released: u64,
    pub udp_requests: u64,
    pub udp_admission_rejections: u64,
    pub ip_packets_received: u64,
    pub ip_bytes_received: u64,
    pub ip_packets_sent: u64,
    pub ip_bytes_sent: u64,
    pub malformed_ip_packets: u64,
}

impl StackStats {
    fn clear_gauges(&mut self) {
        self.active_tcp = 0;
        self.pending_tcp = 0;
        self.active_udp = 0;
        self.time_wait = 0;
        self.socket_count = 0;
        self.command_queue = 0;
        self.incoming_queue = 0;
        self.outgoing_queue = 0;
        self.tcp_buffer_capacity_bytes = 0;
    }
}

#[derive(Clone, Debug)]
pub struct StackConfig {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    pub max_connections: usize,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Seed from a cryptographically secure OS RNG, fresh for each session.
    pub random_seed: u64,
}

impl StackConfig {
    fn validate(&self) -> io::Result<()> {
        if self.ipv4.is_unspecified()
            || self.ipv4.is_multicast()
            || self.ipv4.is_broadcast()
            || self
                .ipv6
                .is_some_and(|a| a.is_unspecified() || a.is_multicast())
            || !(576..=9000).contains(&self.mtu)
            || (self.ipv6.is_some() && self.mtu < 1280)
            || !(1..=8192).contains(&self.max_connections)
            || self.connect_timeout.is_zero()
            || self.idle_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid userspace stack configuration",
            ));
        }
        Ok(())
    }
}

/// A capability for one live VPN generation. It never resolves or dials using the host.
#[derive(Clone)]
pub struct StackHandle {
    commands: mpsc::Sender<Command>,
    cancel: CancellationToken,
    connect_timeout: Duration,
    mtu: usize,
    stats: Arc<Mutex<StackStats>>,
}

impl StackHandle {
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Queue identity is the generation identity, including after cancellation.
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.commands.same_channel(&other.commands)
    }

    pub async fn connect(&self, remote: SocketAddr) -> io::Result<DuplexStream> {
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.commands
                .send(Command::Connect { remote, reply })
                .await
                .map_err(|_| disconnected())?;
            response.await.map_err(|_| disconnected())?
        };
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(disconnected()),
            result = tokio::time::timeout(self.connect_timeout, operation) =>
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VPN TCP connect timed out"))?,
        }
    }

    /// One datagram request and one matching peer response, intended for tunnel DNS.
    /// No retry or fallback occurs here. Cancellation drops the outstanding socket.
    pub async fn udp_exchange(&self, remote: SocketAddr, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        let overhead = if remote.is_ipv4() { 28 } else { 48 };
        if payload.len() > self.mtu - overhead {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP datagram exceeds VPN MTU",
            ));
        }
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.commands
                .send(Command::Udp {
                    remote,
                    payload,
                    reply,
                })
                .await
                .map_err(|_| disconnected())?;
            response.await.map_err(|_| disconnected())?
        };
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(disconnected()),
            result = tokio::time::timeout(UDP_TIMEOUT, operation) =>
                result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VPN UDP request timed out"))?,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled() || self.commands.is_closed()
    }

    /// Last actor snapshot. Actor exit clears gauges but preserves counters and
    /// peaks through existing handles, including after unexpected transport loss.
    pub fn stats(&self) -> StackStats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Start a fresh stack with bounded, complete-IP-packet channels.
/// Dropping either packet channel terminates the stack and all active connections.
pub fn spawn(
    config: StackConfig,
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) -> io::Result<(StackHandle, JoinHandle<io::Result<()>>)> {
    config.validate()?;
    let (commands, receive_commands) = mpsc::channel(config.max_connections.min(128));
    let actor = Actor::new(config.clone());
    let handle = StackHandle {
        commands,
        cancel: cancel.clone(),
        connect_timeout: config.connect_timeout,
        mtu: config.mtu,
        stats: actor.stats.clone(),
    };
    let task = tokio::spawn(actor.run(inbound, outbound, receive_commands, cancel));
    Ok((handle, task))
}

enum Command {
    Connect {
        remote: SocketAddr,
        reply: oneshot::Sender<io::Result<DuplexStream>>,
    },
    Udp {
        remote: SocketAddr,
        payload: Vec<u8>,
        reply: oneshot::Sender<io::Result<Vec<u8>>>,
    },
}

struct TcpFlow {
    handle: SocketHandle,
    port: u16,
    stream: DuplexStream,
    client: Option<DuplexStream>,
    reply: Option<oneshot::Sender<io::Result<DuplexStream>>>,
    deadline: Instant,
    last_activity: Instant,
    local_eof: bool,
    remote_eof: bool,
}

struct UdpFlow {
    handle: SocketHandle,
    port: u16,
    remote: IpEndpoint,
    reply: Option<oneshot::Sender<io::Result<Vec<u8>>>>,
    deadline: Instant,
}

struct RetiredTcp {
    handle: SocketHandle,
    port: u16,
}

struct Actor {
    config: StackConfig,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: Vec<TcpFlow>,
    time_wait: Vec<RetiredTcp>,
    udp: Vec<UdpFlow>,
    next_port: u16,
    started: Instant,
    metrics: StackStats,
    stats: Arc<Mutex<StackStats>>,
}

impl Drop for Actor {
    fn drop(&mut self) {
        self.metrics.tcp_flows_released += self.tcp.len() as u64;
        self.publish_stats(0);
        self.metrics.clear_gauges();
        *self.stats.lock().unwrap_or_else(|e| e.into_inner()) = self.metrics.clone();
    }
}

impl Actor {
    fn new(config: StackConfig) -> Self {
        let mut device = PacketDevice::new(config.mtu);
        let mut settings = Config::new(HardwareAddress::Ip);
        settings.random_seed = config.random_seed;
        let mut iface = Interface::new(settings, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(config.ipv4.into(), 32))
                .expect("two addresses fit default smoltcp capacity");
            if let Some(ipv6) = config.ipv6 {
                addrs
                    .push(IpCidr::new(ipv6.into(), 128))
                    .expect("two addresses fit default smoltcp capacity");
            }
        });
        // These routes exist only inside smoltcp. The IP medium has no ARP/ND.
        iface
            .routes_mut()
            .add_default_ipv4_route(config.ipv4)
            .expect("default route capacity");
        if let Some(ipv6) = config.ipv6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(ipv6)
                .expect("default route capacity");
        }
        let next_port = FIRST_PORT + (config.random_seed % 16384) as u16;
        Self {
            config,
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            tcp: vec![],
            time_wait: vec![],
            udp: vec![],
            next_port,
            started: Instant::now(),
            metrics: StackStats::default(),
            stats: Arc::new(Mutex::new(StackStats::default())),
        }
    }

    fn timestamp(&self) -> SmolInstant {
        SmolInstant::from_millis(self.started.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }

    fn publish_stats(&mut self, command_queue: usize) {
        let stats = &mut self.metrics;
        stats.active_tcp = self.tcp.len();
        stats.pending_tcp = self.tcp.iter().filter(|flow| flow.reply.is_some()).count();
        stats.active_udp = self.udp.len();
        stats.time_wait = self.time_wait.len();
        stats.socket_count = self.sockets.iter().count();
        stats.command_queue = command_queue;
        stats.incoming_queue = self.device.incoming.len();
        stats.outgoing_queue = self.device.outgoing.len();
        stats.tcp_buffer_capacity_bytes = self
            .sockets
            .iter()
            .map(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(socket) => {
                    socket.recv_capacity() + socket.send_capacity()
                }
                _ => 0,
            })
            .sum::<usize>()
            + stats.active_tcp * STREAM_BUFFER * 2;
        stats.peak_active_tcp = stats.peak_active_tcp.max(stats.active_tcp);
        stats.peak_active_udp = stats.peak_active_udp.max(stats.active_udp);
        stats.peak_time_wait = stats.peak_time_wait.max(stats.time_wait);
        stats.peak_socket_count = stats.peak_socket_count.max(stats.socket_count);
        stats.peak_command_queue = stats.peak_command_queue.max(stats.command_queue);
        stats.peak_incoming_queue = stats.peak_incoming_queue.max(stats.incoming_queue);
        stats.peak_outgoing_queue = stats.peak_outgoing_queue.max(stats.outgoing_queue);
        stats.peak_tcp_buffer_capacity_bytes = stats
            .peak_tcp_buffer_capacity_bytes
            .max(stats.tcp_buffer_capacity_bytes);
        *self.stats.lock().unwrap_or_else(|e| e.into_inner()) = stats.clone();
    }

    async fn run(
        mut self,
        mut inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
        mut commands: mpsc::Receiver<Command>,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        // Every exit invalidates this generation, including unexpected packet-channel closure.
        let _cancel_on_exit = cancel.clone().drop_guard();
        let signal = Arc::new(StreamWake(Notify::new()));
        let waker = Waker::from(signal.clone());
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            while let Some(packet) = self.device.outgoing.pop_front() {
                let length = packet.len();
                match outbound.try_send(packet) {
                    Ok(()) => {
                        self.metrics.ip_packets_sent += 1;
                        self.metrics.ip_bytes_sent += length as u64;
                    }
                    Err(mpsc::error::TrySendError::Full(packet)) => {
                        self.device.outgoing.push_front(packet);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return Err(disconnected()),
                }
            }
            let timestamp = self.timestamp();
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);
            self.service_flows(&waker);
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);

            self.publish_stats(commands.len());

            // A bounded timer covers TCP retransmissions and request/idle deadlines.
            // Stream wakers and packet channels normally wake us earlier.
            let delay = self
                .iface
                .poll_delay(timestamp, &self.sockets)
                .map(|d| Duration::from_millis(d.total_millis()))
                .unwrap_or(Duration::from_millis(100))
                .clamp(Duration::from_millis(1), Duration::from_millis(100));
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = outbound.closed() => return Err(disconnected()),
                packet = inbound.recv(), if self.device.incoming.len() < PACKET_QUEUE => {
                    match packet {
                        Some(packet) if valid_ip_packet(&packet, self.config.mtu) => {
                            self.metrics.ip_packets_received += 1;
                            self.metrics.ip_bytes_received += packet.len() as u64;
                            self.device.incoming.push_back(packet);
                            self.metrics.peak_incoming_queue = self.metrics.peak_incoming_queue.max(self.device.incoming.len());
                        },
                        Some(_) => self.metrics.malformed_ip_packets += 1,
                        None => return Err(disconnected()),
                    }
                }
                command = commands.recv() => match command {
                    Some(command) => self.command(command),
                    None => return Ok(()),
                },
                _ = signal.0.notified() => {},
                _ = outbound.reserve(), if !self.device.outgoing.is_empty() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
    }

    fn port(&mut self) -> io::Result<u16> {
        for _ in FIRST_PORT..=u16::MAX {
            let port = self.next_port;
            self.next_port = if port == u16::MAX {
                FIRST_PORT
            } else {
                port + 1
            };
            if !self.tcp.iter().any(|f| f.port == port)
                && !self.udp.iter().any(|f| f.port == port)
                && !self.time_wait.iter().any(|f| f.port == port)
            {
                return Ok(port);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "VPN ephemeral ports exhausted",
        ))
    }

    fn admit(&mut self, remote: SocketAddr, tcp: bool) -> io::Result<u16> {
        self.reap_time_wait();
        if self.tcp.len() + self.udp.len() >= self.config.max_connections {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VPN connection limit reached",
            ));
        }
        if tcp && self.time_wait.len() >= self.time_wait_limit() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VPN TCP closing-state budget exhausted",
            ));
        }
        if remote.port() == 0
            || remote.ip().is_unspecified()
            || remote.ip().is_multicast()
            || (remote.is_ipv6() && self.config.ipv6.is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination unsupported by VPN stack",
            ));
        }
        self.port()
    }

    fn time_wait_limit(&self) -> usize {
        (self.config.max_connections * 2).min(512)
    }

    fn reap_time_wait(&mut self) {
        self.time_wait.retain(|flow| {
            if self.sockets.get::<tcp::Socket>(flow.handle).state() == tcp::State::Closed {
                self.sockets.remove(flow.handle);
                false
            } else {
                true
            }
        });
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Connect { remote, reply } => {
                self.metrics.tcp_connect_requests += 1;
                if reply.is_closed() {
                    return;
                }
                let result = self.admit(remote, true).and_then(|port| {
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    );
                    socket.set_keep_alive(Some(SmolDuration::from_secs(30)));
                    socket.set_timeout(Some(SmolDuration::from_secs(120)));
                    socket
                        .connect(self.iface.context(), endpoint(remote), port)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "invalid VPN TCP endpoint")
                        })?;
                    Ok((port, self.sockets.add(socket)))
                });
                match result {
                    Ok((port, handle)) => {
                        let (client, stream) = tokio::io::duplex(STREAM_BUFFER);
                        self.tcp.push(TcpFlow {
                            handle,
                            port,
                            stream,
                            client: Some(client),
                            reply: Some(reply),
                            deadline: Instant::now() + self.config.connect_timeout,
                            last_activity: Instant::now(),
                            local_eof: false,
                            remote_eof: false,
                        });
                    }
                    Err(error) => {
                        self.metrics.tcp_admission_rejections += 1;
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Command::Udp {
                remote,
                payload,
                reply,
            } => {
                self.metrics.udp_requests += 1;
                if reply.is_closed() {
                    return;
                }
                let result = self.admit(remote, false).and_then(|port| {
                    // Fragmentation is deliberately disabled. DNS callers should
                    // advertise an EDNS payload no larger than 1232 bytes.
                    let overhead = if remote.is_ipv4() { 28 } else { 48 };
                    if payload.len() > self.config.mtu - overhead {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "UDP datagram exceeds VPN MTU",
                        ));
                    }
                    let mut socket = udp::Socket::new(
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 4],
                            vec![0; self.config.mtu * 4],
                        ),
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 1],
                            vec![0; self.config.mtu],
                        ),
                    );
                    socket.bind(port).map_err(|_| {
                        io::Error::new(io::ErrorKind::AddrInUse, "VPN UDP bind failed")
                    })?;
                    socket.send_slice(&payload, endpoint(remote)).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "VPN UDP payload rejected")
                    })?;
                    Ok((port, self.sockets.add(socket)))
                });
                match result {
                    Ok((port, handle)) => self.udp.push(UdpFlow {
                        handle,
                        port,
                        remote: endpoint(remote),
                        reply: Some(reply),
                        deadline: Instant::now() + UDP_TIMEOUT,
                    }),
                    Err(error) => {
                        self.metrics.udp_admission_rejections += 1;
                        let _ = reply.send(Err(error));
                    }
                }
            }
        }
    }

    fn service_flows(&mut self, waker: &Waker) {
        let mut cx = Context::from_waker(waker);
        let now = Instant::now();
        self.reap_time_wait();
        let time_wait_limit = self.time_wait_limit();
        let mut aborted = Vec::new();
        self.tcp.retain_mut(|flow| {
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            let keep = service_tcp(
                flow,
                socket,
                &mut cx,
                now,
                self.config.idle_timeout,
                &mut self.metrics,
            );
            if socket.state() == tcp::State::TimeWait
                && !socket.can_recv()
                && flow.remote_eof
                && self.time_wait.len() < time_wait_limit
            {
                // Retain smoltcp's TIME_WAIT handling, including repeated FIN ACKs,
                // but release the application bridge and its admission slot.
                self.time_wait.push(RetiredTcp {
                    handle: flow.handle,
                    port: flow.port,
                });
                self.metrics.tcp_flows_released += 1;
                return false;
            }
            if !keep {
                self.metrics.tcp_flows_released += 1;
                socket.abort();
                aborted.push(flow.handle);
            }
            keep
        });
        if !aborted.is_empty() {
            // Give smoltcp an opportunity to emit resets before releasing sockets.
            // If the bounded packet queue is full, session safety still wins over
            // retaining unbounded dead flows solely to deliver a best-effort RST.
            self.iface
                .poll(self.timestamp(), &mut self.device, &mut self.sockets);
            for handle in aborted {
                self.sockets.remove(handle);
            }
        }
        self.udp.retain_mut(|flow| {
            let socket = self.sockets.get_mut::<udp::Socket>(flow.handle);
            let keep = if flow.reply.as_ref().is_none_or(|r| r.is_closed()) {
                false
            } else if now >= flow.deadline {
                let _ = flow.reply.take().unwrap().send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VPN UDP response timed out",
                )));
                false
            } else {
                let mut keep = true;
                while let Ok((data, meta)) = socket.recv() {
                    if meta.endpoint == flow.remote {
                        let _ = flow.reply.take().unwrap().send(Ok(data.to_vec()));
                        keep = false;
                        break;
                    }
                }
                keep
            };
            if !keep {
                self.sockets.remove(flow.handle);
            }
            keep
        });
    }
}

fn service_tcp(
    flow: &mut TcpFlow,
    socket: &mut tcp::Socket<'_>,
    cx: &mut Context<'_>,
    now: Instant,
    idle_timeout: Duration,
    stats: &mut StackStats,
) -> bool {
    if let Some(reply) = flow.reply.as_ref() {
        if reply.is_closed() {
            return false;
        }
        if now >= flow.deadline {
            let _ = flow.reply.take().unwrap().send(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VPN TCP handshake timed out",
            )));
            return false;
        }
        if socket.state() == tcp::State::Established {
            if flow
                .reply
                .take()
                .unwrap()
                .send(Ok(flow.client.take().unwrap()))
                .is_err()
            {
                return false;
            }
            stats.tcp_connects_established += 1;
        } else if !socket.is_open() {
            let _ = flow.reply.take().unwrap().send(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "VPN TCP connection refused",
            )));
            return false;
        } else {
            return true;
        }
    }
    if socket.state() != tcp::State::TimeWait
        && now.duration_since(flow.last_activity) >= idle_timeout
    {
        return false;
    }

    // Discover a dropped application even when the peer's TCP window is full.
    // Otherwise local EOF cannot be read until can_send(), pinning the bridge
    // and its admission slot until a much later TCP/idle timeout.
    if !flow.remote_eof
        && matches!(
            Pin::new(&mut flow.stream).poll_write(cx, &[]),
            Poll::Ready(Err(_))
        )
    {
        return false;
    }

    if socket.can_recv() {
        let result = socket.recv(
            |bytes| match Pin::new(&mut flow.stream).poll_write(cx, bytes) {
                Poll::Ready(Ok(count)) => (count, Ok(count)),
                Poll::Ready(Err(error)) => (0, Err(error)),
                Poll::Pending => (0, Ok(0)),
            },
        );
        match result {
            Ok(Ok(count)) if count > 0 => flow.last_activity = now,
            Ok(Err(_)) | Err(_) => return false,
            _ => {}
        }
    }
    if !socket.may_recv() && !flow.remote_eof {
        match Pin::new(&mut flow.stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => flow.remote_eof = true,
            Poll::Ready(Err(_)) => return false,
            Poll::Pending => {}
        }
    }
    if socket.can_send() && !flow.local_eof {
        let mut buffer = [0u8; 8192];
        let capacity = buffer
            .len()
            .min(socket.send_capacity().saturating_sub(socket.send_queue()));
        let mut read = ReadBuf::new(&mut buffer[..capacity]);
        match Pin::new(&mut flow.stream).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                flow.local_eof = true;
                socket.close();
            }
            Poll::Ready(Ok(())) => {
                let bytes = read.filled();
                if socket.send_slice(bytes).ok() != Some(bytes.len()) {
                    return false;
                }
                flow.last_activity = now;
            }
            Poll::Ready(Err(_)) => return false,
            Poll::Pending => {}
        }
    }
    // FIN/ACK can complete before the application drains the receive buffer.
    // Also retain TIME_WAIT so a recently used local port is not recycled early.
    socket.state() != tcp::State::Closed || socket.can_recv()
}

fn endpoint(remote: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(remote.ip()), remote.port())
}

fn disconnected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "GlobalProtect session is unavailable",
    )
}

struct StreamWake(Notify);
impl Wake for StreamWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

fn valid_ip_packet(packet: &[u8], mtu: usize) -> bool {
    if packet.len() > mtu {
        return false;
    }
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = (packet[0] & 0xf) as usize * 4;
            header >= 20
                && header <= packet.len()
                && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            u16::from_be_bytes([packet[4], packet[5]]) as usize + 40 == packet.len()
        }
        _ => false,
    }
}

/// This is an in-memory packet adapter, not an operating-system network device.
struct PacketDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl PacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            mtu,
        }
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = PacketRx;
    type TxToken<'a> = PacketTx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= PACKET_QUEUE {
            return None;
        }
        self.incoming
            .pop_front()
            .map(|packet| (PacketRx(packet), PacketTx(&mut self.outgoing)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        (self.outgoing.len() < PACKET_QUEUE).then_some(PacketTx(&mut self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(PACKET_QUEUE);
        caps
    }
}

struct PacketRx(Vec<u8>);
impl RxToken for PacketRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct PacketTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for PacketTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy::Policy,
        proxy::{BoxStream, ConnectFuture, Connector, ProxyConfig, ProxyServer, Target},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestConnector(StackHandle);
    impl Connector for TestConnector {
        fn connect(&self, target: Target) -> ConnectFuture<'_> {
            Box::pin(async move {
                let address = target.host.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "test accepts IP literals only")
                })?;
                let stream = self
                    .0
                    .connect(SocketAddr::new(address, target.port))
                    .await?;
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    async fn http_response_header(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 1024);
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    }

    fn config(address: Ipv4Addr) -> StackConfig {
        StackConfig {
            ipv4: address,
            ipv6: None,
            mtu: 1400,
            max_connections: 8,
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(30),
            random_seed: 0x319a_5402_af12_3157,
        }
    }

    type StackPair = (
        StackHandle,
        CancellationToken,
        JoinHandle<io::Result<()>>,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
    );

    fn pair() -> StackPair {
        let (from_stack, peer_rx) = mpsc::channel(4);
        let (peer_tx, to_stack) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let (handle, task) = spawn(
            config(Ipv4Addr::new(10, 77, 0, 2)),
            to_stack,
            from_stack,
            cancel.clone(),
        )
        .unwrap();
        (handle, cancel, task, peer_rx, peer_tx)
    }

    async fn tcp_echo_peer(
        mut rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        stop: CancellationToken,
    ) -> Vec<u8> {
        let mut peer = Actor::new(config(Ipv4Addr::new(10, 77, 0, 1)));
        // smoltcp listeners have no backlog: a second listening socket permits
        // another SYN while the previous socket is finishing LAST_ACK.
        let mut flows = Vec::new();
        for _ in 0..2 {
            let mut tcp = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 8192]),
                tcp::SocketBuffer::new(vec![0; 8192]),
            );
            tcp.listen(443).unwrap();
            flows.push((peer.sockets.add(tcp), Vec::new(), false));
        }
        let mut received = Vec::new();
        loop {
            peer.iface
                .poll(peer.timestamp(), &mut peer.device, &mut peer.sockets);
            for (handle, pending, connected) in &mut flows {
                let socket = peer.sockets.get_mut::<tcp::Socket>(*handle);
                *connected |= socket.state() == tcp::State::Established;
                if socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            received.extend_from_slice(bytes);
                            pending.extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                }
                if socket.can_send() && !pending.is_empty() {
                    let sent = socket.send_slice(pending).unwrap();
                    pending.drain(..sent);
                }
                if *connected && !socket.may_recv() && pending.is_empty() {
                    socket.close();
                }
                if *connected && socket.state() == tcp::State::Closed {
                    socket.listen(443).unwrap();
                    *connected = false;
                }
            }
            peer.iface
                .poll(peer.timestamp(), &mut peer.device, &mut peer.sockets);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                tokio::select! {
                    _ = stop.cancelled() => return received,
                    result = tx.send(packet) => if result.is_err() { return received; },
                }
            }
            tokio::select! {
                _ = stop.cancelled() => return received,
                packet = rx.recv() => match packet {
                    Some(packet) => peer.device.incoming.push_back(packet),
                    None => return received,
                },
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
        }
    }

    #[tokio::test]
    async fn real_tcp_packets_transfer_large_stream_and_half_close() {
        let (stack, stop, task, rx, tx) = pair();
        let peer_stop = CancellationToken::new();
        let peer = tokio::spawn(tcp_echo_peer(rx, tx, peer_stop.clone()));
        let stream = stack
            .connect("10.77.0.1:443".parse().unwrap())
            .await
            .unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let payload: Vec<u8> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let send = async {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            // Accumulate enough data to exercise receive-side backpressure before
            // the application begins reading the echo stream.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let mut echoed = Vec::new();
            reader.read_to_end(&mut echoed).await.unwrap();
            echoed
        };
        let (_, echoed) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(send, receive)
        })
        .await
        .unwrap();
        assert_eq!(echoed, expected);
        peer_stop.cancel();
        assert_eq!(peer.await.unwrap(), expected);
        stop.cancel();
        let _ = task.await.unwrap();
    }

    #[tokio::test]
    async fn real_http_and_socks_proxies_reach_only_the_userspace_peer() {
        tokio::time::timeout(Duration::from_secs(15), async {
            for socks in [false, true] {
                let (stack, stop, task, rx, tx) = pair();
                let peer_stop = CancellationToken::new();
                let peer = tokio::spawn(tcp_echo_peer(rx, tx, peer_stop.clone()));
                let proxy = ProxyServer::bind(ProxyConfig {
                    http_addr: "127.0.0.1:0".parse().unwrap(),
                    socks_addr: "127.0.0.1:0".parse().unwrap(),
                    ..ProxyConfig::default()
                })
                .await
                .unwrap();
                let (http_addr, socks_addr) = proxy.local_addrs();
                let (_policy_tx, policy) = tokio::sync::watch::channel(Arc::new(
                    Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap(),
                ));
                let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
                let proxy_task =
                    tokio::spawn(proxy.serve(Arc::new(TestConnector(stack)), policy, shutdown));
                let mut application =
                    tokio::net::TcpStream::connect(if socks { socks_addr } else { http_addr })
                        .await
                        .unwrap();
                let payload = b"only raw IP packets can reach this peer";
                if socks {
                    application.write_all(&[5, 1, 0]).await.unwrap();
                    let mut greeting = [0; 2];
                    application.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 0]);
                    application
                        .write_all(&[5, 1, 0, 1, 10, 77, 0, 1, 1, 187])
                        .await
                        .unwrap();
                    let mut accepted = [0; 10];
                    application.read_exact(&mut accepted).await.unwrap();
                    assert_eq!(&accepted[..4], &[5, 0, 0, 1]);
                    application.write_all(payload).await.unwrap();
                } else {
                    let mut request =
                        b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n".to_vec();
                    request.extend_from_slice(payload);
                    application.write_all(&request).await.unwrap();
                    assert!(http_response_header(&mut application)
                        .await
                        .starts_with(b"HTTP/1.1 200"));
                }
                application.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                application.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, payload);
                stop.cancel();
                task.await.unwrap().unwrap();
                let mut offline = tokio::net::TcpStream::connect(http_addr).await.unwrap();
                offline
                    .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
                    .await
                    .unwrap();
                assert!(http_response_header(&mut offline)
                    .await
                    .starts_with(b"HTTP/1.1 502"));
                shutdown_tx.send(true).unwrap();
                proxy_task.await.unwrap().unwrap();
                peer_stop.cancel();
                assert_eq!(peer.await.unwrap(), payload);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancellation_invalidates_existing_and_new_connections() {
        let (stack, stop, task, rx, tx) = pair();
        let peer_stop = CancellationToken::new();
        let peer = tokio::spawn(tcp_echo_peer(rx, tx, peer_stop.clone()));
        let mut stream = stack
            .connect("10.77.0.1:443".parse().unwrap())
            .await
            .unwrap();
        stop.cancel();
        task.await.unwrap().unwrap();
        let mut buffer = [0; 1];
        assert_eq!(stream.read(&mut buffer).await.unwrap(), 0);
        assert_eq!(
            stack
                .connect("10.77.0.1:443".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert!(stack.is_closed());
        peer_stop.cancel();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_transport_closes_generation_and_pending_connect() {
        let (stack, stop, task, mut rx, tx) = pair();
        let connecting = tokio::spawn({
            let stack = stack.clone();
            async move { stack.connect("10.77.0.1:443".parse().unwrap()).await }
        });
        let syn = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&syn[16..20], &[10, 77, 0, 1]);
        drop(tx);
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            connecting.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(stop.is_cancelled());
    }

    #[tokio::test]
    async fn exhausted_connection_budget_rejects_and_timeout_reclaims() {
        let (from_stack, mut peer_rx) = mpsc::channel(4);
        let (_peer_tx, to_stack) = mpsc::channel(4);
        let stop = CancellationToken::new();
        let mut settings = config(Ipv4Addr::new(10, 77, 0, 2));
        settings.max_connections = 1;
        settings.connect_timeout = Duration::from_millis(150);
        let (stack, task) = spawn(settings, to_stack, from_stack, stop.clone()).unwrap();
        let connecting = tokio::spawn({
            let stack = stack.clone();
            async move { stack.connect("10.77.0.1:443".parse().unwrap()).await }
        });
        tokio::time::timeout(Duration::from_secs(1), peer_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stack
                .connect("10.77.0.1:444".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            connecting.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        // Actor's deadline sweep removes the cancelled request within 100 ms.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            stack
                .connect("10.77.0.1:444".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        stop.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn short_connections_have_separate_bounded_time_wait_budget() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (from_stack, peer_rx) = mpsc::channel(4);
            let (peer_tx, to_stack) = mpsc::channel(4);
            let stop = CancellationToken::new();
            let peer_stop = CancellationToken::new();
            let mut settings = config(Ipv4Addr::new(10, 77, 0, 2));
            settings.max_connections = 1;
            let (stack, task) = spawn(settings, to_stack, from_stack, stop.clone()).unwrap();
            let peer = tokio::spawn(tcp_echo_peer(peer_rx, peer_tx, peer_stop.clone()));
            for _ in 0..2 {
                let mut stream = stack
                    .connect("10.77.0.1:443".parse().unwrap())
                    .await
                    .unwrap();
                stream.write_all(b"short").await.unwrap();
                stream.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).await.unwrap();
                assert_eq!(echoed, b"short");
            }
            // TIME_WAIT does not consume the one active slot, so the second
            // connection succeeds. Its own two-slot memory budget is now full.
            let error = stack
                .connect("10.77.0.1:443".parse().unwrap())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(error.to_string().contains("closing-state budget"));
            stop.cancel();
            task.await.unwrap().unwrap();
            peer_stop.cancel();
            assert_eq!(peer.await.unwrap(), b"shortshort");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_exchange_uses_ip_packets_and_checks_response_peer() {
        let (stack, stop, task, mut rx, tx) = pair();
        let peer = tokio::spawn(async move {
            let mut peer = Actor::new(config(Ipv4Addr::new(10, 77, 0, 1)));
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            );
            socket.bind(53).unwrap();
            let udp = peer.sockets.add(socket);
            peer.device.incoming.push_back(rx.recv().await.unwrap());
            peer.iface
                .poll(peer.timestamp(), &mut peer.device, &mut peer.sockets);
            let socket = peer.sockets.get_mut::<udp::Socket>(udp);
            let (request, meta) = socket.recv().unwrap();
            assert_eq!(request, b"dns query");
            let destination = meta.endpoint;
            let mut wrong_peer = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 4096]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 1], vec![0; 4096]),
            );
            wrong_peer.bind(54).unwrap();
            wrong_peer.send_slice(b"wrong peer", destination).unwrap();
            peer.sockets.add(wrong_peer);
            peer.iface
                .poll(peer.timestamp(), &mut peer.device, &mut peer.sockets);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                tx.send(packet).await.unwrap();
            }
            peer.sockets
                .get_mut::<udp::Socket>(udp)
                .send_slice(b"dns response", destination)
                .unwrap();
            peer.iface
                .poll(peer.timestamp(), &mut peer.device, &mut peer.sockets);
            while let Some(packet) = peer.device.outgoing.pop_front() {
                tx.send(packet).await.unwrap();
            }
            // Keep input alive until the client has consumed the response.
            rx.recv().await;
        });
        assert_eq!(
            stack
                .udp_exchange("10.77.0.1:53".parse().unwrap(), b"dns query".to_vec())
                .await
                .unwrap(),
            b"dns response"
        );
        stop.cancel();
        task.await.unwrap().unwrap();
        peer.await.unwrap();
    }

    #[test]
    fn malformed_and_oversized_ip_packets_are_rejected() {
        assert!(!valid_ip_packet(&[], 1400));
        assert!(!valid_ip_packet(&[0x40; 20], 1400));
        let mut ipv4 = vec![0; 20];
        ipv4[0] = 0x45;
        ipv4[3] = 20;
        assert!(valid_ip_packet(&ipv4, 1400));
        assert!(!valid_ip_packet(&ipv4, 19));
        ipv4[0] = 0x4f;
        assert!(!valid_ip_packet(&ipv4, 1400));
    }
}
