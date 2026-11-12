//! Bounded independent smoltcp raw-IP echo peer, shared by lifecycle and soak tests.
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpCidr},
};
use std::{
    collections::VecDeque,
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;
#[path = "socket_priority.rs"]
mod socket_priority;
const PACKETS: usize = 64;
const PEER_BUFFER: usize = 32 * 1024;
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PeerStats {
    pub tcp_connections: u64,
    pub tcp_closed: u64,
    pub tcp_bytes_received: u64,
    pub tcp_bytes_echoed: u64,
    pub udp_requests: u64,
    pub peak_pending_echo_bytes: usize,
}

struct PacketDevice {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
impl Device for PacketDevice {
    type RxToken<'a> = PacketRx;
    type TxToken<'a> = PacketTx<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.output.len() >= PACKETS {
            return None;
        }
        self.input
            .pop_front()
            .map(|packet| (PacketRx(packet), PacketTx(&mut self.output)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        (self.output.len() < PACKETS).then_some(PacketTx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1400;
        caps.max_burst_size = Some(PACKETS);
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
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        assert!(length <= 1400);
        let mut bytes = vec![0; length];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_peer(
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    stop: CancellationToken,
    shared: Arc<Mutex<PeerStats>>,
    paused: Arc<AtomicBool>,
    listener_count: usize,
    seed: u64,
) -> io::Result<()> {
    let mut device = PacketDevice {
        input: VecDeque::new(),
        output: VecDeque::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed.wrapping_add(71);
    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(Ipv4Addr::new(10, 77, 0, 1).into(), 24))
            .unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut flows = vec![];
    for _ in 0..listener_count {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; PEER_BUFFER]),
            tcp::SocketBuffer::new(vec![0; PEER_BUFFER]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
        socket.listen(443).unwrap();
        flows.push((sockets.add(socket), VecDeque::<u8>::new(), false));
    }
    let mut udp = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 5600]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 5600]),
    );
    udp.bind(53).unwrap();
    let mut udp_handle = sockets.add(udp);
    let started = Instant::now();
    let mut stats = PeerStats::default();
    loop {
        let now = SmolInstant::from_millis(started.elapsed().as_millis() as i64);
        prioritize_peer_sockets(&mut sockets, &mut flows, &mut udp_handle);
        iface.poll(now, &mut device, &mut sockets);
        for (handle, pending, connected) in &mut flows {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);
            if !*connected
                && matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            {
                *connected = true;
                stats.tcp_connections += 1;
            }
            if !paused.load(Ordering::Relaxed) && socket.can_recv() && pending.len() < PEER_BUFFER {
                socket
                    .recv(|bytes| {
                        let count = bytes.len().min(PEER_BUFFER - pending.len());
                        pending.extend(bytes[..count].iter().copied());
                        stats.tcp_bytes_received += count as u64;
                        (count, ())
                    })
                    .unwrap();
                stats.peak_pending_echo_bytes = stats.peak_pending_echo_bytes.max(pending.len());
            }
            if socket.can_send() && !pending.is_empty() {
                let sent = socket.send_slice(pending.as_slices().0).unwrap();
                pending.drain(..sent);
                stats.tcp_bytes_echoed += sent as u64;
            }
            if *connected && !socket.may_recv() && pending.is_empty() {
                socket.close();
            }
            if socket.state() == tcp::State::Closed {
                if *connected {
                    stats.tcp_closed += 1;
                }
                socket.listen(443).unwrap();
                *connected = false;
                pending.clear();
            }
        }
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if socket.can_recv() && socket.can_send() {
            let (bytes, metadata) = socket.recv().unwrap();
            let bytes = bytes.to_vec();
            socket.send_slice(&bytes, metadata.endpoint).unwrap();
            stats.udp_requests += 1;
        }
        prioritize_peer_sockets(&mut sockets, &mut flows, &mut udp_handle);
        iface.poll(now, &mut device, &mut sockets);
        while let Some(packet) = device.output.pop_front() {
            match output.try_send(packet) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(packet)) => {
                    device.output.push_front(packet);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }
        *shared.lock().unwrap() = stats.clone();
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = output.closed() => return Ok(()),
            packet = input.recv(), if device.input.len() < PACKETS => match packet { Some(packet) => device.input.push_back(packet), None => return Ok(()) },
            _ = output.reserve(), if !device.output.is_empty() => {},
            _ = tokio::time::sleep(Duration::from_millis(1)) => {},
        }
    }
}

fn prioritize_peer_sockets(
    sockets: &mut SocketSet<'_>,
    flows: &mut [(SocketHandle, VecDeque<u8>, bool)],
    udp_handle: &mut SocketHandle,
) {
    if let Some(mapping) = socket_priority::prioritize_connections(sockets) {
        for (handle, _, _) in flows {
            *handle = socket_priority::remap(&mapping, *handle);
        }
        *udp_handle = socket_priority::remap(&mapping, *udp_handle);
    }
}
