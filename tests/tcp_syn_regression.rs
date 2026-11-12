//! Delayed SYN regression for the synthetic server's recycled listeners.
//! Every original packet is delivered; exact connection tuples take priority.
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv4Packet, TcpPacket, TcpSeqNumber},
};
use std::collections::VecDeque;

const CLIENT: Ipv4Address = Ipv4Address::new(10, 44, 0, 2);
const SERVER: Ipv4Address = Ipv4Address::new(10, 44, 0, 1);
const PORT: u16 = 49152;
const QUEUE: usize = 64;

struct MemoryIp {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
impl Device for MemoryIp {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.output.len() == QUEUE {
            return None;
        }
        self.input
            .pop_front()
            .map(|packet| (Rx(packet), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        (self.output.len() < QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1400;
        caps.max_burst_size = Some(QUEUE);
        caps
    }
}
struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        assert!(length <= 1400);
        let mut packet = vec![0; length];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

struct Endpoint {
    iface: Interface,
    device: MemoryIp,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
    highest_sent: Option<TcpSeqNumber>,
}
impl Endpoint {
    fn new(client: bool, capacity: usize, seed: u64) -> Self {
        let mut device = MemoryIp {
            input: VecDeque::new(),
            output: VecDeque::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(if client { CLIENT } else { SERVER }.into(), 24))
                .unwrap();
        });
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; capacity]),
            tcp::SocketBuffer::new(vec![0; capacity]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        if client {
            socket
                .connect(iface.context(), (SERVER, 443), PORT)
                .unwrap();
        } else {
            socket.listen(443).unwrap();
        }
        let mut sockets = SocketSet::new(vec![]);
        let tcp = sockets.add(socket);
        Self {
            iface,
            device,
            sockets,
            tcp,
            highest_sent: None,
        }
    }
    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.tcp)
    }
    fn poll(&mut self, milliseconds: i64) {
        self.iface.poll(
            Instant::from_millis(milliseconds),
            &mut self.device,
            &mut self.sockets,
        );
    }
    fn take_packets(&mut self) -> VecDeque<Vec<u8>> {
        for packet in &self.device.output {
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            let end = tcp.seq_number()
                + tcp.payload().len()
                + usize::from(tcp.syn())
                + usize::from(tcp.fin());
            self.highest_sent = Some(self.highest_sent.map_or(end, |previous| previous.max(end)));
        }
        std::mem::take(&mut self.device.output)
    }
    fn deliver(&mut self, packets: VecDeque<Vec<u8>>, drop_ack: bool) {
        for packet in packets {
            let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if drop_ack
                && tcp.payload().is_empty()
                && tcp.ack()
                && !tcp.syn()
                && !tcp.fin()
                && !tcp.rst()
            {
                continue;
            }
            assert!(self.device.input.len() < QUEUE);
            self.device.input.push_back(packet);
        }
    }
    fn receive(&mut self, output: &mut Vec<u8>) {
        while self.socket().can_recv() {
            self.socket()
                .recv(|bytes| {
                    output.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
    }
}

fn exchange_packets(left: &mut Endpoint, right: &mut Endpoint, now: i64, drop_ack: bool) {
    for _ in 0..64 {
        // Poll both before delivery so initial data flights cannot piggyback an
        // ACK for data from the opposite endpoint.
        left.poll(now);
        right.poll(now);
        let to_right = left.take_packets();
        let to_left = right.take_packets();
        if to_right.is_empty() && to_left.is_empty() {
            return;
        }
        right.deliver(to_right, drop_ack);
        left.deliver(to_left, drop_ack);
    }
}

#[path = "support/socket_priority.rs"]
mod socket_priority;

#[test]
fn delayed_duplicate_syn_cannot_rebind_an_established_peer_connection() {
    let mut left = Endpoint::new(true, 8192, 42);
    let mut right = Endpoint::new(false, 8192, 43);
    let mut recycled = right.tcp;
    right.socket().abort();
    let mut second = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 8192]),
        tcp::SocketBuffer::new(vec![0; 8192]),
    );
    second.set_nagle_enabled(false);
    second.set_ack_delay(None);
    second.listen(443).unwrap();
    right.tcp = right.sockets.add(second);

    left.poll(0);
    let opening = left.take_packets();
    assert_eq!(opening.len(), 1);
    let delayed_syn = opening.front().unwrap().clone();
    assert!(
        TcpPacket::new_checked(Ipv4Packet::new_checked(&delayed_syn[..]).unwrap().payload())
            .unwrap()
            .syn()
    );
    right.deliver(opening, false);
    for now in 1..50 {
        exchange_packets(&mut left, &mut right, now, false);
    }
    assert_eq!(left.socket().state(), tcp::State::Established);
    assert_eq!(right.socket().state(), tcp::State::Established);
    let existing_peer = right.socket().remote_endpoint();
    left.socket().send_slice(b"before delayed SYN").unwrap();
    for now in 50..60 {
        exchange_packets(&mut left, &mut right, now, false);
    }
    let mut received = Vec::new();
    right.receive(&mut received);
    assert_eq!(received, b"before delayed SYN");
    right.socket().send_slice(b"queued before reorder").unwrap();

    // An earlier flow has closed, so the peer reuses its slot as a listener.
    right
        .sockets
        .get_mut::<tcp::Socket>(recycled)
        .listen(443)
        .unwrap();
    // This is the same priority helper used by the long-running echo peer.
    if let Some(mapping) = socket_priority::prioritize_connections(&mut right.sockets) {
        right.tcp = socket_priority::remap(&mapping, right.tcp);
        recycled = socket_priority::remap(&mapping, recycled);
    }
    assert_eq!(right.socket().remote_endpoint(), existing_peer);
    assert_eq!(right.socket().send_queue(), b"queued before reorder".len());
    assert!(socket_priority::prioritize_connections(&mut right.sockets).is_none());
    right.device.input.push_back(delayed_syn);
    right.poll(100);
    assert_eq!(
        right.sockets.get::<tcp::Socket>(recycled).state(),
        tcp::State::Listen,
        "a recycled listener claimed the established connection's delayed SYN"
    );
    assert_eq!(right.socket().state(), tcp::State::Established);
    let outgoing = right.take_packets();
    for packet in &outgoing {
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(
            !tcp.syn() && !tcp.rst(),
            "duplicate SYN created a new handshake or reset"
        );
    }
    left.deliver(outgoing, false);
    left.socket().send_slice(b"after delayed SYN").unwrap();
    for now in 101..150 {
        exchange_packets(&mut left, &mut right, now, false);
    }
    received.clear();
    right.receive(&mut received);
    assert_eq!(received, b"after delayed SYN");
    received.clear();
    left.receive(&mut received);
    assert_eq!(received, b"queued before reorder");
    assert_eq!(left.socket().state(), tcp::State::Established);
    assert_eq!(right.socket().state(), tcp::State::Established);
}
