//! Independent full-window FIN regression using two in-memory IP endpoints.
//! No application reads reopen the window until both FINs are acknowledged.
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

fn connected(capacity: usize, seed: u64) -> (Endpoint, Endpoint) {
    let mut left = Endpoint::new(true, capacity, seed);
    let mut right = Endpoint::new(false, capacity, seed + 1);
    for time in 0..50 {
        exchange_packets(&mut left, &mut right, time, false);
    }
    assert_eq!(left.socket().state(), tcp::State::Established);
    assert_eq!(right.socket().state(), tcp::State::Established);
    (left, right)
}

#[test]
fn full_window_simultaneous_fin_recovers_after_lost_ack_without_reads() {
    let (mut left, mut right) = connected(8192, 42);
    let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let mut now = 100i64;
    for _ in 0..8 {
        left.socket().send_slice(&data).unwrap();
        right.socket().send_slice(&data).unwrap();
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..1000 {
            now += 10;
            exchange_packets(&mut left, &mut right, now, false);
            left.receive(&mut a);
            right.receive(&mut b);
            if a.len() == data.len()
                && b.len() == data.len()
                && left.socket().send_queue() == 0
                && right.socket().send_queue() == 0
            {
                break;
            }
        }
        assert_eq!(a, data);
        assert_eq!(b, data);
    }
    now += 10;
    exchange_packets(&mut left, &mut right, now, false);
    left.socket().send_slice(&data).unwrap();
    right.socket().send_slice(&data).unwrap();
    left.socket().close();
    right.socket().close();
    now += 10;
    // Both initial full flights, including FIN, arrive; the pure ACKs are lost.
    exchange_packets(&mut left, &mut right, now, true);
    assert_eq!(left.socket().recv_queue(), data.len());
    assert_eq!(right.socket().recv_queue(), data.len());
    assert_eq!(left.socket().state(), tcp::State::Closing);
    assert_eq!(right.socket().state(), tcp::State::Closing);
    for _ in 0..2000 {
        now += 10;
        exchange_packets(&mut left, &mut right, now, false);
        if left.socket().send_queue() == 0 && right.socket().send_queue() == 0 {
            break;
        }
    }
    assert_eq!(
        (left.socket().send_queue(), right.socket().send_queue()),
        (0, 0)
    );
    assert!(matches!(
        left.socket().state(),
        tcp::State::TimeWait | tcp::State::Closed
    ));
    assert!(matches!(
        right.socket().state(),
        tcp::State::TimeWait | tcp::State::Closed
    ));
    let mut a = Vec::new();
    let mut b = Vec::new();
    left.receive(&mut a);
    right.receive(&mut b);
    assert_eq!(a, data);
    assert_eq!(b, data);
}
