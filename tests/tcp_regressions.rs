//! Deterministic raw-IP regressions for the narrowly patched smoltcp dependency.
//! These independent reproductions exercise real handshakes and wire checksums.
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr,
        TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    },
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
fn simultaneous_ack_loss_recovers_without_stale_ack_sequence_deadlock() {
    for capacity in [2048, 8192, 32768] {
        simultaneous_ack_loss(capacity);
    }
}

fn simultaneous_ack_loss(capacity: usize) {
    let (mut left, mut right) = connected(capacity, 42);
    let length = capacity.min(8192);
    let a: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
    let b: Vec<u8> = (0..length).map(|i| (255 - i % 251) as u8).collect();
    left.socket().send_slice(&a).unwrap();
    right.socket().send_slice(&b).unwrap();
    for time in 50..100 {
        exchange_packets(&mut left, &mut right, time, true);
    }
    let mut received_left = vec![];
    let mut received_right = vec![];
    for time in (100..20_000).step_by(10) {
        exchange_packets(&mut left, &mut right, time, false);
        // Do not send fresh window-update ACKs before both RTOs have fired.
        if time >= 1200 {
            left.receive(&mut received_left);
            right.receive(&mut received_right);
        }
        if received_left.len() == b.len()
            && received_right.len() == a.len()
            && left.socket().send_queue() == 0
            && right.socket().send_queue() == 0
        {
            break;
        }
    }
    assert_eq!(
        received_left.len(),
        b.len(),
        "left peer stalled after simultaneous ACK loss"
    );
    assert_eq!(
        received_right.len(),
        a.len(),
        "right peer stalled after simultaneous ACK loss"
    );
    assert_eq!(received_left, b);
    assert_eq!(received_right, a);
    assert_eq!(
        left.socket().send_queue(),
        0,
        "left ACK did not recover after a full window"
    );
    assert_eq!(
        right.socket().send_queue(),
        0,
        "right ACK did not recover after a full window"
    );
}

fn ack_packet(sequence: TcpSeqNumber, acknowledgement: TcpSeqNumber) -> Vec<u8> {
    let checksum = ChecksumCapabilities::default();
    let mut bytes = vec![0; 40];
    Ipv4Repr {
        src_addr: SERVER,
        dst_addr: CLIENT,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    }
    .emit(&mut Ipv4Packet::new_unchecked(&mut bytes[..20]), &checksum);
    TcpRepr {
        src_port: 443,
        dst_port: PORT,
        control: TcpControl::None,
        seq_number: sequence,
        ack_number: Some(acknowledgement),
        window_len: 32768,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    }
    .emit(
        &mut TcpPacket::new_unchecked(&mut bytes[20..]),
        &IpAddress::Ipv4(SERVER),
        &IpAddress::Ipv4(CLIENT),
        &checksum,
    );
    bytes
}

#[test]
fn ack_cannot_discard_queued_but_unsent_bytes() {
    for seed in [1, 7, 42, 113] {
        let (mut sender, peer) = connected(32768, seed);
        let payload = vec![0x9a; 512];
        sender.socket().send_slice(&payload).unwrap();
        let forged = ack_packet(
            peer.highest_sent.unwrap(),
            sender.highest_sent.unwrap() + payload.len(),
        );
        sender.device.input.push_back(forged);
        sender.poll(100);
        assert_eq!(
            sender.socket().send_queue(),
            payload.len(),
            "ACK accepted bytes that were never put on the wire (seed {seed})"
        );
    }
}

#[test]
fn full_window_partial_loss_recovers_without_application_read() {
    let (mut left, mut right) = connected(8192, 42);
    let data = vec![0x51; 8192];
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
            if a.len() == 8192
                && b.len() == 8192
                && left.socket().send_queue() == 0
                && right.socket().send_queue() == 0
            {
                break;
            }
        }
        assert_eq!(a.len(), 8192);
        assert_eq!(b.len(), 8192);
    }
    now += 10;
    exchange_packets(&mut left, &mut right, now, false);
    now += 10;
    let left_data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let right_data: Vec<u8> = (0..8192).map(|i| (255 - i % 251) as u8).collect();
    left.socket().send_slice(&left_data).unwrap();
    right.socket().send_slice(&right_data).unwrap();
    left.poll(now);
    right.poll(now);
    let mut a = left.take_packets();
    let mut b = right.take_packets();
    let first_a = TcpPacket::new_checked(
        Ipv4Packet::new_checked(&a.front().unwrap()[..])
            .unwrap()
            .payload(),
    )
    .unwrap()
    .seq_number();
    let first_b = TcpPacket::new_checked(
        Ipv4Packet::new_checked(&b.front().unwrap()[..])
            .unwrap()
            .payload(),
    )
    .unwrap()
    .seq_number();
    let total_a: usize = a
        .iter()
        .map(|p| {
            TcpPacket::new_checked(Ipv4Packet::new_checked(&p[..]).unwrap().payload())
                .unwrap()
                .payload()
                .len()
        })
        .sum();
    let total_b: usize = b
        .iter()
        .map(|p| {
            TcpPacket::new_checked(Ipv4Packet::new_checked(&p[..]).unwrap().payload())
                .unwrap()
                .payload()
                .len()
        })
        .sum();
    assert_eq!(total_a, 8192);
    assert_eq!(total_b, 8192);
    a.retain(|p| {
        TcpPacket::new_checked(Ipv4Packet::new_checked(&p[..]).unwrap().payload())
            .unwrap()
            .seq_number()
            < first_a + 2048
    });
    b.retain(|p| {
        TcpPacket::new_checked(Ipv4Packet::new_checked(&p[..]).unwrap().payload())
            .unwrap()
            .seq_number()
            < first_b + 2048
    });
    right.deliver(a, false);
    left.deliver(b, false);
    for _ in 0..2000 {
        now += 10;
        exchange_packets(&mut left, &mut right, now, false);
    }
    assert_eq!(
        (
            left.socket().recv_queue(),
            right.socket().recv_queue(),
            left.socket().send_queue(),
            right.socket().send_queue()
        ),
        (8192, 8192, 0, 0)
    );
    // Read only after the no-progress condition has been ruled out, so consuming
    // application bytes cannot repair the receive-window boundary under test.
    let mut left_received = Vec::new();
    let mut right_received = Vec::new();
    left.receive(&mut left_received);
    right.receive(&mut right_received);
    assert_eq!(left_received, right_data);
    assert_eq!(right_received, left_data);
}

#[test]
fn rejected_new_byte_probe_does_not_move_pure_ack_outside_zero_window() {
    let (mut left, mut right) = connected(2048, 301);
    let first = vec![0x37; 2048];
    left.socket().send_slice(&first).unwrap();
    for now in 50..1000 {
        exchange_packets(&mut left, &mut right, now, false);
    }
    assert_eq!(left.socket().send_queue(), 0);
    assert_eq!(right.socket().recv_queue(), first.len());
    let frontier = left.highest_sent.unwrap();

    // Keep the receiver full. This sends a new-byte probe, which the zero
    // window must reject. Its byte is emitted but has not advanced RCV.NXT.
    left.socket().send_slice(b"deferred").unwrap();
    for now in 1000..4000 {
        exchange_packets(&mut left, &mut right, now, false);
    }
    assert_eq!(left.highest_sent, Some(frontier + 1));
    assert_eq!(left.socket().send_queue(), 8);

    // The opposite direction remains independently usable even while its
    // application has not drained the receive buffer. No window update or
    // new outgoing data may repair the ACK sequence under test.
    right.socket().send_slice(b"opposite-direction").unwrap();
    let mut received_left = Vec::new();
    for now in 4000..9000 {
        exchange_packets(&mut left, &mut right, now, false);
        left.receive(&mut received_left);
    }
    assert_eq!(received_left, b"opposite-direction");
    assert_eq!(
        right.socket().send_queue(),
        0,
        "pure ACK rejected after probe"
    );
    assert_eq!(right.socket().recv_queue(), first.len());

    // Once the application reads again, deferred bytes must still be sent
    // exactly once and the probe byte must not have been discarded.
    let mut received_right = Vec::new();
    right.receive(&mut received_right);
    for now in 9000..14000 {
        exchange_packets(&mut left, &mut right, now, false);
        right.receive(&mut received_right);
    }
    let mut expected = first;
    expected.extend_from_slice(b"deferred");
    assert_eq!(received_right, expected);
    assert_eq!(left.socket().send_queue(), 0);
}
