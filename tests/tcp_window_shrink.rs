//! Bounded sender-side checks for a peer retracting an advertised receive window.
//! The synthetic peer checks wire contents; this is not a live Linux interop test.

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

const CLIENT: Ipv4Address = Ipv4Address::new(10, 52, 0, 2);
const PEER: Ipv4Address = Ipv4Address::new(10, 52, 0, 1);
const PORT: u16 = 49152;
const QUEUE: usize = 32;

#[derive(Default)]
struct MemoryIp {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        assert!(length <= 1400);
        let mut packet = vec![0; length];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
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

struct Client {
    iface: Interface,
    device: MemoryIp,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
}

impl Client {
    fn new() -> Self {
        let mut device = MemoryIp::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 41;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addresses| {
            addresses.push(IpCidr::new(CLIENT.into(), 24)).unwrap();
        });
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 8192]),
            tcp::SocketBuffer::new(vec![0; 8192]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket.connect(iface.context(), (PEER, 443), PORT).unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        Self {
            iface,
            device,
            sockets,
            handle,
        }
    }

    fn socket(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.handle)
    }

    fn poll(&mut self, milliseconds: i64) -> VecDeque<Vec<u8>> {
        self.iface.poll(
            Instant::from_millis(milliseconds),
            &mut self.device,
            &mut self.sockets,
        );
        std::mem::take(&mut self.device.output)
    }
}

fn from_peer(repr: TcpRepr<'_>) -> Vec<u8> {
    let checksum = ChecksumCapabilities::default();
    let mut packet = vec![0; 20 + repr.buffer_len()];
    Ipv4Repr {
        src_addr: PEER,
        dst_addr: CLIENT,
        next_header: IpProtocol::Tcp,
        payload_len: repr.buffer_len(),
        hop_limit: 64,
    }
    .emit(&mut Ipv4Packet::new_unchecked(&mut packet[..20]), &checksum);
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut packet[20..]),
        &IpAddress::Ipv4(PEER),
        &IpAddress::Ipv4(CLIENT),
        &checksum,
    );
    packet
}

fn packet_tcp(packet: &[u8]) -> TcpPacket<&[u8]> {
    // All synthetic IP packets have the fixed 20-byte IPv4 header above.
    TcpPacket::new_checked(&packet[20..]).unwrap()
}

#[test]
fn shrink_preserves_unacknowledged_data_and_reopening_resumes_sending() {
    // Post-SYN windows are scaled: the final case retracts 4096 to 256 bytes.
    // Neither ordinary zero-window flow control nor scaling alone demonstrates
    // successful reception by an arbitrary strict-window peer.
    for (window_scale, shrunk_window) in [(0, 0), (0, 3), (8, 1)] {
        let mut client = Client::new();
        let opening = client.poll(0);
        assert_eq!(opening.len(), 1);
        let syn = packet_tcp(opening.front().unwrap());
        assert!(syn.syn());
        let start = syn.seq_number() + 1;
        let mut peer = TcpRepr {
            src_port: 443,
            dst_port: PORT,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(i32::MAX - 3),
            ack_number: Some(start),
            window_len: 4096,
            window_scale: Some(window_scale),
            max_seg_size: Some(1360),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        client.device.input.push_back(from_peer(peer));
        client.poll(1);
        assert_eq!(client.socket().state(), tcp::State::Established);
        peer.control = TcpControl::None;
        peer.seq_number += 1;
        peer.window_scale = None;
        peer.max_seg_size = None;

        let original: Vec<u8> = (0..1024).map(|n| (n % 251) as u8).collect();
        client.socket().send_slice(&original).unwrap();
        let sent = client.poll(2);
        assert_eq!(sent.len(), 1);
        let data = packet_tcp(sent.front().unwrap());
        assert_eq!(data.seq_number(), start);
        assert_eq!(data.payload(), original);
        let frontier = start + original.len();

        let pending = b"only after reopening";
        client.socket().send_slice(pending).unwrap();
        peer.window_len = shrunk_window;
        peer.payload = b"response";
        client.device.input.push_back(from_peer(peer));
        let replies = client.poll(3);
        assert_eq!(replies.len(), 1);
        let ack = packet_tcp(replies.front().unwrap());
        assert!(ack.ack() && !ack.syn() && !ack.fin() && !ack.rst());
        assert!(
            ack.payload().is_empty(),
            "new data escaped the retracted window"
        );
        assert_eq!(ack.seq_number(), frontier);
        assert_eq!(ack.ack_number(), peer.seq_number + peer.payload.len());
        assert_eq!(client.socket().send_queue(), original.len() + pending.len());
        let mut received = [0; 8];
        assert_eq!(client.socket().recv_slice(&mut received).unwrap(), 8);
        assert_eq!(&received, b"response");

        peer.seq_number += peer.payload.len();
        peer.payload = &[];
        peer.ack_number = Some(frontier);
        peer.window_len = 4096;
        client.device.input.push_back(from_peer(peer));
        let resumed = client.poll(4);
        assert_eq!(resumed.len(), 1);
        let data = packet_tcp(resumed.front().unwrap());
        assert_eq!(data.seq_number(), frontier);
        assert_eq!(data.payload(), pending);
        peer.ack_number = Some(frontier + pending.len());
        client.device.input.push_back(from_peer(peer));
        client.poll(5);
        assert_eq!(client.socket().send_queue(), 0);
        assert_eq!(client.socket().state(), tcp::State::Established);
    }
}

fn established(window_scale: u8) -> (Client, TcpRepr<'static>, TcpSeqNumber) {
    let mut client = Client::new();
    let opening = client.poll(0);
    let start = packet_tcp(opening.front().unwrap()).seq_number() + 1;
    let mut peer = TcpRepr {
        src_port: 443,
        dst_port: PORT,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(i32::MAX - 3),
        ack_number: Some(start),
        window_len: 4096,
        window_scale: Some(window_scale),
        max_seg_size: Some(1360),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    client.device.input.push_back(from_peer(peer));
    client.poll(1);
    assert_eq!(client.socket().state(), tcp::State::Established);
    peer.control = TcpControl::None;
    peer.seq_number += 1;
    peer.window_scale = None;
    peer.max_seg_size = None;
    (client, peer, start)
}

#[test]
fn history_window_accepts_ack_that_current_zero_window_rejects() {
    // RFC 7323 requires receivers to honor their previous advertised window.
    // Older implementations can instead validate against the current window.
    // Explicitly reproduce both models: the second is a known compatibility
    // limitation, not a claim that a live strict-window peer interoperates.
    for (scale, window, close) in [(0, 3, false), (8, 1, false), (0, 3, true), (8, 1, true)] {
        let (mut client, mut peer, start) = established(scale);
        client.socket().send_slice(&[0x5a; 1024]).unwrap();
        if close {
            client.socket().close();
        }
        let sent = client.poll(2);
        assert_eq!(packet_tcp(sent.front().unwrap()).payload().len(), 1024);
        assert_eq!(packet_tcp(sent.front().unwrap()).fin(), close);

        // Lose the full flight, then retract the window while sending reverse
        // data. The strict peer rejects this first ACK beyond its new edge.
        peer.window_len = window;
        peer.payload = b"response";
        client.device.input.push_back(from_peer(peer));
        let first_ack = client.poll(3);
        assert_eq!(
            packet_tcp(first_ack.front().unwrap()).seq_number(),
            start + 1024 + usize::from(close)
        );
        let retransmission = client.poll(1005);
        assert_eq!(retransmission.len(), 1);
        let retransmission = packet_tcp(retransmission.front().unwrap());
        let accepted = usize::from(window) << scale;
        assert_eq!(retransmission.seq_number(), start);
        assert_eq!(retransmission.payload(), &[0x5a; 1024][..accepted]);

        // These bytes fill the smaller receive buffer. Only the ACK for them
        // arrives; the reverse response still needs an acknowledgement.
        let response_start = peer.seq_number;
        peer.seq_number += peer.payload.len();
        peer.payload = &[];
        peer.ack_number = Some(start + accepted);
        peer.window_len = 0;
        client.device.input.push_back(from_peer(peer));
        client.poll(1006);
        assert_eq!(client.socket().send_queue(), 1024 - accepted);

        // New reverse data takes the ordinary dispatch ACK path, while its
        // retransmission below takes the immediate corrective-ACK path.
        peer.payload = b"more";
        client.device.input.push_back(from_peer(peer));
        let replies = client.poll(1007);
        assert_eq!(replies.len(), 1);
        let ack = packet_tcp(replies.front().unwrap());
        assert!(ack.payload().is_empty());
        assert_eq!(ack.ack_number(), response_start + 12);
        let frontier = start + 1024 + usize::from(close);
        assert_eq!(ack.seq_number(), frontier);
        assert!(
            start + accepted <= ack.seq_number() && ack.seq_number() < start + 4096,
            "RFC 7323's historical advertised-window model must accept this ACK"
        );
        assert_ne!(
            ack.seq_number(),
            start + accepted,
            "known limitation: a current-window-only peer rejects this ACK"
        );

        peer.seq_number = response_start;
        peer.payload = b"responsemore";
        client.device.input.push_back(from_peer(peer));
        let duplicate = client.poll(1008);
        assert_eq!(duplicate.len(), 1);
        let ack = packet_tcp(duplicate.front().unwrap());
        assert_eq!(ack.seq_number(), frontier);
        assert_eq!(ack.ack_number(), response_start + 12);
        assert!(start + accepted <= ack.seq_number() && ack.seq_number() < start + 4096);
        assert_ne!(ack.seq_number(), start + accepted);

        // The historical-window model processes this ACK and reopens. This
        // particular test does not drive persist/corrective replies, so its
        // strict rejection alone cannot establish a persistent stall. The
        // Linux-ordered peer test below exercises that later progression.
        peer.seq_number += peer.payload.len();
        peer.payload = &[];
        peer.window_len = 4096;
        client.device.input.push_back(from_peer(peer));
        let resumed = client.poll(1009);
        assert_eq!(resumed.len(), 1);
        let data = packet_tcp(resumed.front().unwrap());
        assert_eq!(data.seq_number(), start + accepted);
        assert_eq!(data.payload(), &[0x5a; 1024][accepted..]);
        assert_eq!(data.fin(), close);
        peer.ack_number = Some(start + 1024 + usize::from(close));
        client.device.input.push_back(from_peer(peer));
        client.poll(1010);
        assert_eq!(client.socket().send_queue(), 0);
        let mut received = [0; 12];
        assert_eq!(client.socket().recv_slice(&mut received).unwrap(), 12);
        assert_eq!(&received, b"responsemore");
    }
}

#[test]
fn delayed_zero_window_before_fin_does_not_rewind_fin_ack_sequence() {
    for (payload, old_ack_bytes) in [(&[][..], 0), (&[0x5a; 1024][..], 0), (&[0x5a; 1024][..], 3)] {
        let (mut client, mut peer, start) = established(0);
        client.socket().send_slice(payload).unwrap();
        client.socket().close();
        let sent = client.poll(2);
        assert_eq!(sent.len(), 1);
        let fin = packet_tcp(sent.front().unwrap());
        assert!(fin.fin());
        assert_eq!(fin.payload(), payload);
        let after_fin = start + payload.len() + 1;

        // The peer generated this zero-window announcement before reading and
        // receiving our flight/FIN. It is delayed past the FIN transmission.
        // It is still an acceptable old ACK and does not confirm the FIN.
        peer.window_len = 0;
        // The partial-ACK variant also enters persist: a persist timer by
        // itself cannot prove that the FIN was lost instead of its ACK.
        peer.ack_number = Some(start + old_ack_bytes);
        client.device.input.push_back(from_peer(peer));
        client.poll(3);
        assert_eq!(client.socket().state(), tcp::State::FinWait1);

        // The peer's own FIN also crossed our FIN, carrying the same old ACK.
        // The peer has since consumed our FIN; its exact zero-window position
        // is now after_fin. Selecting UNA would make this ACK unusable.
        peer.control = TcpControl::Fin;
        peer.payload = b"response";
        client.device.input.push_back(from_peer(peer));
        let replies = client.poll(4);
        assert_eq!(replies.len(), 1);
        let ack = packet_tcp(replies.front().unwrap());
        assert!(ack.payload().is_empty() && !ack.fin());
        assert_eq!(ack.seq_number(), after_fin);
        assert_eq!(ack.ack_number(), peer.seq_number + 9);
        assert_eq!(client.socket().state(), tcp::State::Closing);

        // Losing this corrective ACK must not regress the duplicate FIN path.
        client.device.input.push_back(from_peer(peer));
        let duplicate = client.poll(5);
        assert_eq!(duplicate.len(), 1);
        let ack = packet_tcp(duplicate.front().unwrap());
        assert_eq!(ack.seq_number(), after_fin);
        assert_eq!(ack.ack_number(), peer.seq_number + 9);

        peer.control = TcpControl::None;
        peer.seq_number += 9;
        peer.payload = &[];
        peer.ack_number = Some(after_fin);
        client.device.input.push_back(from_peer(peer));
        client.poll(6);
        assert_eq!(client.socket().send_queue(), 0);
        assert_eq!(client.socket().state(), tcp::State::TimeWait);
    }
}

fn zero_window_after_lost_flight_must_probe(close: bool) {
    let (mut client, mut peer, start) = established(0);
    client.socket().send_slice(&[0x5a; 1024]).unwrap();
    if close {
        client.socket().close();
    }
    let lost = client.poll(2);
    assert_eq!(lost.len(), 1);
    assert_eq!(packet_tcp(lost.front().unwrap()).payload().len(), 1024);
    assert_eq!(packet_tcp(lost.front().unwrap()).fin(), close);

    // The original flight is lost. This valid window update acknowledges no
    // new bytes, and the peer has no reverse payload to retransmit later.
    peer.window_len = 0;
    peer.ack_number = Some(start);
    client.device.input.push_back(from_peer(peer));
    client.poll(3);
    assert_eq!(client.socket().send_queue(), 1024);

    // Drive real retransmission/persist timers without injecting more input.
    // RFC 9293 3.8.6.1 requires probes even if the peer stays silent.
    let mut probe_times = Vec::new();
    for milliseconds in (1005..=30_005).step_by(1000) {
        for packet in client.poll(milliseconds) {
            let tcp = packet_tcp(&packet);
            eprintln!(
                "RETRACTED_ZERO_WINDOW close={close} t_ms={milliseconds} seq={:?} payload={} fin={}",
                tcp.seq_number(),
                tcp.payload().len(),
                tcp.fin()
            );
            if !tcp.payload().is_empty() {
                assert_eq!(tcp.seq_number(), start);
                assert_eq!(tcp.payload(), &[0x5a]);
                assert!(!tcp.fin(), "probe must not relocate the queued FIN");
                probe_times.push(milliseconds);
            }
        }
    }
    assert_eq!(client.socket().send_queue(), 1024);
    assert!(
        !probe_times.is_empty(),
        "no persist probe after 30 simulated seconds; close={close}"
    );
    assert_eq!(probe_times[0], 1005, "first expired RTO must make progress");
    assert!((2..=5).contains(&probe_times.len()), "unbounded probe rate");
    let intervals: Vec<_> = probe_times
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();
    assert!(intervals.iter().all(|delay| *delay >= 1000));
    assert!(intervals.windows(2).all(|pair| pair[1] >= pair[0] * 2));

    peer.window_len = 4096;
    client.device.input.push_back(from_peer(peer));
    let reopened = client.poll(30_006);
    assert_eq!(reopened.len(), 1);
    let data = packet_tcp(reopened.front().unwrap());
    assert_eq!(data.seq_number(), start);
    assert_eq!(data.payload(), &[0x5a; 1024]);
    assert_eq!(data.fin(), close);
    peer.ack_number = Some(start + 1024 + usize::from(close));
    client.device.input.push_back(from_peer(peer));
    client.poll(30_007);
    assert_eq!(client.socket().send_queue(), 0);
    assert_eq!(
        client.socket().state(),
        if close {
            tcp::State::FinWait2
        } else {
            tcp::State::Established
        }
    );
    assert!(
        client.poll(100_000).is_empty(),
        "persist survived the reopening ACK"
    );
}

#[test]
fn zero_window_retraction_without_ack_progress_still_probes() {
    zero_window_after_lost_flight_must_probe(false);
}

#[test]
fn zero_window_retraction_after_lost_data_and_fin_still_probes() {
    zero_window_after_lost_flight_must_probe(true);
}

#[test]
fn delayed_zero_window_after_received_fin_recovers_its_lost_ack() {
    for payload in [&[][..], &[0x5a; 1024][..]] {
        let (mut client, mut peer, start) = established(0);
        client.socket().send_slice(payload).unwrap();
        client.socket().close();
        let sent = client.poll(2);
        let fin = packet_tcp(sent.front().unwrap());
        assert!(fin.fin());
        let after_fin = start + payload.len() + 1;
        // The complete flight reached the peer, but its ACK was lost. An older
        // zero-window announcement then arrives. This is indistinguishable
        // from the lost-flight case until a fresh peer response is received.
        peer.window_len = 0;
        client.device.input.push_back(from_peer(peer));
        client.poll(3);
        let retry = client.poll(1005);
        assert_eq!(retry.len(), 1);
        let retry = packet_tcp(retry.front().unwrap());
        assert_eq!(retry.seq_number(), start);
        if payload.is_empty() {
            assert!(retry.fin() && retry.payload().is_empty());
        } else {
            assert_eq!(retry.payload(), &payload[..1]);
            assert!(!retry.fin());
        }
        // A current-window peer rejects old data and advertises its actual
        // post-FIN RCV.NXT. No send frontier is guessed or clamped.
        peer.ack_number = Some(after_fin);
        client.device.input.push_back(from_peer(peer));
        client.poll(1006);
        assert_eq!(client.socket().send_queue(), 0);
        assert_eq!(client.socket().state(), tcp::State::FinWait2);
        let after_ack = client.poll(100_000);
        eprintln!(
            "FIN_ACKED_ZERO_WINDOW payload={} late_packets={}",
            payload.len(),
            after_ack.len()
        );
        assert!(after_ack.is_empty());
    }
}

#[test]
fn nonzero_window_rto_remains_an_ordinary_full_retransmission() {
    let (mut client, mut peer, start) = established(0);
    client.socket().send_slice(&[0x5a; 1024]).unwrap();
    client.poll(2);
    client.device.input.push_back(from_peer(peer));
    client.poll(3);
    let retried = client.poll(1005);
    assert_eq!(retried.len(), 1);
    let data = packet_tcp(retried.front().unwrap());
    assert_eq!(data.seq_number(), start);
    assert_eq!(data.payload(), &[0x5a; 1024]);
    assert!(!data.fin());
    peer.ack_number = Some(start + 1024);
    client.device.input.push_back(from_peer(peer));
    client.poll(1006);
    assert_eq!(client.socket().send_queue(), 0);
}

#[test]
fn last_data_ack_at_zero_window_retains_unacknowledged_fin_retransmission() {
    let (mut client, mut peer, start) = established(0);
    client.socket().send_slice(&[0x5a; 1024]).unwrap();
    client.socket().close();
    client.poll(2);
    peer.window_len = 0;
    client.device.input.push_back(from_peer(peer));
    client.poll(3);
    let probe = client.poll(1005);
    assert_eq!(packet_tcp(probe.front().unwrap()).payload(), &[0x5a]);
    // The original data arrived but its FIN did not. A fresh response to the
    // probe acknowledges all payload, leaving exactly the FIN outstanding.
    peer.ack_number = Some(start + 1024);
    client.device.input.push_back(from_peer(peer));
    let fin = client.poll(1006);
    assert_eq!(client.socket().send_queue(), 0);
    assert_eq!(client.socket().state(), tcp::State::FinWait1);
    assert_eq!(fin.len(), 1);
    let fin = packet_tcp(fin.front().unwrap());
    assert!(fin.fin() && fin.payload().is_empty());
    assert_eq!(fin.seq_number(), start + 1024);
    // Drop this FIN too: leaving persist must not erase its normal RTO.
    assert!(client.poll(1007).is_empty());
    let retry = client.poll(3007);
    assert_eq!(retry.len(), 1);
    let retry = packet_tcp(retry.front().unwrap());
    assert!(retry.fin() && retry.payload().is_empty());
    assert_eq!(retry.seq_number(), start + 1024);
    peer.ack_number = Some(start + 1025);
    client.device.input.push_back(from_peer(peer));
    client.poll(3008);
    assert_eq!(client.socket().state(), tcp::State::FinWait2);
    assert!(client.poll(100_000).is_empty());
}

#[test]
fn legacy_linux_ordered_peer_processes_probe_ack_before_zero_window_data_drop() {
    // Independently modeled from Linux v6.12 tcp_input.c: tcp_sequence permits
    // seq at the current right edge; tcp_ack precedes tcp_data_queue's zero
    // window payload rejection (also in closing states). This is a synthetic
    // peer over IP packets, not execution of the Linux kernel or copied code.
    // https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_input.c
    for (scale, close, reverse_fin) in [
        (0, false, false),
        (8, false, false),
        (0, true, false),
        (8, true, true),
    ] {
        let (mut client, mut peer, start) = established(scale);
        let payload: Vec<u8> = (0..1024).map(|n| (n % 251) as u8).collect();
        client.socket().send_slice(&payload).unwrap();
        if close {
            client.socket().close();
        }
        client.poll(2); // Lose the original data, including FIN if present.
        peer.window_len = if scale == 0 { 3 } else { 1 };
        peer.payload = b"response";
        client.device.input.push_back(from_peer(peer));
        let first = client.poll(3);
        assert_eq!(
            packet_tcp(first.front().unwrap()).seq_number(),
            start + 1024 + usize::from(close)
        );
        let retransmitted = client.poll(1005);
        let retransmitted = packet_tcp(retransmitted.front().unwrap());
        let accepted = usize::from(peer.window_len) << scale;
        assert_eq!(retransmitted.payload(), &payload[..accepted]);
        // This accepted retransmission already acknowledges the first reverse
        // response. Send more response bytes that the peer's application needs
        // acknowledged before it reads the now-full receive buffer.
        assert_eq!(retransmitted.ack_number(), peer.seq_number + 8);
        peer.seq_number += 8;
        peer.ack_number = Some(start + accepted);
        peer.window_len = 0;
        peer.payload = b"more";
        if reverse_fin {
            peer.control = TcpControl::Fin;
        }
        let reverse_end = peer.seq_number + 4 + usize::from(reverse_fin);
        client.device.input.push_back(from_peer(peer));
        let mut wire = client.poll(1006);
        peer.seq_number = reverse_end;
        peer.payload = &[];
        peer.control = TcpControl::None;
        let mut received = payload[..accepted].to_vec();
        let mut next_receive = start + accepted;
        let mut window: usize = 0;
        let mut advertised_left = next_receive;
        let mut rejected_ack = 0;
        let mut probe_ack_progress = 0;
        let mut received_fin = false;
        let mut reopened = false;

        for milliseconds in (1006..=20_006).step_by(20) {
            for packet in wire.drain(..) {
                let tcp = packet_tcp(&packet);
                assert!(!tcp.syn() && !tcp.rst());
                let end = tcp.seq_number() + tcp.payload().len() + usize::from(tcp.fin());
                // The v6.12 sequence gate is inclusive at the right edge and
                // distinct from its later receive-data/window validation.
                let sequence_valid =
                    end >= advertised_left && tcp.seq_number() <= next_receive + window;
                let mut acknowledge = false;
                let mut wake_reader = false;
                if !sequence_valid {
                    rejected_ack += usize::from(tcp.payload().is_empty());
                    acknowledge = true; // Corrective ACK reports actual RCV.NXT.
                } else {
                    // ACK processing happens before data admission. It can wake
                    // the application even when this packet's data is dropped.
                    assert!(tcp.ack_number() <= reverse_end);
                    if tcp.ack_number() == reverse_end && !reopened {
                        assert_eq!(window, 0);
                        assert_eq!(tcp.payload().len(), 1);
                        probe_ack_progress += 1;
                        wake_reader = true;
                    }
                    if !tcp.payload().is_empty() || tcp.fin() {
                        acknowledge = true;
                        if tcp.seq_number() == next_receive && window > 0 {
                            let count = tcp.payload().len().min(window);
                            assert_eq!(
                                &tcp.payload()[..count],
                                &payload[received.len()..received.len() + count]
                            );
                            received.extend_from_slice(&tcp.payload()[..count]);
                            next_receive += count;
                            window -= count;
                            if tcp.fin() && count == tcp.payload().len() {
                                next_receive += 1;
                                received_fin = true;
                            }
                        }
                        // At zero window the probe byte stays unconsumed. Bare
                        // FIN is a separate Linux exception; no probe here has it.
                        if window == 0 && !reopened {
                            assert!(!tcp.fin());
                        }
                    }
                }
                peer.ack_number = Some(next_receive);
                peer.window_len = (window >> scale) as u16;
                advertised_left = next_receive;
                if acknowledge {
                    client.device.input.push_back(from_peer(peer));
                }
                if wake_reader {
                    // Application consumes only as a consequence of its write
                    // being acknowledged, not an external forced reopening.
                    reopened = true;
                    window = 4096;
                    peer.window_len = (window >> scale) as u16;
                    client.device.input.push_back(from_peer(peer));
                }
            }
            wire = client.poll(milliseconds + 1);
            if client.socket().send_queue() == 0 && received_fin == close {
                break;
            }
        }
        assert!(
            rejected_ack > 0,
            "ordinary frontier ACK must first be rejected"
        );
        assert_eq!(
            probe_ack_progress, 1,
            "persist ACK did not unblock reverse data"
        );
        assert!(reopened);
        assert_eq!(received, payload);
        assert_eq!(received_fin, close);
        assert_eq!(client.socket().send_queue(), 0);
        assert_eq!(
            client.socket().state(),
            if reverse_fin {
                tcp::State::TimeWait
            } else if close {
                tcp::State::FinWait2
            } else {
                tcp::State::Established
            }
        );
        eprintln!("LEGACY_LINUX_ORDER scale={scale} close={close} reverse_fin={reverse_fin} frontier_rejections={rejected_ack} probe_ack_progress={probe_ack_progress} delivered={}", received.len());
    }
}
