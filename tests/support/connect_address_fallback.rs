//! Real Resolver + TunnelConnector + stack, with an independent raw-IP peer.
//! No host socket, interface, gateway, credentials or system DNS is used.
use super::*;
use hickory_proto::{
    op::{Message, MessageType},
    rr::{rdata::A, RData, Record},
};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
        UdpPacket, UdpRepr,
    },
};
use std::{collections::HashMap, sync::Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const DNS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 53);
const FIRST: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 40);
const SECOND: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 42);
const BUDGET: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
enum Behavior {
    Blackhole,
    Refuse,
    Echo,
    EchoFirstSynLost,
    EchoAfter(Duration),
    RefuseAfter(Duration),
}

#[derive(Default)]
struct Evidence {
    dns_queries: usize,
    syns: Vec<Ipv4Addr>,
    echo_bytes: usize,
}

struct TcpState {
    expected: TcpSeqNumber,
    next: TcpSeqNumber,
}

fn ipv4_reply(ip: &Ipv4Packet<&[u8]>, protocol: IpProtocol, length: usize) -> Vec<u8> {
    let mut response = vec![0; 20 + length];
    Ipv4Repr {
        src_addr: ip.dst_addr(),
        dst_addr: ip.src_addr(),
        next_header: protocol,
        payload_len: length,
        hop_limit: 64,
    }
    .emit(
        &mut Ipv4Packet::new_unchecked(&mut response[..20]),
        &ChecksumCapabilities::default(),
    );
    response
}

fn dns_reply(ip: &Ipv4Packet<&[u8]>, answers: &[Ipv4Addr]) -> Vec<u8> {
    let udp = UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(udp.dst_port(), 53);
    let mut reply = Message::from_vec(udp.payload()).unwrap();
    reply.metadata.message_type = MessageType::Response;
    for address in answers {
        reply.add_answer(Record::from_rdata(
            reply.queries[0].name().clone(),
            300,
            RData::A(A(*address)),
        ));
    }
    let bytes = reply.to_vec().unwrap();
    let mut response = ipv4_reply(ip, IpProtocol::Udp, 8 + bytes.len());
    UdpRepr {
        src_port: 53,
        dst_port: udp.src_port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut response[20..]),
        &IpAddress::Ipv4(ip.dst_addr()),
        &IpAddress::Ipv4(ip.src_addr()),
        bytes.len(),
        |buffer| buffer.copy_from_slice(&bytes),
        &ChecksumCapabilities::default(),
    );
    response
}

fn tcp_reply(
    ip: &Ipv4Packet<&[u8]>,
    behavior: Behavior,
    connections: &mut HashMap<(Ipv4Addr, u16), TcpState>,
    evidence: &mut Evidence,
) -> Option<Vec<u8>> {
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!(tcp.dst_port(), 443);
    let key = (ip.dst_addr(), tcp.src_port());
    if tcp.rst() {
        connections.remove(&key);
        return None;
    }
    let syn = tcp.syn() && !tcp.ack();
    if syn {
        assert!(evidence.syns.len() < 2048);
        evidence.syns.push(ip.dst_addr());
        if matches!(behavior, Behavior::EchoFirstSynLost)
            && evidence
                .syns
                .iter()
                .filter(|address| **address == ip.dst_addr())
                .count()
                == 1
        {
            return None;
        }
    }
    if matches!(behavior, Behavior::Blackhole) {
        return None;
    }
    let (control, sequence, ack, payload) =
        if matches!(behavior, Behavior::Refuse | Behavior::RefuseAfter(_)) {
            if !syn {
                return None;
            }
            (
                TcpControl::Rst,
                TcpSeqNumber(0),
                tcp.seq_number() + 1,
                &[][..],
            )
        } else if syn {
            assert!(connections.len() < 16 || connections.contains_key(&key));
            connections.insert(
                key,
                TcpState {
                    expected: tcp.seq_number() + 1,
                    next: TcpSeqNumber(8001),
                },
            );
            (
                TcpControl::Syn,
                TcpSeqNumber(8000),
                tcp.seq_number() + 1,
                &[][..],
            )
        } else {
            let state = connections.get_mut(&key)?;
            if tcp.payload().is_empty() && !tcp.fin() {
                return None;
            }
            let sequence = state.next;
            let mut payload = &[][..];
            let mut control = TcpControl::None;
            if tcp.seq_number() == state.expected {
                payload = tcp.payload();
                state.expected += payload.len();
                state.next += payload.len();
                evidence.echo_bytes += payload.len();
                if tcp.fin() {
                    state.expected += 1;
                    state.next += 1;
                    control = TcpControl::Fin;
                }
            }
            (control, sequence, state.expected, payload)
        };
    let repr = TcpRepr {
        src_port: 443,
        dst_port: tcp.src_port(),
        control,
        seq_number: sequence,
        ack_number: Some(ack),
        window_len: 16384,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let mut response = ipv4_reply(ip, IpProtocol::Tcp, repr.buffer_len());
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut response[20..]),
        &IpAddress::Ipv4(ip.dst_addr()),
        &IpAddress::Ipv4(ip.src_addr()),
        &ChecksumCapabilities::default(),
    );
    Some(response)
}

struct Fixture {
    connector: Arc<TunnelConnector>,
    stack: StackHandle,
    stop: CancellationToken,
    actor: JoinHandle<io::Result<()>>,
    peer: JoinHandle<()>,
    evidence: Arc<Mutex<Evidence>>,
}

impl Fixture {
    fn new(answers: Vec<(Ipv4Addr, Behavior)>) -> Self {
        Self::configured(answers, 4, Duration::ZERO, vec![])
    }

    fn configured(
        answers: Vec<(Ipv4Addr, Behavior)>,
        max_connections: usize,
        dns_delay: Duration,
        excludes: Vec<ipnet::IpNet>,
    ) -> Self {
        Self::with_policy(
            answers,
            max_connections,
            dns_delay,
            Policy::new(vec!["service.corp.example".into()], vec![])
                .unwrap()
                .with_excludes(excludes),
        )
    }

    fn with_policy(
        answers: Vec<(Ipv4Addr, Behavior)>,
        max_connections: usize,
        dns_delay: Duration,
        policy: Policy,
    ) -> Self {
        let stop = CancellationToken::new();
        let (incoming, input) = mpsc::channel(64);
        let (output, mut outgoing) = mpsc::channel::<Vec<u8>>(64);
        let (stack, actor) = stack::spawn(
            StackConfig {
                ipv4: CLIENT,
                ipv6: None,
                mtu: 1400,
                max_connections,
                connect_timeout: BUDGET,
                idle_timeout: Duration::from_secs(60),
                random_seed: 17,
            },
            input,
            output,
            stop.clone(),
        )
        .unwrap();
        let connector = Arc::new(TunnelConnector::default());
        connector.activate(Generation {
            stack: stack.clone(),
            dial_hedges: Arc::new(Semaphore::new(MAX_DIAL_HEDGES)),
            resolver: Resolver::new(vec![DNS]),
            policy,
            address: CLIENT,
            cancel: stop.clone(),
            lease: Lease::new(),
            renew_at: None,
        });
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        let observed = evidence.clone();
        let peer_stop = stop.clone();
        let peer = tokio::spawn(async move {
            let mut connections = HashMap::new();
            let started = Instant::now();
            let mut delayed = Vec::<(Instant, Vec<u8>)>::new();
            let addresses: Vec<_> = answers.iter().map(|(address, _)| *address).collect();
            loop {
                while delayed.first().is_some_and(|(at, _)| *at <= Instant::now()) {
                    let (_, response) = delayed.remove(0);
                    tokio::select! {
                        _ = peer_stop.cancelled() => return,
                        sent = incoming.send(response) => if sent.is_err() { return; },
                    }
                }
                let due = delayed
                    .first()
                    .map(|(at, _)| *at)
                    .unwrap_or_else(Instant::now);
                let packet = tokio::select! {
                    _ = peer_stop.cancelled() => break,
                    packet = outgoing.recv() => match packet { Some(packet) => packet, None => break },
                    _ = tokio::time::sleep_until(due), if !delayed.is_empty() => continue,
                };
                let ip = Ipv4Packet::new_checked(packet.as_slice()).unwrap();
                assert_eq!(ip.src_addr(), CLIENT);
                let response = match ip.next_header() {
                    IpProtocol::Udp => {
                        assert_eq!(ip.dst_addr(), DNS);
                        observed.lock().unwrap().dns_queries += 1;
                        Some(dns_reply(&ip, &addresses))
                    }
                    IpProtocol::Tcp => {
                        let behavior = answers
                            .iter()
                            .find(|(address, _)| *address == ip.dst_addr())
                            .map(|(_, behavior)| *behavior)
                            .expect("SYN to a non-DNS-authorized address");
                        tcp_reply(
                            &ip,
                            behavior,
                            &mut connections,
                            &mut observed.lock().unwrap(),
                        )
                    }
                    _ => panic!("unexpected transport"),
                };
                if let Some(response) = response {
                    if ip.next_header() == IpProtocol::Tcp {
                        let delay = answers.iter().find_map(|(address, behavior)| {
                            if *address != ip.dst_addr() {
                                return None;
                            }
                            match behavior {
                                Behavior::EchoAfter(delay) | Behavior::RefuseAfter(delay) => {
                                    Some(*delay)
                                }
                                _ => None,
                            }
                        });
                        if let Some(delay) = delay {
                            let at = started + delay;
                            if at > Instant::now() {
                                assert!(delayed.len() < 64);
                                delayed.push((at, response));
                                delayed.sort_by_key(|(at, _)| *at);
                                continue;
                            }
                        }
                    }
                    if ip.next_header() == IpProtocol::Udp && !dns_delay.is_zero() {
                        tokio::select! {
                            _ = peer_stop.cancelled() => break,
                            _ = tokio::time::sleep(dns_delay) => {}
                        }
                    }
                    tokio::select! {
                        _ = peer_stop.cancelled() => break,
                        sent = incoming.send(response) => if sent.is_err() { break; },
                    }
                }
            }
        });
        Self {
            connector,
            stack,
            stop,
            actor,
            peer,
            evidence,
        }
    }

    async fn finish(self) {
        self.connector.disconnect();
        self.stop.cancel();
        if let Err(error) = self.actor.await.unwrap() {
            // Peer channel shutdown may win the actor's cancellation select.
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        self.peer.await.unwrap();
        let stats = self.stack.stats();
        assert_eq!(
            (
                stats.active_tcp,
                stats.pending_tcp,
                stats.active_udp,
                stats.time_wait
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(stats.tcp_buffer_capacity_bytes, 0);
        assert_eq!(stats.command_queue, 0);
    }
}

async fn address_fallback(first: Behavior) {
    let fixture = Fixture::new(vec![(FIRST, first), (SECOND, Behavior::Echo)]);
    let started = Instant::now();
    // HTTP CONNECT and SOCKS both use this same total connector timeout.
    let connected = timeout(
        BUDGET,
        fixture
            .connector
            .connect(Target::new("service.corp.example", 443).unwrap()),
    )
    .await;
    let elapsed = started.elapsed();
    let succeeded = matches!(connected, Ok(Ok(_)));
    if let Ok(Ok(mut stream)) = connected {
        for payload in [
            b"first request".as_slice(),
            b"same established stream".as_slice(),
        ] {
            stream.write_all(payload).await.unwrap();
            let mut echoed = vec![0; payload.len()];
            timeout(Duration::from_secs(1), stream.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echoed, payload);
            tokio::time::advance(Duration::from_secs(2)).await;
        }
    }
    let syns = fixture.evidence.lock().unwrap().syns.clone();
    eprintln!(
        "address fallback: succeeded={succeeded}, elapsed={elapsed:?}, SYN destinations={syns:?}"
    );
    assert_eq!(fixture.evidence.lock().unwrap().dns_queries, 1);
    fixture.finish().await;
    assert!(
        succeeded,
        "a healthy later A record was unreachable within the proxy's total budget"
    );
    assert!(elapsed < BUDGET);
    assert!(syns.contains(&FIRST) && syns.contains(&SECOND));
}

#[tokio::test(start_paused = true)]
async fn blackholed_first_a_does_not_consume_the_entire_dial_budget() {
    address_fallback(Behavior::Blackhole).await;
}

#[tokio::test(start_paused = true)]
async fn refused_first_a_reaches_the_healthy_successor() {
    address_fallback(Behavior::Refuse).await;
}

#[tokio::test(start_paused = true)]
async fn connector_itself_bounds_dns_and_all_blackholed_addresses_together() {
    let fixture = Fixture::configured(
        vec![(FIRST, Behavior::Blackhole), (SECOND, Behavior::Blackhole)],
        4,
        Duration::from_secs(2),
        vec![],
    );
    let started = Instant::now();
    // This calls the real connector directly: correctness must not depend on
    // each library consumer independently adding the proxy's timeout wrapper.
    let result = timeout(
        BUDGET * 3,
        fixture
            .connector
            .connect(Target::new("service.corp.example", 443).unwrap()),
    )
    .await
    .expect("fixture safety deadline");
    let elapsed = started.elapsed();
    let error = result.err().expect("blackholes cannot connect");
    let syns = fixture.evidence.lock().unwrap().syns.clone();
    eprintln!(
        "total dial budget: elapsed={elapsed:?}, kind={:?}, SYN destinations={syns:?}",
        error.kind()
    );
    assert!(
        fixture.connector.status().available,
        "a dial timeout must not expire the VPN session"
    );
    fixture.finish().await;
    assert!(
        elapsed <= BUDGET,
        "DNS or later A records restarted the total dial budget"
    );
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(syns.contains(&FIRST) && syns.contains(&SECOND));
}

#[tokio::test(start_paused = true)]
async fn filtering_happens_before_any_syn_and_does_not_spend_attempt_budget() {
    let forbidden = [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED, FIRST, CLIENT];
    let mut answers: Vec<_> = forbidden
        .into_iter()
        .map(|ip| (ip, Behavior::Echo))
        .collect();
    answers.push((SECOND, Behavior::Echo));
    let fixture = Fixture::configured(
        answers,
        1,
        Duration::ZERO,
        vec!["10.77.0.40/32".parse().unwrap()],
    );
    let result = fixture
        .connector
        .connect(Target::new("service.corp.example", 443).unwrap())
        .await;
    assert!(result.is_ok());
    drop(result);
    assert_eq!(fixture.evidence.lock().unwrap().syns, [SECOND]);
    let denied = fixture
        .connector
        .connect(Target::new("unapproved.example", 443).unwrap())
        .await;
    assert_eq!(
        denied.err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fixture.evidence.lock().unwrap().dns_queries, 1);
    fixture.finish().await;
}

#[tokio::test(start_paused = true)]
async fn final_of_sixteen_addresses_is_attempted_without_extra_socket_capacity() {
    let mut answers: Vec<_> = (100..115)
        .map(|last| (Ipv4Addr::new(10, 77, 0, last), Behavior::Blackhole))
        .collect();
    answers.push((SECOND, Behavior::Echo));
    let fixture = Fixture::configured(answers, 1, Duration::ZERO, vec![]);
    let result = timeout(
        BUDGET,
        fixture
            .connector
            .connect(Target::new("service.corp.example", 443).unwrap()),
    )
    .await;
    let succeeded = matches!(result, Ok(Ok(_)));
    drop(result);
    let syns = fixture.evidence.lock().unwrap().syns.clone();
    let stats = fixture.stack.stats();
    eprintln!("16-address single-slot fallback: succeeded={succeeded}, peak_tcp={}, SYN destinations={syns:?}", stats.peak_active_tcp);
    fixture.finish().await;
    assert!(
        succeeded,
        "the final healthy address was starved by earlier blackholes"
    );
    assert_eq!(stats.peak_active_tcp, 1);
    assert!(syns.contains(&SECOND));
}

async fn wait_for_active(fixture: &Fixture, count: usize) {
    timeout(Duration::from_secs(1), async {
        loop {
            let stats = fixture.stack.stats();
            if stats.active_tcp == count && stats.pending_tcp == 0 && stats.command_queue == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn echo(stream: &mut BoxStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    timeout(Duration::from_secs(1), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
}

#[tokio::test(start_paused = true)]
async fn mapped_targets_use_only_the_authorized_in_memory_ipv4_path() {
    let payload: Vec<_> = (0..4096).map(|index| (index % 251) as u8).collect();
    for network in ["10.77.0.42/32", "::ffff:10.77.0.42/128"] {
        for host in [
            "10.77.0.42",
            "::ffff:10.77.0.42",
            "::FFFF:0a4d:002a",
            "0:0:0:0:0:ffff:a4d:2a",
            "0000:0000:0000:0000:0000:ffff:0a4d:002a",
        ] {
            let fixture = Fixture::with_policy(
                vec![(SECOND, Behavior::Echo)],
                1,
                Duration::ZERO,
                Policy::new(vec![], vec![network.parse().unwrap()]).unwrap(),
            );
            // Public fields deliberately bypass Target::new. The connector
            // itself must canonicalize before authorization and DNS handling.
            let mut stream = fixture
                .connector
                .connect(Target {
                    host: host.into(),
                    port: 443,
                })
                .await
                .unwrap();
            echo(&mut stream, &payload).await;
            drop(stream);
            {
                let evidence = fixture.evidence.lock().unwrap();
                assert_eq!(evidence.dns_queries, 0, "{network}: {host}");
                assert_eq!(evidence.syns, [SECOND], "{network}: {host}");
                assert_eq!(evidence.echo_bytes, payload.len());
            }
            fixture.finish().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn mapped_targets_cannot_bypass_exclusions_or_ipv4_authorization() {
    for (network, excluded, host) in [
        ("10.0.0.0/8", Some("10.77.0.42/32"), "::ffff:10.77.0.42"),
        ("10.0.0.0/8", Some("::ffff:10.77.0.42/128"), "10.77.0.42"),
        ("10.0.0.0/8", Some("::ffff:10.77.0.42/128"), "::ffff:a4d:2a"),
        ("::/0", None, "::ffff:10.77.0.42"),
        ("10.77.0.40/32", None, "::ffff:10.77.0.42"),
        ("10.0.0.0/8", None, "2001:db8::42"),
    ] {
        let policy = Policy::new(vec![], vec![network.parse().unwrap()])
            .unwrap()
            .with_excludes(
                excluded
                    .into_iter()
                    .map(|value| value.parse().unwrap())
                    .collect(),
            );
        let fixture =
            Fixture::with_policy(vec![(SECOND, Behavior::Echo)], 1, Duration::ZERO, policy);
        let result = fixture
            .connector
            .connect(Target {
                host: host.into(),
                port: 443,
            })
            .await;
        assert_eq!(
            result.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fixture.evidence.lock().unwrap().dns_queries, 0);
        assert!(fixture.evidence.lock().unwrap().syns.is_empty());
        fixture.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn mapped_reserved_addresses_are_rejected_without_dns_or_packets() {
    for address in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::UNSPECIFIED,
        CLIENT,
        Ipv4Addr::new(169, 254, 1, 2),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(0, 2, 3, 4),
    ] {
        let fixture = Fixture::with_policy(
            vec![(address, Behavior::Echo)],
            1,
            Duration::ZERO,
            Policy::new(vec![], vec!["0.0.0.0/0".parse().unwrap()]).unwrap(),
        );
        assert!(fixture
            .connector
            .connect(Target {
                host: address.to_ipv6_mapped().to_string(),
                port: 443,
            })
            .await
            .is_err());
        assert_eq!(fixture.evidence.lock().unwrap().dns_queries, 0);
        assert!(fixture.evidence.lock().unwrap().syns.is_empty());
        fixture.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn first_and_last_of_sixteen_can_retransmit_a_lost_syn() {
    for healthy_index in [0, 15] {
        let answers: Vec<_> = (0..16)
            .map(|index| {
                (
                    Ipv4Addr::new(10, 77, 0, 100 + index),
                    if index == healthy_index {
                        Behavior::EchoFirstSynLost
                    } else {
                        Behavior::Blackhole
                    },
                )
            })
            .collect();
        let fixture = Fixture::configured(answers, 8, Duration::ZERO, vec![]);
        let started = Instant::now();
        let mut stream = fixture
            .connector
            .connect(Target::new("service.corp.example", 443).unwrap())
            .await
            .unwrap();
        let elapsed = started.elapsed();
        echo(&mut stream, b"recovered SYN loss").await;
        wait_for_active(&fixture, 1).await;
        let healthy = Ipv4Addr::new(10, 77, 0, 100 + healthy_index);
        let syns = fixture.evidence.lock().unwrap().syns.clone();
        assert!(syns.iter().filter(|ip| **ip == healthy).count() >= 2);
        assert!(elapsed < BUDGET);
        assert!(fixture.stack.stats().peak_active_tcp <= MAX_DIAL_ATTEMPTS);
        assert_eq!(
            fixture
                .connector
                .state
                .read()
                .unwrap()
                .current
                .as_ref()
                .unwrap()
                .dial_hedges
                .available_permits(),
            MAX_DIAL_HEDGES
        );
        eprintln!("16-address SYN loss: healthy_index={healthy_index}, connected_at={elapsed:?}, SYN destinations={syns:?}");
        // The dial budget ends at establishment; it must not become a deadline
        // on an otherwise live, authorized long-running application stream.
        tokio::time::advance(BUDGET + Duration::from_secs(1)).await;
        echo(
            &mut stream,
            b"existing stream beyond its former dial deadline",
        )
        .await;
        drop(stream);
        fixture.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn ready_success_wins_over_other_successes_and_errors_and_releases_losers() {
    for behaviors in [
        [
            Behavior::EchoAfter(Duration::from_secs(1)),
            Behavior::EchoAfter(Duration::from_secs(1)),
        ],
        [
            Behavior::RefuseAfter(Duration::from_secs(1)),
            Behavior::EchoAfter(Duration::from_secs(1)),
        ],
        [
            Behavior::EchoAfter(Duration::from_secs(2)),
            Behavior::RefuseAfter(Duration::from_secs(1)),
        ],
    ] {
        let fixture = Fixture::new(vec![(FIRST, behaviors[0]), (SECOND, behaviors[1])]);
        let mut stream = fixture
            .connector
            .connect(Target::new("service.corp.example", 443).unwrap())
            .await
            .unwrap();
        echo(&mut stream, b"only the winning stream is exposed").await;
        wait_for_active(&fixture, 1).await;
        assert!(fixture.stack.stats().peak_active_tcp <= 2);
        assert_eq!(
            fixture
                .connector
                .state
                .read()
                .unwrap()
                .current
                .as_ref()
                .unwrap()
                .dial_hedges
                .available_permits(),
            MAX_DIAL_HEDGES
        );
        drop(stream);
        fixture.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn global_hedge_budget_and_caller_cancellation_bound_actual_stack_sockets() {
    let answers: Vec<_> = (100..116)
        .map(|last| (Ipv4Addr::new(10, 77, 0, last), Behavior::Blackhole))
        .collect();
    let fixture = Fixture::configured(
        answers,
        8 + crate::dns::MAX_DNS_SERVERS + MAX_DIAL_HEDGES,
        Duration::ZERO,
        vec![],
    );
    let mut callers = Vec::new();
    for _ in 0..8 {
        let connector = fixture.connector.clone();
        callers.push(tokio::spawn(async move {
            connector
                .connect(Target::new("service.corp.example", 443).unwrap())
                .await
        }));
    }
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    // Let each 250ms stagger run at its own time. Jumping directly to one
    // second only wakes the first overdue timer and schedules the next from
    // that new time, which does not model normal executor progression.
    timeout(Duration::from_secs(2), async {
        while fixture.stack.stats().active_tcp != 8 + MAX_DIAL_HEDGES {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let stats = fixture.stack.stats();
    assert_eq!(stats.active_tcp, 8 + MAX_DIAL_HEDGES);
    assert_eq!(stats.peak_active_tcp, 8 + MAX_DIAL_HEDGES);
    assert_eq!(
        fixture
            .connector
            .state
            .read()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .dial_hedges
            .available_permits(),
        0
    );
    for caller in &callers {
        caller.abort();
    }
    for caller in callers {
        assert!(caller.await.err().unwrap().is_cancelled());
    }
    wait_for_active(&fixture, 0).await;
    assert_eq!(
        fixture
            .connector
            .state
            .read()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .dial_hedges
            .available_permits(),
        MAX_DIAL_HEDGES
    );
    assert!(fixture.connector.status().available);
    eprintln!(
        "8 callers: peak_tcp={}, global_extra_limit={}, caller_cancel_final_tcp={}",
        stats.peak_active_tcp,
        MAX_DIAL_HEDGES,
        fixture.stack.stats().active_tcp
    );
    fixture.finish().await;
}

#[tokio::test(start_paused = true)]
async fn no_extra_permit_uses_finite_sequential_attempts_without_shortening_syn_retry() {
    let answers: Vec<_> = (100..116)
        .map(|last| (Ipv4Addr::new(10, 77, 0, last), Behavior::Blackhole))
        .collect();
    let fixture = Fixture::configured(answers, 1, Duration::ZERO, vec![]);
    let generation = fixture
        .connector
        .state
        .read()
        .unwrap()
        .current
        .clone()
        .unwrap();
    let held = generation
        .dial_hedges
        .clone()
        .try_acquire_many_owned(MAX_DIAL_HEDGES as u32)
        .unwrap();
    let started = Instant::now();
    let error = fixture
        .connector
        .connect(Target::new("service.corp.example", 443).unwrap())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(started.elapsed(), BUDGET);
    let syns = fixture.evidence.lock().unwrap().syns.clone();
    assert!(
        syns.iter()
            .filter(|ip| **ip == Ipv4Addr::new(10, 77, 0, 100))
            .count()
            >= 2
    );
    assert!(syns.contains(&Ipv4Addr::new(10, 77, 0, 101)));
    assert!(!syns.contains(&Ipv4Addr::new(10, 77, 0, 115)), "the two-second floor intentionally cannot visit sixteen blackholes with one slot in fifteen seconds");
    assert_eq!(fixture.stack.stats().peak_active_tcp, 1);
    drop(held);
    fixture.finish().await;
}

#[tokio::test(start_paused = true)]
async fn all_excluded_dns_addresses_keep_the_previous_error_without_emitting_syn() {
    let fixture = Fixture::configured(
        vec![(FIRST, Behavior::Echo)],
        4,
        Duration::ZERO,
        vec!["10.77.0.40/32".parse().unwrap()],
    );
    let error = fixture
        .connector
        .connect(Target::new("service.corp.example", 443).unwrap())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert!(fixture.evidence.lock().unwrap().syns.is_empty());
    assert!(fixture.connector.status().available);
    fixture.finish().await;
}

#[tokio::test(start_paused = true)]
async fn generation_cancellation_aborts_all_address_attempts_and_releases_permits() {
    let fixture = Fixture::new(
        (100..104)
            .map(|last| (Ipv4Addr::new(10, 77, 0, last), Behavior::Blackhole))
            .collect(),
    );
    let generation = fixture
        .connector
        .state
        .read()
        .unwrap()
        .current
        .clone()
        .unwrap();
    let connector = fixture.connector.clone();
    let caller = tokio::spawn(async move {
        connector
            .connect(Target::new("service.corp.example", 443).unwrap())
            .await
    });
    timeout(Duration::from_secs(2), async {
        while fixture.stack.stats().active_tcp != 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    fixture.connector.disconnect();
    let error = caller.await.unwrap().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert_eq!(generation.dial_hedges.available_permits(), MAX_DIAL_HEDGES);
    assert!(!fixture.connector.status().available);
    fixture.finish().await;
}

#[tokio::test(start_paused = true)]
async fn wall_only_dial_expiry_does_not_poison_the_session_or_the_next_request() {
    let fixture = Fixture::new(vec![(FIRST, Behavior::Blackhole), (SECOND, Behavior::Echo)]);
    let clock = crate::lease::TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(600)));
    {
        let mut state = fixture.connector.state.write().unwrap();
        let generation = Arc::get_mut(state.current.as_mut().unwrap()).unwrap();
        generation.lease = lease.clone();
        state.lease = Some(lease.clone());
    }
    let connector = fixture.connector.clone();
    let caller = tokio::spawn(async move {
        connector
            .connect(Target::new("service.corp.example", 443).unwrap())
            .await
    });
    for _ in 0..128 {
        if !fixture.evidence.lock().unwrap().syns.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(fixture.evidence.lock().unwrap().syns, [FIRST]);
    let monotonic = clock.sample().monotonic;
    clock.advance(Duration::ZERO, BUDGET + Duration::from_secs(1));
    assert_eq!(clock.sample().monotonic, monotonic);
    let error = caller.await.unwrap().err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(lease.check(), Ok(()));
    assert!(fixture.connector.status().available);
    wait_for_active(&fixture, 0).await;
    assert_eq!(
        fixture.evidence.lock().unwrap().syns,
        [FIRST],
        "expired operation must not start its delayed hedge"
    );
    let mut next = fixture
        .connector
        .connect(Target::new("service.corp.example", 443).unwrap())
        .await
        .unwrap();
    echo(&mut next, b"new request has a fresh local budget").await;
    drop(next);
    fixture.finish().await;
}
