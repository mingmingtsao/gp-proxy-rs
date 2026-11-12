//! Independent resource regressions using actual stack-generated IP datagrams.
//! The synthetic DNS peer never opens a host socket or external connection.
use gp_proxy::{
    config::Config,
    dns::{Resolver, MAX_DNS_PENDING_NAMES, MAX_DNS_SERVERS, MAX_DNS_WAITERS_PER_NAME},
    stack::{self, StackConfig, StackHandle},
};
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
use std::{
    future::{poll_fn, Future},
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, Barrier, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;

const HEALTHY: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 55);
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 42);

// A small independent wire peer for one DNS-over-TCP exchange, not a second
// copy of the production stack. Its first SYN is deliberately unanswered.
struct TcpDns {
    syns: Arc<AtomicUsize>,
    expected: Option<TcpSeqNumber>,
    next_sequence: TcpSeqNumber,
    request: Vec<u8>,
    answered: bool,
}

impl TcpDns {
    fn respond(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        let ip = Ipv4Packet::new_checked(bytes).unwrap();
        if ip.dst_addr() != HEALTHY {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        if tcp.rst() {
            return None;
        }
        let (sequence, acknowledgement, control, payload) = if tcp.syn() && !tcp.ack() {
            if self.syns.fetch_add(1, Ordering::SeqCst) == 0 {
                return None;
            }
            self.expected = Some(tcp.seq_number() + 1);
            (
                TcpSeqNumber(1000),
                self.expected.unwrap(),
                TcpControl::Syn,
                vec![],
            )
        } else {
            let mut expected = self.expected?;
            if tcp.payload().is_empty() {
                return None;
            }
            let sequence = self.next_sequence;
            let mut payload = vec![];
            if tcp.seq_number() == expected {
                self.request.extend_from_slice(tcp.payload());
                assert!(self.request.len() <= 1024);
                expected += tcp.payload().len();
                self.expected = Some(expected);
                if self.request.len() >= 2 {
                    let len = u16::from_be_bytes([self.request[0], self.request[1]]) as usize;
                    if !self.answered && self.request.len() >= len + 2 {
                        let mut reply = Message::from_vec(&self.request[2..len + 2]).unwrap();
                        reply.metadata.message_type = MessageType::Response;
                        reply.add_answer(Record::from_rdata(
                            reply.queries[0].name().clone(),
                            300,
                            RData::A(A(ANSWER)),
                        ));
                        let answer = reply.to_vec().unwrap();
                        payload.extend_from_slice(&(answer.len() as u16).to_be_bytes());
                        payload.extend_from_slice(&answer);
                        self.next_sequence += payload.len();
                        self.answered = true;
                    }
                }
            }
            (sequence, expected, TcpControl::None, payload)
        };
        let checksum = ChecksumCapabilities::default();
        let repr = TcpRepr {
            src_port: 53,
            dst_port: tcp.src_port(),
            control,
            seq_number: sequence,
            ack_number: Some(acknowledgement),
            window_len: 16384,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &payload,
        };
        let mut response = vec![0; 20 + repr.buffer_len()];
        Ipv4Repr {
            src_addr: ip.dst_addr(),
            dst_addr: ip.src_addr(),
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        }
        .emit(
            &mut Ipv4Packet::new_unchecked(&mut response[..20]),
            &checksum,
        );
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut response[20..]),
            &IpAddress::Ipv4(ip.dst_addr()),
            &IpAddress::Ipv4(ip.src_addr()),
            &checksum,
        );
        Some(response)
    }
}

struct DnsPeer {
    stack: StackHandle,
    stop: CancellationToken,
    stack_task: Option<JoinHandle<io::Result<()>>>,
    peer_task: Option<JoinHandle<()>>,
    questions: Arc<Mutex<Vec<(Ipv4Addr, String)>>>,
    tcp_syns: Arc<AtomicUsize>,
}

impl DnsPeer {
    fn new(response_delay: Duration) -> Self {
        Self::configured(response_delay, 32, false)
    }

    fn configured(response_delay: Duration, max_connections: usize, tcp_fallback: bool) -> Self {
        Self::with_ttl(response_delay, max_connections, tcp_fallback, 300)
    }

    fn with_ttl(
        response_delay: Duration,
        max_connections: usize,
        tcp_fallback: bool,
        ttl: u32,
    ) -> Self {
        Self::with_options(response_delay, max_connections, tcp_fallback, ttl, None)
    }

    fn with_options(
        response_delay: Duration,
        max_connections: usize,
        tcp_fallback: bool,
        ttl: u32,
        response_gate: Option<Arc<Semaphore>>,
    ) -> Self {
        let stop = CancellationToken::new();
        let (incoming, input) = mpsc::channel(64);
        let (output, mut outgoing) = mpsc::channel::<Vec<u8>>(64);
        let (stack, stack_task) = stack::spawn(
            StackConfig {
                ipv4: Ipv4Addr::new(10, 77, 0, 2),
                ipv6: None,
                mtu: 1400,
                max_connections,
                connect_timeout: Duration::from_secs(15),
                idle_timeout: Duration::from_secs(30),
                random_seed: 17,
            },
            input,
            output,
            stop.clone(),
        )
        .unwrap();
        let questions = Arc::new(Mutex::new(Vec::new()));
        let peer_questions = questions.clone();
        let peer_stop = stop.clone();
        let tcp_syns = Arc::new(AtomicUsize::new(0));
        let mut tcp = TcpDns {
            syns: tcp_syns.clone(),
            expected: None,
            next_sequence: TcpSeqNumber(1001),
            request: vec![],
            answered: false,
        };
        let peer_task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = peer_stop.cancelled() => return,
                    packet = outgoing.recv() => match packet { Some(packet) => packet, None => return },
                };
                let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
                if tcp_fallback && ip.next_header() == IpProtocol::Tcp {
                    if let Some(response) = tcp.respond(&packet) {
                        tokio::select! {
                            _ = peer_stop.cancelled() => return,
                            result = incoming.send(response) => if result.is_err() { return; },
                        }
                    }
                    continue;
                }
                if ip.next_header() != IpProtocol::Udp {
                    continue;
                }
                let udp = UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(udp.dst_port(), 53);
                let mut reply = Message::from_vec(udp.payload()).unwrap();
                {
                    let mut questions = peer_questions.lock().unwrap();
                    assert!(questions.len() < 4096);
                    questions.push((ip.dst_addr(), reply.queries[0].name().to_utf8()));
                }
                // Other configured DNS addresses are deliberate blackholes,
                // including their TCP SYNs; HEALTHY responds with a valid RRset.
                if tcp_fallback || ip.dst_addr() != HEALTHY {
                    continue;
                }
                reply.metadata.message_type = MessageType::Response;
                reply.add_answer(Record::from_rdata(
                    reply.queries[0].name().clone(),
                    ttl,
                    RData::A(A(ANSWER)),
                ));
                let bytes = reply.to_vec().unwrap();
                let mut response = vec![0; 28 + bytes.len()];
                let checksum = ChecksumCapabilities::default();
                Ipv4Repr {
                    src_addr: ip.dst_addr(),
                    dst_addr: ip.src_addr(),
                    next_header: IpProtocol::Udp,
                    payload_len: 8 + bytes.len(),
                    hop_limit: 64,
                }
                .emit(
                    &mut Ipv4Packet::new_unchecked(&mut response[..20]),
                    &checksum,
                );
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
                    &checksum,
                );
                if !response_delay.is_zero() {
                    tokio::select! { _ = peer_stop.cancelled() => return, _ = tokio::time::sleep(response_delay) => {} }
                }
                if let Some(gate) = &response_gate {
                    tokio::select! {
                        _ = peer_stop.cancelled() => return,
                        permit = gate.acquire() => permit.unwrap().forget(),
                    }
                }
                tokio::select! {
                    _ = peer_stop.cancelled() => return,
                    result = incoming.send(response) => if result.is_err() { return; },
                }
            }
        });
        Self {
            stack,
            stop,
            stack_task: Some(stack_task),
            peer_task: Some(peer_task),
            questions,
            tcp_syns,
        }
    }

    async fn wait_idle(&self) {
        timeout(Duration::from_secs(2), async {
            loop {
                let stats = self.stack.stats();
                if stats.active_tcp + stats.active_udp + stats.socket_count + stats.command_queue
                    == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled DNS futures retained stack sockets or queued commands");
    }

    async fn close(mut self) {
        self.stop.cancel();
        let result = timeout(Duration::from_secs(2), self.stack_task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        if let Err(error) = result {
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        timeout(Duration::from_secs(2), self.peer_task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        let stats = self.stack.stats();
        assert_eq!(
            stats.active_tcp + stats.active_udp + stats.time_wait + stats.socket_count,
            0
        );
    }
}

impl Drop for DnsPeer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.stack_task {
            task.abort();
        }
        if let Some(task) = &self.peer_task {
            task.abort();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn healthy_dns_control_uses_the_userspace_stack_and_cache() {
    let peer = DnsPeer::new(Duration::ZERO);
    let resolver = Resolver::new(vec![HEALTHY]);
    for host in ["control.corp.example", "CONTROL.corp.example."] {
        assert_eq!(resolver.resolve(&peer.stack, host).await.unwrap(), [ANSWER]);
    }
    assert_eq!(peer.questions.lock().unwrap().len(), 1);
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn healthy_third_dns_is_reachable_within_the_default_proxy_budget() {
    // Production reserves four temporary DNS slots independently of the one
    // business connection configured by the user.
    let peer = DnsPeer::configured(Duration::ZERO, 1 + MAX_DNS_SERVERS, false);
    let control = Resolver::new(vec![HEALTHY]);
    assert_eq!(
        control
            .resolve(&peer.stack, "control.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    peer.questions.lock().unwrap().clear();
    let resolver = Resolver::new(vec![
        Ipv4Addr::new(10, 77, 0, 53),
        Ipv4Addr::new(10, 77, 0, 54),
        HEALTHY,
    ]);
    let started = Instant::now();
    let result = timeout(
        Duration::from_secs(Config::default().connect_timeout_secs),
        resolver.resolve(&peer.stack, "budget.corp.example"),
    )
    .await;
    let questions = peer.questions.lock().unwrap().clone();
    eprintln!(
        "DNS budget evidence: elapsed={:?}, result={result:?}, attempted={questions:?}",
        started.elapsed()
    );
    peer.wait_idle().await;
    assert!(peer.stack.stats().peak_active_udp <= MAX_DNS_SERVERS);
    peer.close().await;
    assert!(
        matches!(result, Ok(Ok(ref addresses)) if addresses == &[ANSWER]),
        "a healthy configured DNS server was never reached before the normal proxy deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn inserting_one_name_does_not_flush_a_recently_cached_unexpired_name() {
    let peer = DnsPeer::new(Duration::ZERO);
    let resolver = Resolver::new(vec![HEALTHY]);
    for name in 0..256 {
        resolver
            .resolve(&peer.stack, &format!("name-{name}.corp.example"))
            .await
            .unwrap();
    }
    // The most recently inserted entry is not the earliest expiry candidate.
    resolver
        .resolve(&peer.stack, "one-new.corp.example")
        .await
        .unwrap();
    let before = peer.questions.lock().unwrap().len();
    resolver
        .resolve(&peer.stack, "name-255.corp.example")
        .await
        .unwrap();
    let after = peer.questions.lock().unwrap().len();
    eprintln!("DNS cache evidence: wire_queries_before_hot_lookup={before}, after={after}");
    peer.close().await;
    assert_eq!(
        after, before,
        "inserting one name flushed the entire 256-entry cache"
    );
}

#[tokio::test(start_paused = true)]
async fn udp_timeout_then_tcp_survives_first_syn_loss() {
    let peer = DnsPeer::configured(Duration::ZERO, 1 + MAX_DNS_SERVERS, true);
    let resolver = Resolver::new(vec![HEALTHY]);
    let started = Instant::now();
    let result = resolver
        .resolve(&peer.stack, "tcp-fallback.corp.example")
        .await;
    let elapsed = started.elapsed();
    let syns = peer.tcp_syns.load(Ordering::SeqCst);
    eprintln!("DNS TCP fallback evidence: elapsed={elapsed:?}, SYNs={syns}, result={result:?}");
    peer.wait_idle().await;
    peer.close().await;
    assert_eq!(result.unwrap(), [ANSWER]);
    assert!(syns >= 2, "the deliberate first SYN loss was not recovered");
    assert!((Duration::from_secs(6)..Duration::from_secs(10)).contains(&elapsed));
}

#[tokio::test(start_paused = true)]
async fn cancelling_hedged_dns_releases_all_slots_before_session_shutdown() {
    let peer = DnsPeer::configured(Duration::ZERO, 1 + MAX_DNS_SERVERS, false);
    let resolver = Resolver::new(
        (60..64)
            .map(|last| Ipv4Addr::new(10, 77, 0, last))
            .collect(),
    );
    let stack = peer.stack.clone();
    let query = tokio::spawn(async move { resolver.resolve(&stack, "cancel.corp.example").await });
    timeout(Duration::from_secs(1), async {
        while peer.stack.stats().active_udp < MAX_DNS_SERVERS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());
    peer.wait_idle().await;
    assert!(
        !peer.stack.is_closed(),
        "cleanup must not depend on cancelling the session"
    );
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn all_blackholes_and_exhausted_dns_slots_obey_one_total_deadline() {
    // The public stack API may be given fewer slots than production reserves.
    // It must remain bounded and fail explicitly, never hang or open a host socket.
    for slots in [1, 1 + MAX_DNS_SERVERS] {
        let peer = DnsPeer::configured(Duration::ZERO, slots, false);
        let resolver = Resolver::new(
            (60..64)
                .map(|last| Ipv4Addr::new(10, 77, 0, last))
                .collect(),
        );
        let started = Instant::now();
        let error = resolver
            .resolve(&peer.stack, "blackhole.corp.example")
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        eprintln!(
            "DNS total-budget evidence: stack_slots={slots}, elapsed={elapsed:?}, error={:?}",
            error.kind()
        );
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(elapsed, Duration::from_secs(10));
        peer.wait_idle().await;
        assert!(peer.stack.stats().peak_socket_count <= slots.min(MAX_DNS_SERVERS));
        peer.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn simultaneous_identical_queries_share_one_wire_operation() {
    let peer = DnsPeer::new(Duration::from_millis(20));
    let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
    let ready = Arc::new(Barrier::new(17));
    let mut queries = JoinSet::new();
    for _ in 0..16 {
        let resolver = resolver.clone();
        let stack = peer.stack.clone();
        let ready = ready.clone();
        queries.spawn(async move {
            ready.wait().await;
            resolver.resolve(&stack, "shared.corp.example").await
        });
    }
    ready.wait().await;
    while let Some(result) = queries.join_next().await {
        assert_eq!(result.unwrap().unwrap(), [ANSWER]);
    }
    let count = peer.questions.lock().unwrap().len();
    let peak = peer.stack.stats().peak_active_udp;
    eprintln!(
        "DNS concurrency evidence: identical_callers=16, wire_queries={count}, peak_udp={peak}"
    );
    peer.close().await;
    assert_eq!(
        count, 1,
        "same-name callers each sent their own DNS request"
    );
    assert_eq!(peak, 1, "same-name callers consumed multiple UDP slots");
}

// The returned task has actually polled resolve once, so cancellation tests
// cannot accidentally abort a "leader" before any followers subscribed.
async fn begin_query(
    resolver: &Arc<Resolver>,
    stack: &StackHandle,
    host: &str,
    tcp_only: bool,
) -> JoinHandle<io::Result<Vec<Ipv4Addr>>> {
    let resolver = resolver.clone();
    let stack = stack.clone();
    let host = host.to_string();
    let (started, ready) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut started = Some(started);
        let mut query = Box::pin(async {
            if tcp_only {
                resolver.resolve_tcp(&stack, &host).await
            } else {
                resolver.resolve(&stack, &host).await
            }
        });
        poll_fn(|context| {
            let result = query.as_mut().poll(context);
            if let Some(started) = started.take() {
                let _ = started.send(());
            }
            result
        })
        .await
    });
    ready.await.unwrap();
    task
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(1), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

async fn cancel_queries(queries: Vec<JoinHandle<io::Result<Vec<Ipv4Addr>>>>) {
    for query in &queries {
        query.abort();
    }
    for query in queries {
        assert!(query.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_first_caller_preserves_followers_and_the_shared_answer() {
    let peer = DnsPeer::new(Duration::from_millis(200));
    let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
    let first = begin_query(&resolver, &peer.stack, "leader.corp.example", false).await;
    wait_for(|| peer.questions.lock().unwrap().len() == 1).await;
    let mut followers = Vec::new();
    for _ in 0..8 {
        followers.push(begin_query(&resolver, &peer.stack, "LEADER.corp.example.", false).await);
    }
    let cancelled_follower = followers.pop().unwrap();
    cancel_queries(vec![first, cancelled_follower]).await;
    for follower in followers {
        assert_eq!(follower.await.unwrap().unwrap(), [ANSWER]);
    }
    assert_eq!(
        resolver
            .resolve(&peer.stack, "leader.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    assert_eq!(peer.questions.lock().unwrap().len(), 1);
    assert_eq!(peer.stack.stats().peak_active_udp, 1);
    peer.wait_idle().await;
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn last_cancelled_waiter_releases_wire_query_without_populating_cache() {
    let peer = DnsPeer::new(Duration::from_millis(200));
    let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
    let mut queries = Vec::new();
    for _ in 0..8 {
        queries.push(begin_query(&resolver, &peer.stack, "cancel-all.corp.example", false).await);
    }
    wait_for(|| peer.stack.stats().active_udp == 1).await;
    cancel_queries(queries).await;
    peer.wait_idle().await;
    assert!(!peer.stack.is_closed());
    // Let the cancelled request's delayed packet arrive. There must be no
    // detached resolver left to consume it and cache the answer.
    tokio::time::advance(Duration::from_millis(300)).await;
    assert_eq!(peer.questions.lock().unwrap().len(), 1);
    assert_eq!(
        resolver
            .resolve(&peer.stack, "cancel-all.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    assert_eq!(peer.questions.lock().unwrap().len(), 2);
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn late_follower_and_leader_cancellation_do_not_restart_the_total_budget() {
    let peer = DnsPeer::configured(Duration::ZERO, 5, false);
    let resolver = Arc::new(Resolver::new(vec![Ipv4Addr::new(10, 77, 0, 60)]));
    let started = Instant::now();
    let first = begin_query(&resolver, &peer.stack, "deadline.corp.example", false).await;
    tokio::time::advance(Duration::from_secs(9)).await;
    let joined = Instant::now();
    let last = begin_query(&resolver, &peer.stack, "deadline.corp.example", false).await;
    cancel_queries(vec![first]).await;
    assert_eq!(
        last.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(joined.elapsed(), Duration::from_secs(1));
    peer.wait_idle().await;
    // A completed failure is not a negative cache entry or a permanent flight.
    let retry = begin_query(&resolver, &peer.stack, "deadline.corp.example", false).await;
    assert!(!retry.is_finished());
    cancel_queries(vec![retry]).await;
    peer.wait_idle().await;
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn pending_name_and_waiter_limits_reject_then_reuse_cancelled_capacity() {
    let peer = DnsPeer::configured(Duration::ZERO, MAX_DNS_PENDING_NAMES, false);
    let resolver = Arc::new(Resolver::new(vec![Ipv4Addr::new(10, 77, 0, 60)]));
    let mut same_name = Vec::new();
    for _ in 0..MAX_DNS_WAITERS_PER_NAME {
        same_name.push(begin_query(&resolver, &peer.stack, "full.corp.example", false).await);
    }
    let error = resolver
        .resolve(&peer.stack, "full.corp.example")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    cancel_queries(vec![same_name.pop().unwrap()]).await;
    same_name.push(begin_query(&resolver, &peer.stack, "full.corp.example", false).await);
    assert!(!same_name.last().unwrap().is_finished());
    wait_for(|| peer.stack.stats().active_udp == 1).await;
    assert_eq!(peer.questions.lock().unwrap().len(), 1);
    cancel_queries(same_name).await;
    peer.wait_idle().await;

    let mut names = Vec::new();
    for index in 0..MAX_DNS_PENDING_NAMES {
        names.push(
            begin_query(
                &resolver,
                &peer.stack,
                &format!("pending-{index}.corp.example"),
                false,
            )
            .await,
        );
    }
    assert_eq!(
        resolver
            .resolve(&peer.stack, "overflow.corp.example")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    cancel_queries(vec![names.pop().unwrap()]).await;
    names.push(begin_query(&resolver, &peer.stack, "reused.corp.example", false).await);
    assert!(!names.last().unwrap().is_finished());
    cancel_queries(names).await;
    peer.wait_idle().await;
    assert!(peer.stack.stats().peak_active_udp <= MAX_DNS_PENDING_NAMES);
    assert!(!peer.stack.is_closed());
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn tcp_diagnostic_flights_are_shared_but_separate_from_udp_flights() {
    let peer = DnsPeer::configured(Duration::ZERO, 5, false);
    let resolver = Arc::new(Resolver::new(vec![Ipv4Addr::new(10, 77, 0, 60)]));
    let mut queries = Vec::new();
    for tcp_only in [true, true, false, false] {
        queries
            .push(begin_query(&resolver, &peer.stack, "transports.corp.example", tcp_only).await);
    }
    wait_for(|| peer.stack.stats().pending_tcp == 1 && peer.stack.stats().active_udp == 1).await;
    assert_eq!(peer.stack.stats().tcp_connect_requests, 1);
    assert_eq!(peer.stack.stats().udp_requests, 1);
    cancel_queries(queries).await;
    peer.wait_idle().await;
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn resolver_generation_binding_precedes_cache_and_literal_success() {
    let first = DnsPeer::new(Duration::ZERO);
    let next = DnsPeer::new(Duration::ZERO);
    let resolver = Resolver::new(vec![HEALTHY]);
    assert_eq!(
        resolver
            .resolve(&first.stack, "generation.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    for host in ["generation.corp.example", "10.77.0.42"] {
        assert_eq!(
            resolver
                .resolve(&next.stack, host)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(next.questions.lock().unwrap().is_empty());
    let new_resolver = Resolver::new(vec![HEALTHY]);
    assert_eq!(
        new_resolver
            .resolve(&next.stack, "generation.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    assert_eq!(first.questions.lock().unwrap().len(), 1);
    assert_eq!(next.questions.lock().unwrap().len(), 1);
    first.stop.cancel();
    for host in ["generation.corp.example", "10.77.0.42"] {
        assert_eq!(
            resolver
                .resolve(&first.stack, host)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
    first.close().await;
    next.close().await;
}

async fn parked_query(
    resolver: &Arc<Resolver>,
    stack: &StackHandle,
    host: &str,
) -> (oneshot::Sender<()>, JoinHandle<io::Result<Vec<Ipv4Addr>>>) {
    let resolver = resolver.clone();
    let stack = stack.clone();
    let host = host.to_string();
    let (started, ready) = oneshot::channel();
    let (resume, resumed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut query = Box::pin(resolver.resolve(&stack, &host));
        poll_fn(|context| {
            assert!(query.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        started.send(()).unwrap();
        resumed.await.unwrap();
        query.await
    });
    ready.await.unwrap();
    (resume, task)
}

#[tokio::test(start_paused = true)]
async fn a_parked_subscriber_cannot_consume_success_after_cancellation_or_deadline() {
    for cancel in [false, true] {
        let peer = DnsPeer::new(Duration::from_millis(20));
        let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
        let first = begin_query(&resolver, &peer.stack, "parked.corp.example", false).await;
        let (resume, parked) = parked_query(&resolver, &peer.stack, "parked.corp.example").await;
        assert_eq!(first.await.unwrap().unwrap(), [ANSWER]);
        assert_eq!(peer.questions.lock().unwrap().len(), 1);
        if cancel {
            peer.stop.cancel();
        } else {
            tokio::time::advance(Duration::from_secs(10)).await;
        }
        resume.send(()).unwrap();
        assert_eq!(
            parked.await.unwrap().unwrap_err().kind(),
            if cancel {
                io::ErrorKind::NotConnected
            } else {
                io::ErrorKind::TimedOut
            }
        );
        peer.close().await;
    }
}

#[tokio::test]
async fn a_completed_short_ttl_flight_cannot_override_cache_expiry_for_new_or_parked_callers() {
    timeout(Duration::from_secs(4), async {
        let peer = DnsPeer::with_ttl(Duration::from_millis(20), 5, false, 1);
        let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
        let first = begin_query(&resolver, &peer.stack, "short.corp.example", false).await;
        let (resume, parked) = parked_query(&resolver, &peer.stack, "short.corp.example").await;
        assert_eq!(first.await.unwrap().unwrap(), [ANSWER]);
        // Cache uses actual monotonic + wall samples, so wait rather than using
        // Tokio's unrelated simulated clock for this positive-TTL expiration.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            resolver
                .resolve(&peer.stack, "short.corp.example")
                .await
                .unwrap(),
            [ANSWER]
        );
        assert_eq!(peer.questions.lock().unwrap().len(), 2);
        resume.send(()).unwrap();
        assert_eq!(
            parked.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        peer.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn zero_ttl_completed_flight_serves_original_waiters_but_not_new_callers() {
    let peer = DnsPeer::with_ttl(Duration::from_millis(20), 5, false, 0);
    let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
    let first = begin_query(&resolver, &peer.stack, "zero.corp.example", false).await;
    let (resume, parked) = parked_query(&resolver, &peer.stack, "zero.corp.example").await;
    assert_eq!(first.await.unwrap().unwrap(), [ANSWER]);
    assert_eq!(
        resolver
            .resolve(&peer.stack, "zero.corp.example")
            .await
            .unwrap(),
        [ANSWER]
    );
    assert_eq!(peer.questions.lock().unwrap().len(), 2);
    resume.send(()).unwrap();
    assert_eq!(parked.await.unwrap().unwrap(), [ANSWER]);
    peer.close().await;
}

#[tokio::test(start_paused = true)]
async fn coalesced_hedges_still_use_only_four_servers_and_release_on_last_cancel() {
    let peer = DnsPeer::configured(Duration::ZERO, 5, false);
    let resolver = Arc::new(Resolver::new(
        (60..64)
            .map(|last| Ipv4Addr::new(10, 77, 0, last))
            .collect(),
    ));
    let mut queries = Vec::new();
    for _ in 0..8 {
        queries.push(begin_query(&resolver, &peer.stack, "hedged.corp.example", false).await);
    }
    wait_for(|| peer.questions.lock().unwrap().len() == 4).await;
    assert_eq!(peer.stack.stats().active_udp, 4);
    cancel_queries(queries).await;
    peer.wait_idle().await;
    assert_eq!(peer.stack.stats().peak_active_udp, 4);
    assert!(!peer.stack.is_closed());
    peer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_executor_wakes_remaining_waiters_after_cross_thread_cancellation() {
    timeout(Duration::from_secs(5), async {
        let gate = Arc::new(Semaphore::new(0));
        let peer = DnsPeer::with_options(Duration::ZERO, 5, false, 300, Some(gate.clone()));
        let resolver = Arc::new(Resolver::new(vec![HEALTHY]));
        let mut queries = Vec::new();
        for _ in 0..MAX_DNS_WAITERS_PER_NAME {
            queries.push(begin_query(&resolver, &peer.stack, "parallel.corp.example", false).await);
        }
        wait_for(|| peer.questions.lock().unwrap().len() == 1).await;
        let surviving = queries.split_off(16);
        cancel_queries(queries).await;
        gate.add_permits(1);
        for query in surviving {
            assert_eq!(query.await.unwrap().unwrap(), [ANSWER]);
        }
        peer.wait_idle().await;
        assert_eq!(peer.questions.lock().unwrap().len(), 1);
        assert_eq!(peer.stack.stats().peak_active_udp, 1);
        peer.close().await;
    })
    .await
    .unwrap();
}
