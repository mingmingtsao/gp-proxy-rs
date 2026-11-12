//! Frame operations and heartbeat scheduling with independent injected clocks.
use super::*;
use crate::lease::TestClock;
use std::{
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncReadExt, ReadBuf};

fn tunnel_config() -> TunnelConfig {
    gp::parse_config("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>").unwrap()
}

fn assert_pending_read(peer: &mut tokio::io::DuplexStream) {
    let mut byte = [0];
    let mut buffer = ReadBuf::new(&mut byte);
    assert!(
        Pin::new(peer)
            .poll_read(&mut Context::from_waker(Waker::noop()), &mut buffer)
            .is_pending(),
        "heartbeat burst or premature close"
    );
}

#[tokio::test(start_paused = true)]
async fn wall_read_timeout_revokes_generation_and_joins_stack() {
    let clock = TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(600)));
    let observer = lease.clone();
    let connector = Arc::new(TunnelConnector::default());
    let active = connector.clone();
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    let (transport, mut peer) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        run_generation(
            &Config::default(),
            tunnel_config(),
            Policy::new(vec![], vec![]).unwrap(),
            transport,
            active,
            GenerationControl {
                cancel,
                lease,
                maintenance: pending(),
            },
        )
        .await
    });
    assert_eq!(
        gp::read_frame(&mut peer, 1400).await.unwrap(),
        Frame::Keepalive
    );
    let generation = connector.state.read().unwrap().current.clone().unwrap();
    clock.advance(Duration::ZERO, TUNNEL_READ_TIMEOUT);
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = task.await.unwrap().unwrap_err();
    assert!(retryable(&error));
    assert_eq!(
        failure_reason(&error, &observer),
        Reason::TransportUnavailable
    );
    assert_eq!(
        observer.check(),
        Ok(()),
        "I/O timeout invalidated the login lease"
    );
    assert!(stopped.is_cancelled());
    assert!(connector.state.read().unwrap().current.is_none());
    let stats = generation.stack.stats();
    assert_eq!(
        (
            stats.active_tcp,
            stats.pending_tcp,
            stats.active_udp,
            stats.time_wait
        ),
        (0, 0, 0, 0)
    );
    let mut remainder = Vec::new();
    peer.read_to_end(&mut remainder).await.unwrap();
    // Writer and reader wake concurrently: at most the single catch-up DPD
    // can precede read-timeout observation. Never an unbounded backlog of DPDs.
    assert!(remainder.len() <= Frame::Keepalive.encode(1400).unwrap().len());
}

#[tokio::test(start_paused = true)]
async fn heartbeat_catches_up_once_and_restarts_from_actual_send_time() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let (writer, mut peer) = tokio::io::duplex(4096);
    let (outgoing, packets) = mpsc::channel(4);
    let task = tokio::spawn(write_packets(
        writer,
        packets,
        1400,
        lease,
        CancellationToken::new(),
    ));
    assert_eq!(
        gp::read_frame(&mut peer, 1400).await.unwrap(),
        Frame::Keepalive
    );
    clock.advance(Duration::ZERO, Duration::from_secs(65));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        gp::read_frame(&mut peer, 1400).await.unwrap(),
        Frame::Keepalive
    );
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_pending_read(&mut peer);
    clock.advance(Duration::ZERO, Duration::from_secs(19));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_pending_read(&mut peer);
    clock.advance(Duration::ZERO, Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        gp::read_frame(&mut peer, 1400).await.unwrap(),
        Frame::Keepalive
    );
    drop(outgoing);
    assert!(task.await.unwrap().is_err());
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn blocked_partial_frame_write_cannot_resume_after_wall_timeout() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let (writer, mut peer) = tokio::io::duplex(1);
    let (_outgoing, packets) = mpsc::channel(1);
    let task = tokio::spawn(write_packets(
        writer,
        packets,
        1400,
        lease,
        CancellationToken::new(),
    ));
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, TUNNEL_WRITE_TIMEOUT);
    // Freeing space wakes the in-flight frame before the periodic timer; its
    // next actual write poll must still reject the expired operation.
    assert_eq!(
        peer.read_u8().await.unwrap(),
        Frame::Keepalive.encode(1400).unwrap()[0]
    );
    assert!(matches!(task.await.unwrap(), Err(GpError::Timeout)));
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

struct CrossingIo {
    clock: TestClock,
    calls: Arc<AtomicUsize>,
}
impl AsyncRead for CrossingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance(Duration::ZERO, TUNNEL_READ_TIMEOUT);
        buffer.put_slice(&[0x1a]);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for CrossingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(!bytes.is_empty());
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance(Duration::ZERO, TUNNEL_WRITE_TIMEOUT);
        Poll::Ready(Ok(1))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn ready_write_cannot_continue_frame_past_its_wall_deadline() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let calls = Arc::new(AtomicUsize::new(0));
    let io = CrossingIo {
        clock,
        calls: calls.clone(),
    };
    let (_outgoing, packets) = mpsc::channel(1);
    assert!(matches!(
        write_packets(io, packets, 1400, lease, CancellationToken::new()).await,
        Err(GpError::Timeout)
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "readiness hid a second write past the deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn ready_read_cannot_continue_or_deliver_frame_past_its_wall_deadline() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let calls = Arc::new(AtomicUsize::new(0));
    let io = CrossingIo {
        clock,
        calls: calls.clone(),
    };
    let (incoming, mut packets) = mpsc::channel(1);
    assert!(matches!(
        read_packets(io, incoming, 1400, lease, CancellationToken::new()).await,
        Err(GpError::Timeout)
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "readiness hid a second read past the deadline"
    );
    assert!(packets.try_recv().is_err());
}

// A full generation with actual userspace TCP connections, but no host socket.
// These cases cover directional transport stalls while the opposite direction
// remains live; the existing deadline tests above start with an empty stack.
mod business_blackholes {
    use super::*;
    use crate::session::proxy_lifecycle_tests::echo_peer;
    use std::sync::{atomic::AtomicBool, Mutex};
    use tokio::{io::AsyncWriteExt, sync::watch, task::JoinHandle};

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Fault {
        Healthy,
        InboundBlackhole,
        OutboundBlackhole,
    }

    #[derive(Default)]
    struct Observed {
        blocked_write: AtomicBool,
        read_bytes: AtomicUsize,
        received_dpd: AtomicUsize,
        sent_dpd: AtomicUsize,
    }

    struct Transport {
        stream: tokio::io::DuplexStream,
        observed: Arc<Observed>,
    }
    impl AsyncRead for Transport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.stream).poll_read(cx, buffer);
            self.observed
                .read_bytes
                .fetch_add(buffer.filled().len() - before, Ordering::SeqCst);
            result
        }
    }
    impl AsyncWrite for Transport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
            if result.is_pending() {
                self.observed.blocked_write.store(true, Ordering::SeqCst);
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

    struct Harness {
        connector: Arc<TunnelConnector>,
        observed: Arc<Observed>,
        mode: watch::Sender<Fault>,
        heartbeat: mpsc::Sender<()>,
        stop: CancellationToken,
        generation: Option<JoinHandle<Result<(), GpError>>>,
        peer: Option<JoinHandle<()>>,
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.cancel();
            if let Some(task) = &self.generation {
                task.abort();
            }
            if let Some(task) = &self.peer {
                task.abort();
            }
        }
    }

    async fn eventually(stage: &str, predicate: impl Fn() -> bool) {
        timeout(Duration::from_secs(2), async {
            while !predicate() {
                tokio::task::yield_now().await;
                tokio::time::advance(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("bounded fixture progress timed out: {stage}"));
    }

    impl Harness {
        async fn start(connector: Arc<TunnelConnector>, lease: Lease) -> Self {
            let observed = Arc::new(Observed::default());
            // Smaller than one full data frame: an unread write side must reach
            // Pending in the first TCP flight, independently of cwnd/RTO growth.
            let (stream, wire) = tokio::io::duplex(1024);
            let transport = Transport {
                stream,
                observed: observed.clone(),
            };
            let stop = CancellationToken::new();
            let (mode, mut read_mode) = watch::channel(Fault::Healthy);
            let mut write_mode = mode.subscribe();
            let (heartbeat, mut heartbeats) = mpsc::channel(1);
            let (to_peer, input) = mpsc::channel(16);
            let (output, mut from_peer) = mpsc::channel(16);
            let (mut reader, mut writer) = tokio::io::split(wire);
            let stopping = stop.clone();
            let counters = observed.clone();
            let peer = tokio::spawn(async move {
                let mut workers = JoinSet::new();
                workers.spawn(echo_peer::run_peer(
                    input,
                    output,
                    stopping.clone(),
                    Arc::new(Mutex::new(echo_peer::PeerStats::default())),
                    Arc::new(AtomicBool::new(false)),
                    2,
                    77,
                ));
                let reading = stopping.clone();
                let read_counters = counters.clone();
                workers.spawn(async move {
                    loop {
                        tokio::select! {
                            biased;
                            _ = reading.cancelled() => return Ok(()),
                            changed = read_mode.changed() => { if changed.is_err() { return Ok(()); } },
                            frame = gp::read_frame(&mut reader, 1400), if *read_mode.borrow() != Fault::OutboundBlackhole => match frame {
                                Ok(Frame::Keepalive) => { read_counters.received_dpd.fetch_add(1, Ordering::SeqCst); },
                                Ok(Frame::Ip(packet)) => { if to_peer.send(packet).await.is_err() { return Ok(()); } },
                                Err(_) => return Ok(()),
                            },
                        }
                    }
                });
                let writing = stopping.clone();
                workers.spawn(async move {
                    loop {
                        let frame = tokio::select! {
                            biased;
                            _ = writing.cancelled() => return Ok(()),
                            changed = write_mode.changed() => { if changed.is_err() { return Ok(()); } continue; },
                            heartbeat = heartbeats.recv() => { if heartbeat.is_none() { return Ok(()); } Frame::Keepalive },
                            packet = from_peer.recv() => { let Some(packet) = packet else { return Ok(()); }; Frame::Ip(packet) },
                        };
                        if *write_mode.borrow() == Fault::InboundBlackhole { continue; }
                        let keepalive = matches!(frame, Frame::Keepalive);
                        tokio::select! {
                            biased;
                            _ = writing.cancelled() => return Ok(()),
                            result = gp::write_frame(&mut writer, &frame, 1400) => { if result.is_err() { return Ok(()); } },
                        }
                        if keepalive { counters.sent_dpd.fetch_add(1, Ordering::SeqCst); }
                    }
                });
                stopping.cancelled().await;
                workers.abort_all();
                while let Some(result) = workers.join_next().await {
                    match result {
                        Ok(result) => result.unwrap(),
                        Err(error) => assert!(error.is_cancelled()),
                    }
                }
            });
            let active = connector.clone();
            let shutdown = stop.child_token();
            let generation = tokio::spawn(async move {
                run_generation(
                    &Config {
                        max_connections: 4,
                        connect_timeout_secs: 120,
                        idle_timeout_secs: 600,
                        ..Config::default()
                    },
                    tunnel_config(),
                    Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap(),
                    transport,
                    active,
                    GenerationControl {
                        cancel: shutdown,
                        lease,
                        maintenance: pending(),
                    },
                )
                .await
            });
            let harness = Self {
                connector,
                observed,
                mode,
                heartbeat,
                stop,
                generation: Some(generation),
                peer: Some(peer),
            };
            eventually("generation publication and initial DPD", || {
                harness.connector.status().available
                    && harness.observed.received_dpd.load(Ordering::SeqCst) >= 1
            })
            .await;
            harness
        }

        async fn live(&self) -> BoxStream {
            timeout(Duration::from_secs(2), async {
                let mut stream = self
                    .connector
                    .connect(Target::new("10.77.0.1", 443).unwrap())
                    .await
                    .unwrap();
                stream.write_all(b"live-before-blackhole").await.unwrap();
                let mut response = [0; 21];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"live-before-blackhole");
                stream
            })
            .await
            .unwrap()
        }

        async fn fail(&mut self) -> GpError {
            let result = timeout(Duration::from_secs(2), self.generation.as_mut().unwrap())
                .await
                .unwrap()
                .unwrap();
            self.generation.take();
            result.unwrap_err()
        }

        async fn close(mut self) {
            self.stop.cancel();
            if let Some(task) = self.generation.as_mut() {
                timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .ok();
                self.generation.take();
            }
            timeout(Duration::from_secs(2), self.peer.as_mut().unwrap())
                .await
                .unwrap()
                .unwrap();
            self.peer.take();
        }
    }

    async fn exercise(fault: Fault) {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(600)));
        let connector = Arc::new(TunnelConnector::default());
        let mut old = Harness::start(connector.clone(), lease.clone()).await;
        let mut live = old.live().await;
        let (old_generation, stack) = {
            let state = connector.state.read().unwrap();
            let generation = state.current.as_ref().unwrap();
            (Arc::downgrade(generation), generation.stack.clone())
        };
        let stale = connector.connect(Target::new("10.77.0.1", 443).unwrap());
        let connecting = connector.clone();
        let pending_dial = tokio::spawn(async move {
            connecting
                .connect(Target::new("10.77.0.99", 443).unwrap())
                .await
        });
        eventually("pending TCP admission", || stack.stats().pending_tcp == 1).await;
        old.observed.blocked_write.store(false, Ordering::SeqCst);
        old.mode.send_replace(fault);
        // Drain already-ready frame work before advancing either clock. No host
        // time changes, OS sockets or process suspension are involved here.
        for _ in 0..128 {
            tokio::task::yield_now().await;
        }
        let application = tokio::spawn(async move {
            if fault == Fault::OutboundBlackhole {
                live.write_all(&vec![0x5a; 1024 * 1024]).await
            } else {
                live.read_u8().await.map(|_| ())
            }
        });
        if fault == Fault::InboundBlackhole {
            for index in 1..=4 {
                clock.advance(Duration::ZERO, Duration::from_secs(20));
                tokio::time::advance(Duration::from_secs(1)).await;
                eventually("DPD reception during inbound blackhole", || {
                    old.observed.received_dpd.load(Ordering::SeqCst) > index
                })
                .await;
                assert!(
                    connector.status().available,
                    "outbound DPD must not hide inbound timeout before its deadline"
                );
            }
            clock.advance(Duration::ZERO, Duration::from_secs(10));
        } else {
            eventually("outbound transport write actually became Pending", || {
                old.observed.blocked_write.load(Ordering::SeqCst)
            })
            .await;
            assert!(
                !application.is_finished(),
                "application did not actually encounter backpressure"
            );
            let before = old.observed.read_bytes.load(Ordering::SeqCst);
            for index in 1..=9 {
                clock.advance(Duration::ZERO, Duration::from_secs(1));
                old.heartbeat.send(()).await.unwrap();
                eventually("DPD emission during outbound blackhole", || {
                    old.observed.sent_dpd.load(Ordering::SeqCst) >= index
                })
                .await;
                tokio::time::advance(Duration::from_millis(100)).await;
            }
            assert!(
                old.observed.read_bytes.load(Ordering::SeqCst) > before,
                "opposite direction did not remain active"
            );
            assert!(connector.status().available);
            clock.advance(Duration::ZERO, Duration::from_secs(1));
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = old.fail().await;
        assert!(retryable(&error));
        assert_eq!(failure_reason(&error, &lease), Reason::TransportUnavailable);
        assert_eq!(
            lease.check(),
            Ok(()),
            "transport failure must not invalidate the login lease"
        );
        assert!(timeout(Duration::from_secs(2), application)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(timeout(Duration::from_secs(2), pending_dial)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(!connector.status().available);
        assert!(stack.is_closed());
        let stats = stack.stats();
        assert_eq!(
            stats.active_tcp
                + stats.pending_tcp
                + stats.active_udp
                + stats.time_wait
                + stats.socket_count
                + stats.command_queue
                + stats.incoming_queue
                + stats.outgoing_queue
                + stats.tcp_buffer_capacity_bytes,
            0
        );
        old.close().await;
        let replacement = Harness::start(connector.clone(), lease.clone()).await;
        assert_eq!(
            stale.await.err().unwrap().kind(),
            io::ErrorKind::NotConnected,
            "old capability crossed into replacement generation"
        );
        drop(stack);
        eventually("old generation weak reference released", || {
            old_generation.strong_count() == 0
        })
        .await;
        drop(replacement.live().await);
        replacement.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_blackhole_revokes_live_pending_and_stale_generation_despite_outbound_dpd() {
        exercise(Fault::InboundBlackhole).await;
    }

    #[tokio::test(start_paused = true)]
    async fn outbound_blackhole_revokes_backpressured_and_pending_business_despite_inbound_dpd() {
        exercise(Fault::OutboundBlackhole).await;
    }
}
