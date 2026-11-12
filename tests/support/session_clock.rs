//! Independent wall/monotonic clocks model suspend without changing host time.
use super::*;
use crate::lease::TestClock;
use tokio::io::AsyncReadExt;

fn config(clock: &TestClock, timeout: Option<Duration>) -> TunnelConfig {
    let mut tunnel = gp::parse_config("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>").unwrap();
    let anchor = clock.sample();
    tunnel.received_at = anchor.monotonic;
    tunnel.received_wall = anchor.wall;
    tunnel.timeout = timeout;
    tunnel
}

#[tokio::test(start_paused = true)]
async fn wall_expiry_and_rollback_revoke_status_and_connect_before_supervisor_runs() {
    for (rollback, status_first) in [(false, false), (false, true), (true, false), (true, true)] {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(60)));
        let tunnel = config(&clock, None);
        let connector = Arc::new(TunnelConnector::default());
        let active = connector.clone();
        let (transport, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            run_generation(
                &Config::default(),
                tunnel,
                Policy::new(vec![], vec!["10.77.0.0/24".parse().unwrap()]).unwrap(),
                transport,
                active,
                GenerationControl {
                    cancel: CancellationToken::new(),
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
        assert!(connector.status().available);
        if rollback {
            clock.rollback(Duration::from_secs(1));
        } else {
            clock.advance(Duration::ZERO, Duration::from_secs(3600));
        }
        // No await between changing wall time and querying readiness. The
        // background supervisor has had no chance to run its timer.
        assert!(connector.state.read().unwrap().current.is_some());
        if !status_first {
            assert_eq!(
                connector
                    .connect(Target::new("10.77.0.1", 443).unwrap())
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::NotConnected
            );
        }
        let snapshot = connector.status();
        assert!(!snapshot.available);
        assert_eq!(
            snapshot.reason,
            if rollback {
                Reason::AuthenticationRequired
            } else {
                Reason::SessionExpired
            }
        );
        assert_eq!(
            connector
                .connect(Target::new("10.77.0.1", 443).unwrap())
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::NotConnected
        );
        assert!(matches!(task.await.unwrap(), Err(GpError::Authentication)));
        let mut remaining = Vec::new();
        peer.read_to_end(&mut remaining).await.unwrap();
        assert!(
            remaining.is_empty(),
            "expired generation emitted another GP frame"
        );
        if rollback {
            clock.advance(Duration::ZERO, Duration::from_secs(2));
            assert_eq!(connector.status().reason, Reason::AuthenticationRequired);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn wall_tunnel_renewal_closes_generation_without_reclassifying_login() {
    let clock = TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(600)));
    let observed = lease.clone();
    let tunnel = config(&clock, Some(Duration::from_secs(60)));
    let connector = Arc::new(TunnelConnector::default());
    let active = connector.clone();
    let (transport, mut peer) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        run_generation(
            &Config::default(),
            tunnel,
            Policy::new(vec![], vec![]).unwrap(),
            transport,
            active,
            GenerationControl {
                cancel: CancellationToken::new(),
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
    clock.advance(Duration::ZERO, Duration::from_secs(60));
    assert!(!connector.status().available);
    assert_ne!(connector.status().reason, Reason::SessionExpired);
    assert!(
        task.await.unwrap().is_ok(),
        "renewal must return Ok for immediate getconfig without backoff"
    );
    assert_eq!(
        observed.check(),
        Ok(()),
        "tunnel renewal must not invalidate the login"
    );
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn suspended_setup_cannot_publish_expired_generation() {
    let clock = TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(60)));
    let tunnel = config(&clock, None);
    clock.advance(Duration::ZERO, Duration::from_secs(3600));
    let connector = Arc::new(TunnelConnector::default());
    let (transport, mut peer) = tokio::io::duplex(4096);
    assert!(matches!(
        run_generation(
            &Config::default(),
            tunnel,
            Policy::new(vec![], vec![]).unwrap(),
            transport,
            connector.clone(),
            GenerationControl {
                cancel: CancellationToken::new(),
                lease,
                maintenance: pending()
            }
        )
        .await,
        Err(GpError::Authentication)
    ));
    assert!(connector.state.read().unwrap().current.is_none());
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn stalled_control_operation_notices_wall_expiry_within_recheck_interval() {
    let clock = TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(60)));
    let worker = tokio::spawn(async move {
        session_operation(
            &CancellationToken::new(),
            &lease,
            pending::<Result<(), GpError>>(),
        )
        .await
    });
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, Duration::from_secs(3600));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        worker.await.unwrap(),
        Err(GpError::Authentication)
    ));
}

#[tokio::test(start_paused = true)]
async fn successful_control_result_cannot_cross_wall_expiry_boundary() {
    let clock = TestClock::new();
    let lease = clock.lease(Some(Duration::from_secs(60)));
    let result = session_operation(&CancellationToken::new(), &lease, async {
        clock.advance(Duration::ZERO, Duration::from_secs(60));
        Ok(())
    })
    .await;
    assert!(matches!(result, Err(GpError::Authentication)));
}
