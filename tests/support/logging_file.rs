//! Public synthetic DNS bytes only. No filesystem logs or network are read.
use super::*;
use std::{
    sync::{Condvar, Mutex},
    time::Instant,
};

struct Memory(Arc<Mutex<Vec<u8>>>);
impl Write for Memory {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn malformed_dns_response() -> (Vec<u8>, hickory_proto::op::Message) {
    // One OPT additional record, declaring 8 option data bytes but containing
    // only 4. The complete OPT RDLENGTH is 8, so Hickory's partial Data state
    // reaches its warning rather than the earlier option-length rejection.
    let request = hickory_proto::op::Message::new(
        47,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    let mut response = vec![0, 47, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    response.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 8]);
    response.extend_from_slice(&[0xfd, 0xe8, 0, 8, 77, 91, 123, 211]);
    (response, request)
}

#[test]
fn hickory_raw_dns_warning_cannot_reach_the_logging_sink() {
    for directives in ["info", "trace,hickory_proto::rr::rdata::opt=trace"] {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (writer, mut guard) = start(Memory(bytes.clone())).unwrap();
        let owner = guard.owner.take().unwrap();
        let subscriber = subscriber(
            writer,
            guard.metrics.counters.clone(),
            EnvFilter::new(directives),
        );
        tracing::subscriber::with_default(subscriber, || {
            let (response, request) = malformed_dns_response();
            crate::dns::decode_for_logging_test(&response, &request).unwrap();
            tracing::warn!("application warning survives dependency filter");
        });
        guard.shutdown();
        owner.join().unwrap();
        let bytes = bytes.lock().unwrap();
        let output = std::str::from_utf8(&bytes).unwrap();
        assert!(output.contains("application warning survives dependency filter"));
        assert!(
            !output.contains("77, 91, 123, 211"),
            "synthetic EDNS bytes were logged"
        );
        assert!(!output.contains("incomplete or poorly formatted EDNS"));
    }
}

#[test]
fn factory_failure_is_redacted_preserves_kind_and_cancels_initialization() {
    let mut startup = Startup::spawn(|_| {
        Err::<Memory, _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic-private-path-should-not-be-propagated",
        ))
    })
    .unwrap();
    let error = startup.wait(INITIALIZATION_WAIT).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "logging writer initialization failed");
    assert!(startup.cancelled.load(Ordering::Acquire));
    startup
        .done
        .take()
        .unwrap()
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    startup.owner.take().unwrap().join().unwrap();
}

struct FactoryGate {
    released: Mutex<bool>,
    wake: Condvar,
}

struct ReleaseFactory(Arc<FactoryGate>);
impl Drop for ReleaseFactory {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.wake.notify_all();
    }
}

struct LateSink {
    dropped_on: SyncSender<String>,
    io_calls: Arc<AtomicUsize>,
}
impl Write for LateSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for LateSink {
    fn drop(&mut self) {
        let _ = self
            .dropped_on
            .send(thread::current().name().unwrap_or("unnamed").to_owned());
    }
}

#[test]
fn timed_out_factory_drops_late_sink_on_owner_without_starting_worker() {
    let gate = Arc::new(FactoryGate {
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let release = ReleaseFactory(gate.clone());
    let io_calls = Arc::new(AtomicUsize::new(0));
    let observed_io = io_calls.clone();
    let (entered, entered_rx) = mpsc::sync_channel(1);
    let (dropped_on, dropped_rx) = mpsc::sync_channel(1);
    let mut startup = Startup::spawn(move |cancelled| {
        entered.send(()).unwrap();
        let locked = gate.released.lock().unwrap();
        let (locked, _) = gate
            .wake
            .wait_timeout_while(locked, Duration::from_secs(5), |released| !*released)
            .unwrap();
        assert!(*locked, "test releases its factory after timeout");
        assert!(cancelled.load(Ordering::Acquire));
        Ok(LateSink {
            dropped_on,
            io_calls,
        })
    })
    .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let start = Instant::now();
    let error = startup.wait(INITIALIZATION_WAIT).err().unwrap();
    let elapsed = start.elapsed();
    let owner_still_gated = !startup.owner.as_ref().unwrap().is_finished();
    drop(release);
    let dropped_on = dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    startup
        .done
        .take()
        .unwrap()
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    startup.owner.take().unwrap().join().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(owner_still_gated);
    assert!(elapsed >= INITIALIZATION_WAIT && elapsed < Duration::from_secs(3));
    assert_eq!(dropped_on, "gp-log-owner");
    assert_eq!(observed_io.load(Ordering::SeqCst), 0);
}

#[test]
fn healthy_factory_runs_on_owner_and_preserves_bounded_writer_flush() {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let stored = bytes.clone();
    let (mut writer, mut guard) = start_factory(move |cancelled| {
        assert_eq!(thread::current().name(), Some("gp-log-owner"));
        assert!(!cancelled.load(Ordering::Acquire));
        Ok(Memory(stored))
    })
    .unwrap();
    let owner = guard.owner.take().unwrap();
    writer.write_all(b"synthetic healthy factory").unwrap();
    drop(writer);
    guard.shutdown();
    owner.join().unwrap();
    assert_eq!(&*bytes.lock().unwrap(), b"synthetic healthy factory");
}

#[test]
fn log_bridge_and_normalized_target_cannot_bypass_hickory_block() {
    // Only this test installs the process-global log bridge. Its otherwise
    // empty registry avoids routing unrelated parallel tests to our memory sink.
    tracing_subscriber::registry().try_init().unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (writer, mut guard) = start(Memory(bytes.clone())).unwrap();
    let owner = guard.owner.take().unwrap();
    tracing::subscriber::with_default(
        subscriber(
            writer,
            guard.metrics.counters.clone(),
            EnvFilter::new(
                "trace,hickory_proto=trace,hickory_proto::rr::rdata::opt=trace,log=trace",
            ),
        ),
        || {
            log::warn!(target: "external_safe_dependency", "safe external bridge survives");
            log::warn!(target: "hickory_proto", "blocked root log bridge canary");
            log::warn!(target: "hickory_proto::rr::rdata::opt", "blocked nested log bridge canary");
            tracing::warn!(target: "hickory_proto", "blocked root tracing canary");
            tracing::warn!(target: "hickory_proto_extra", "distinct target remains available");
            // tracing-log 0.2.0 envelopes use target=log plus this string field.
            tracing::warn!(target: "log", { "log.target" = "hickory_proto::rr::rdata::opt" }, "blocked normalized envelope canary");
        },
    );
    guard.shutdown();
    owner.join().unwrap();
    let bytes = bytes.lock().unwrap();
    let output = std::str::from_utf8(&bytes).unwrap();
    assert!(output.contains("safe external bridge survives"));
    assert!(output.contains("distinct target remains available"));
    assert!(!output.contains("canary"));
}
