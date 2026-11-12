//! Bounded, lossy diagnostics. Logging must not delay session cleanup.

use std::{
    fmt::{self, Write as _},
    fs::File,
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, OnceLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub use crate::log_store::{DEFAULT_SLOT_BYTES, MAX_SLOT_BYTES, MIN_SLOT_BYTES, SLOT_COUNT};
use serde::Serialize;
use tracing::{field::Visit, Event, Subscriber};
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder};
use tracing_subscriber::{
    field::RecordFields,
    fmt::{format::Writer, FmtContext, FormatEvent, FormatFields, FormattedFields},
    layer::{Context, Filter, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

pub const MAX_RECORD_BYTES: usize = 4096;
pub const QUEUED_RECORDS: usize = 128;
const SHUTDOWN_WAIT: Duration = Duration::from_millis(250);
const INITIALIZATION_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct LogMetrics {
    pub dropped: usize,
    pub truncated: usize,
    pub write_errors: usize,
}

#[derive(Default)]
struct Counters {
    truncated: AtomicUsize,
    write_errors: AtomicUsize,
}

#[derive(Clone)]
struct Metrics {
    counters: Arc<Counters>,
    dropped: ErrorCounter,
}

impl Metrics {
    fn snapshot(&self) -> LogMetrics {
        LogMetrics {
            dropped: self.dropped.dropped_lines(),
            truncated: self.counters.truncated.load(Ordering::Relaxed),
            write_errors: self.counters.write_errors.load(Ordering::Relaxed),
        }
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Counters only: no log text, paths, credentials, or server responses.
pub fn snapshot() -> LogMetrics {
    METRICS
        .get()
        .map_or_else(LogMetrics::default, Metrics::snapshot)
}

fn increment(counter: &AtomicUsize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Keeps the upstream guard on an already existing thread. Dropping this guard
/// waits at most 250 ms for acknowledgement, never for a blocked writer's join.
/// OS scheduling can delay return beyond that requested wait.
pub struct LoggingGuard {
    stop: Option<SyncSender<()>>,
    done: Receiver<()>,
    owner: Option<JoinHandle<()>>,
    metrics: Metrics,
}

impl LoggingGuard {
    pub fn metrics(&self) -> LogMetrics {
        self.metrics.snapshot()
    }

    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.try_send(());
            let _ = self.done.recv_timeout(SHUTDOWN_WAIT);
        }
        // A blocked sink (or upstream guard's stdout warning) can outlive us.
        // Even is_finished() is not an OS thread join guarantee. Never join
        // on this lifecycle path; process exit ends any remaining threads.
        drop(self.owner.take());
    }
}

/// Install a process-wide subscriber. Call once, before starting service tasks.
pub fn init() -> io::Result<LoggingGuard> {
    let (writer, guard) = start(duplicate_stderr()?)?;
    install(writer, guard)
}

/// Open the optional private file store on the logging owner, not the caller.
/// Cancellation cannot interrupt an in-flight kernel filesystem operation.
pub fn init_file(directory: PathBuf, slot_bytes: Option<u64>) -> io::Result<LoggingGuard> {
    let (writer, guard) = start_factory(move |cancelled| {
        crate::log_store::FileRing::open(directory, slot_bytes, cancelled)
    })?;
    install(writer, guard)
}

fn install(writer: NonBlocking, guard: LoggingGuard) -> io::Result<LoggingGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    subscriber(writer, guard.metrics.counters.clone(), filter)
        .try_init()
        .map_err(|_| io::Error::other("logging initialization failed"))?;
    let _ = METRICS.set(guard.metrics.clone());
    Ok(guard)
}

#[cfg(unix)]
fn duplicate_stderr() -> io::Result<File> {
    use std::os::fd::AsFd;
    Ok(File::from(io::stderr().as_fd().try_clone_to_owned()?))
}

#[cfg(windows)]
fn duplicate_stderr() -> io::Result<File> {
    use std::os::windows::io::AsHandle;
    Ok(File::from(io::stderr().as_handle().try_clone_to_owned()?))
}

#[cfg(not(any(unix, windows)))]
fn duplicate_stderr() -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stderr duplication unsupported",
    ))
}

fn start(writer: impl Write + Send + 'static) -> io::Result<(NonBlocking, LoggingGuard)> {
    start_factory(move |_| Ok(writer))
}

fn start_factory<W: Write + Send + 'static>(
    factory: impl FnOnce(&AtomicBool) -> io::Result<W> + Send + 'static,
) -> io::Result<(NonBlocking, LoggingGuard)> {
    Startup::spawn(factory)?.wait(INITIALIZATION_WAIT)
}

struct Startup {
    ready: Receiver<io::Result<NonBlocking>>,
    stop: Option<SyncSender<()>>,
    done: Option<Receiver<()>>,
    owner: Option<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

impl Startup {
    fn spawn<W: Write + Send + 'static>(
        factory: impl FnOnce(&AtomicBool) -> io::Result<W> + Send + 'static,
    ) -> io::Result<Self> {
        let counters = Arc::new(Counters::default());
        let worker_counters = counters.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let owner_cancelled = cancelled.clone();
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let (stop, stop_rx) = mpsc::sync_channel(1);
        let (done_tx, done) = mpsc::sync_channel(1);
        // Create the owner before doing filesystem work or enabling producers.
        // This thread also owns upstream WorkerGuard's possibly blocking Drop.
        let owner = thread::Builder::new()
            .name("gp-log-owner".into())
            .spawn(move || {
                let result = factory(&owner_cancelled);
                if owner_cancelled.load(Ordering::Acquire) {
                    drop(result);
                } else {
                    match result {
                        Err(error) => {
                            let _ = ready_tx.send(Err(io::Error::new(
                                error.kind(),
                                "logging writer initialization failed",
                            )));
                        }
                        Ok(sink) => {
                            let (writer, guard) = NonBlockingBuilder::default()
                                .buffered_lines_limit(QUEUED_RECORDS)
                                .lossy(true)
                                .thread_name("gp-log-writer")
                                .finish(CountedWriter {
                                    inner: sink,
                                    counters: worker_counters,
                                });
                            if ready_tx.send(Ok(writer)).is_ok() {
                                let _ = stop_rx.recv();
                            }
                            drop(guard);
                        }
                    }
                }
                let _ = done_tx.send(());
            })
            .map_err(|error| io::Error::new(error.kind(), "logging owner could not start"))?;
        Ok(Self {
            ready,
            stop: Some(stop),
            done: Some(done),
            owner: Some(owner),
            cancelled,
            counters,
        })
    }

    fn wait(&mut self, duration: Duration) -> io::Result<(NonBlocking, LoggingGuard)> {
        let result = self.ready.recv_timeout(duration).unwrap_or_else(|error| {
            Err(io::Error::new(
                match error {
                    mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                    mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::Other,
                },
                "logging worker did not initialize",
            ))
        });
        let writer = match result {
            Ok(writer) => writer,
            Err(error) => {
                self.cancel();
                return Err(error);
            }
        };
        let metrics = Metrics {
            counters: self.counters.clone(),
            dropped: writer.error_counter(),
        };
        Ok((
            writer,
            LoggingGuard {
                stop: self.stop.take(),
                done: self.done.take().expect("startup can complete only once"),
                owner: self.owner.take(),
                metrics,
            },
        ))
    }

    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(stop) = self.stop.take() {
            let _ = stop.try_send(());
        }
    }
}

impl Drop for Startup {
    fn drop(&mut self) {
        if self.owner.is_some() {
            self.cancel();
        }
        // Detach a blocked factory. Never turn initialization failure into an
        // unbounded join. On its return it observes cancellation and drops sink.
        drop(self.owner.take());
    }
}

struct CountedWriter<W> {
    inner: W,
    counters: Arc<Counters>,
}

impl<W: Write> Write for CountedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(bytes);
        if result.is_err() {
            increment(&self.counters.write_errors);
        }
        result
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let result = self.inner.write_all(bytes);
        if result.is_err() {
            increment(&self.counters.write_errors);
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.inner.flush().is_err() {
            increment(&self.counters.write_errors);
        }
        // The upstream worker prints flush errors synchronously to stderr.
        // Count them instead; no logging error recursively emits another log.
        Ok(())
    }
}

fn subscriber(
    writer: NonBlocking,
    counters: Arc<Counters>,
    filter: EnvFilter,
) -> impl Subscriber + Send + Sync {
    tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .log_internal_errors(false)
            .fmt_fields(BoundedFields(counters.clone()))
            .event_format(BoundedEvent(counters))
            .with_writer(writer)
            .with_filter(BlockDnsPayloads),
    )
}

fn blocked_target(target: &str) -> bool {
    target == "hickory_proto" || target.starts_with("hickory_proto::")
}

// This filter is independent of EnvFilter. A more specific RUST_LOG directive
// must never re-enable dependency diagnostics containing raw DNS data.
struct BlockDnsPayloads;

impl<S> Filter<S> for BlockDnsPayloads {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _: &Context<'_, S>) -> bool {
        !blocked_target(metadata.target())
    }

    fn event_enabled(&self, event: &Event<'_>, _: &Context<'_, S>) -> bool {
        if blocked_target(event.metadata().target()) {
            return false;
        }
        // tracing-log 0.2 carries normalized targets in a string field on its
        // shared `log` callsite. Inspect it before any field gets formatted.
        struct LogTarget(bool);
        impl Visit for LogTarget {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "log.target" {
                    self.0 |= blocked_target(value);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn fmt::Debug) {}
        }
        let mut target = LogTarget(false);
        event.record(&mut target);
        !target.0
    }
}

struct Buffer {
    bytes: [u8; MAX_RECORD_BYTES],
    len: usize,
    limit: usize,
    truncated: bool,
}

impl Buffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: [0; MAX_RECORD_BYTES],
            len: 0,
            limit,
            truncated: false,
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("only UTF-8 strings appended")
    }

    fn note_truncation(&self, counters: &Counters) {
        if self.truncated {
            increment(&counters.truncated);
        }
    }
}

impl fmt::Write for Buffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated {
            return Ok(());
        }
        let available = self.limit - self.len;
        let mut end = value.len().min(available);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.bytes[self.len..self.len + end].copy_from_slice(&value.as_bytes()[..end]);
        self.len += end;
        self.truncated |= end != value.len();
        // Truncation is successful formatting. Returning Err would make
        // tracing-subscriber print an unbounded span formatting error.
        Ok(())
    }
}

struct Fields<'a>(&'a mut Buffer);

struct Sanitized<'a>(&'a mut Buffer);

impl fmt::Write for Sanitized<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for ch in value.chars() {
            if self.0.truncated {
                break;
            }
            if ch.is_control() {
                for escaped in ch.escape_default() {
                    self.0.write_char(escaped)?;
                }
            } else {
                self.0.write_char(ch)?;
            }
        }
        Ok(())
    }
}

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if self.0.len != 0 {
            let _ = self.0.write_char(' ');
        }
        if field.name() != "message" {
            let _ = write!(self.0, "{}=", field.name());
        }
        let _ = write!(Sanitized(self.0), "{value:?}");
    }
}

#[derive(Clone)]
struct BoundedFields(Arc<Counters>);

impl<'writer> FormatFields<'writer> for BoundedFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut buffer = Buffer::new(MAX_RECORD_BYTES);
        fields.record(&mut Fields(&mut buffer));
        buffer.note_truncation(&self.0);
        let _ = writer.write_str(buffer.as_str());
        Ok(())
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut buffer = Buffer::new(MAX_RECORD_BYTES);
        let _ = buffer.write_str(&current.fields);
        fields.record(&mut Fields(&mut buffer));
        buffer.note_truncation(&self.0);
        // Replace with one bounded allocation, instead of repeatedly appending
        // to the subscriber's span String and retaining its growth capacity.
        current.fields = buffer.as_str().to_owned();
        Ok(())
    }
}

struct BoundedEvent(Arc<Counters>);

impl<S, N> FormatEvent<S, N> for BoundedEvent
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        const TRUNCATED: &str = " [truncated]\n";
        let mut buffer = Buffer::new(MAX_RECORD_BYTES - TRUNCATED.len());
        if tracing_subscriber::fmt::format()
            .with_ansi(false)
            .format_event(ctx, Writer::new(&mut buffer), event)
            .is_err()
        {
            buffer.truncated = true;
        }
        buffer.note_truncation(&self.0);
        let _ = writer.write_str(buffer.as_str().trim_end_matches('\n'));
        let _ = writer.write_str(if buffer.truncated { TRUNCATED } else { "\n" });
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/support/logging_file.rs"]
mod file_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::Instant;
    use tracing_subscriber::{layer::Context, Layer};

    struct GateState {
        released: Mutex<bool>,
        wake: Condvar,
    }

    struct Release(Arc<GateState>);

    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.released.lock().unwrap() = true;
            self.0.wake.notify_all();
        }
    }

    struct GatedWriter {
        gate: Arc<GateState>,
        entered: Option<SyncSender<()>>,
        ended: SyncSender<()>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            let released = self.gate.released.lock().unwrap();
            let (released, _) = self
                .gate
                .wake
                .wait_timeout_while(released, Duration::from_secs(4), |released| !*released)
                .unwrap();
            if !*released {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for GatedWriter {
        fn drop(&mut self) {
            let _ = self.ended.send(());
        }
    }

    fn gated() -> (GatedWriter, Release, Receiver<()>, Receiver<()>) {
        let gate = Arc::new(GateState {
            released: Mutex::new(false),
            wake: Condvar::new(),
        });
        let (entered, entered_rx) = mpsc::sync_channel(1);
        let (ended, ended_rx) = mpsc::sync_channel(1);
        (
            GatedWriter {
                gate: gate.clone(),
                entered: Some(entered),
                ended,
            },
            Release(gate),
            entered_rx,
            ended_rx,
        )
    }

    #[test]
    fn blocked_writer_cannot_hold_shutdown_until_release() {
        let (sink, release, entered, ended) = gated();
        let (mut writer, mut guard) = start(sink).unwrap();
        let owner = guard.owner.take().unwrap();
        writer.write_all(b"blocked").unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let before = Instant::now();
        guard.shutdown();
        let elapsed = before.elapsed();
        let still_blocked = ended.try_recv().is_err();
        drop(writer);
        drop(release);
        ended.recv_timeout(Duration::from_secs(2)).unwrap();
        owner.join().unwrap();
        assert!(
            still_blocked,
            "the writer must remain gated throughout shutdown"
        );
        // Permit scheduler variation; the production requested wait is 250ms.
        assert!(elapsed < Duration::from_millis(750), "{elapsed:?}");
    }

    #[test]
    fn full_queue_is_lossy_and_all_test_threads_finish_after_release() {
        let (sink, release, entered, ended) = gated();
        let (mut writer, mut guard) = start(sink).unwrap();
        let owner = guard.owner.take().unwrap();
        writer.write_all(b"in flight").unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..QUEUED_RECORDS + 7 {
            writer.write_all(b"queued").unwrap();
        }
        let metrics = guard.metrics();
        let before = Instant::now();
        guard.shutdown();
        let elapsed = before.elapsed();
        drop(writer);
        drop(release);
        ended.recv_timeout(Duration::from_secs(2)).unwrap();
        owner.join().unwrap();
        assert_eq!(metrics.dropped, 7);
        assert_eq!(metrics.write_errors, 0);
        assert!(elapsed < Duration::from_millis(750), "{elapsed:?}");
    }

    struct MemoryWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        ended: SyncSender<()>,
    }

    impl Write for MemoryWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for MemoryWriter {
        fn drop(&mut self) {
            let _ = self.ended.send(());
        }
    }

    #[test]
    fn healthy_sink_flushes_bounded_unicode_events_and_sanitizes_controls() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (ended, ended_rx) = mpsc::sync_channel(1);
        let (writer, mut guard) = start(MemoryWriter {
            bytes: bytes.clone(),
            ended,
        })
        .unwrap();
        let owner = guard.owner.take().unwrap();
        let subscriber = subscriber(
            writer,
            guard.metrics.counters.clone(),
            EnvFilter::new("info"),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("healthy flush");
            tracing::info!(message = %"界🙂".repeat(MAX_RECORD_BYTES));
            tracing::info!(message = %"literal\n\r\x1b[31m control");
        });
        let metrics = guard.metrics.clone();
        guard.shutdown();
        ended_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        owner.join().unwrap();
        let bytes = bytes.lock().unwrap();
        let output = std::str::from_utf8(&bytes).unwrap();
        let lines: Vec<_> = output.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("healthy flush"));
        assert!(lines[1].ends_with(" [truncated]\n"));
        assert!(lines.iter().all(|line| line.len() <= MAX_RECORD_BYTES));
        assert!(lines[2].contains("\\n\\r\\u{1b}[31m"));
        assert!(!output.contains('\x1b'));
        assert!(metrics.snapshot().truncated > 0);
        assert_eq!(metrics.snapshot().dropped, 0);
        assert_eq!(metrics.snapshot().write_errors, 0);
    }

    #[test]
    fn truncation_keeps_a_utf8_prefix_without_later_fragment_insertion() {
        let mut buffer = Buffer::new(5);
        buffer.write_str("界界").unwrap();
        buffer.write_str("XY").unwrap();
        assert_eq!(buffer.as_str(), "界");
        assert!(buffer.truncated);
    }

    struct InspectSpans {
        max_len: Arc<AtomicUsize>,
        max_capacity: Arc<AtomicUsize>,
    }

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for InspectSpans {
        fn on_record(
            &self,
            id: &tracing::span::Id,
            _: &tracing::span::Record<'_>,
            ctx: Context<'_, S>,
        ) {
            let span = ctx.span(id).unwrap();
            let extensions = span.extensions();
            let fields = extensions.get::<FormattedFields<BoundedFields>>().unwrap();
            self.max_len.fetch_max(fields.len(), Ordering::Relaxed);
            self.max_capacity
                .fetch_max(fields.capacity(), Ordering::Relaxed);
        }
    }

    #[test]
    fn repeated_span_records_cannot_grow_the_cached_field_string() {
        let counters = Arc::new(Counters::default());
        let max_len = Arc::new(AtomicUsize::new(0));
        let max_capacity = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .log_internal_errors(false)
                    .fmt_fields(BoundedFields(counters.clone()))
                    .with_writer(io::sink),
            )
            .with(InspectSpans {
                max_len: max_len.clone(),
                max_capacity: max_capacity.clone(),
            });
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("bounded", value = "initial");
            for _ in 0..600 {
                span.record("value", "repeated unicode 界🙂 field");
            }
        });
        assert!(max_len.load(Ordering::Relaxed) > MAX_RECORD_BYTES / 2);
        assert!(max_len.load(Ordering::Relaxed) <= MAX_RECORD_BYTES);
        assert!(max_capacity.load(Ordering::Relaxed) <= MAX_RECORD_BYTES);
        assert!(counters.truncated.load(Ordering::Relaxed) > 0);
    }

    struct FailingWriter(SyncSender<()>);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::Other.into())
        }
    }

    impl Drop for FailingWriter {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn sink_errors_are_counted_without_recursive_logging() {
        let (ended, ended_rx) = mpsc::sync_channel(1);
        let (mut writer, mut guard) = start(FailingWriter(ended)).unwrap();
        let owner = guard.owner.take().unwrap();
        writer.write_all(b"failed write").unwrap();
        let metrics = guard.metrics.clone();
        drop(writer);
        guard.shutdown();
        ended_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        owner.join().unwrap();
        assert_eq!(metrics.snapshot().dropped, 0);
        assert!(metrics.snapshot().write_errors >= 2);
    }
}
