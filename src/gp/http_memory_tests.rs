//! Inspect the actual HTTP reader's guarded allocations before deallocation.
//! All markers are synthetic; no heap scanning or production credentials.
use super::*;
use crate::gp::secret_buffer::audit::Audit;
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

const MARKER: &str = "synthetic-control-secret";
const CHUNK_HEADER: &str = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

#[derive(Clone, Copy)]
enum Ending {
    Eof,
    Error,
    Pending,
}

#[derive(Default)]
struct Progress {
    consumed: AtomicUsize,
    parked: AtomicBool,
}

struct Input {
    bytes: Vec<u8>,
    cursor: usize,
    ending: Ending,
    progress: Arc<Progress>,
}

impl Input {
    fn new(bytes: Vec<u8>, ending: Ending) -> Self {
        Self {
            bytes,
            cursor: 0,
            ending,
            progress: Arc::new(Progress::default()),
        }
    }
}

impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cursor < this.bytes.len() {
            let count = output
                .remaining()
                .min(7)
                .min(this.bytes.len() - this.cursor);
            output.put_slice(&this.bytes[this.cursor..this.cursor + count]);
            this.cursor += count;
            this.progress.consumed.store(this.cursor, Ordering::SeqCst);
            return Poll::Ready(Ok(()));
        }
        match this.ending {
            Ending::Eof => Poll::Ready(Ok(())),
            Ending::Error => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            Ending::Pending => {
                this.progress.parked.store(true, Ordering::SeqCst);
                Poll::Pending
            }
        }
    }
}

fn assert_clean(audit: &Audit, marked_allocations: usize) {
    let snapshot = audit.snapshot();
    assert!(snapshot.created > 0);
    assert_eq!(
        snapshot.records.len(),
        snapshot.created,
        "live owner remained"
    );
    assert!(
        snapshot.records.iter().all(|record| {
            record.post_all_zero && record.address_stable && record.logical_len <= record.capacity
        }),
        "reader released nonzero or relocated storage: {snapshot:?}"
    );
    assert!(
        snapshot
            .records
            .iter()
            .filter(|record| record.needle_present && record.pre_nonzero >= MARKER.len())
            .count()
            >= marked_allocations,
        "required partial secret never reached a guarded allocation: {snapshot:?}"
    );
}

async fn rejects(bytes: Vec<u8>, ending: Ending, marked_allocations: usize) {
    let audit = Audit::new(MARKER.as_bytes());
    let mut input = Input::new(bytes, ending);
    assert!(audit.scope(read_http_body(&mut input)).await.is_err());
    assert_clean(&audit, marked_allocations);
}

fn chunk() -> String {
    format!("{:x}\r\n{MARKER}\r\n", MARKER.len())
}

#[tokio::test]
async fn successful_fragmented_bodies_keep_only_the_output_owner_then_wipe_it() {
    let cases = [
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{MARKER}",
                MARKER.len()
            ),
            MARKER.len(),
        ),
        (format!("{CHUNK_HEADER}{}0\r\n\r\n", chunk()), MAX_XML),
        (format!("HTTP/1.1 200 OK\r\n\r\n{MARKER}"), MAX_XML + 1),
    ];
    for (wire, capacity) in cases {
        let audit = Audit::new(MARKER.as_bytes());
        let mut input = Input::new(wire.into_bytes(), Ending::Eof);
        let output = audit.scope(read_http_body(&mut input)).await.unwrap();
        assert_eq!(&*output, MARKER.as_bytes());
        assert_eq!(output.capacity(), capacity);
        let snapshot = audit.snapshot();
        assert_eq!(snapshot.created, snapshot.records.len() + 1);
        assert!(snapshot.records.iter().all(|record| !record.needle_present));
        drop(output);
        assert_clean(&audit, 1);
    }
}

#[tokio::test]
async fn truncated_bodies_bad_chunk_endings_and_failed_trailers_wipe_received_secrets() {
    rejects(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{MARKER}",
            MARKER.len() + 9
        )
        .into_bytes(),
        Ending::Eof,
        1,
    )
    .await;
    for ending in ["\r", "!!"] {
        rejects(
            format!("{CHUNK_HEADER}{:x}\r\n{MARKER}{ending}", MARKER.len()).into_bytes(),
            Ending::Eof,
            1,
        )
        .await;
    }
    rejects(
        format!("{CHUNK_HEADER}{}0\r\nX-Trailer: {MARKER}", chunk()).into_bytes(),
        Ending::Eof,
        2,
    )
    .await;
    rejects(
        format!(
            "{CHUNK_HEADER}{}0\r\nX-Trailer: {MARKER}{}",
            chunk(),
            "t".repeat(MAX_HEADERS)
        )
        .into_bytes(),
        Ending::Eof,
        2,
    )
    .await;
}

#[tokio::test]
async fn unknown_length_errors_and_overflow_wipe_full_initialized_storage() {
    rejects(
        format!("HTTP/1.1 200 OK\r\n\r\n{MARKER}").into_bytes(),
        Ending::Error,
        1,
    )
    .await;
    let mut wire = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    wire.extend_from_slice(MARKER.as_bytes());
    wire.resize(wire.len() + MAX_XML + 1 - MARKER.len(), b'x');
    rejects(wire, Ending::Eof, 1).await;
}

#[tokio::test]
async fn malformed_status_headers_and_chunk_sizes_wipe_line_storage() {
    for mut wire in [
        format!("HTTP/1.1 200 {MARKER} ").into_bytes(),
        format!("HTTP/1.1 200 OK\r\nX-Secret: {MARKER} ").into_bytes(),
    ] {
        wire.extend_from_slice(b"\xff\r\n\r\n");
        rejects(wire, Ending::Eof, 1).await;
    }
    rejects(
        format!("HTTP/1.1 200 OK\r\n{MARKER}\r\n\r\n").into_bytes(),
        Ending::Eof,
        1,
    )
    .await;
    rejects(
        format!("{CHUNK_HEADER}{MARKER}\r\n").into_bytes(),
        Ending::Eof,
        1,
    )
    .await;
    rejects(
        format!(
            "HTTP/1.1 200 OK\r\nX-Secret: {MARKER}{}",
            "x".repeat(MAX_HEADERS)
        )
        .into_bytes(),
        Ending::Eof,
        1,
    )
    .await;
}

#[tokio::test]
async fn cancelling_at_each_receive_phase_wipes_partial_data_after_audit_scope_exits() {
    let prefixes = [
        (format!("HTTP/1.1 200 OK\r\nX-Secret: {MARKER}"), 1),
        (
            format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{MARKER}"),
            1,
        ),
        (format!("{CHUNK_HEADER}64\r\n{MARKER}"), 1),
        (format!("HTTP/1.1 200 OK\r\n\r\n{MARKER}"), 1),
        (
            format!("{CHUNK_HEADER}{}0\r\nX-Secret: {MARKER}", chunk()),
            2,
        ),
    ];
    for (wire, marks) in prefixes {
        let audit = Audit::new(MARKER.as_bytes());
        let mut input = Input::new(wire.as_bytes().to_vec(), Ending::Pending);
        let progress = input.progress.clone();
        let mut operation = Box::pin(audit.scope(read_http_body(&mut input)));
        assert!(futures_util::poll!(operation.as_mut()).is_pending());
        assert!(progress.parked.load(Ordering::SeqCst));
        assert_eq!(progress.consumed.load(Ordering::SeqCst), wire.len());
        drop(operation);
        assert_clean(&audit, marks);
    }
}

#[tokio::test]
async fn aborting_a_pending_task_does_not_bypass_received_body_cleanup() {
    let audit = Audit::new(MARKER.as_bytes());
    let scoped = audit.clone();
    let mut input = Input::new(
        format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{MARKER}").into_bytes(),
        Ending::Pending,
    );
    let progress = input.progress.clone();
    let task = tokio::spawn(async move { scoped.scope(read_http_body(&mut input)).await });
    timeout(Duration::from_secs(2), async {
        while !progress.parked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    match task.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("pending read completed without cancellation"),
    }
    assert_clean(&audit, 1);
}
