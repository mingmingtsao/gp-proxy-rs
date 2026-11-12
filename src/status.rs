//! Read-only, non-sensitive local diagnostics. This schema deliberately cannot
//! contain gateway identities, destinations, credentials or free-form errors.
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

pub const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_RESPONSE: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Unknown,
    Connecting,
    Connected,
    RetryWait,
    Stopped,
}

/// Only categories belong here; never add free-form gateway/error text.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    #[default]
    None,
    SessionExpired,
    AuthenticationRequired,
    UnsupportedAuthentication,
    ConfigurationRejected,
    ProtocolError,
    TransportUnavailable,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u8,
    pub phase: Phase,
    pub reason: Reason,
    pub available: bool,
    /// Number of transport retry waits scheduled since this process started.
    pub retry_count: u64,
    pub active_tcp: usize,
    pub pending_tcp: usize,
    pub active_udp: usize,
    pub closing_tcp: usize,
    pub command_queue: usize,
    pub incoming_packets: usize,
    pub outgoing_packets: usize,
    /// Logging overload is observable without relying on the affected sink.
    pub dropped_log_records: usize,
    pub log_truncations: usize,
    pub log_write_errors: usize,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: 2,
            phase: Phase::Unknown,
            reason: Reason::None,
            available: false,
            retry_count: 0,
            active_tcp: 0,
            pending_tcp: 0,
            active_udp: 0,
            closing_tcp: 0,
            command_queue: 0,
            incoming_packets: 0,
            outgoing_packets: 0,
            dropped_log_records: 0,
            log_truncations: 0,
            log_write_errors: 0,
        }
    }
}

/// No DNS, environment proxy, redirect or configuration lookup is involved.
/// The single deadline includes connect, write, response body and EOF.
pub async fn query(address: SocketAddr) -> io::Result<Snapshot> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "status requires a numeric loopback address and nonzero HTTP port",
        ));
    }
    timeout(QUERY_TIMEOUT, async {
        let stream = TcpStream::connect(address).await?;
        exchange(stream, address).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "local status query timed out"))?
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    address: SocketAddr,
) -> io::Result<Snapshot> {
    stream
        .write_all(
            format!("GET /status HTTP/1.1\r\nHost: {address}\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut bytes = Vec::with_capacity(1024);
    stream
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    parse_response(&bytes)
}

fn invalid_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid local status response")
}

fn parse_response(bytes: &[u8]) -> io::Result<Snapshot> {
    if bytes.len() > MAX_RESPONSE {
        return Err(invalid_response());
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let header_end = match response.parse(bytes).map_err(|_| invalid_response())? {
        httparse::Status::Complete(end) => end,
        _ => return Err(invalid_response()),
    };
    if response.code != Some(200) || response.version != Some(1) {
        return Err(invalid_response());
    }
    let mut length = None;
    let mut json = false;
    for header in response.headers {
        let value = std::str::from_utf8(header.value).map_err(|_| invalid_response())?;
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_response());
            }
            length = Some(value.parse::<usize>().map_err(|_| invalid_response())?);
        } else if header.name.eq_ignore_ascii_case("content-type") {
            if json || !value.eq_ignore_ascii_case("application/json") {
                return Err(invalid_response());
            }
            json = true;
        } else if header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("content-encoding")
        {
            return Err(invalid_response());
        }
    }
    if !json || length != Some(bytes.len() - header_end) {
        return Err(invalid_response());
    }
    let snapshot: Snapshot =
        serde_json::from_slice(&bytes[header_end..]).map_err(|_| invalid_response())?;
    if snapshot.version != 2
        || snapshot.available != (snapshot.phase == Phase::Connected)
        || (snapshot.available && snapshot.reason != Reason::None)
    {
        return Err(invalid_response());
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(snapshot: &Snapshot) -> Vec<u8> {
        let body = serde_json::to_string(snapshot).unwrap();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn status_response_requires_valid_bounded_unambiguous_schema() {
        let snapshot = Snapshot {
            dropped_log_records: 7,
            log_truncations: 3,
            log_write_errors: 1,
            ..Snapshot::default()
        };
        let valid = response(&snapshot);
        assert_eq!(parse_response(&valid).unwrap(), snapshot);
        for malformed in [
            valid[..valid.len() - 1].to_vec(),
            [valid.as_slice(), b"x"].concat(),
            vec![b'x'; MAX_RESPONSE + 1],
            String::from_utf8(valid.clone())
                .unwrap()
                .replace("200 OK", "302 Found")
                .into_bytes(),
            String::from_utf8(valid.clone())
                .unwrap()
                .replace(
                    "Content-Type:",
                    "Transfer-Encoding: chunked\r\nContent-Type:",
                )
                .into_bytes(),
            String::from_utf8(valid.clone())
                .unwrap()
                .replace("Content-Type:", "Content-Length: 0\r\nContent-Type:")
                .into_bytes(),
            response(&Snapshot {
                available: true,
                ..Snapshot::default()
            }),
            response(&Snapshot {
                version: 1,
                ..Snapshot::default()
            }),
            response(&Snapshot {
                version: 3,
                ..Snapshot::default()
            }),
            response(&Snapshot {
                phase: Phase::Connected,
                available: true,
                reason: Reason::SessionExpired,
                ..Snapshot::default()
            }),
        ] {
            assert_eq!(
                parse_response(&malformed).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn status_reason_is_a_closed_enum_not_free_form_text() {
        for reason in [
            Reason::None,
            Reason::SessionExpired,
            Reason::AuthenticationRequired,
            Reason::UnsupportedAuthentication,
            Reason::ConfigurationRejected,
            Reason::ProtocolError,
            Reason::TransportUnavailable,
            Reason::Stopped,
        ] {
            let snapshot = Snapshot {
                reason,
                ..Snapshot::default()
            };
            assert_eq!(parse_response(&response(&snapshot)).unwrap(), snapshot);
        }
        let mut value = serde_json::to_value(Snapshot::default()).unwrap();
        value["reason"] = serde_json::json!("raw-error-with-private-detail");
        assert!(serde_json::from_value::<Snapshot>(value).is_err());
    }

    #[tokio::test]
    async fn status_query_rejects_nonlocal_or_zero_port_before_connect() {
        for address in [
            "192.0.2.1:8080",
            "0.0.0.0:8080",
            "[::]:8080",
            "[::ffff:127.0.0.1]:8080",
            "127.0.0.1:0",
        ] {
            assert_eq!(
                query(address.parse().unwrap()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_response_stall_and_oversize_are_bounded() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let (client, mut peer) = tokio::io::duplex(1024);
        let worker = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(peer.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"));
            // A peer that never closes a syntactically complete response cannot
            // keep the query alive past the one total deadline.
            peer.write_all(&response(&Snapshot::default()))
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        assert!(timeout(QUERY_TIMEOUT, exchange(client, address))
            .await
            .is_err());
        worker.abort();
        let _ = worker.await;

        let (client, mut peer) = tokio::io::duplex(MAX_RESPONSE + 1024);
        peer.write_all(&vec![b'x'; MAX_RESPONSE + 1]).await.unwrap();
        assert_eq!(
            exchange(client, address).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
