//! A bounded, session-scoped resolver. DNS transport is exclusively through the VPN stack.
use crate::stack::StackHandle;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::{
    collections::{HashMap, HashSet},
    future::{poll_fn, Future},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    task::Poll,
    time::{Duration, Instant, SystemTime},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Production stacks reserve this many transient DNS slots beyond the proxy's
/// independent application-connection limit. Each lookup owns at most four futures.
pub const MAX_DNS_SERVERS: usize = 4;
const HEDGE_DELAY: Duration = Duration::from_millis(100);
const ADMISSION_RETRY: Duration = Duration::from_millis(100);
const CACHE_ENTRIES: usize = 256;
/// Concurrent canonical name/transport keys retained by one generation resolver.
pub const MAX_DNS_PENDING_NAMES: usize = 64;
/// Includes the first caller; additional callers fail explicitly with WouldBlock.
pub const MAX_DNS_WAITERS_PER_NAME: usize = 64;

mod shared;

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod robustness;

#[derive(Clone, Copy)]
struct CacheTime {
    monotonic: Instant,
    wall: SystemTime,
}

impl CacheTime {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

struct CacheEntry {
    monotonic_until: Instant,
    wall_until: SystemTime,
    addresses: Vec<Ipv4Addr>,
}

impl CacheEntry {
    fn remaining(&self, now: CacheTime) -> Option<Duration> {
        let monotonic = self.monotonic_until.checked_duration_since(now.monotonic)?;
        let wall = self.wall_until.duration_since(now.wall).ok()?;
        let remaining = monotonic.min(wall);
        (!remaining.is_zero()).then_some(remaining)
    }
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    last_wall: Option<SystemTime>,
}

impl CacheState {
    fn observe(&mut self, now: CacheTime) {
        if self.last_wall.is_some_and(|previous| now.wall < previous) {
            // A backwards wall observation invalidates every old deadline.
            // Samples are taken inside the mutex, never before waiting for it.
            self.entries.clear();
        }
        self.last_wall = Some(now.wall);
    }

    fn get(&mut self, key: &str, now: CacheTime) -> Option<Vec<Ipv4Addr>> {
        self.observe(now);
        if let Some(entry) = self.entries.get(key) {
            if entry.remaining(now).is_some() {
                return Some(entry.addresses.clone());
            }
        }
        self.entries.remove(key);
        None
    }

    fn insert(&mut self, key: String, addresses: Vec<Ipv4Addr>, ttl: u32, now: CacheTime) {
        self.observe(now);
        self.entries
            .retain(|_, entry| entry.remaining(now).is_some());
        if ttl == 0 {
            self.entries.remove(&key);
            return;
        }
        let ttl = Duration::from_secs(ttl.min(300) as u64);
        let (Some(monotonic_until), Some(wall_until)) =
            (now.monotonic.checked_add(ttl), now.wall.checked_add(ttl))
        else {
            self.entries.remove(&key);
            return;
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= CACHE_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.remaining(now))
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                monotonic_until,
                wall_until,
                addresses,
            },
        );
    }
}

pub struct Resolver {
    servers: Vec<Ipv4Addr>,
    cache: Arc<Mutex<CacheState>>,
    pending: Mutex<Pending>,
}

#[derive(Default)]
struct Pending {
    stack: Option<StackHandle>,
    queries: HashMap<(String, bool), shared::Entry>,
}

impl Resolver {
    pub fn new(servers: Vec<Ipv4Addr>) -> Self {
        Self {
            servers: servers.into_iter().take(MAX_DNS_SERVERS).collect(),
            cache: Arc::new(Mutex::new(CacheState::default())),
            pending: Mutex::new(Pending::default()),
        }
    }

    pub async fn resolve(&self, stack: &StackHandle, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        self.resolve_with_transport(stack, host, false).await
    }

    /// Verify DNS over tunnel TCP explicitly, bypassing the UDP path and cache.
    /// This is useful for diagnosing TCP interoperability independently of an
    /// application's destination policy. It still uses only gateway DNS servers.
    pub async fn resolve_tcp(&self, stack: &StackHandle, host: &str) -> io::Result<Vec<Ipv4Addr>> {
        self.resolve_with_transport(stack, host, true).await
    }

    async fn resolve_with_transport(
        &self,
        stack: &StackHandle,
        host: &str,
        tcp_only: bool,
    ) -> io::Result<Vec<Ipv4Addr>> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let lookup = {
            let mut pending = self.pending.lock().unwrap();
            // A resolver is a capability for exactly one stack generation,
            // including cached and literal results. Cloned stack handles share
            // a command channel; a new generation never does.
            if stack.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "VPN DNS generation closed",
                ));
            }
            match &pending.stack {
                Some(bound) if !bound.same_generation(stack) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "resolver belongs to another VPN generation",
                    ));
                }
                None => pending.stack = Some(stack.clone()),
                _ => {}
            }
            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                return Ok(vec![ip]);
            }
            if !tcp_only {
                // Check cache while admission is serialized: a completed flight
                // inserts before Ready, so a concurrent late caller cannot miss
                // both its shared result and its newly inserted cache entry.
                let mut cache = self.cache.lock().unwrap();
                if let Some(addresses) = cache.get(&key, CacheTime::now()) {
                    return Ok(addresses);
                }
            }
            let name = absolute_name(&key)?;
            pending.queries.retain(|_, flight| flight.is_pending());
            let query_key = (key.clone(), tcp_only);
            if let Some(lookup) = pending
                .queries
                .get(&query_key)
                .and_then(shared::Entry::join)
            {
                lookup?
            } else {
                pending.queries.remove(&query_key);
                // The previous flight may have completed between cache lookup
                // and admission. Completed Shared output is never joined anew.
                if !tcp_only {
                    let mut cache = self.cache.lock().unwrap();
                    if let Some(addresses) = cache.get(&key, CacheTime::now()) {
                        return Ok(addresses);
                    }
                }
                if pending.queries.len() >= MAX_DNS_PENDING_NAMES {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "too many pending tunnel DNS names",
                    ));
                }
                let deadline = tokio::time::Instant::now() + LOOKUP_TIMEOUT;
                let cache = self.cache.clone();
                let stack = stack.clone();
                let servers = self.servers.clone();
                let (entry, lookup) = shared::Entry::new(deadline, async move {
                    let timed_out =
                        || io::Error::new(io::ErrorKind::TimedOut, "tunnel DNS lookup timed out");
                    if tokio::time::Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    let mut request =
                        Message::new(rand::random(), MessageType::Query, OpCode::Query);
                    request.metadata.recursion_desired = true;
                    request.add_query(Query::query(name, RecordType::A));
                    let bytes = request
                        .to_vec()
                        .map_err(|_| invalid("cannot encode DNS query"))?;
                    let (ips, ttl) = tokio::time::timeout_at(
                        deadline,
                        query_servers(&stack, &servers, &bytes, &request, tcp_only),
                    )
                    .await
                    .map_err(|_| timed_out())??;
                    if tokio::time::Instant::now() >= deadline || stack.is_closed() {
                        return Err(if stack.is_closed() {
                            io::Error::new(io::ErrorKind::NotConnected, "VPN DNS generation closed")
                        } else {
                            timed_out()
                        });
                    }
                    let mut cache = cache.lock().unwrap();
                    let now = CacheTime::now();
                    cache.insert(key, ips.clone(), ttl, now);
                    Ok(shared::Answer::new(ips, ttl, now))
                });
                pending.queries.insert(query_key, entry);
                lookup
            }
        };
        // Every subscriber drives the same future. The registry retains only a
        // WeakShared, so the last cancellation drops all transports immediately.
        let result = lookup.run().await;
        // A paused subscriber can resume after another caller completed the
        // query and after this generation was revoked. Success is not authority.
        if stack.is_closed() {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "VPN DNS generation closed",
            ))
        } else {
            result
        }
    }
}

async fn query_servers(
    stack: &StackHandle,
    servers: &[Ipv4Addr],
    bytes: &[u8],
    request: &Message,
    tcp_only: bool,
) -> io::Result<(Vec<Ipv4Addr>, u32)> {
    let mut attempts: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(index, server)| {
            Box::pin(async move {
                tokio::time::sleep(HEDGE_DELAY * index as u32).await;
                let destination = SocketAddr::new(IpAddr::V4(*server), 53);
                let response = if tcp_only {
                    retry_admission(|| async {
                        query_tcp(stack.connect(destination).await?, bytes, request).await
                    })
                    .await?
                } else {
                    let udp =
                        retry_admission(|| stack.udp_exchange(destination, bytes.to_vec())).await;
                    // A TC reply may cut a record in half. The fresh TCP answer
                    // still undergoes complete ID, question and RRset validation.
                    let tcp_needed = match &udp {
                        Ok(reply) => has_truncation(reply, request.id),
                        Err(_) => true,
                    };
                    if tcp_needed {
                        retry_admission(|| async {
                            query_tcp(stack.connect(destination).await?, bytes, request).await
                        })
                        .await?
                    } else {
                        decode(&udp?, request)?
                    }
                };
                answers(&response, request)
            })
        })
        .collect();
    let mut last_error = io::Error::new(
        io::ErrorKind::NotFound,
        "gateway supplied no IPv4 DNS server",
    );
    poll_fn(|context| {
        let mut index = 0;
        while index < attempts.len() {
            match attempts[index].as_mut().poll(context) {
                Poll::Ready(Ok(answer)) => return Poll::Ready(Ok(answer)),
                Poll::Ready(Err(error)) => {
                    last_error = error;
                    drop(attempts.swap_remove(index));
                }
                Poll::Pending => index += 1,
            }
        }
        if attempts.is_empty() {
            Poll::Ready(Err(io::Error::new(
                last_error.kind(),
                "no configured tunnel DNS server answered",
            )))
        } else {
            Poll::Pending
        }
    })
    .await
}

async fn retry_admission<T, F, Fut>(mut operation: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    loop {
        let result = operation().await;
        match result {
            // Stack admission is shared with application traffic. In particular
            // max_connections=1 must not permanently discard later DNS servers
            // merely because an earlier hedge owns the sole socket. The outer
            // ten-second deadline bounds all retries; a blocked caller sleeps.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                tokio::time::sleep(ADMISSION_RETRY).await;
            }
            result => return result,
        }
    }
}

fn absolute_name(host: &str) -> io::Result<Name> {
    let mut name = Name::from_ascii(host).map_err(|_| invalid("invalid DNS name"))?;
    // Proxy destinations are exact names, never search-list lookups. DNS wire
    // names always terminate at the root, and Hickory 0.26 equality deliberately
    // distinguishes relative from absolute names. Normalize before comparing a
    // reply's question to the locally constructed query.
    name.set_fqdn(true);
    Ok(name)
}

async fn query_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    bytes: &[u8],
    request: &Message,
) -> io::Result<Message> {
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(bytes).await?;
    let len = stream.read_u16().await? as usize;
    if !(12..=16384).contains(&len) {
        return Err(invalid("DNS TCP response length out of bounds"));
    }
    let mut response_bytes = vec![0; len];
    stream.read_exact(&mut response_bytes).await?;
    let response = decode(&response_bytes, request)?;
    if response.truncation {
        return Err(invalid("truncated DNS TCP response"));
    }
    Ok(response)
}

fn has_truncation(bytes: &[u8], id: u16) -> bool {
    bytes.len() >= 12 && u16::from_be_bytes([bytes[0], bytes[1]]) == id && bytes[2] & 0x82 == 0x82
}

fn decode(bytes: &[u8], request: &Message) -> io::Result<Message> {
    let response =
        Message::from_vec(bytes).map_err(|_| invalid("malformed tunnel DNS response"))?;
    if response.id != request.id
        || response.message_type != MessageType::Response
        || response.op_code != OpCode::Query
        || response.queries != request.queries
    {
        return Err(invalid("DNS response does not match query"));
    }
    if response.response_code != ResponseCode::NoError {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "tunnel DNS returned no usable answer",
        ));
    }
    Ok(response)
}

#[cfg(test)]
pub(crate) fn decode_for_logging_test(bytes: &[u8], request: &Message) -> io::Result<Message> {
    decode(bytes, request)
}

fn answers(response: &Message, request: &Message) -> io::Result<(Vec<Ipv4Addr>, u32)> {
    let mut name = request.queries[0].name().clone();
    let mut visited = HashSet::new();
    let mut ttl = u32::MAX;
    for _ in 0..8 {
        if !visited.insert(name.clone()) {
            return Err(invalid("DNS CNAME cycle"));
        }
        let matching: Vec<_> = response
            .answers
            .iter()
            .filter(|r| r.name == name && r.dns_class == hickory_proto::rr::DNSClass::IN)
            .collect();
        let mut ips = Vec::new();
        for record in &matching {
            if let RData::A(address) = &record.data {
                ttl = ttl.min(effective_ttl(record.ttl));
                // RFC 2181 section 5.2 applies the lowest TTL to the whole
                // RRset, even when we cap the addresses returned to callers.
                if ips.len() < 16 && !ips.contains(&address.0) {
                    ips.push(address.0);
                }
            }
        }
        if !ips.is_empty() {
            return Ok((ips, ttl));
        }
        match matching.iter().find_map(|record| match &record.data {
            RData::CNAME(next) => Some((next.0.clone(), record.ttl)),
            _ => None,
        }) {
            Some((next, record_ttl)) => {
                name = next;
                ttl = ttl.min(effective_ttl(record_ttl));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no IPv4 address in tunnel DNS response",
                ))
            }
        }
    }
    Err(invalid("too many DNS aliases"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn effective_ttl(wire_ttl: u32) -> u32 {
    // RFC 2181 section 8: the high bit is invalid on the wire and means zero,
    // not a large TTL that our cache may clamp to 300 seconds.
    if wire_ttl > i32::MAX as u32 {
        0
    } else {
        wire_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        rdata::{A, CNAME},
        Record,
    };
    fn query() -> Message {
        let mut q = Message::new(42, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("intranet.example.").unwrap(),
            RecordType::A,
        ));
        q
    }
    #[test]
    fn rejects_unrelated_answers_and_transaction_ids() {
        let q = query();
        let mut reply = q.clone();
        reply.metadata.message_type = MessageType::Response;
        reply.add_answer(Record::from_rdata(
            Name::from_ascii("attacker.example.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        assert!(answers(&reply, &q).is_err());
        reply.metadata.id = 43;
        assert!(decode(&reply.to_vec().unwrap(), &q).is_err());
    }

    #[test]
    fn destination_without_trailing_dot_matches_its_wire_question() {
        for host in ["intranet.example", "intranet.example.", "Intranet.Example"] {
            let mut request = Message::new(42, MessageType::Query, OpCode::Query);
            request.add_query(Query::query(absolute_name(host).unwrap(), RecordType::A));
            // The real peer decodes the query from the wire, not by cloning the
            // in-memory Name (which hid this upgrade incompatibility before).
            let mut reply = Message::from_vec(&request.to_vec().unwrap()).unwrap();
            reply.metadata.message_type = MessageType::Response;
            assert!(decode(&reply.to_vec().unwrap(), &request).is_ok());
        }
    }
    #[test]
    fn follows_cname_and_uses_minimum_ttl() {
        let q = query();
        let mut reply = q.clone();
        reply.metadata.message_type = MessageType::Response;
        let alias = Name::from_ascii("alias.example.").unwrap();
        reply.add_answer(Record::from_rdata(
            q.queries[0].name().clone(),
            20,
            RData::CNAME(CNAME(alias.clone())),
        ));
        reply.add_answer(Record::from_rdata(
            alias,
            60,
            RData::A(A(Ipv4Addr::new(10, 1, 2, 3))),
        ));
        assert_eq!(
            answers(&reply, &q).unwrap(),
            (vec![Ipv4Addr::new(10, 1, 2, 3)], 20)
        );
    }
    #[test]
    fn rejects_compression_pointer_cycles() {
        let bytes = [
            0, 42, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
        ];
        assert!(decode(&bytes, &query()).is_err());
    }
    #[test]
    fn partial_truncated_datagram_triggers_tcp_retry_only_for_matching_id() {
        let bytes = [0, 42, 0x82, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1];
        assert!(has_truncation(&bytes, 42));
        assert!(!has_truncation(&bytes, 43));
        assert!(decode(&bytes, &query()).is_err());
    }

    #[tokio::test]
    async fn tcp_dns_checks_fragmented_answers_ids_truncation_and_length() {
        for case in 0..4 {
            let request = query();
            let request_bytes = request.to_vec().unwrap();
            let expected = request_bytes.clone();
            let mut response = request.clone();
            response.metadata.message_type = MessageType::Response;
            if case == 1 {
                response.metadata.id = 43;
            }
            if case == 2 {
                response.metadata.truncation = true;
            }
            let response_bytes = response.to_vec().unwrap();
            let (client, mut server) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move {
                let size = server.read_u16().await.unwrap() as usize;
                let mut received = vec![0; size];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
                server
                    .write_u16(if case == 3 {
                        16385
                    } else {
                        response_bytes.len() as u16
                    })
                    .await
                    .unwrap();
                if case != 3 {
                    for chunk in response_bytes.chunks(3) {
                        server.write_all(chunk).await.unwrap();
                        tokio::task::yield_now().await;
                    }
                }
            });
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                query_tcp(client, &request_bytes, &request),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), case == 0);
            task.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn forced_tcp_does_not_claim_success_from_cached_udp_answer() {
        let resolver = Resolver::new(vec![Ipv4Addr::new(10, 0, 0, 53)]);
        resolver.cache.lock().unwrap().insert(
            "intranet.example".into(),
            vec![Ipv4Addr::new(10, 0, 0, 1)],
            60,
            CacheTime::now(),
        );
        let cancel = tokio_util::sync::CancellationToken::new();
        let (_sender, incoming) = tokio::sync::mpsc::channel(1);
        let (outgoing, _receiver) = tokio::sync::mpsc::channel(1);
        let (stack, task) = crate::stack::spawn(
            crate::stack::StackConfig {
                ipv4: Ipv4Addr::new(10, 0, 0, 2),
                ipv6: None,
                mtu: 1400,
                max_connections: 1,
                connect_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_secs(1),
                random_seed: 1,
            },
            incoming,
            outgoing,
            cancel.clone(),
        )
        .unwrap();
        assert!(resolver.resolve(&stack, "intranet.example").await.is_ok());
        assert!(resolver
            .resolve_tcp(&stack, "intranet.example")
            .await
            .is_err());
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
