//! Bounded deterministic campaigns over the resolver's actual private boundary.
//! DNS messages, TCP streams and addresses below are entirely synthetic.

use super::*;
use hickory_proto::rr::{
    rdata::{A, CNAME},
    Record,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::mpsc,
};

const SEED: u64 = 0x4750_444e_5320_2601;
const ROUNDS: usize = 6000;
const MAX_INPUT: usize = 4096;

fn request() -> Message {
    let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        absolute_name("service.corp.example").unwrap(),
        RecordType::A,
    ));
    request
}

fn response(request: &Message) -> Message {
    let mut response = request.clone();
    response.metadata.message_type = MessageType::Response;
    response
}

fn address(owner: Name, last: u8, ttl: u32) -> Record {
    Record::from_rdata(owner, ttl, RData::A(A(Ipv4Addr::new(10, 77, 0, last))))
}

fn run_bounded(work: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = send.send(catch_unwind(AssertUnwindSafe(work)));
    });
    let result = receive
        .recv_timeout(Duration::from_secs(20))
        .expect("DNS campaign exceeded 20 seconds");
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn bounded_wire_mutations_do_not_panic_or_accept_unrelated_answers() {
    run_bounded(|| {
        let started = Instant::now();
        let request = request();
        let mut valid = response(&request);
        valid.add_answer(address(request.queries[0].name().clone(), 1, 60));
        let seeds = [
            valid.to_vec().unwrap(),
            request.to_vec().unwrap(),
            vec![0; 12],
            vec![
                0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
            ],
        ];
        let mut rng = StdRng::seed_from_u64(SEED);
        let mut accepted = 0;
        for round in 0..ROUNDS {
            let mut wire = seeds[round % seeds.len()].clone();
            for _ in 0..rng.gen_range(1..=4) {
                let index = rng.gen_range(0..=wire.len());
                match rng.gen_range(0..6) {
                    0 if index < wire.len() => wire[index] ^= 1 << rng.gen_range(0..8),
                    1 if index < wire.len() => wire[index] = rng.gen(),
                    2 if wire.len() < MAX_INPUT => wire.insert(index, rng.gen()),
                    3 => wire.truncate(index),
                    4 if wire.len() >= 12 => {
                        let index = rng.gen_range(2..6) * 2;
                        wire[index..index + 2].copy_from_slice(&rng.gen::<u16>().to_be_bytes());
                    }
                    _ if wire.len() + 2 <= MAX_INPUT => {
                        wire.splice(index..index, [0xc0, rng.gen()]);
                    }
                    _ => {}
                }
            }
            assert!(wire.len() <= MAX_INPUT);
            let outcome = catch_unwind(|| {
                assert!(!has_truncation(&wire[..wire.len().min(11)], request.id));
                if let Ok(reply) = decode(&wire, &request) {
                    assert_eq!(reply.id, request.id);
                    assert_eq!(reply.queries, request.queries);
                    if let Ok((ips, _)) = answers(&reply, &request) {
                        assert!(!ips.is_empty() && ips.len() <= 16);
                        let unique: HashSet<_> = ips.iter().collect();
                        assert_eq!(unique.len(), ips.len());
                    }
                    true
                } else {
                    false
                }
            });
            assert!(outcome.is_ok(), "DNS seed={SEED:#x} round={round}");
            accepted += usize::from(outcome.unwrap());
        }
        eprintln!("DNS seed={SEED:#x} rounds={ROUNDS} max_input={MAX_INPUT} accepted={accepted} elapsed={:?}", started.elapsed());
    });
}

#[test]
fn names_aliases_record_counts_and_rrset_ttl_have_limits() {
    run_bounded(|| {
        let request = request();
        for hostname in [
            "a".to_owned(),
            "a".repeat(63),
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61),
            ]
            .join("."),
        ] {
            let mut boundary = Message::new(0x4321, MessageType::Query, OpCode::Query);
            boundary.add_query(Query::query(
                absolute_name(&hostname).unwrap(),
                RecordType::A,
            ));
            let wire = boundary.to_vec().unwrap();
            assert!(wire.len() <= 271);
            let mut echo = Message::from_vec(&wire).unwrap();
            echo.metadata.message_type = MessageType::Response;
            assert!(decode(&echo.to_vec().unwrap(), &boundary).is_ok());
        }
        for name in [
            "x".repeat(64) + ".example",
            ("x".repeat(63) + ".").repeat(5),
        ] {
            assert!(absolute_name(&name).is_err());
        }
        for hops in 0..=12 {
            let mut reply = response(&request);
            let mut current = request.queries[0].name().clone();
            for index in 0..hops {
                let next = absolute_name(&format!("alias{index}.corp.example")).unwrap();
                reply.add_answer(Record::from_rdata(
                    current,
                    60,
                    RData::CNAME(CNAME(next.clone())),
                ));
                current = next;
            }
            reply.add_answer(address(current, 1, 30));
            let decoded = decode(&reply.to_vec().unwrap(), &request).unwrap();
            assert_eq!(
                answers(&decoded, &request).is_ok(),
                hops < 8,
                "CNAME hops={hops}"
            );
        }
        let mut cycle = response(&request);
        let owner = request.queries[0].name().clone();
        cycle.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::CNAME(CNAME(owner.clone())),
        ));
        assert!(answers(&cycle, &request).is_err());

        let mut unrelated = response(&request);
        unrelated.add_answer(address(absolute_name("unrelated.example").unwrap(), 1, 60));
        assert!(answers(
            &decode(&unrelated.to_vec().unwrap(), &request).unwrap(),
            &request
        )
        .is_err());

        let mut many = response(&request);
        for index in 1..=32 {
            many.add_answer(address(
                owner.clone(),
                index,
                if index == 32 { 0 } else { 60 },
            ));
        }
        let (ips, ttl) = answers(
            &decode(&many.to_vec().unwrap(), &request).unwrap(),
            &request,
        )
        .unwrap();
        assert_eq!(ips.len(), 16);
        // RFC 2181 section 5.2: differing TTLs within one RRset use the lowest TTL,
        // including entries omitted by the application's address-count bound.
        assert_eq!(
            ttl, 0,
            "address truncation must not extend the RRset lifetime"
        );
        for (alias_ttl, final_ttl, expected) in [(60, 0, 0), (5, 30, 5)] {
            let mut chained = response(&request);
            let alias = absolute_name("alias.corp.example").unwrap();
            chained.add_answer(Record::from_rdata(
                owner.clone(),
                alias_ttl,
                RData::CNAME(CNAME(alias.clone())),
            ));
            for index in 1..=32 {
                chained.add_answer(address(
                    alias.clone(),
                    index,
                    if index == 32 { final_ttl } else { 60 },
                ));
            }
            let decoded = decode(&chained.to_vec().unwrap(), &request).unwrap();
            let (ips, ttl) = answers(&decoded, &request).unwrap();
            assert_eq!(ips.len(), 16);
            assert_eq!(ttl, expected);
        }
    });
}

#[test]
fn ttl_high_bit_is_not_interpreted_as_a_long_cache_lifetime() {
    run_bounded(|| {
        let request = request();
        let owner = request.queries[0].name().clone();
        for (ttl, expected) in [
            (0, 0),
            (1, 1),
            (0x7fff_ffff, 0x7fff_ffff),
            (0x8000_0000, 0),
            (u32::MAX, 0),
        ] {
            let mut direct = response(&request);
            direct.add_answer(address(owner.clone(), 1, ttl));
            let decoded = decode(&direct.to_vec().unwrap(), &request).unwrap();
            assert_eq!(
                answers(&decoded, &request).unwrap().1,
                expected,
                "wire TTL={ttl:#x}"
            );
            let mut chained = response(&request);
            let alias = absolute_name("alias.corp.example").unwrap();
            chained.add_answer(Record::from_rdata(
                owner.clone(),
                ttl,
                RData::CNAME(CNAME(alias.clone())),
            ));
            chained.add_answer(address(alias, 1, 60));
            let decoded = decode(&chained.to_vec().unwrap(), &request).unwrap();
            assert_eq!(
                answers(&decoded, &request).unwrap().1,
                expected.min(60),
                "CNAME TTL={ttl:#x}"
            );
        }
    });
}

#[tokio::test]
async fn tcp_framing_handles_split_prefixes_truncation_and_oversized_lengths() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let request = request();
        let mut reply = response(&request);
        reply.add_answer(address(request.queries[0].name().clone(), 1, 60));
        let complete = reply.to_vec().unwrap();
        let bytes = request.to_vec().unwrap();
        for chunk in [1, 2, 3, 7, 31] {
            for length in [0usize, 1, 11, 12, complete.len(), 16_384, 16_385, 65_535] {
                let (client, mut server) = tokio::io::duplex(128);
                let response_bytes = complete.clone();
                let task = tokio::spawn(async move {
                    let request_len = server.read_u16().await.unwrap() as usize;
                    let mut received = vec![0; request_len];
                    server.read_exact(&mut received).await.unwrap();
                    let mut wire = (length as u16).to_be_bytes().to_vec();
                    wire.extend_from_slice(&response_bytes[..length.min(response_bytes.len())]);
                    for segment in wire.chunks(chunk) {
                        if server.write_all(segment).await.is_err() {
                            break;
                        }
                    }
                });
                let result = query_tcp(client, &bytes, &request).await;
                assert_eq!(
                    result.is_ok(),
                    length == complete.len(),
                    "length={length} chunk={chunk}"
                );
                task.await.unwrap();
            }
        }
        for end in 0..complete.len() {
            assert!(
                decode(&complete[..end], &request).is_err(),
                "truncated at {end}"
            );
        }
    })
    .await
    .expect("bounded DNS TCP campaign timed out");
}
