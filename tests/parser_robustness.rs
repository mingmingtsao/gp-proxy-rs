//! Deterministic, bounded mutation campaigns over public GP parser interfaces.
//! Synthetic fixtures only; these tests never create sockets or read session files.

use gp_proxy::gp::{parse_config, parse_login, read_frame, Frame};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    io,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::mpsc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, ReadBuf};

const XML_SEED: u64 = 0x4750_584d_4c20_2601;
const FRAME_SEED: u64 = 0x4750_4652_4d20_2601;
const ROUNDS: usize = 6000;
const MUTATION_MAX: usize = 8192;
const CAMPAIGN_TIMEOUT: Duration = Duration::from_secs(20);
const CONFIG: &str = "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.23.1.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><timeout>3600</timeout><lifetime>86400</lifetime><dns><member>10.23.0.53</member></dns><dns-suffix><member>corp.example</member></dns-suffix><access-routes><member>10.0.0.0/8</member></access-routes></response>";

fn login() -> String {
    let args = [
        "",
        "synthetic-cookie",
        "",
        "synthetic-portal",
        "synthetic-user",
        "",
        "",
        "synthetic-domain",
        "",
        "",
        "",
        "",
        "tunnel",
        "",
        "4100",
        "10.23.1.2",
    ];
    format!(
        "<jnlp><application-desc>{}</application-desc></jnlp>",
        args.iter()
            .map(|value| format!("<argument>{value}</argument>"))
            .collect::<String>()
    )
}

// A stuck parser cannot keep this test successful indefinitely. The worker only
// owns synthetic memory; a timeout fails the harness, which terminates workers
// when its process exits. Normal cases join and propagate the original panic.
fn bounded(name: &'static str, work: impl FnOnce() + Send + 'static) {
    let started = Instant::now();
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(work));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(CAMPAIGN_TIMEOUT)
        .unwrap_or_else(|_| panic!("{name} exceeded bounded campaign deadline"));
    worker.join().unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    eprintln!("{name}: completed in {:?}", started.elapsed());
}

fn mutate(rng: &mut StdRng, bytes: &mut Vec<u8>) {
    for _ in 0..rng.gen_range(1..=4) {
        let index = rng.gen_range(0..=bytes.len());
        match rng.gen_range(0..7) {
            0 if index < bytes.len() => bytes[index] ^= 1 << rng.gen_range(0..8),
            1 if index < bytes.len() => bytes[index] = rng.gen(),
            2 if bytes.len() < MUTATION_MAX => bytes.insert(index, rng.gen()),
            3 if index < bytes.len() => {
                bytes.remove(index);
            }
            4 => bytes.truncate(index),
            5 if index < bytes.len() => {
                let end = (index + rng.gen_range(1..=64)).min(bytes.len());
                let duplicate = bytes[index..end].to_vec();
                if bytes.len() + duplicate.len() <= MUTATION_MAX {
                    bytes.splice(index..index, duplicate);
                }
            }
            _ => {
                let tokens: &[&[u8]] = &[
                    b"\0",
                    b"\xff\xfe",
                    b"&",
                    b"&#0;",
                    b"&#x110000;",
                    b"<!DOCTYPE x>",
                    b"<x/>",
                    b"<!--x-->",
                    b"%ff",
                    b"%00",
                    b"\xc0\x0c",
                ];
                let token = tokens[rng.gen_range(0..tokens.len())];
                if bytes.len() + token.len() <= MUTATION_MAX {
                    bytes.splice(index..index, token.iter().copied());
                }
            }
        }
    }
}

#[test]
fn gp_xml_mutation_campaign_is_bounded_and_never_panics() {
    bounded("GP XML campaign", || {
        let started = Instant::now();
        let valid_login = login();
        assert!(parse_login(&valid_login, "synthetic-host").is_ok());
        assert!(parse_config(CONFIG).is_ok());
        let seeds = [
            CONFIG.as_bytes(),
            valid_login.as_bytes(),
            b"",
            b"<response status='error'/>",
        ];
        let mut rng = StdRng::seed_from_u64(XML_SEED);
        let mut utf8_rejections = 0;
        let mut parsed_inputs = 0;
        for round in 0..ROUNDS {
            let mut bytes = seeds[round % seeds.len()].to_vec();
            mutate(&mut rng, &mut bytes);
            assert!(bytes.len() <= MUTATION_MAX);
            // Public parsers accept &str. Invalid UTF-8 is tracked separately,
            // never silently replaced with U+FFFD before entering the parser.
            let Ok(text) = std::str::from_utf8(&bytes) else {
                utf8_rejections += 1;
                continue;
            };
            let result = catch_unwind(|| {
                if let Ok(config) = parse_config(text) {
                    assert!((576..=9000).contains(&config.mtu));
                    assert!(config.ssl_tunnel_path.starts_with('/'));
                    assert!(!config.ssl_tunnel_path.starts_with("//"));
                    assert!(config.dns.len() <= 4096);
                    assert!(config.dns_suffixes.len() <= 4096);
                    assert!(config.include_routes.len() <= 4096);
                    for deadline in [config.timeout, config.lifetime].into_iter().flatten() {
                        assert!((1..=366 * 86400).contains(&deadline.as_secs()));
                    }
                }
                if let Ok(session) = parse_login(text, "synthetic-host") {
                    assert!(!session.user.is_empty());
                    assert!(session.user.len() <= 8192);
                    assert!(!session.user.chars().any(char::is_control));
                    assert!(!format!("{session:?}").contains("synthetic-cookie"));
                }
            });
            assert!(result.is_ok(), "XML seed={XML_SEED:#x} round={round}");
            parsed_inputs += 1;
        }
        assert!(parsed_inputs > 1000 && utf8_rejections > 100);
        eprintln!("XML seed={XML_SEED:#x} rounds={ROUNDS} max_input={MUTATION_MAX} utf8_rejected={utf8_rejections} parsed={parsed_inputs} elapsed={:?}", started.elapsed());
    });
}

#[test]
fn xml_size_nodes_duplicates_and_dtd_are_rejected() {
    bounded("GP XML boundary cases", || {
        let valid_login = login();
        let mut cases = Vec::new();
        for prefix in [
            "<!DOCTYPE response [<!ENTITY x 'yes'>]>",
            "<!DOCTYPE response SYSTEM 'file:///synthetic-never-opened'>",
        ] {
            cases.push(format!("{prefix}{CONFIG}"));
        }
        cases.push(format!("{}{}", " ".repeat(1024 * 1024 + 1), CONFIG));
        cases.push(format!(
            "<response status='success'>{}</response>",
            "<x/>".repeat(20_001)
        ));
        cases.push(format!("{}{}", "<x>".repeat(20_001), "</x>".repeat(20_001)));
        for text in cases {
            assert!(parse_config(&text).is_err());
            assert!(parse_login(&text, "synthetic-host").is_err());
        }
        // A deeply nested unknown extension below the node budget must remain
        // bounded during successful parse and document destruction as well.
        let extension = format!("{}{}", "<x>".repeat(18_000), "</x>".repeat(18_000));
        assert!(
            parse_config(&CONFIG.replace("</response>", &format!("{extension}</response>")))
                .is_ok()
        );
        assert!(parse_login(
            &valid_login.replace("</jnlp>", &format!("{extension}</jnlp>")),
            "synthetic-host"
        )
        .is_ok());
        for field in [
            "need-tunnel",
            "ip-address",
            "ssl-tunnel-url",
            "mtu",
            "timeout",
            "lifetime",
            "dns",
            "dns-suffix",
            "access-routes",
        ] {
            let marker = format!("</{field}>");
            let duplicate = CONFIG.replace(&marker, &format!("{marker}<{field}/>"));
            assert!(parse_config(&duplicate).is_err(), "duplicate field {field}");
        }
        assert!(parse_login(
            &valid_login.replace("</jnlp>", "<application-desc/></jnlp>"),
            "synthetic-host"
        )
        .is_err());
        for invalid_char in ['\0', '\u{1}', '\u{b}', '\u{fffe}', '\u{ffff}'] {
            assert!(parse_config(
                &CONFIG.replace("10.23.1.2", &format!("10.23.1.2{invalid_char}"))
            )
            .is_err());
        }
    });
}

#[test]
fn security_fields_reject_mixed_xml_content() {
    bounded("GP scalar ambiguity", || {
        for field in [
            "need-tunnel",
            "ip-address",
            "ssl-tunnel-url",
            "mtu",
            "timeout",
            "lifetime",
        ] {
            let close = format!("</{field}>");
            for hidden in ["<hidden/>ignored", "<!--split-->ignored"] {
                let text = CONFIG.replace(&close, &format!("{hidden}{close}"));
                assert!(
                    parse_config(&text).is_err(),
                    "ambiguous field {field}: {hidden}"
                );
            }
        }
        for value in ["10.23.0.53", "corp.example", "10.0.0.0/8"] {
            assert!(
                parse_config(&CONFIG.replace(value, &format!("{value}<hidden/>ignored"))).is_err()
            );
        }
        for value in ["synthetic-cookie", "synthetic-user", "tunnel", "4100"] {
            assert!(parse_login(
                &login().replace(value, &format!("{value}<hidden/>ignored")),
                "synthetic-host"
            )
            .is_err());
        }
    });
}

#[test]
fn scalar_hardening_preserves_valid_gateway_shapes_and_unknown_extensions() {
    bounded("GP valid scalar compatibility", || {
        let configuration = CONFIG
            .replace(
                "<need-tunnel>yes</need-tunnel>",
                "<need-tunnel>\n yes \n</need-tunnel>",
            )
            .replace("<mtu>1400</mtu>", "<mtu><![CDATA[1400]]></mtu>")
            .replace(
                "</response>",
                "<vendor-extension><nested>unused</nested></vendor-extension></response>",
            );
        let parsed = parse_config(&configuration).unwrap();
        assert_eq!(parsed.address.to_string(), "10.23.1.2");
        assert_eq!(parsed.mtu, 1400);
        assert_eq!(parsed.timeout, Some(Duration::from_secs(3600)));
        let login = login()
            .replace("<argument></argument>", "<argument/>")
            .replace(
                "</jnlp>",
                "<vendor-extension><nested>unused</nested></vendor-extension></jnlp>",
            );
        let parsed = parse_login(&login, "synthetic-host").unwrap();
        assert_eq!(parsed.user, "synthetic-user");
        assert_eq!(parsed.domain, "synthetic-domain");
        assert_eq!(parsed.preferred_ip.unwrap().to_string(), "10.23.1.2");
    });
}

struct Fragmented<'a> {
    bytes: &'a [u8],
    chunk: usize,
}

impl AsyncRead for Fragmented<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = self.bytes.len().min(self.chunk).min(output.remaining());
        output.put_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Poll::Ready(Ok(()))
    }
}

fn ip4(payload: usize) -> Frame {
    let mut bytes = vec![0; 20 + payload];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + payload) as u16).to_be_bytes());
    Frame::Ip(bytes)
}

fn ip6(payload: usize) -> Frame {
    let mut bytes = vec![0; 40 + payload];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
    Frame::Ip(bytes)
}

#[test]
fn frame_mutation_and_fragmentation_campaign_is_bounded() {
    bounded("GP frame campaign", || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let started = Instant::now();
            let seeds = [Frame::Keepalive.encode(1400).unwrap(), ip4(0).encode(1400).unwrap(), ip4(100).encode(1400).unwrap(), ip6(0).encode(1400).unwrap(), ip6(100).encode(1400).unwrap()];
            let mut rng = StdRng::seed_from_u64(FRAME_SEED);
            let mut accepted = 0;
            for round in 0..ROUNDS {
                let mut bytes = seeds[round % seeds.len()].clone();
                mutate(&mut rng, &mut bytes);
                let mtu = [0, 19, 20, 39, 40, 576, 1400, 9000][round % 8];
                let mut contiguous = bytes.as_slice();
                let reference = read_frame(&mut contiguous, mtu).await;
                let mut fragmented = Fragmented { bytes: &bytes, chunk: round % 17 + 1 };
                let divided = read_frame(&mut fragmented, mtu).await;
                assert_eq!(reference.is_ok(), divided.is_ok(), "frame seed={FRAME_SEED:#x} round={round}");
                if let (Ok(reference), Ok(divided)) = (reference, divided) {
                    assert_eq!(reference, divided);
                    assert_eq!(contiguous, fragmented.bytes);
                    let canonical = reference.encode(mtu).unwrap();
                    assert_eq!(read_frame(&mut canonical.as_slice(), mtu).await.unwrap(), reference);
                    if let Frame::Ip(packet) = reference { assert!(packet.len() <= mtu); }
                    accepted += 1;
                }
            }
            for frame in [Frame::Keepalive, ip4(0), ip4(1380), ip6(0), ip6(1360)] {
                let encoded = frame.encode(1400).unwrap();
                for end in 0..encoded.len() { assert!(read_frame(&mut &encoded[..end], 1400).await.is_err()); }
                let mut stream = encoded;
                stream.extend_from_slice(&Frame::Keepalive.encode(1400).unwrap());
                for chunk in [1, 2, 3, 7, 16, 31] {
                    let mut fragmented = Fragmented { bytes: &stream, chunk };
                    assert_eq!(read_frame(&mut fragmented, 1400).await.unwrap(), frame);
                    assert_eq!(read_frame(&mut fragmented, 1400).await.unwrap(), Frame::Keepalive);
                    assert!(fragmented.bytes.is_empty());
                }
            }
            eprintln!("frame seed={FRAME_SEED:#x} rounds={ROUNDS} max_input={MUTATION_MAX} accepted={accepted} elapsed={:?}", started.elapsed());
        });
    });
}
