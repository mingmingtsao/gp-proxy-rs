#![no_main]

use gp_proxy::{
    gp::{parse_config, parse_login, read_frame, Frame},
    proxy::Target,
};
use libfuzzer_sys::fuzz_target;
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

fn frame(bytes: &[u8]) -> Result<Frame, gp_proxy::gp::GpError> {
    let mut input = bytes;
    let mut future = Box::pin(read_frame(&mut input, 9000));
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        // A byte slice always returns data or EOF without a scheduler.
        Poll::Pending => panic!("in-memory GP frame parsing unexpectedly stalled"),
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&kind, bytes)) = input.split_first() else {
        return;
    };
    match kind % 4 {
        0 => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                if let Ok(config) = parse_config(text) {
                    assert!((576..=9000).contains(&config.mtu));
                    assert!(config.ssl_tunnel_path.starts_with('/'));
                    assert!(!config.ssl_tunnel_path.starts_with("//"));
                    assert!(config.dns.len() <= 4096);
                    assert!(config.include_routes.len() <= 4096);
                    for duration in [config.timeout, config.lifetime].into_iter().flatten() {
                        assert!((1..=366 * 86400).contains(&duration.as_secs()));
                    }
                }
            }
        }
        1 => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                if let Ok(session) = parse_login(text, "synthetic-fuzz-host") {
                    assert!(!session.user.is_empty());
                    assert!(session.user.len() <= 8192);
                    assert!(!session.user.chars().any(char::is_control));
                }
            }
        }
        2 => {
            if let Ok(decoded) = frame(bytes) {
                let encoded = decoded.encode(9000).expect("accepted frame must encode");
                assert_eq!(frame(&encoded).unwrap(), decoded);
            }
        }
        _ => {
            if let Ok(host) = std::str::from_utf8(bytes) {
                if let Ok(target) = Target::new(host, 443) {
                    assert_eq!(Target::new(&target.host, target.port).unwrap(), target);
                }
            }
        }
    }
});
