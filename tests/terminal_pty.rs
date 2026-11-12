#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Public synthetic PTY fixtures only. The default helper test returns without
//! opening any terminal; owned child sessions exercise the real /dev/tty API.
use gp_proxy::terminal::{Terminal, MAX_PROMPT_BYTES, MAX_SECRET_BYTES};
use rustix::{
    fd::OwnedFd,
    fs::{self, Mode, OFlags},
    io::{self as rio, Errno, FdFlags},
    process,
    pty::{self, OpenptFlags},
    termios::{self, LocalModes},
};
use std::{
    future::Future,
    io::{self, Read, Write},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(8);
const PROMPT: &str = "Synthetic token: ";
static SERIAL: Mutex<()> = Mutex::new(());

fn pause() {
    std::thread::sleep(Duration::from_millis(5));
}
fn descriptors() -> usize {
    std::fs::read_dir(if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    })
    .unwrap()
    .count()
}
fn child_command(case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "terminal_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("GP_TERMINAL_CASE", case)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    command
}
struct ChildGuard {
    child: Option<Child>,
    master: Option<OwnedFd>,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // A session leader's exit must not wait on output to our unread master.
        self.master.take();
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn pump(reader: &mut impl Read, output: &mut Vec<u8>) {
    let mut bytes = [0; 512];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => return,
            Ok(size) => {
                output.extend_from_slice(&bytes[..size]);
                assert!(output.len() <= 16384);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) => panic!("owned child protocol read: {error}"),
        }
    }
}
fn wait_marker(reader: &mut impl Read, output: &mut Vec<u8>, marker: &str, until: Instant) {
    while !output
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
    {
        pump(reader, output);
        assert!(
            Instant::now() < until,
            "owned child marker timeout: {}",
            String::from_utf8_lossy(output)
        );
        pause();
    }
}
fn send(fd: &OwnedFd, mut data: &[u8], until: Instant) {
    while !data.is_empty() {
        assert!(Instant::now() < until, "owned PTY send timeout");
        match rio::write(fd, data) {
            Ok(0) => panic!("owned PTY write stopped"),
            Ok(size) => data = &data[size..],
            Err(Errno::AGAIN | Errno::INTR) => pause(),
            Err(error) => panic!("owned PTY send: {error}"),
        }
    }
}
fn drain(fd: &OwnedFd) -> Vec<u8> {
    let mut output = Vec::new();
    let mut bytes = [0; 4096];
    loop {
        match rio::read(fd, &mut bytes) {
            Ok(0) | Err(Errno::AGAIN | Errno::IO) => return output,
            Ok(size) => {
                output.extend_from_slice(&bytes[..size]);
                assert!(output.len() <= 512 * 1024);
            }
            Err(Errno::INTR) => {}
            Err(error) => panic!("owned PTY drain: {error}"),
        }
    }
}
fn finish_child(guard: &mut ChildGuard, until: Instant) {
    let child = guard.child.as_mut().unwrap();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            child.wait().unwrap();
            assert!(status.success(), "terminal child failed");
            guard.child.take();
            return;
        }
        assert!(Instant::now() < until, "terminal child did not exit");
        pause();
    }
}
fn acknowledge() {
    let mut input = io::stdin(); // Our dedicated parent pipe, never the user's tty.
    fs::fcntl_setfl(&input, fs::fcntl_getfl(&input).unwrap() | OFlags::NONBLOCK).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    let mut byte = [0];
    loop {
        match input.read(&mut byte) {
            Ok(1) if byte[0] == b'+' => return,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            _ => panic!("parent acknowledgement closed or invalid"),
        }
        assert!(Instant::now() < until, "parent acknowledgement timeout");
        pause();
    }
}

#[test]
fn terminal_child() {
    let Ok(case) = std::env::var("GP_TERMINAL_CASE") else {
        return;
    };
    if case == "background_worker" {
        let session: i32 = std::env::var("GP_TERMINAL_SESSION")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            process::getsid(None).unwrap().as_raw_nonzero().get(),
            session
        );
        let mut previously_foreground = Terminal::open().unwrap();
        process::setpgid(None, None).unwrap();
        let error = Terminal::open().err().expect("background open succeeded");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(previously_foreground.read_secret(PROMPT))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        return;
    }
    let session = process::setsid().unwrap();
    assert_eq!(session, process::getpid());
    if case == "no_terminal" {
        assert!(Terminal::open().is_err());
        return;
    }
    let path = std::env::var("GP_TERMINAL_SLAVE").unwrap();
    let dev: u64 = std::env::var("GP_TERMINAL_DEV").unwrap().parse().unwrap();
    let ino: u64 = std::env::var("GP_TERMINAL_INO").unwrap().parse().unwrap();
    let slave = fs::open(
        path.as_str(),
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let stat = fs::fstat(&slave).unwrap();
    #[allow(clippy::unnecessary_cast)]
    {
        assert_eq!((stat.st_dev as u64, stat.st_ino as u64), (dev, ino));
    }
    process::ioctl_tiocsctty(&slave).unwrap();
    termios::tcsetpgrp(&slave, process::getpgrp()).unwrap();
    assert_eq!(termios::tcgetsid(&slave).unwrap(), session);
    let before = format!("{:?}", termios::tcgetattr(&slave).unwrap());
    if case == "background" {
        let worker = child_command("background_worker")
            .env(
                "GP_TERMINAL_SESSION",
                session.as_raw_nonzero().get().to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut worker = ChildGuard {
            child: Some(worker),
            master: None,
        };
        finish_child(&mut worker, Instant::now() + WAIT);
        assert_eq!(format!("{:?}", termios::tcgetattr(&slave).unwrap()), before);
        println!("TTY_READY\nTTY_RESULT background");
        acknowledge();
        return;
    }
    let mut terminal = Terminal::open().unwrap(); // Only after adopting our own PTY.
    assert_eq!(
        format!("{:?}", termios::tcgetattr(&slave).unwrap()),
        before,
        "open changed termios"
    );
    if case == "unpolled" {
        drop(terminal.read_secret(PROMPT));
        assert_eq!(format!("{:?}", termios::tcgetattr(&slave).unwrap()), before);
        println!("TTY_READY\nTTY_RESULT unpolled");
        acknowledge();
        return;
    }
    if case == "pressure" {
        let filler = [b'x'; 4096];
        let mut filled = 0;
        loop {
            match rio::write(&slave, &filler) {
                Ok(size) => {
                    assert!(size > 0);
                    filled += size;
                    assert!(filled <= 256 * 1024);
                }
                Err(Errno::AGAIN) => break,
                Err(error) => panic!("PTY pressure setup: {error}"),
            }
        }
        println!("TTY_FILLED {filled}");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let started = Instant::now();
    let result = runtime.block_on(async {
        let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        println!("TTY_READY");
        io::stdout().flush().unwrap();
        let prompt = match case.as_str() {
            "prompt_control" => "Token:\n\u{1b}[31m\u{202e}ok".to_owned(),
            "prompt_oversize" => "x".repeat(MAX_PROMPT_BYTES + 1),
            _ => PROMPT.to_owned(),
        };
        let delay = if matches!(case.as_str(), "cancel" | "cancel_partial" | "timeout" | "pressure") { 180 } else { 5000 };
        if case == "concurrent" {
            let mut other = Terminal::open().unwrap();
            let mut first = Box::pin(terminal.read_secret(PROMPT));
            assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(first.as_mut().poll(cx))).await.is_pending());
            let error = other.read_secret("other").await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            drop(first);
            // Cancellation releases the process-wide admission and permits a
            // new hidden read on a different already-open terminal handle.
            let mut retry = Box::pin(other.read_secret(""));
            assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(retry.as_mut().poll(cx))).await.is_pending());
            drop(retry);
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        tokio::select! {
            biased;
            _ = interrupt.recv() => Err(io::Error::new(io::ErrorKind::Interrupted, "typed_interrupt")),
            _ = terminate.recv() => Err(io::Error::new(io::ErrorKind::Interrupted, "terminate")),
            _ = hangup.recv() => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "hangup")),
            _ = tokio::time::sleep(Duration::from_millis(delay)) => Err(io::Error::new(io::ErrorKind::TimedOut, "cancelled")),
            result = terminal.read_secret(&prompt) => result,
        }
    });
    drop(runtime);
    match (case.as_str(), result) {
        ("ascii" | "prompt_control", Ok(value)) => assert_eq!(&*value, "synthetic-token"),
        ("backspace", Ok(value)) => assert_eq!(&*value, "aZ"),
        ("utf8", Ok(value)) => assert_eq!(&*value, "密Z"),
        ("partial_utf8_backspace", Ok(value)) => assert_eq!(&*value, "ok"),
        ("crlf", Ok(value)) => assert_eq!(&*value, "abc"),
        ("limit", Ok(value)) => {
            assert_eq!(value.len(), MAX_SECRET_BYTES);
            assert!(value.bytes().all(|b| b == b'x'));
        }
        (
            "oversize" | "invalid_utf8" | "escape" | "suspend" | "quit" | "unicode_control"
            | "prompt_oversize",
            Err(error),
        ) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        ("eof", Err(error)) => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
        ("hangup", Err(_)) => {}
        ("cancel" | "cancel_partial" | "timeout" | "pressure", Err(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut)
        }
        ("typed_interrupt" | "external_interrupt" | "terminate" | "concurrent", Err(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::Interrupted)
        }
        (_, Err(error)) => panic!(
            "unexpected terminal error for synthetic case {case}: {:?}",
            error.kind()
        ),
        _ => panic!("unexpected successful terminal result for synthetic case {case}"),
    }
    if case != "hangup" {
        assert_eq!(
            format!("{:?}", termios::tcgetattr(&slave).unwrap()),
            before,
            "terminal attributes not restored"
        );
    }
    println!(
        "TTY_RESULT {case} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    acknowledge();
}

fn run_case(case: &str) {
    let master = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    rio::fcntl_setfd(&master, FdFlags::CLOEXEC).unwrap();
    fs::fcntl_setfl(
        &master,
        fs::fcntl_getfl(&master).unwrap() | OFlags::NONBLOCK,
    )
    .unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let path = pty::ptsname(&master, Vec::new()).unwrap();
    let slave = fs::open(
        &*path,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let original = format!("{:?}", termios::tcgetattr(&slave).unwrap());
    let stat = fs::fstat(&slave).unwrap();
    let mut command = child_command(case);
    #[allow(clippy::unnecessary_cast)]
    {
        command
            .env("GP_TERMINAL_SLAVE", path.to_str().unwrap())
            .env("GP_TERMINAL_DEV", (stat.st_dev as u64).to_string())
            .env("GP_TERMINAL_INO", (stat.st_ino as u64).to_string());
    }
    let child = command.spawn().unwrap();
    let child_pid = child.id();
    let started = Instant::now();
    let mut guard = ChildGuard {
        child: Some(child),
        master: Some(master),
    };
    let mut input = guard.child.as_mut().unwrap().stdin.take().unwrap();
    let mut output = guard.child.as_mut().unwrap().stdout.take().unwrap();
    fs::fcntl_setfl(
        &output,
        fs::fcntl_getfl(&output).unwrap() | OFlags::NONBLOCK,
    )
    .unwrap();
    let until = Instant::now() + WAIT;
    let mut protocol = Vec::new();
    wait_marker(&mut output, &mut protocol, "TTY_READY", until);
    let quiet = matches!(case, "background" | "unpolled" | "prompt_oversize");
    let expected_prompt = if case == "prompt_control" {
        "Token:??[31m?ok"
    } else {
        PROMPT
    };
    if !quiet && case != "pressure" {
        let mut prompt = Vec::new();
        while prompt.len() < expected_prompt.len() {
            prompt.extend(drain(guard.master.as_ref().unwrap()));
            assert!(Instant::now() < until, "prompt timeout for {case}");
            pause();
        }
        assert_eq!(prompt, expected_prompt.as_bytes());
    }
    if !quiet && case != "concurrent" {
        loop {
            let modes = termios::tcgetattr(&slave).unwrap().local_modes;
            if !modes.intersects(
                LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON | LocalModes::ISIG,
            ) {
                break;
            }
            assert!(Instant::now() < until, "hidden input mode was not entered");
            pause();
        }
    }
    let master = guard.master.as_ref().unwrap();
    match case {
        "ascii" | "prompt_control" => send(master, b"synthetic-token\n", until),
        "backspace" => send(master, b"abc\x7f\x7fZ\n", until),
        "utf8" => {
            for byte in "密码".as_bytes() {
                send(master, &[*byte], until);
                std::thread::sleep(Duration::from_millis(30));
            }
            send(master, b"\x7fZ\n", until);
        }
        "partial_utf8_backspace" => send(master, &[0xe5, 0xaf, 127, b'o', b'k', b'\n'], until),
        "crlf" => send(master, b"abc\r\n", until),
        "limit" | "oversize" => {
            // These cases check the byte limit, not paced keystrokes. Let the
            // nonblocking PTY apply backpressure: fixed sleeps between small
            // chunks accumulate scheduler delay and can consume the child's
            // read deadline before a valid boundary input is complete.
            send(
                master,
                &vec![b'x'; MAX_SECRET_BYTES + usize::from(case == "oversize")],
                until,
            );
            if case == "limit" {
                send(master, b"\n", until);
            }
        }
        "cancel_partial" => send(master, b"synthetic-unsubmitted", until),
        "invalid_utf8" => send(master, &[0xff], until),
        "unicode_control" => send(master, "\u{85}".as_bytes(), until),
        "escape" => send(master, &[27], until),
        "eof" => send(master, &[4], until),
        "typed_interrupt" => send(master, &[3], until),
        "suspend" => send(master, &[26], until),
        "quit" => send(master, &[28], until),
        "external_interrupt" => process::kill_process(
            process::Pid::from_raw(guard.child.as_ref().unwrap().id() as i32).unwrap(),
            process::Signal::INT,
        )
        .unwrap(),
        "terminate" => process::kill_process(
            process::Pid::from_raw(guard.child.as_ref().unwrap().id() as i32).unwrap(),
            process::Signal::TERM,
        )
        .unwrap(),
        "hangup" => {
            guard.master.take();
        }
        "cancel" | "timeout" | "pressure" | "background" | "unpolled" | "prompt_oversize"
        | "concurrent" => {}
        _ => panic!("unknown test case"),
    }
    wait_marker(&mut output, &mut protocol, "TTY_RESULT", until);
    if case != "hangup" {
        assert_eq!(
            format!("{:?}", termios::tcgetattr(&slave).unwrap()),
            original,
            "{case}: termios changed"
        );
        let master = guard.master.as_ref().unwrap();
        let printed = drain(master);
        if case == "pressure" {
            assert!(!printed.is_empty());
            let text = String::from_utf8_lossy(&protocol);
            let filled: usize = text
                .split("TTY_FILLED ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap();
            assert!(printed.len() >= filled);
            assert!(printed[..filled].iter().all(|b| *b == b'x'));
            assert!(PROMPT.as_bytes().starts_with(&printed[filled..]));
            assert!(
                printed.len() < filled + PROMPT.len(),
                "pressure fixture allowed the full prompt to be written"
            );
            eprintln!(
                "terminal_pty pressure filled_bytes={filled} prompt_bytes_before_cancel={}",
                printed.len() - filled
            );
        } else {
            assert!(
                printed.is_empty(),
                "{case}: secret or unexpected output echoed"
            );
        }
        // A no-data read cannot prove an incomplete canonical line was cleared.
        send(master, b"\n", until);
        let mut bytes = [0; 64];
        let count = loop {
            match rio::read(&slave, &mut bytes) {
                Ok(size) => break size,
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(error) => panic!("restored tty read: {error}"),
            }
            assert!(Instant::now() < until);
            pause();
        };
        assert_eq!(&bytes[..count], b"\n", "{case}: partial answer remained");
        let mut echoed = Vec::new();
        while echoed.is_empty() {
            echoed = drain(master);
            assert!(Instant::now() < until);
            pause();
        }
        assert!(matches!(echoed.as_slice(), b"\n" | b"\r\n"));
    }
    input.write_all(b"+").unwrap();
    drop(input);
    finish_child(&mut guard, until);
    eprintln!(
        "terminal_pty case={case} pid={child_pid} elapsed_ms={} joined=true passed",
        started.elapsed().as_millis()
    );
}

fn cases(names: &[&str]) {
    let _serial = SERIAL.lock().unwrap();
    let baseline = descriptors();
    for case in names {
        run_case(case);
        assert_eq!(
            descriptors(),
            baseline,
            "owned terminal descriptors leaked after {case}"
        );
        eprintln!("terminal_pty case={case} fd_before={baseline} fd_after={baseline}");
    }
}

#[test]
fn hidden_input_editing_limits_and_controls() {
    cases(&[
        "ascii",
        "backspace",
        "utf8",
        "partial_utf8_backspace",
        "crlf",
        "limit",
        "oversize",
        "invalid_utf8",
        "unicode_control",
        "escape",
        "suspend",
        "quit",
        "eof",
    ]);
}
#[test]
fn cancellation_signals_and_hangup_restore_or_close() {
    cases(&[
        "cancel",
        "cancel_partial",
        "timeout",
        "typed_interrupt",
        "external_interrupt",
        "terminate",
        "hangup",
    ]);
}
#[test]
fn prompts_are_sanitized_bounded_and_backpressure_is_cancellable() {
    cases(&["prompt_control", "prompt_oversize", "pressure"]);
}
#[test]
fn terminal_ownership_and_read_admission() {
    cases(&["background", "unpolled", "concurrent"]);
    let _serial = SERIAL.lock().unwrap();
    let baseline = descriptors();
    let child = child_command("no_terminal")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = ChildGuard {
        child: Some(child),
        master: None,
    };
    finish_child(&mut guard, Instant::now() + WAIT);
    assert_eq!(descriptors(), baseline);
    eprintln!(
        "terminal_pty case=no_terminal fd_before={baseline} fd_after={baseline} joined=true passed"
    );
}
