//! Bounded, cancellable hidden input from the foreground controlling terminal.
//! Callers supply cancellation/deadlines and handle process signals. No input
//! threads, blocking pool tasks, stdin reads, or background drivers are created.
use std::io;
use zeroize::Zeroizing;

pub const MAX_SECRET_BYTES: usize = 8192;
pub const MAX_PROMPT_BYTES: usize = 4096;

pub const fn supported() -> bool {
    cfg!(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
}

#[cfg(any(
    test,
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(any(
    test,
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn unsafe_control(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(any(
    test,
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn prompt_text(prompt: &str) -> io::Result<String> {
    if prompt.len() > MAX_PROMPT_BYTES {
        return Err(invalid("terminal prompt exceeds limit"));
    }
    // Replacement never expands the byte length. Remote labels cannot emit
    // terminal escape sequences, bidi formatting, newlines, or control bytes.
    Ok(prompt
        .chars()
        .map(|c| if unsafe_control(c) { '?' } else { c })
        .collect())
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod platform {
    use super::*;
    use rustix::{
        fd::OwnedFd,
        fs::{self, FileType, Mode, OFlags},
        io::{self as rio, Errno, FdFlags},
        process::{self, Pid},
        termios::{
            self, InputModes, LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex, Termios,
        },
    };
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use zeroize::Zeroize;

    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    static READING: AtomicBool = AtomicBool::new(false);

    struct Admission;
    impl Admission {
        fn acquire() -> io::Result<Self> {
            READING
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "another terminal prompt is active",
                    )
                })?;
            Ok(Self)
        }
    }
    impl Drop for Admission {
        fn drop(&mut self) {
            READING.store(false, Ordering::Release);
        }
    }

    /// An owned nonblocking descriptor for this process's controlling terminal.
    /// Opening validates foreground ownership but does not change termios.
    /// This type deliberately does not implement Clone or Debug.
    pub struct Terminal {
        fd: OwnedFd,
        identity: (u64, u64, u64),
        session: Pid,
        group: Pid,
        poisoned: bool,
    }

    fn identity(fd: &OwnedFd) -> io::Result<(u64, u64, u64)> {
        let stat = fs::fstat(fd)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::CharacterDevice
            || !termios::isatty(fd)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controlling terminal identity is invalid",
            ));
        }
        // dev_t differs in signedness/width between supported platforms.
        #[allow(clippy::unnecessary_cast)]
        Ok((stat.st_dev as u64, stat.st_ino as u64, stat.st_rdev as u64))
    }

    impl Terminal {
        pub fn open() -> io::Result<Self> {
            let terminal = Self {
                fd: fs::open(
                    "/dev/tty",
                    OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
                    Mode::empty(),
                )?,
                identity: (0, 0, 0),
                session: process::getsid(None)?,
                group: process::getpgrp(),
                poisoned: false,
            };
            let mut terminal = terminal;
            terminal.identity = identity(&terminal.fd)?;
            terminal.check()?;
            Ok(terminal)
        }

        fn check(&self) -> io::Result<()> {
            if self.poisoned {
                return Err(io::Error::other("terminal restoration previously failed"));
            }
            if identity(&self.fd)? != self.identity
                || process::getsid(None)? != self.session
                || process::getpgrp() != self.group
                || termios::tcgetsid(&self.fd)? != self.session
                || termios::tcgetpgrp(&self.fd)? != self.group
                || !fs::fcntl_getfl(&self.fd)?.contains(OFlags::NONBLOCK)
                || !rio::fcntl_getfd(&self.fd)?.contains(FdFlags::CLOEXEC)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "terminal is not owned by the foreground process group",
                ));
            }
            Ok(())
        }

        /// Display a bounded sanitized prompt and read one secret. Cancellation
        /// is implemented by dropping this future; the terminal mode guard is
        /// then restored synchronously. Caller handles SIGINT/SIGTERM/deadlines.
        /// SIGKILL or a suspended process cannot execute a restoration guard.
        pub async fn read_secret(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
            let prompt = prompt_text(prompt)?;
            let admission = Admission::acquire()?;
            self.check()?;
            let original = termios::tcgetattr(&self.fd)?;
            let mut guard = ReadGuard {
                terminal: self,
                original,
                restored: false,
                _admission: admission,
            };
            guard.enter()?;
            let result = guard.read(&prompt).await;
            // A successful input must not hide a terminal restoration error.
            let restored = guard.restore();
            match (result, restored) {
                (Ok(secret), Ok(())) => Ok(secret),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
    }

    struct ReadGuard<'a> {
        terminal: &'a mut Terminal,
        original: Termios,
        restored: bool,
        _admission: Admission,
    }

    impl ReadGuard<'_> {
        fn enter(&mut self) -> io::Result<()> {
            let mut mode = self.original.clone();
            mode.local_modes.remove(
                LocalModes::ECHO
                    | LocalModes::ECHONL
                    | LocalModes::ICANON
                    | LocalModes::IEXTEN
                    | LocalModes::ISIG,
            );
            // Treat typed Ctrl-C as cancellation. Other control characters must
            // reach the parser instead of suspending or terminating the process
            // while echo is disabled. External signals remain caller-managed.
            mode.input_modes.remove(
                InputModes::ICRNL
                    | InputModes::INLCR
                    | InputModes::IGNCR
                    | InputModes::IXON
                    | InputModes::IXOFF
                    | InputModes::ISTRIP,
            );
            mode.special_codes[SpecialCodeIndex::VMIN] = 1;
            mode.special_codes[SpecialCodeIndex::VTIME] = 0;
            termios::tcflush(&self.terminal.fd, QueueSelector::IFlush)?;
            termios::tcsetattr(&self.terminal.fd, OptionalActions::Now, &mode)?;
            Ok(())
        }

        fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            self.restored = true;
            // Darwin sets PENDIN when canonical mode is restored. Flush on both
            // sides so a partial answer cannot become input to a later prompt.
            let before = termios::tcflush(&self.terminal.fd, QueueSelector::IFlush);
            let mode = termios::tcsetattr(&self.terminal.fd, OptionalActions::Now, &self.original);
            let after = termios::tcflush(&self.terminal.fd, QueueSelector::IFlush);
            let result = before.and(mode).and(after).map_err(io::Error::from);
            self.terminal.poisoned = result.is_err();
            result
        }

        async fn read(&self, prompt: &str) -> io::Result<Zeroizing<String>> {
            let mut remaining = prompt.as_bytes();
            while !remaining.is_empty() {
                self.terminal.check()?;
                match rio::write(&self.terminal.fd, &remaining[..remaining.len().min(256)]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "terminal prompt write stopped",
                        ))
                    }
                    Ok(size) => remaining = &remaining[size..],
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(error) => return Err(error.into()),
                }
                if !remaining.is_empty() {
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
            let mut secret = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES));
            let mut buffer = Zeroizing::new([0u8; 256]);
            let mut valid = 0;
            loop {
                self.terminal.check()?;
                match rio::read(&self.terminal.fd, &mut buffer[..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "terminal input ended",
                        ))
                    }
                    Ok(size) => {
                        for byte in &buffer[..size] {
                            match *byte {
                                b'\n' | b'\r' => {
                                    if valid != secret.len() {
                                        return Err(invalid("incomplete UTF-8 terminal input"));
                                    }
                                    return match String::from_utf8(std::mem::take(&mut *secret)) {
                                        Ok(value) => Ok(Zeroizing::new(value)),
                                        Err(error) => {
                                            let _discard = Zeroizing::new(error.into_bytes());
                                            Err(invalid("invalid UTF-8 terminal input"))
                                        }
                                    };
                                }
                                8 | 127 => {
                                    let start = if valid != secret.len() {
                                        valid
                                    } else {
                                        secret
                                            .iter()
                                            .rposition(|byte| byte & 0xc0 != 0x80)
                                            .unwrap_or(0)
                                    };
                                    secret[start..].zeroize();
                                    secret.truncate(start);
                                    valid = start;
                                }
                                3 => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Interrupted,
                                        "terminal input cancelled",
                                    ))
                                }
                                4 => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "terminal input ended",
                                    ))
                                }
                                0..=31 => {
                                    return Err(invalid("unsupported terminal input control"))
                                }
                                value => {
                                    if secret.len() == MAX_SECRET_BYTES {
                                        return Err(invalid("terminal input exceeds limit"));
                                    }
                                    secret.push(value);
                                    match std::str::from_utf8(&secret[valid..]) {
                                        Ok(text) => {
                                            if text.chars().any(unsafe_control) {
                                                return Err(invalid(
                                                    "unsupported terminal input control",
                                                ));
                                            }
                                            valid = secret.len();
                                        }
                                        Err(error) if error.error_len().is_none() => {}
                                        Err(_) => {
                                            return Err(invalid("invalid UTF-8 terminal input"))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(Errno::AGAIN | Errno::INTR) => {}
                    Err(error) => return Err(error.into()),
                }
                buffer.zeroize();
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }

    impl Drop for ReadGuard<'_> {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod platform {
    use super::*;
    pub struct Terminal {
        _private: (),
    }
    impl Terminal {
        pub fn open() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cancellable terminal input is unsupported on this platform",
            ))
        }
        pub async fn read_secret(&mut self, _prompt: &str) -> io::Result<Zeroizing<String>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cancellable terminal input is unsupported on this platform",
            ))
        }
    }
}

pub use platform::Terminal;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prompts_are_bounded_and_cannot_emit_terminal_controls() {
        assert_eq!(
            prompt_text("Token:\n\u{1b}[31m\u{202e}ok").unwrap(),
            "Token:??[31m?ok"
        );
        assert_eq!(
            prompt_text(&"a".repeat(MAX_PROMPT_BYTES)).unwrap().len(),
            MAX_PROMPT_BYTES
        );
        assert!(prompt_text(&"a".repeat(MAX_PROMPT_BYTES + 1)).is_err());
        assert_eq!(prompt_text("验证码: ").unwrap(), "验证码: ");
    }
}
