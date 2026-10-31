//! Where our log lines go: stderr, written so that it never blocks and never
//! fails (see `LogSink`), or the file given with `--log-file`.

use anyhow::{ensure, Context, Result};
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::filter::EnvFilter;

/// stderr for our log lines, which never blocks and never fails: a reader
/// that stalls (Ctrl+S, a pipe nobody reads) must not freeze every relay
/// with it, nor one that is gone (`2>&1 | head`, a hung-up terminal) turn
/// each log line into a panic. A line that cannot be written at once is
/// dropped. Pipes and terminals get a description of their own, opened
/// non-blocking (the program shares the one on fd 2: switching that would
/// change it for the program too); where that open is refused (someone
/// else's terminal, after `su`), fd 2 is written only while poll says it
/// takes more, a pipe's atomic 4 KiB at a time; sockets (the journal) are
/// sent to without waiting; anything else (a file) is written as it is.
#[derive(Clone, Copy)]
struct LogSink {
    fd: std::os::fd::RawFd,
    socket: bool,
    /// Blocking: poll before each write.
    gated: bool,
}

impl LogSink {
    fn stderr() -> LogSink {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat fills a local struct.
        let kind = if unsafe { libc::fstat(2, &mut st) } == 0 {
            st.st_mode & libc::S_IFMT
        } else {
            0
        };
        let sink = |fd, socket, gated| LogSink { fd, socket, gated };
        if kind == libc::S_IFSOCK {
            return sink(2, true, false);
        }
        if kind == libc::S_IFIFO || kind == libc::S_IFCHR {
            let flags = libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
            // SAFETY: plain open; the fd is ours for good (logging lasts as
            // long as the process).
            let fd = unsafe { libc::open(c"/proc/self/fd/2".as_ptr(), flags) };
            return if fd >= 0 {
                sink(fd, false, false)
            } else {
                sink(2, false, true)
            };
        }
        sink(2, false, false)
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut rest = buf;
        while !rest.is_empty() {
            let mut chunk = rest;
            if self.gated {
                let mut p = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: a local pollfd.
                if unsafe { libc::poll(&mut p, 1, 0) } != 1 || p.revents & libc::POLLOUT == 0 {
                    break; // full: the rest is dropped
                }
                chunk = &rest[..rest.len().min(libc::PIPE_BUF)];
            }
            // SAFETY: plain writes of our own buffer.
            let n = unsafe {
                if self.socket {
                    libc::send(
                        self.fd,
                        chunk.as_ptr().cast(),
                        chunk.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                } else {
                    libc::write(self.fd, chunk.as_ptr().cast(), chunk.len())
                }
            };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if n <= 0 {
                break; // full, or nobody reading: the rest is dropped
            }
            rest = &rest[n as usize..];
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn init_logging(filter: &str, file: Option<&Path>) -> Result<()> {
    let filter = EnvFilter::try_new(filter).with_context(|| format!("bad log filter {filter:?}"))?;
    // A write that fails is not reported on stderr in turn: that would panic
    // when stderr is what failed.
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .log_internal_errors(false);
    match file {
        // Only our own writer moves: stderr stays as it was, and std opens the
        // file close-on-exec, so the program inherits neither.
        Some(path) => {
            // Not through a link, and only into a file of our own: in /tmp,
            // someone else may have created it first, readable by them, or as
            // a FIFO nobody reads, which would block a plain open forever.
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .with_context(|| format!("open log file {}", path.display()))?;
            let meta = f.metadata()?;
            ensure!(
                meta.is_file() && meta.uid() == nix::unistd::geteuid().as_raw(),
                "log file {} is not a regular file of yours",
                path.display()
            );
            fmt.with_ansi(false).with_writer(Arc::new(f)).init();
        }
        None => {
            let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
            let sink = LogSink::stderr();
            fmt.with_ansi(color).with_writer(move || sink).init();
        }
    }
    Ok(())
}
