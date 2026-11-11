//! Thin wrappers over libc calls that modules otherwise unrelated to each
//! other make alike (the sudo helper, the signal witness, signal handling,
//! the setup process, the control channel).

use anyhow::{bail, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// A close-on-exec pipe: (read end, write end).
pub fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut p = [0; 2];
    // SAFETY: pipe2 fills both fds, owned right away.
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) })
}

/// The signal set holding `sigs`.
pub fn sigset(sigs: &[libc::c_int]) -> libc::sigset_t {
    // SAFETY: sigemptyset initialises the set, sigaddset adds to it.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in sigs {
            libc::sigaddset(&mut set, s);
        }
        set
    }
}

/// Wait at most `within` for something to read on `fd` (or its end): false
/// if nothing came, so that a peer gone quiet cannot hold us.
pub fn readable_within(fd: &impl AsRawFd, within: Duration) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = within.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    // 1: ready (data, or POLLHUP at its end); 0, a timeout, and -1, an error
    // (EINTR included), both count as nothing.
    // SAFETY: plain syscall on a local pollfd.
    unsafe { libc::poll(&mut p, 1, ms) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quiet_fd_is_given_up_on_and_data_or_its_end_is_not() {
        let (r, w) = pipe().unwrap();
        let start = std::time::Instant::now();
        assert!(!readable_within(&r, Duration::from_millis(100)), "nothing written");
        assert!(start.elapsed() >= Duration::from_millis(100), "it waited");
        // SAFETY: plain write of one byte to our own pipe.
        assert_eq!(unsafe { libc::write(w.as_raw_fd(), b"x".as_ptr().cast(), 1) }, 1);
        assert!(readable_within(&r, Duration::from_secs(5)), "a byte");
        let (r, w) = pipe().unwrap();
        drop(w);
        assert!(readable_within(&r, Duration::from_secs(5)), "the writer gone: EOF");
    }
}
