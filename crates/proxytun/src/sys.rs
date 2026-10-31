//! Thin wrappers over libc calls that modules otherwise unrelated to each
//! other make alike (the sudo helper, the signal witness, app).

use anyhow::{bail, Result};
use std::os::fd::{FromRawFd, OwnedFd};

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
