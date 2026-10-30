//! Was a SIGINT / SIGQUIT / SIGTERM sent to our whole process group (or to
//! every process of a cgroup, as systemd does), so the program got it too, or
//! to proxytun alone, so it must be passed on? Both arrive as SI_USER.
//!
//! proxyhook watched the program receive it through ptrace. Without ptrace we
//! keep a witness: a tiny process in our process group that keeps the three
//! signals blocked, so one sent to the group stays pending there for us to
//! read in /proc/<witness>/status.
//!
//! The witness is double-forked so that it is not our child (we wait for all
//! our children before exiting) and quits when its pipe from us closes,
//! however we exit.

use anyhow::{bail, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct Witness {
    pid: libc::pid_t,
    /// Our end of its pipe: a byte = "forget what is pending"; EOF = quit.
    ctl: OwnedFd,
}

/// Bit for `sig` in a /proc status signal mask.
fn bit(sig: libc::c_int) -> u64 {
    1 << (sig - 1)
}

impl Witness {
    /// Start the witness. Must be called while we are single-threaded, with
    /// `sigs` already blocked (the witness inherits the mask), and before we
    /// become a subreaper.
    pub fn start(sigs: &[libc::c_int]) -> Result<Witness> {
        let mut ctl = [0; 2];
        let mut back = [0; 2];
        // SAFETY: plain syscalls; the children only use async-signal-safe
        // calls on data prepared here.
        unsafe {
            if libc::pipe2(ctl.as_mut_ptr(), libc::O_CLOEXEC) != 0
                || libc::pipe2(back.as_mut_ptr(), libc::O_CLOEXEC) != 0
            {
                bail!("pipe2: {}", std::io::Error::last_os_error());
            }
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for &s in sigs {
                libc::sigaddset(&mut set, s);
            }
            match libc::fork() {
                -1 => bail!("fork: {}", std::io::Error::last_os_error()),
                0 => {
                    libc::close(ctl[1]);
                    libc::close(back[0]);
                    match libc::fork() {
                        0 => witness_loop(ctl[0], back[1], &set),
                        _ => libc::_exit(0),
                    }
                }
                child => {
                    libc::close(ctl[0]);
                    libc::close(back[1]);
                    let mut status = 0;
                    libc::waitpid(child, &mut status, 0);
                    // Blocks until the witness is ready (or EOF if it died).
                    let mut pid: libc::pid_t = 0;
                    let n = libc::read(back[0], &mut pid as *mut _ as *mut _, std::mem::size_of_val(&pid));
                    libc::close(back[0]);
                    let ctl = OwnedFd::from_raw_fd(ctl[1]);
                    if n != std::mem::size_of_val(&pid) as isize {
                        bail!("starting the signal witness failed");
                    }
                    Ok(Witness { pid, ctl })
                }
            }
        }
    }

    /// Is `sig` pending in the witness, i.e. was it sent to our group?
    pub fn saw(&self, sig: libc::c_int) -> bool {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", self.pid)) else {
            return false;
        };
        pending(&status) & bit(sig) != 0
    }

    /// Forget the pending signals, so the next one can be told apart.
    pub fn clear(&self) {
        // SAFETY: plain write of one byte on a pipe we own.
        unsafe { libc::write(self.ctl.as_raw_fd(), b"c".as_ptr() as *const _, 1) };
    }
}

/// Signals pending for the process or one of its threads, from /proc status.
fn pending(status: &str) -> u64 {
    status
        .lines()
        .filter_map(|l| l.strip_prefix("ShdPnd:").or_else(|| l.strip_prefix("SigPnd:")))
        .filter_map(|v| u64::from_str_radix(v.trim(), 16).ok())
        .fold(0, |a, b| a | b)
}

/// The witness itself: hold the signals blocked; on a byte, drain them; on
/// EOF (proxytun is gone), quit. Reports its pid on `back` once it is ready.
unsafe fn witness_loop(ctl: libc::c_int, back: libc::c_int, set: &libc::sigset_t) -> ! {
    // Nothing but the pipes stays open: the program must not find stray fds
    // of ours in a process it can see.
    for fd in 0..1024 {
        if fd != ctl && fd != back {
            libc::close(fd);
        }
    }
    // Only the watched signals may reach it: a terminal hangup (SIGHUP to the
    // foreground group) or Ctrl+Z must neither kill nor stop the witness.
    for sig in 1..libc::SIGRTMAX() {
        if libc::sigismember(set, sig) == 0 && sig != libc::SIGKILL && sig != libc::SIGSTOP {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
    let pid = libc::getpid();
    libc::write(back, &pid as *const _ as *const _, std::mem::size_of_val(&pid));
    libc::close(back);
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut b = [0u8; 1];
    while libc::read(ctl, b.as_mut_ptr() as *mut _, 1) == 1 {
        while libc::sigtimedwait(set, std::ptr::null_mut(), &zero) > 0 {}
    }
    libc::_exit(0)
}

/// The process group of `pid`, from /proc/<pid>/stat.
pub fn pgrp_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    parse_pgrp(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// "pid (comm) state ppid pgrp ...": comm may hold spaces and parentheses.
fn parse_pgrp(stat: &str) -> Option<libc::pid_t> {
    let rest = stat.get(stat.rfind(')')? + 2..)?;
    rest.split_whitespace().nth(2)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_masks_combine_process_and_thread_signals() {
        let status = "Name:\tsleep\nSigPnd:\t0000000000000002\nShdPnd:\t0000000000004000\nSigBlk:\t0000000000004006\n";
        assert_eq!(pending(status), bit(libc::SIGINT) | bit(libc::SIGTERM));
        assert_eq!(pending("Name:\tx\n"), 0);
    }

    fn status(pid: libc::pid_t, field: &str) -> u64 {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        s.lines()
            .find_map(|l| l.strip_prefix(field))
            .map_or(0, |v| u64::from_str_radix(v.trim(), 16).unwrap())
    }

    #[test]
    fn the_witness_holds_group_signals_ignores_the_rest_and_quits_with_us() {
        let watched = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];
        // As in proxytun: the watched signals are blocked before the start.
        let w = unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in watched {
                libc::sigaddset(&mut set, s);
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            let w = Witness::start(&watched);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            w.unwrap()
        };
        let pid = w.pid;
        let all = watched.iter().fold(0, |m, &s| m | bit(s));
        assert_eq!(status(pid, "SigBlk:") & all, all, "watched signals stay pending");
        for s in [libc::SIGHUP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGUSR1, libc::SIGPIPE] {
            assert_ne!(status(pid, "SigIgn:") & bit(s), 0, "signal {s} would kill or stop it");
        }
        assert_eq!(
            status(pid, "SigIgn:") & all,
            0,
            "an ignored signal would not stay pending"
        );

        assert!(!w.saw(libc::SIGTERM));
        unsafe { libc::kill(pid, libc::SIGTERM) };
        assert!(w.saw(libc::SIGTERM));
        assert!(!w.saw(libc::SIGINT));
        w.clear();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while w.saw(libc::SIGTERM) {
            assert!(std::time::Instant::now() < deadline, "clear() did not drain it");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        drop(w);
        while std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.contains(") Z")) {
            assert!(std::time::Instant::now() < deadline, "the witness outlived its pipe");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn pgrp_is_read_past_a_command_name_with_spaces_and_parens() {
        assert_eq!(parse_pgrp("4242 (my (odd) prog) S 1 777 777 0 -1 4194560"), Some(777));
        assert_eq!(parse_pgrp("garbage"), None);
        let me = std::process::id() as libc::pid_t;
        assert_eq!(pgrp_of(me), Some(unsafe { libc::getpgrp() }));
    }
}
