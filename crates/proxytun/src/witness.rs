//! Was a SIGINT / SIGQUIT / SIGTERM sent to our whole process group (or to
//! every process of a cgroup, as systemd does), so the program got it too, or
//! to proxytun alone, so it must be passed on? Both arrive as SI_USER.
//!
//! proxyhook watched the program receive it through ptrace. Without ptrace we
//! keep a witness: a tiny process in our process group that keeps the three
//! signals blocked, so one sent to the group stays pending there, and tells
//! us on its pipe (not through /proc, which `hidepid` may hide it from).
//!
//! It goes by the name `WITNESS_NAME`, in `ps` and to pkill / killall /
//! pidof alike: were it called proxytun, `pkill proxytun` would signal it
//! too, which would look like a group signal the program already has.
//!
//! The witness is double-forked so that it is not our child (we wait for all
//! our children before exiting) and quits when its pipe from us closes,
//! however we exit. Where it ends up our child after all (we are a pid
//! namespace's init, or were made a subreaper), `stop` closes the pipe once
//! the program is gone.

use anyhow::{bail, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;

/// The witness's name: anything but "proxytun".
pub const WITNESS_NAME: &str = "signal-witness";

pub struct Witness {
    /// (The tests signal it directly.)
    #[cfg_attr(not(test), allow(dead_code))]
    pid: libc::pid_t,
    /// Our ends of its pipes, `None` once stopped. To it: `q` = "what is
    /// pending?" (it answers with the mask, 8 bytes, on the other), `c` =
    /// "forget it"; EOF = quit.
    pipes: Mutex<Option<(OwnedFd, OwnedFd)>>,
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
                    let pipes = (OwnedFd::from_raw_fd(ctl[1]), OwnedFd::from_raw_fd(back[0]));
                    if n != std::mem::size_of_val(&pid) as isize {
                        bail!("starting the signal witness failed");
                    }
                    Ok(Witness {
                        pid,
                        pipes: Mutex::new(Some(pipes)),
                    })
                }
            }
        }
    }

    /// Is `sig` pending in the witness, i.e. was it sent to our group?
    pub fn saw(&self, sig: libc::c_int) -> bool {
        let pipes = self.pipes.lock().unwrap_or_else(|e| e.into_inner());
        let Some((to, from)) = pipes.as_ref() else {
            return false;
        };
        let mut mask = [0u8; 8];
        // SAFETY: plain syscalls on pipes we own and local buffers.
        let answered = unsafe {
            let mut p = libc::pollfd {
                fd: from.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            libc::write(to.as_raw_fd(), b"q".as_ptr().cast(), 1) == 1
                && libc::poll(&mut p, 1, 1000) == 1
                && libc::read(from.as_raw_fd(), mask.as_mut_ptr().cast(), 8) == 8
        };
        answered && u64::from_ne_bytes(mask) & bit(sig) != 0
    }

    /// Forget the pending signals, so the next one can be told apart.
    pub fn clear(&self) {
        if let Some((to, _)) = self.pipes.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            // SAFETY: plain write of one byte on a pipe we own.
            unsafe { libc::write(to.as_raw_fd(), b"c".as_ptr().cast(), 1) };
        }
    }

    /// Let the witness go (the program is gone): it quits.
    pub fn stop(&self) {
        self.pipes.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

/// Take the name `WITNESS_NAME`: as the command (`comm`, what pkill and
/// killall match) and as the command line (`pkill -f`, `ps`), overwriting
/// the arguments we were started with.
unsafe fn rename_self() {
    let name = WITNESS_NAME.as_bytes();
    let mut comm = [0u8; 16];
    comm[..name.len()].copy_from_slice(name);
    libc::prctl(libc::PR_SET_NAME, comm.as_ptr(), 0, 0, 0);
    // arg_start and arg_end, fields 48 and 49 of /proc/self/stat (Linux 3.5).
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return;
    };
    let Some(rest) = stat.rfind(')').and_then(|i| stat.get(i + 2..)) else {
        return;
    };
    let mut f = rest.split_whitespace().skip(45).map(|v| v.parse::<usize>().ok());
    let (Some(Some(start)), Some(Some(end))) = (f.next(), f.next()) else {
        return;
    };
    if start == 0 || end <= start {
        return;
    }
    // Our own (copied on fork) argument strings: overwritten in place.
    let args = std::slice::from_raw_parts_mut(start as *mut u8, end - start);
    args.fill(0);
    let n = name.len().min(args.len() - 1);
    args[..n].copy_from_slice(&name[..n]);
}

/// Bit `sig` of a signal mask as /proc shows it.
fn mask_of(set: &libc::sigset_t) -> u64 {
    (1..=64)
        .filter(|&s| unsafe { libc::sigismember(set, s) } == 1)
        .fold(0, |m, s| m | bit(s))
}

/// The witness itself: hold the signals blocked; answer `q` with what is
/// pending, drain on any other byte; on EOF (proxytun is gone, or done with
/// us), quit. Reports its pid on `back` once it is ready.
unsafe fn witness_loop(ctl: libc::c_int, back: libc::c_int, set: &libc::sigset_t) -> ! {
    rename_self();
    // Nothing but the pipes stays open: the program must not find stray fds
    // of ours in a process it can see.
    for fd in 0..1024 {
        if fd != ctl && fd != back {
            libc::close(fd);
        }
    }
    // Only the watched signals may reach it: a terminal hangup (SIGHUP to the
    // foreground group) or Ctrl+Z must neither kill nor stop the witness.
    for sig in 1..=libc::SIGRTMAX() {
        if libc::sigismember(set, sig) == 0 && sig != libc::SIGKILL && sig != libc::SIGSTOP {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
    let pid = libc::getpid();
    libc::write(back, &pid as *const _ as *const _, std::mem::size_of_val(&pid));
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut b = [0u8; 1];
    while libc::read(ctl, b.as_mut_ptr() as *mut _, 1) == 1 {
        if b[0] == b'q' {
            let mut pending: libc::sigset_t = std::mem::zeroed();
            libc::sigpending(&mut pending);
            let mask = mask_of(&pending).to_ne_bytes();
            libc::write(back, mask.as_ptr().cast(), 8);
        } else {
            while libc::sigtimedwait(set, std::ptr::null_mut(), &zero) > 0 {}
        }
    }
    libc::_exit(0)
}

/// The fields of /proc/<pid>/stat proxytun looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    pub ppid: libc::pid_t,
    pub pgrp: libc::pid_t,
    pub session: libc::pid_t,
}

pub fn proc_stat(pid: libc::pid_t) -> Option<ProcStat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// The process group of `pid`.
pub fn pgrp_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    proc_stat(pid).map(|s| s.pgrp)
}

/// "pid (comm) state ppid pgrp session ...": comm may hold spaces and
/// parentheses, so fields are counted from the last ')'.
fn parse_stat(stat: &str) -> Option<ProcStat> {
    let mut f = stat.get(stat.rfind(')')? + 2..)?.split_whitespace().skip(1);
    let mut next = || f.next()?.parse().ok();
    Some(ProcStat {
        ppid: next()?,
        pgrp: next()?,
        session: next()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for s in [
            libc::SIGHUP,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGUSR1,
            libc::SIGPIPE,
            libc::SIGRTMAX(),
        ] {
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

        // Not called proxytun (this test binary's name starts so), for pkill
        // and friends, nor in what ps shows.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
        assert_eq!(comm, format!("{WITNESS_NAME}\n"));
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
        let cmdline = String::from_utf8_lossy(&cmdline);
        assert!(cmdline.starts_with(WITNESS_NAME), "{cmdline:?}");
        assert!(!cmdline.contains("proxytun"), "{cmdline:?}");

        // Told to stop (the program is gone), it quits; asked after, nothing.
        w.stop();
        while std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.contains(") Z")) {
            assert!(std::time::Instant::now() < deadline, "the witness did not stop");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!w.saw(libc::SIGTERM));
    }

    #[test]
    fn pgrp_is_read_past_a_command_name_with_spaces_and_parens() {
        assert_eq!(
            parse_stat("4242 (my (odd) prog) S 1 777 778 0 -1 4194560"),
            Some(ProcStat {
                ppid: 1,
                pgrp: 777,
                session: 778
            })
        );
        assert_eq!(parse_stat("garbage"), None);
        let me = std::process::id() as libc::pid_t;
        assert_eq!(pgrp_of(me), Some(unsafe { libc::getpgrp() }));
    }
}
