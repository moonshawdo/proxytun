//! How proxytun ends, and the signals that would end it. SIGINT, SIGQUIT and
//! SIGTERM are blocked before any thread exists and read from a signalfd:
//! whether to pass one on to the program depends on who sent it, and on what
//! the witness got (see witness.rs). proxytun itself ends once the program's
//! whole tree is gone, the way the program did. SIGHUP and SIGUSR1 are
//! app.rs's.

use crate::procfs;
use crate::witness::Witness;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

/// How proxytun ends: as the program did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    /// Killed by this signal.
    Signal(libc::c_int),
}

/// End the process as `exit` says. Killed by a signal, the program has us
/// end by the same one, as timeout(1) and sudo do: a shell sees WIFSIGNALED
/// (bash stops a loop on Ctrl+C only then), and a service stopped with
/// SIGTERM counts as stopped, not failed. Without a core dump of ours.
pub fn finish(exit: Exit) -> ! {
    let sig = match exit {
        Exit::Code(c) => std::process::exit(c),
        Exit::Signal(sig) => sig,
    };
    // SAFETY: plain syscalls on our own process.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        libc::signal(sig, libc::SIG_DFL);
        let set = crate::sys::sigset(&[sig]);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
    }
    // A signal whose default is not to end a process (SIGCHLD, SIGWINCH).
    std::process::exit(128 + sig)
}

/// Wait until every process of the program's tree is gone (we are their
/// subreaper) and return how the program itself ended. Once it has, the
/// witness is let go: should it be our child too (we are a pid namespace's
/// init, or were made a subreaper), it is part of what we wait for.
pub fn wait_tree(main: libc::pid_t, main_pid: &AtomicI32, witness: Option<&Witness>) -> Exit {
    let (mut main, mut exit) = (Some(main), Exit::Code(1));
    loop {
        let mut status = 0;
        // SAFETY: plain syscall.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return exit; // ECHILD: nobody left
        }
        // Once only: its pid may be reused by a later child of the tree.
        if main == Some(pid) {
            main = None;
            exit = if libc::WIFEXITED(status) {
                Exit::Code(libc::WEXITSTATUS(status))
            } else {
                Exit::Signal(libc::WTERMSIG(status))
            };
            main_pid.store(0, Ordering::SeqCst);
            tracing::info!(?exit, "program exited");
            if let Some(w) = witness {
                w.stop();
            }
        }
    }
}

/// Which of `sigs` are ignored right now. A caller that ignores a signal
/// (`cmd &` in a script ignores SIGINT/SIGQUIT, nohup ignores SIGHUP) means the
/// program should start with it ignored too, as it would if run directly.
pub fn ignored_signals(sigs: &[libc::c_int]) -> Vec<libc::c_int> {
    sigs.iter()
        .copied()
        .filter(|&s| unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(s, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
        })
        .collect()
}

/// SIGINT, SIGQUIT and SIGTERM are read from a signalfd rather than through a
/// tokio handler: whether to forward one depends on who sent it (`ssi_code`),
/// which tokio does not report. They are blocked here, before any thread
/// exists, so every thread inherits the mask (netns.rs unblocks them again for
/// the program). Signals the caller ignores are left ignored and not handled.
pub fn exit_signal_fd(sigs: &[libc::c_int]) -> Option<OwnedFd> {
    if sigs.is_empty() {
        return None;
    }
    unsafe {
        let set = crate::sys::sigset(sigs);
        let fd = libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            tracing::warn!("signalfd: {}", std::io::Error::last_os_error());
            return None;
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        Some(OwnedFd::from_raw_fd(fd))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ExitSignal {
    /// End now, by the signal received. The program's tree keeps running,
    /// cut off from the network (the TUN device goes with us).
    Exit,
    /// From the terminal, to our whole foreground group: pass it on only if
    /// the program is not in that group (see `forward_to`).
    Terminal,
    /// From a process: pass it on unless it got it too.
    Forward,
}

/// SIGINT / SIGQUIT / SIGTERM never stop proxytun while the main program runs:
/// the program decides, and proxytun exits when its tree is gone. `code` is
/// the sender's si_code; `terms` counts SIGTERMs so far.
fn on_exit_signal(sig: libc::c_int, code: i32, program_running: bool, terms: u32) -> ExitSignal {
    // Nobody left to decide (e.g. only a background child keeps us waiting),
    // or a second SIGTERM: whoever sent it wants us gone.
    if !program_running || (sig == libc::SIGTERM && terms >= 2) {
        return ExitSignal::Exit;
    }
    // Sent by the kernel: the terminal's Ctrl+C / Ctrl+\ signals the whole
    // foreground group, the program included if it is still in it.
    if code == libc::SI_KERNEL {
        return ExitSignal::Terminal;
    }
    // From a process: `kill <proxytun>`, or `kill -- -<group>` / `kill %1` /
    // systemd, which look the same from here.
    ExitSignal::Forward
}

/// Where to pass on a signal we got, if anywhere (a pid, or minus a process
/// group). Sent to our whole group (`to_group`: by the terminal, or the
/// witness has it), the program has it too if it is still in that group.
/// From the terminal (`terminal`: Ctrl+C) while the program leads a group of
/// its own (sudo's `use_pty` gave it a session of its own), that whole group
/// gets it, as the terminal would have done: a pipeline or a child is no
/// less interrupted there. A group signal from a process may have reached
/// every process already (systemd signals each one of a service): the
/// program alone gets the copy we pass on. Sent to proxytun alone: the
/// program.
fn forward_to(
    to_group: bool,
    terminal: bool,
    program: libc::pid_t,
    program_pgrp: Option<libc::pid_t>,
    our_pgrp: libc::pid_t,
) -> Option<libc::pid_t> {
    match program_pgrp {
        Some(p) if to_group && p == our_pgrp => None,
        Some(p) if terminal && p == program => Some(-p),
        _ => Some(program),
    }
}

/// How long to wait before asking the witness: a group-wide signal is
/// delivered to the members one after another, and we may run first.
const WITNESS_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

pub fn spawn_exit_signal_task(fd: OwnedFd, main_pid: Arc<AtomicI32>, witness: Option<Arc<Witness>>) {
    tokio::spawn(async move {
        // SAFETY: an OwnedFd stays open and is the same fd for as long as the
        // AsyncFd owns it.
        let afd = match unsafe { tokio::io::unix::AsyncFd::register(fd) } {
            Ok(a) => a,
            Err(e) => return tracing::warn!("cannot watch the signalfd: {e}"),
        };
        let mut terms = 0;
        loop {
            let Ok(mut ready) = afd.readable().await else { return };
            // SAFETY: a plain C struct of integers, filled by read().
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::signalfd_siginfo>();
            let n = unsafe { libc::read(afd.as_raw_fd(), &mut info as *mut _ as *mut libc::c_void, size) };
            if n != size as isize {
                ready.clear_ready(); // EAGAIN: drained
                continue;
            }
            let sig = info.ssi_signo as libc::c_int;
            if sig == libc::SIGTERM {
                terms += 1;
            }
            let pid = main_pid.load(Ordering::SeqCst);
            let action = on_exit_signal(sig, info.ssi_code, pid > 0, terms);
            if action == ExitSignal::Exit {
                tracing::info!(sig, "exiting on a signal");
                finish(Exit::Signal(sig))
            }
            let (witness, main_pid) = (witness.clone(), main_pid.clone());
            tokio::spawn(async move {
                tokio::time::sleep(WITNESS_DELAY).await;
                // Reaped meanwhile: the pid may already be someone else's.
                if main_pid.load(Ordering::SeqCst) != pid {
                    return;
                }
                let terminal = action == ExitSignal::Terminal;
                // Asking the witness blocks (a second at most): not on a
                // runtime worker.
                let saw = match (&witness, terminal) {
                    (Some(w), false) => {
                        let w = w.clone();
                        tokio::task::spawn_blocking(move || w.saw(sig)).await.unwrap_or(false)
                    }
                    _ => false,
                };
                // SAFETY: plain syscall.
                let ours = unsafe { libc::getpgrp() };
                if let Some(to) = forward_to(terminal || saw, terminal, pid, procfs::pgrp_of(pid), ours) {
                    tracing::debug!(sig, to, "forwarding the signal to the program");
                    unsafe { libc::kill(to, sig) };
                }
                if let Some(w) = witness {
                    w.clear();
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const SI_USER: i32 = 0;

    #[test]
    fn exit_signals_are_left_to_the_running_program() {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            // Ctrl+C / Ctrl+\ on the terminal: the program got it too.
            assert_eq!(on_exit_signal(sig, libc::SI_KERNEL, true, 1), ExitSignal::Terminal);
            // kill(2) from some process: maybe only we got it.
            assert_eq!(on_exit_signal(sig, SI_USER, true, 1), ExitSignal::Forward);
            // Main program gone (a background child keeps us waiting): exit,
            // or Ctrl+C would do nothing at all.
            assert_eq!(on_exit_signal(sig, SI_USER, false, 1), ExitSignal::Exit);
            assert_eq!(on_exit_signal(sig, libc::SI_KERNEL, false, 1), ExitSignal::Exit);
        }
        assert_eq!(
            on_exit_signal(libc::SIGTERM, SI_USER, true, 2),
            ExitSignal::Exit,
            "second SIGTERM"
        );
        assert_eq!(
            on_exit_signal(libc::SIGINT, SI_USER, true, 2),
            ExitSignal::Forward,
            "only SIGTERM counts"
        );
    }

    #[test]
    fn a_signal_is_only_held_back_when_the_program_shares_our_group() {
        // Program 50; our group 7. (to_group, terminal, ...)
        // Sent to the group, and the program is in it: it has its own copy.
        assert_eq!(forward_to(true, false, 50, Some(7), 7), None);
        assert_eq!(forward_to(true, true, 50, Some(7), 7), None);
        // Sent to proxytun alone.
        assert_eq!(forward_to(false, false, 50, Some(7), 7), Some(50));
        // Ctrl+C, the program leading a group of its own (sudo's use_pty):
        // that whole group gets it, its pipeline too.
        assert_eq!(forward_to(true, true, 50, Some(50), 7), Some(-50));
        // A group signal from a process (systemd's, one to each process):
        // the others may have theirs already; the program alone.
        assert_eq!(forward_to(true, false, 50, Some(50), 7), Some(50));
        // Moved into someone else's group: the program alone.
        assert_eq!(forward_to(true, true, 50, Some(9), 7), Some(50));
        // Program already gone: nothing to hold back for.
        assert_eq!(forward_to(true, false, 50, None, 7), Some(50));
        // Sent to proxytun alone, the program leading its own group: only it.
        assert_eq!(forward_to(false, false, 50, Some(50), 7), Some(50));
    }
}
