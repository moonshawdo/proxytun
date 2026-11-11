//! sudo mode, the root helper: checks who called it and in what context,
//! builds the empty namespaces, forks the program side, rechecks the
//! request it passes on, fills the namespaces and hands them back.

use super::program::become_program;
use super::{seqpacket, set_timeouts, Identity, Request, HELPER_ARG, MAX_INHERIT, REQUEST_MAX};
use crate::ctl::{send_error, send_ok, SetupError};
use crate::netns;
use anyhow::{anyhow, bail, ensure, Context, Result};
use nix::sys::socket::{connect, getsockopt, sockopt, SockFlag, UnixAddr};
use std::ffi::OsString;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// The program's identity: the user sudo was run by, who must also own the
/// socket we were called on (`peer_uid`, `peer_gid`: SO_PEERCRED), with the
/// supplementary groups of that process (`peer_status`: its /proc status).
fn identity(sudo_uid: u32, peer_uid: u32, peer_gid: u32, peer_status: &str) -> Result<Identity> {
    ensure!(
        peer_uid == sudo_uid,
        "the socket belongs to uid {peer_uid}, but sudo was run by uid {sudo_uid}"
    );
    ensure!(sudo_uid != 0, "refusing to set up for root through sudo");
    let field = |name: &str| {
        peer_status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::split_whitespace)
    };
    // Uid: lists the real, effective, saved and filesystem uid. The real one
    // must still be the socket owner's, or the pid now names another process
    // (or none: an empty status).
    let real_uid = field("Uid:").and_then(|mut f| f.next()?.parse::<u32>().ok());
    ensure!(real_uid == Some(peer_uid), "the process behind the socket is gone");
    let groups = field("Groups:")
        .ok_or_else(|| anyhow!("no Groups line for the process behind the socket"))?
        .map(|g| g.parse().context("bad group id"))
        .collect::<Result<_>>()?;
    Ok(Identity {
        uid: peer_uid,
        gid: peer_gid,
        groups,
    })
}

/// No fd number reaches this (the kernel's default fs.nr_open).
const FD_CEILING: RawFd = 1 << 20;

/// How long the helper waits for its client.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// The request, checked again by the helper: the client may not be proxytun.
fn validate(req: &Request, caller_pgrp: libc::pid_t) -> Result<()> {
    // The bounds the config file puts on fake_ip_range (its last /24 holds
    // proxytun's own addresses); the helper reads no config, so it checks here.
    let p = req.fake_range.prefix_len();
    ensure!((8..=22).contains(&p), "fake-ip range {} out of bounds", req.fake_range);
    // Root binds these inside the namespace, low ports included. At most as
    // many as fit in the handover message with the TUN device and the capture
    // listener (`hostports::MAX_FORWARDS`).
    ensure!(
        req.forwards.len() <= crate::hostports::MAX_FORWARDS,
        "too many host ports ({})",
        req.forwards.len()
    );
    // Only what proxytun's own scan produces (hostports.rs): loopback
    // addresses with a real port, never 53 (DNS must reach the fake-ip DNS),
    // each once.
    let mut seen = std::collections::HashSet::new();
    for a in &req.forwards {
        ensure!(
            a.ip().is_loopback() && a.port() != 0 && a.port() != 53 && seen.insert(a),
            "host port {a} not allowed"
        );
    }
    // The program is put into this group (`setpgid` in `helper`): the
    // caller's own, never another job's, whose signals it would then share.
    ensure!(
        req.pgrp > 0 && req.pgrp == caller_pgrp,
        "process group {} is not the caller's",
        req.pgrp
    );
    ensure!(req.umask <= 0o777, "umask {:o} out of bounds", req.umask);
    ensure!(
        req.inherit.len() <= MAX_INHERIT,
        "too many inherited fds ({})",
        req.inherit.len()
    );
    // The program side dup2s each back to its number (`restore_inherited`):
    // never onto stdio, never two onto one number, never past any fd limit.
    let mut seen = std::collections::HashSet::new();
    for &n in &req.inherit {
        ensure!(
            (3..FD_CEILING).contains(&n) && seen.insert(n),
            "inherited fd {n} not allowed"
        );
    }
    Ok(())
}

/// The resource limits of `pid`: all 16 Linux has had since 2.6.25. The
/// program takes them (see `adopt_limits`).
fn limits_of(pid: libc::pid_t) -> Result<Vec<libc::rlimit>> {
    (0..16)
        .map(|r| {
            let mut l = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: reads into a local struct; as root we may read anyone's.
            if unsafe { libc::prlimit(pid, r as _, std::ptr::null(), &mut l) } != 0 {
                bail!("read the resource limits of {pid}: {}", std::io::Error::last_os_error());
            }
            Ok(l)
        })
        .collect()
}

/// Is `target` among the first `hops` ancestors, starting from `parent`?
fn ancestor_within(
    parent: libc::pid_t,
    target: libc::pid_t,
    hops: usize,
    ppid_of: impl Fn(libc::pid_t) -> Option<libc::pid_t>,
) -> bool {
    let mut p = parent;
    for _ in 0..hops {
        if p == target {
            return true;
        }
        // Up one level. A ppid of 0 (above init) or a process gone (no stat
        // to read) ends the walk.
        match ppid_of(p) {
            Some(next) if next > 0 => p = next,
            _ => return false,
        }
    }
    false
}

/// Run `f` as the caller: effective uid and gid `uid`/`gid`, no
/// supplementary groups, no capabilities. What the caller cannot reach, root
/// does not reach for them, and a socket connected meanwhile carries their
/// credentials, not root's, to whatever listens there. The saved uid stays 0
/// to come back.
fn as_caller<T>(uid: libc::uid_t, gid: libc::gid_t, f: impl FnOnce() -> T) -> Result<T> {
    const KEEP: u32 = u32::MAX; // -1: leave this id as it is

    // Groups and gid first: once the effective uid is not 0, the effective
    // capabilities are gone and neither could be set to the caller's.
    // SAFETY: plain syscalls on our own credentials.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(KEEP, gid, KEEP) != 0
            || libc::setresuid(KEEP, uid, KEEP) != 0
        {
            bail!("taking the caller's identity: {}", std::io::Error::last_os_error());
        }
        ensure!(
            libc::geteuid() == uid && libc::getegid() == gid,
            "could not take the caller's identity"
        );
        let r = f();
        // Back in the other order: the uid (allowed, the real and saved uid
        // being 0), which restores root's capabilities, then the gid.
        if libc::setresuid(KEEP, 0, KEEP) != 0 || libc::setresgid(KEEP, 0, KEEP) != 0 {
            bail!("back to root: {}", std::io::Error::last_os_error());
        }
        Ok(r)
    }
}

/// Entry point of the root helper (`proxytun HELPER_ARG <socket>`). Never
/// returns.
pub fn helper_main(args: &[OsString]) -> ! {
    let code = match helper(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("proxytun (sudo helper): {e:#}");
            1
        }
    };
    std::process::exit(code)
}

/// Tell the client why, then fail.
fn refuse<T>(ctl: &OwnedFd, e: anyhow::Error) -> Result<T> {
    send_error(
        ctl,
        &SetupError {
            userns: false,
            err: anyhow!("sudo helper: {e:#}"),
        },
    );
    Err(e)
}

fn helper(args: &[OsString]) -> Result<()> {
    // Exactly `proxytun HELPER_ARG <socket>`: a sudoers rule ending in `*`
    // would let more through.
    let [_, mode, path] = args else {
        bail!("{HELPER_ARG} is internal to proxytun");
    };
    ensure!(mode == HELPER_ARG, "{HELPER_ARG} is internal to proxytun");
    // sudo makes both the real and the effective uid 0. A setuid copy would
    // leave the real uid the caller's, and SUDO_UID would be theirs to set.
    ensure!(
        nix::unistd::getuid().is_root() && nix::unistd::geteuid().is_root(),
        "the helper must be started by sudo"
    );
    let id = |v: &str| -> Result<u32> {
        std::env::var(v)
            .with_context(|| format!("{v} is not set: run proxytun as yourself, it calls sudo itself"))?
            .parse()
            .with_context(|| format!("{v} is not a number"))
    };
    // sudo sets these to the ids of the user who ran it. They serve to reach
    // the socket as that user and to check its owner; the program's own ids
    // come from the socket (`identity`).
    let (sudo_uid, sudo_gid) = (id("SUDO_UID")?, id("SUDO_GID")?);

    // Never closed by us, only by the kernel when we exit: the client may
    // queue fds on it, and the last close releases them, where a socket with
    // SO_LINGER would keep root waiting. At exit lingering does not apply.
    let ctl = ManuallyDrop::new(seqpacket(SockFlag::empty())?);
    // Bounds our connect and sends on it, and the program side's read of the
    // request (same socket after the fork): a silent client cannot hold root.
    set_timeouts(&ctl, HELPER_TIMEOUT)?;
    let addr = UnixAddr::new(path.as_os_str())?;
    // The path is the caller's choice: followed with their rights, not root's.
    as_caller(sudo_uid, sudo_gid, || connect(ctl.as_raw_fd(), &addr))?.context("connect to proxytun")?;
    // For a connected socket, the pid, uid and gid of the process listening at
    // the other end, as the kernel recorded them at its listen().
    let cred = getsockopt(&*ctl, sockopt::PeerCredentials).context("SO_PEERCRED")?;
    // The socket's creator must be the process that ran sudo: one of our
    // ancestors (sudo, sudo's pty monitor in between), alive, so its pid has
    // not been reused and its /proc entries are its own.
    // SAFETY: plain syscall.
    let parent = unsafe { libc::getppid() };
    // Anyone else's socket learns nothing from us, not even why.
    if !ancestor_within(parent, cred.pid(), 4, |p| crate::procfs::proc_stat(p).map(|s| s.ppid)) {
        bail!("the socket was not created by the process that ran sudo");
    }
    // Its /proc status (uid, groups, seccomp). Should it have died since,
    // `identity` refuses an empty status or another uid's.
    let status = std::fs::read_to_string(format!("/proc/{}/status", cred.pid())).unwrap_or_default();
    let who = identity(sudo_uid, cred.uid(), cred.gid(), &status).or_else(|e| refuse(&ctl, e))?;
    // sudoers may run its command in another security context (ROLE/TYPE, an
    // AppArmor profile): the program would carry it. Only the caller's will do.
    let label = |p: String| std::fs::read(format!("/proc/{p}/attr/current")).ok();
    if label("self".into()) != label(cred.pid().to_string()) {
        return refuse(
            &ctl,
            anyhow!("sudo runs its command in another security context than yours (sudoers ROLE/TYPE?)"),
        );
    }
    let own = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    same_confinement(&own, &status).or_else(|e| refuse(&ctl, e))?;
    // The caller's process group (for `validate`) and session (to tell
    // `use_pty` below), and its resource limits for the program. Unreadable
    // means refused: no stand-in value may reach the checks.
    let caller = crate::procfs::proc_stat(cred.pid())
        .context("the process behind the socket is gone")
        .or_else(|e| refuse(&ctl, e))?;
    let caller_pgrp = caller.pgrp;
    let limits = limits_of(cred.pid()).or_else(|e| refuse(&ctl, e))?;

    // The namespaces first, still empty: the program is forked into them
    // before anything the client sends reaches a process of ours. The
    // request and its fds go to the program, once it is the user; it passes
    // the request on to us as bytes, on a pipe, which carries no fds.
    if let Err(e) = netns::enter_namespace(false) {
        send_error(&ctl, &e);
        return Err(e.err);
    }
    // sudo gave us a terminal session of its own (`use_pty`): when its
    // leader, sudo's monitor, exits after us, the terminal hangs up whatever
    // is still in it. The program leaves first and tells us on this pipe.
    // SAFETY: plain syscall.
    let (left, detach) = if caller.session != unsafe { libc::getsid(0) } {
        let (r, w) = crate::sys::pipe()?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    // The program side's report: the request it read, or why it read none
    // (see `read_report`).
    let (from_program, to_parent) = crate::sys::pipe()?;
    // SAFETY: we are single-threaded.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        drop((left, from_program));
        let why = become_program(&who, &limits, detach, &ctl, to_parent);
        // Only reached on failure; stderr is the user's by now, or ours.
        // Empty: the parent got the reason, and says it.
        if !why.is_empty() {
            eprintln!("proxytun (sudo helper): {why}");
        }
        // SAFETY: _exit has no preconditions. Not exit: this forked child
        // must run nothing inherited from the helper (atexit handlers,
        // buffered output).
        unsafe { libc::_exit(126) };
    }
    drop((detach, to_parent)); // EOF should the program side die

    // From here on, any failure must also end the program side (below).
    let served = (|| -> Result<()> {
        if let Some(left) = left {
            // Said at once, still as root; only a stop (job control, before
            // it left the session) can hold it up, and that must not hold
            // root: given up on as the report is.
            if !crate::sys::readable_within(&left, HELPER_TIMEOUT) {
                return refuse(&ctl, anyhow!("the program side did not leave sudo's session in time"));
            }
            // Its byte, or EOF if it failed first: then its report says why.
            let mut b = [0u8; 1];
            // SAFETY: plain read into a local buffer.
            unsafe { libc::read(left.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        }
        // The request, as the program side took it from the client: checked
        // before root acts on any of it.
        let req = read_report(&from_program).or_else(|e| refuse(&ctl, e))?;
        validate(&req, caller_pgrp).or_else(|e| refuse(&ctl, e))?;
        // The program side, forked after `enter_namespace`, shares these
        // namespaces: what is set up now is what the program will find.
        let ns = match netns::configure_namespace(req.fake_range, false, &req.forwards) {
            Ok(v) => v,
            Err(e) => {
                send_error(&ctl, &e);
                return Err(e.err);
            }
        };
        // Join proxytun's group. Safe from the parent alone: the program
        // cannot exec (and so make setpgid fail) before the go-ahead, which
        // follows our report.
        // With `use_pty` the program side has made itself a session leader in
        // a session of its own, which setpgid refuses: it stays alone.
        // SAFETY: plain syscall.
        let joined = unsafe { libc::setpgid(pid, req.pgrp) } == 0 || crate::procfs::pgrp_of(pid) == Some(req.pgrp);
        // Parsed by `client::spawn`.
        let report = format!("pid={pid} pgrp={}", if joined { "joined" } else { "alone" });
        send_ok(&ctl, &ns, &report)
    })();
    if served.is_err() {
        // Not waited for: it holds the user's fds, and its exit may block on
        // them.
        // SAFETY: plain syscall on our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    served
}

/// The program side's report: `R` and the request it got, or `E` and why it
/// got none. It runs as the user by then, who may stop it: waited for a
/// little longer than it waits for the client, no more.
fn read_report(from: &OwnedFd) -> Result<Request> {
    let deadline = std::time::Instant::now() + HELPER_TIMEOUT + Duration::from_secs(5);
    let mut got = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    // Read up to EOF: the program side closes its end after its one report
    // (`tell`), or by dying.
    loop {
        let wait = deadline.saturating_duration_since(std::time::Instant::now());
        let mut p = libc::pollfd {
            fd: from.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // poll: 0 is the deadline passed; an error goes the way of a failed
        // read, below (EINTR tries again).
        // SAFETY: plain syscalls on a local pollfd and buffer.
        let n = match unsafe { libc::poll(&mut p, 1, wait.as_millis() as libc::c_int) } {
            0 => bail!("no request from the client"),
            n if n < 0 => -1,
            _ => unsafe { libc::read(from.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) },
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            ensure!(e.kind() == std::io::ErrorKind::Interrupted, "reading the request: {e}");
            continue;
        }
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n as usize]);
        // A kind byte and at most REQUEST_MAX (the program side's buffer):
        // anything longer is no report of ours.
        ensure!(got.len() <= 1 + REQUEST_MAX, "request too large");
    }
    match got.split_first() {
        Some((b'R', req)) => Request::decode(req).ok_or_else(|| anyhow!("malformed request")),
        Some((b'E', why)) => Err(anyhow!("{}", String::from_utf8_lossy(why))),
        _ => Err(anyhow!("the program side died before reading the request")),
    }
}

/// sudo may run its command traced, or under a syscall filter of its own
/// (sudoers `intercept`, `log_subcmds`): the program would carry them, with
/// root watching its every exec. Ours must be the caller's.
fn same_confinement(own_status: &str, caller_status: &str) -> Result<()> {
    let field = |s: &str, name: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
            .map(str::to_owned)
    };
    // TracerPid: the pid tracing us, 0 for none. Seccomp: the mode (2:
    // filtered); Seccomp_filters (Linux 5.9 on): how many filters.
    ensure!(
        field(own_status, "TracerPid:").as_deref() == Some("0"),
        "sudo runs its command traced (sudoers intercept or log_subcmds?)"
    );
    // Compared, not required to be none: filters a container puts on every
    // process are on the caller too.
    for name in ["Seccomp:", "Seccomp_filters:"] {
        ensure!(
            field(own_status, name) == field(caller_status, name),
            "sudo runs its command under a syscall filter of its own (sudoers intercept or log_subcmds?)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str =
        "Name:\tproxytun\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t4 27 1000 \n";

    #[test]
    fn the_program_runs_as_the_user_sudo_was_run_by_with_their_groups() {
        assert_eq!(
            identity(1000, 1000, 1000, STATUS).unwrap(),
            Identity {
                uid: 1000,
                gid: 1000,
                groups: vec![4, 27, 1000]
            }
        );
        let no_groups = STATUS.replace("Groups:\t4 27 1000 ", "Groups:\t");
        assert_eq!(
            identity(1000, 1000, 1000, &no_groups).unwrap().groups,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn the_helper_refuses_anyone_but_the_sudo_caller() {
        let err = |r: Result<Identity>| r.unwrap_err().to_string();
        assert!(err(identity(1001, 1000, 1000, STATUS)).contains("sudo was run by uid 1001"));
        assert!(err(identity(0, 0, 0, &STATUS.replace("1000", "0"))).contains("root"));
        // The pid behind the socket now belongs to someone else (or nobody).
        assert!(err(identity(1000, 1000, 1000, &STATUS.replace("Uid:\t1000", "Uid:\t1001"))).contains("gone"));
        assert!(err(identity(1000, 1000, 1000, "")).contains("gone"));
    }

    fn req(range: &str, pgrp: libc::pid_t, forwards: &[&str]) -> Request {
        Request {
            fake_range: range.parse().unwrap(),
            pgrp,
            forwards: forwards.iter().map(|a| a.parse().unwrap()).collect(),
            umask: 0o022,
            sigpipe_ignored: false,
            inherit: vec![],
            argv: vec!["true".into()],
            env: vec![],
        }
    }

    #[test]
    fn the_helper_rechecks_every_request_field() {
        assert!(validate(&req("198.18.0.0/15", 7, &["127.0.0.1:5432", "[::1]:80"]), 7).is_ok());
        for (bad, why) in [
            (req("198.18.0.0/24", 7, &[]), "range too small"),
            (req("10.0.0.0/4", 7, &[]), "range too large"),
            (req("198.18.0.0/15", 7, &["10.0.0.1:22"]), "not loopback"),
            (req("198.18.0.0/15", 7, &["127.0.0.53:53"]), "port 53"),
            (req("198.18.0.0/15", 7, &["127.0.0.1:0"]), "port 0"),
            (req("198.18.0.0/15", 7, &["127.0.0.1:80", "127.0.0.1:80"]), "duplicate"),
            (req("198.18.0.0/15", 8, &[]), "someone else's process group"),
        ] {
            assert!(validate(&bad, 7).is_err(), "{why}");
        }
        // A stand-in for "caller unknown" must never match: only a real group passes.
        assert!(
            validate(&req("198.18.0.0/15", -1, &[]), -1).is_err(),
            "no real process group"
        );
        let many: Vec<String> = (1..=crate::hostports::MAX_FORWARDS as u16 + 1)
            .map(|p| format!("127.0.0.1:{}", 1000 + p))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(validate(&req("198.18.0.0/15", 7, &many), 7).is_err(), "too many");

        let with = |umask, inherit: &[RawFd]| Request {
            umask,
            inherit: inherit.to_vec(),
            ..req("198.18.0.0/15", 7, &[])
        };
        assert!(validate(&with(0o777, &[3, 9, 1000]), 7).is_ok());
        assert!(
            validate(&with(0o1777, &[]), 7).is_err(),
            "umask with more than permission bits"
        );
        assert!(
            validate(&with(0o022, &[2]), 7).is_err(),
            "stdio is not inherited this way"
        );
        assert!(validate(&with(0o022, &[5, 5]), 7).is_err(), "duplicate fd");
        assert!(validate(&with(0o022, &[RawFd::MAX]), 7).is_err(), "beyond any fd limit");
        let fds: Vec<RawFd> = (3..3 + MAX_INHERIT as RawFd).collect();
        assert!(validate(&with(0o022, &fds), 7).is_ok(), "as many as fit");
        let fds: Vec<RawFd> = (3..4 + MAX_INHERIT as RawFd).collect();
        assert!(
            validate(&with(0o022, &fds), 7).is_err(),
            "more than one message carries"
        );
    }

    #[test]
    fn the_program_runs_neither_traced_nor_filtered_beyond_the_caller() {
        let caller = "TracerPid:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n";
        assert!(same_confinement(caller, caller).is_ok());
        // A container's filter, the caller's too: fine. (No Seccomp_filters
        // line before Linux 5.9.)
        let docker = "TracerPid:\t0\nSeccomp:\t2\n";
        assert!(same_confinement(docker, docker).is_ok());
        let traced = caller.replace("TracerPid:\t0", "TracerPid:\t812");
        assert!(same_confinement(&traced, caller)
            .unwrap_err()
            .to_string()
            .contains("traced"));
        let filtered = "TracerPid:\t0\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert!(same_confinement(filtered, caller)
            .unwrap_err()
            .to_string()
            .contains("syscall filter"));
        let one_more = "TracerPid:\t0\nSeccomp:\t2\nSeccomp_filters:\t2\n";
        assert!(
            same_confinement(one_more, filtered).is_err(),
            "sudo's on top of the caller's"
        );
    }

    #[test]
    fn only_an_ancestor_within_reach_counts() {
        // 50 -> 40 -> 30 -> 20 -> 10 -> 1
        let ppid = |p: libc::pid_t| Some(if p > 10 { p - 10 } else { 1 });
        assert!(ancestor_within(50, 50, 4, ppid));
        assert!(ancestor_within(50, 20, 4, ppid));
        assert!(!ancestor_within(50, 10, 4, ppid), "too far up");
        assert!(!ancestor_within(50, 60, 4, ppid), "not an ancestor at all");
        assert!(
            !ancestor_within(50, 20, 4, |_| None),
            "a vanished process ends the walk"
        );
    }
}
