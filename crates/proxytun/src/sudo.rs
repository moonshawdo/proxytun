//! sudo mode, for hosts without usable user namespaces (CentOS 7): a
//! short-lived root helper, started through sudo, creates the namespace and
//! starts the program as the user who ran proxytun, then exits.
//!
//! proxytun listens on a unix socket in a private (0700) directory and runs
//! `sudo -- <proxytun> HELPER_ARG <socket>` (sudo closes inherited fds, hence
//! the socket path). The helper, as root:
//!   * runs only when started by sudo (real and effective uid 0), never setuid;
//!   * reaches the socket with the caller's file permissions, and serves only
//!     the process that ran sudo: the socket's creator must be one of its own
//!     ancestors (alive, so its pid cannot have been reused) and belong to
//!     SUDO_UID; the program's gid and groups are read from that process in
//!     /proc (kernel-provided), never from the request;
//!   * reads no config and opens no path the user chose: the request carries
//!     only the fake-ip range, the argv, the environment and four fds (stdin,
//!     stdout, stderr, working directory), and is checked again here, since
//!     anyone may write their own client;
//!   * gives up after `HELPER_TIMEOUT` on a client that does not talk;
//!   * forks the program, puts it in proxytun's process group, and has it drop
//!     to the user (groups, gid, uid; no capability may survive) and set
//!     no_new_privs, so no setuid program can regain root in a network the
//!     user controls; then take the user's stdio, directory and environment,
//!     and wait for the go-ahead;
//!   * hands the TUN device and listener back and exits: from then on no
//!     process of ours runs as root.

use crate::netns::{self, Child, Handover, Setup, TempDir};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use nix::sys::socket::{
    accept4, bind, connect, getsockopt, listen, sendmsg, socket, sockopt, AddressFamily, Backlog, ControlMessage,
    MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::ffi::{CString, OsString};
use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::time::Duration;

/// argv[1] that makes proxytun run as the root helper.
pub const HELPER_ARG: &str = "__proxytun_root_setup";

/// What proxytun asks of the helper.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    fake_range: Ipv4Net,
    /// proxytun's process group, for the program to join.
    pgrp: libc::pid_t,
    /// Host ports to bind inside.
    forwards: Vec<SocketAddr>,
    argv: Vec<String>,
    env: Vec<OsString>,
}

impl Request {
    /// NUL-separated: version, range, pgrp, forwards, argc, argv..., env...
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |b: &[u8]| {
            out.extend_from_slice(b);
            out.push(0);
        };
        field(b"1");
        field(self.fake_range.to_string().as_bytes());
        field(self.pgrp.to_string().as_bytes());
        field(netns::join_addrs(&self.forwards).as_bytes());
        field(self.argv.len().to_string().as_bytes());
        for a in &self.argv {
            field(a.as_bytes());
        }
        for e in &self.env {
            field(e.as_bytes());
        }
        out
    }

    fn decode(b: &[u8]) -> Option<Request> {
        let mut fields = b.strip_suffix(&[0])?.split(|&c| c == 0);
        let mut text = || std::str::from_utf8(fields.next()?).ok().map(str::to_owned);
        if text()? != "1" {
            return None;
        }
        let fake_range = text()?.parse().ok()?;
        let pgrp = text()?.parse().ok()?;
        let forwards = netns::split_addrs(&text()?)?;
        let argc: usize = text()?.parse().ok()?;
        let argv = (0..argc).map(|_| text()).collect::<Option<Vec<_>>>()?;
        if argv.is_empty() {
            return None;
        }
        let env = fields.map(|e| OsString::from_vec(e.to_vec())).collect();
        Some(Request {
            fake_range,
            pgrp,
            forwards,
            argv,
            env,
        })
    }
}

/// Who the program runs as.
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

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

/// Environment variables that say root was reached from another user.
const ELEVATION_MARKERS: [&str; 5] = ["SUDO_UID", "SUDO_USER", "SUDO_COMMAND", "DOAS_USER", "PKEXEC_UID"];

/// Why this process must not run proxytun as root, if it must not. Reached
/// through sudo, doas, pkexec or a setuid copy, root mode (the program keeps
/// root) would hand a user who may run only proxytun a root program, a
/// root-read config and a root-written log file. Only the helper (checked
/// separately) runs under sudo.
pub fn root_refusal(ruid: libc::uid_t, euid: libc::uid_t, elevated_env: bool) -> Option<String> {
    if euid != 0 {
        return None;
    }
    if ruid != euid {
        return Some("proxytun must not be installed setuid root".into());
    }
    if elevated_env {
        return Some(
            "proxytun refuses to run as root through sudo, doas or pkexec: run it as yourself, \
             it asks sudo only for its namespace helper (see the README)"
                .into(),
        );
    }
    None
}

/// `root_refusal` for this process.
pub fn root_refusal_here() -> Option<String> {
    let elevated = ELEVATION_MARKERS.iter().any(|v| std::env::var_os(v).is_some());
    // SAFETY: plain syscalls.
    root_refusal(unsafe { libc::getuid() }, unsafe { libc::geteuid() }, elevated)
}

/// How long the helper waits for its client.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// The request, checked again by the helper: the client may not be proxytun.
fn validate(req: &Request, caller_pgrp: libc::pid_t) -> Result<()> {
    let p = req.fake_range.prefix_len();
    ensure!((8..=22).contains(&p), "fake-ip range {} out of bounds", req.fake_range);
    ensure!(
        req.forwards.len() <= crate::hostports::MAX_FORWARDS,
        "too many host ports ({})",
        req.forwards.len()
    );
    let mut seen = std::collections::HashSet::new();
    for a in &req.forwards {
        ensure!(
            a.ip().is_loopback() && a.port() != 0 && a.port() != 53 && seen.insert(a),
            "host port {a} not allowed"
        );
    }
    ensure!(
        req.pgrp == caller_pgrp,
        "process group {} is not the caller's",
        req.pgrp
    );
    Ok(())
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
        match ppid_of(p) {
            Some(next) if next > 0 => p = next,
            _ => return false,
        }
    }
    false
}

/// Run `f` with the file permissions of `uid`/`gid` and no supplementary
/// groups: what the caller cannot reach, root does not reach for it either.
/// fsuid != 0 also drops the file capabilities for the duration.
fn as_caller<T>(uid: libc::uid_t, gid: libc::gid_t, f: impl FnOnce() -> T) -> Result<T> {
    // SAFETY: plain syscalls on our own credentials.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            bail!("setgroups: {}", std::io::Error::last_os_error());
        }
        libc::setfsgid(gid);
        libc::setfsuid(uid);
        // setfsuid reports the previous value; asking again confirms it took.
        let (fu, fg) = (libc::setfsuid(u32::MAX), libc::setfsgid(u32::MAX));
        ensure!(
            fu as u32 == uid && fg as u32 == gid,
            "could not take the caller's file permissions"
        );
        let r = f();
        libc::setfsuid(0);
        libc::setfsgid(0);
        Ok(r)
    }
}

fn set_timeouts(fd: &OwnedFd, t: Duration) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: t.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: a timeval for a socket we own.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tv) as libc::socklen_t,
            )
        };
        ensure!(r == 0, "setsockopt timeout: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn seqpacket(flags: SockFlag) -> Result<OwnedFd> {
    socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC | flags,
        None,
    )
    .context("socket")
}

// ------------------------------------------------------------ proxytun --

/// Have sudo start the helper and wait for the namespace. Returns the
/// waiting program, the namespace, and whether the program could join our
/// process group (not when sudo gave it a terminal session of its own:
/// `use_pty`).
pub fn spawn(s: &Setup) -> Result<(Child, Handover, bool)> {
    let dir = TempDir::new()?;
    let path = dir.path().join("ctl");
    // Non-blocking: while waiting we must notice sudo giving up.
    let l = seqpacket(SockFlag::SOCK_NONBLOCK)?;
    bind(l.as_raw_fd(), &UnixAddr::new(&path)?).context("bind the helper socket")?;
    listen(&l, Backlog::new(1)?).context("listen")?;
    let exe = std::env::current_exe().context("locate our own executable for sudo")?;
    // stdio stays ours: sudo asks for the password on the terminal.
    let mut sudo = std::process::Command::new("sudo")
        .arg("--")
        .arg(&exe)
        .arg(HELPER_ARG)
        .arg(&path)
        .spawn()
        .context("run sudo")?;
    let ctl = loop {
        // The password prompt may take a while; give up only if sudo does.
        match accept4(l.as_raw_fd(), SockFlag::SOCK_CLOEXEC) {
            // SAFETY: accept just returned this fd.
            Ok(fd) => break unsafe { OwnedFd::from_raw_fd(fd) },
            Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => {}
            Err(e) => bail!("accept the helper: {e}"),
        }
        if let Some(st) = sudo.try_wait()? {
            bail!("sudo failed ({st}): the namespace was not created");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let cred = getsockopt(&ctl, sockopt::PeerCredentials).context("SO_PEERCRED")?;
    ensure!(
        cred.uid() == 0,
        "the helper socket was answered by uid {}, not root",
        cred.uid()
    );

    let req = Request {
        fake_range: s.fake_range,
        // SAFETY: plain syscall.
        pgrp: unsafe { libc::getpgrp() },
        forwards: s.forwards.clone(),
        argv: s.argv.clone(),
        env: std::env::vars_os()
            .map(|(k, v)| {
                let mut e = k;
                e.push("=");
                e.push(v);
                e
            })
            .collect(),
    };
    // SAFETY: plain syscall; the fd is owned right away.
    let cwd = unsafe { libc::open(c".".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if cwd < 0 {
        bail!("open the working directory: {}", std::io::Error::last_os_error());
    }
    let cwd = unsafe { OwnedFd::from_raw_fd(cwd) };
    let fds = [0, 1, 2, cwd.as_raw_fd()];
    sendmsg::<()>(
        ctl.as_raw_fd(),
        &[IoSlice::new(&req.encode())],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .context("send the request to the helper (environment too large?)")?;
    let handover = netns::recv_setup(&ctl, None)?;
    let report = &handover.report;
    let value = |key: &str| report.split(' ').find_map(|t| t.strip_prefix(key));
    let pid = value("pid=")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("bad report from the helper: {report:?}"))?;
    let joined = value("pgrp=") == Some("joined");
    drop(dir);
    Ok((Child::new(pid, ctl), handover, joined))
}

// -------------------------------------------------------------- helper --

/// Entry point of the root helper (`proxytun HELPER_ARG <socket>`). Never
/// returns.
pub fn helper_main(args: &[String]) -> ! {
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
fn refuse(ctl: &OwnedFd, e: anyhow::Error) -> Result<()> {
    netns::send_error(
        ctl,
        &netns::SetupError {
            userns: false,
            err: anyhow!("sudo helper: {e:#}"),
        },
    );
    Err(e)
}

fn helper(args: &[String]) -> Result<()> {
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
    let (sudo_uid, sudo_gid) = (id("SUDO_UID")?, id("SUDO_GID")?);

    let ctl = seqpacket(SockFlag::empty())?;
    set_timeouts(&ctl, HELPER_TIMEOUT)?;
    let addr = UnixAddr::new(path.as_str())?;
    as_caller(sudo_uid, sudo_gid, || connect(ctl.as_raw_fd(), &addr))?.context("connect to proxytun")?;
    let cred = getsockopt(&ctl, sockopt::PeerCredentials).context("SO_PEERCRED")?;
    // The socket's creator must be the process that ran sudo: one of our
    // ancestors (sudo, sudo's pty monitor in between), alive, so its pid has
    // not been reused and its /proc entries are its own.
    // SAFETY: plain syscall.
    let parent = unsafe { libc::getppid() };
    if !ancestor_within(parent, cred.pid(), 4, |p| crate::witness::proc_stat(p).map(|s| s.ppid)) {
        return refuse(&ctl, anyhow!("the socket was not created by the process that ran sudo"));
    }
    let status = std::fs::read_to_string(format!("/proc/{}/status", cred.pid())).unwrap_or_default();
    let who = match identity(sudo_uid, cred.uid(), cred.gid(), &status) {
        Ok(w) => w,
        Err(e) => return refuse(&ctl, e),
    };
    let caller_pgrp = crate::witness::pgrp_of(cred.pid()).unwrap_or(-1);

    let mut buf = vec![0u8; 1 << 20];
    let (n, fds) = netns::recv_with_fds(&ctl, &mut buf).context("read the request")?;
    let Some(req) = Request::decode(&buf[..n]) else {
        return refuse(&ctl, anyhow!("malformed request"));
    };
    if let Err(e) = validate(&req, caller_pgrp) {
        return refuse(&ctl, e);
    }
    let Ok([stdin, stdout, stderr, cwd]) = <[OwnedFd; 4]>::try_from(fds) else {
        return refuse(&ctl, anyhow!("expected 4 fds"));
    };
    // The program shares this socket and waits on it for the go-ahead for as
    // long as proxytun needs.
    set_timeouts(&ctl, Duration::ZERO)?;

    let ns = match netns::setup_namespace(req.fake_range, false, &req.forwards) {
        Ok(v) => v,
        Err(e) => {
            netns::send_error(&ctl, &e);
            return Err(e.err);
        }
    };
    let prepared = Prepared::new(&req)?;
    // SAFETY: we are single-threaded; the child only uses prepared data.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        drop(ns);
        let why = prepared.become_user(&who, [&stdin, &stdout, &stderr], &cwd, &ctl, &req.argv);
        // Only reached on failure; stderr is the user's by now, or ours.
        eprintln!("proxytun (sudo helper): {why}");
        unsafe { libc::_exit(126) };
    }
    // Join proxytun's group. Safe from the parent alone: the child cannot exec
    // (and so make setpgid fail) before the go-ahead, which follows our report.
    // SAFETY: plain syscall.
    let joined = unsafe { libc::setpgid(pid, req.pgrp) } == 0 || crate::witness::pgrp_of(pid) == Some(req.pgrp);
    let report = format!("pid={pid} pgrp={}", if joined { "joined" } else { "alone" });
    netns::send_ok(&ctl, &ns, &report)?;
    Ok(())
}

/// The user's environment, built before fork.
struct Prepared {
    env: Vec<CString>,
}

impl Prepared {
    fn new(req: &Request) -> Result<Self> {
        let env = req
            .env
            .iter()
            .map(|e| CString::new(e.as_bytes()).context("environment entry contains NUL"))
            .collect::<Result<_>>()?;
        Ok(Prepared { env })
    }

    /// In the forked child: become the user, wait for the go-ahead on `ctl`,
    /// then become the program. Returns only on failure, with the reason.
    fn become_user(
        &self,
        who: &Identity,
        stdio: [&OwnedFd; 3],
        cwd: &OwnedFd,
        ctl: &OwnedFd,
        argv: &[String],
    ) -> String {
        // SAFETY: plain syscalls; the helper is single-threaded, so the
        // child may use the environment and the allocator.
        unsafe {
            if libc::setgroups(who.groups.len(), who.groups.as_ptr()) != 0
                || libc::setresgid(who.gid, who.gid, who.gid) != 0
                || libc::setresuid(who.uid, who.uid, who.uid) != 0
            {
                return format!("dropping to uid {}: {}", who.uid, std::io::Error::last_os_error());
            }
            let (mut r, mut e, mut s) = (0, 0, 0);
            libc::getresuid(&mut r, &mut e, &mut s);
            if (r, e, s) != (who.uid, who.uid, who.uid) || libc::setuid(0) == 0 {
                return "privileges were not dropped".into();
            }
            let caps = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            if caps.lines().any(|l| {
                l.strip_prefix("CapEff:")
                    .or_else(|| l.strip_prefix("CapPrm:"))
                    .is_some_and(|v| !v.trim().trim_start_matches('0').is_empty())
            }) {
                return "capabilities survived the drop to the user".into();
            }
            // The network in here is the user's: a setuid program (sudo, su,
            // anything PAM authenticates over the network) must not regain
            // root in it.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
            {
                return format!("setting no_new_privs: {}", std::io::Error::last_os_error());
            }
            for (i, fd) in stdio.iter().enumerate() {
                libc::dup2(fd.as_raw_fd(), i as libc::c_int);
            }
            // As the user: a directory it cannot enter is its problem, not
            // something root opens for it.
            if libc::fchdir(cwd.as_raw_fd()) != 0 {
                return format!("entering the working directory: {}", std::io::Error::last_os_error());
            }
        }
        // The user's environment; execvp then searches the user's PATH.
        // SAFETY: single-threaded; the strings live in `self` until exec.
        unsafe {
            libc::clearenv();
            for e in &self.env {
                libc::putenv(e.as_ptr() as *mut _);
            }
        }
        netns::wait_go(ctl);
        let code = netns::exec(argv);
        unsafe { libc::_exit(code) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_survive_encoding_including_odd_bytes() {
        let r = Request {
            fake_range: "198.18.0.0/15".parse().unwrap(),
            pgrp: 4242,
            forwards: vec!["127.0.0.1:5432".parse().unwrap(), "[::1]:80".parse().unwrap()],
            argv: vec!["curl".into(), "".into(), "a b=c".into()],
            env: vec![
                OsString::from("HOME=/home/u"),
                OsString::from_vec(b"BIN=\xff\xfe".to_vec()),
            ],
        };
        assert_eq!(Request::decode(&r.encode()), Some(r));
        let no_env = Request {
            fake_range: "10.0.0.0/8".parse().unwrap(),
            pgrp: 1,
            forwards: vec![],
            argv: vec!["true".into()],
            env: vec![],
        };
        assert_eq!(Request::decode(&no_env.encode()), Some(no_env));
        assert_eq!(Request::decode(b"2\0x\0"), None, "unknown version");
        assert_eq!(Request::decode(b"1\x0010.0.0.0/8\x001\0-\x000\0"), None, "no program");
        assert_eq!(
            Request::decode(b"1\x0010.0.0.0/8\x001\0-\x005\0a\0"),
            None,
            "argv cut short"
        );
    }

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

    #[test]
    fn root_mode_is_refused_through_sudo_or_setuid() {
        assert_eq!(root_refusal(1000, 1000, true), None, "not root: nothing to refuse");
        assert_eq!(root_refusal(0, 0, false), None, "root itself");
        assert!(root_refusal(1000, 0, false).unwrap().contains("setuid"));
        assert!(root_refusal(0, 0, true).unwrap().contains("through sudo"));
    }

    fn req(range: &str, pgrp: libc::pid_t, forwards: &[&str]) -> Request {
        Request {
            fake_range: range.parse().unwrap(),
            pgrp,
            forwards: forwards.iter().map(|a| a.parse().unwrap()).collect(),
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
        let many: Vec<String> = (1..=crate::hostports::MAX_FORWARDS as u16 + 1)
            .map(|p| format!("127.0.0.1:{}", 1000 + p))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(validate(&req("198.18.0.0/15", 7, &many), 7).is_err(), "too many");
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
