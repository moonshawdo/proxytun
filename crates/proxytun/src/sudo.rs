//! sudo mode, for hosts without usable user namespaces (CentOS 7): a
//! short-lived root helper, started through sudo, creates the namespace and
//! starts the program as the user who ran proxytun, then exits.
//!
//! proxytun listens on a unix socket in a private (0700) directory and runs
//! `sudo -- <proxytun> HELPER_ARG <socket>` (sudo closes inherited fds, hence
//! the socket path). The helper, as root:
//!   * runs only when started by sudo (real and effective uid 0), never setuid;
//!   * reaches the socket as the caller (effective uid and gid theirs, so
//!     whatever listens there sees them, not root), and serves only the
//!     process that ran sudo: the socket's creator must be one of its own
//!     ancestors (alive, so its pid cannot have been reused) and belong to
//!     SUDO_UID; the program's gid and groups are read from that process in
//!     /proc (kernel-provided), never from the request;
//!   * refuses when sudo would run it in another security context than the
//!     caller's (sudoers ROLE/TYPE), traced, or under a syscall filter of its
//!     own (sudoers intercept, log_subcmds): the program would carry them;
//!   * never receives anything from the client but bytes: it creates the
//!     (empty) namespaces and forks the program, which takes the caller's
//!     resource limits, drops to the user (groups, gid, uid, a session
//!     keyring of its own; no capability may survive) and sets
//!     no_new_privs, so no setuid program can regain root in a network the
//!     user controls; only then does the program read the request and the
//!     fds (stdin, stdout, stderr, working directory, and those it
//!     inherits), and pass the request on to the helper on a pipe. Closing
//!     an fd the user chose may block (SO_LINGER, a file on their FUSE
//!     mount): that happens to the user's process, never to root's;
//!   * reads no config and opens no path the user chose: the request carries
//!     only the fake-ip range, the host ports, the process group, the argv,
//!     the environment, the umask and the inherited fd numbers, and is
//!     checked again here, since anyone may write their own client;
//!   * gives up after `HELPER_TIMEOUT` (and a little) on a client, or a
//!     program side, that does not talk;
//!   * fills the namespaces, puts the program in proxytun's process group
//!     (or, when sudo gave it a terminal session of its own, `use_pty`, has
//!     it leave that session before it ends and hangs the program up),
//!     hands the TUN device and listener back and exits: from then on no
//!     process of ours runs as root. The program takes the user's umask,
//!     stdio, directory and environment, waits for the go-ahead, and puts
//!     the inherited fds back at their numbers.

use crate::netns::{self, Child, Handover, Setup, TempDir};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use nix::sys::socket::{
    accept4, bind, connect, getsockopt, listen, sendmsg, socket, sockopt, AddressFamily, Backlog, ControlMessage,
    MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::ffi::{CString, OsString};
use std::io::IoSlice;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
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
    /// proxytun's umask, for the program.
    umask: libc::mode_t,
    /// Whether proxytun's caller ignored SIGPIPE, for the program.
    sigpipe_ignored: bool,
    /// The fds the program inherits, by their numbers in proxytun. They
    /// follow the four fixed ones in the message, in this order.
    inherit: Vec<RawFd>,
    argv: Vec<OsString>,
    env: Vec<OsString>,
}

impl Request {
    /// NUL-separated: version, range, pgrp, forwards, umask (octal), SIGPIPE
    /// ignored ("1") or not ("0"), inherited fds ("-" for none), argc,
    /// argv..., env...
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |b: &[u8]| {
            out.extend_from_slice(b);
            out.push(0);
        };
        field(b"3");
        field(self.fake_range.to_string().as_bytes());
        field(self.pgrp.to_string().as_bytes());
        field(netns::join_addrs(&self.forwards).as_bytes());
        field(format!("{:o}", self.umask).as_bytes());
        field(if self.sigpipe_ignored { b"1" } else { b"0" });
        let inherit: Vec<String> = self.inherit.iter().map(|n| n.to_string()).collect();
        field(
            if inherit.is_empty() {
                "-".into()
            } else {
                inherit.join(",")
            }
            .as_bytes(),
        );
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
        if text()? != "3" {
            return None;
        }
        let fake_range = text()?.parse().ok()?;
        let pgrp = text()?.parse().ok()?;
        let forwards = netns::split_addrs(&text()?)?;
        let umask = libc::mode_t::from_str_radix(&text()?, 8).ok()?;
        let sigpipe_ignored = match text()?.as_str() {
            "1" => true,
            "0" => false,
            _ => return None,
        };
        let inherit = match text()?.as_str() {
            "-" => Vec::new(),
            list => list.split(',').map(|n| n.parse().ok()).collect::<Option<_>>()?,
        };
        let argc: usize = text()?.parse().ok()?;
        let argv: Vec<OsString> = (0..argc)
            .map(|_| fields.next().map(|a| OsString::from_vec(a.to_vec())))
            .collect::<Option<_>>()?;
        if argv.is_empty() {
            return None;
        }
        let env = fields.map(|e| OsString::from_vec(e.to_vec())).collect();
        Some(Request {
            fake_range,
            pgrp,
            forwards,
            umask,
            sigpipe_ignored,
            inherit,
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

/// SCM_RIGHTS passes at most 253 fds at once; four are stdio and the
/// working directory.
const MAX_INHERIT: usize = 249;

/// No fd number reaches this (the kernel's default fs.nr_open).
const FD_CEILING: RawFd = 1 << 20;

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
    ensure!(req.umask <= 0o777, "umask {:o} out of bounds", req.umask);
    ensure!(
        req.inherit.len() <= MAX_INHERIT,
        "too many inherited fds ({})",
        req.inherit.len()
    );
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

/// The fds a program started by us inherits: 3 and up, open without
/// close-on-exec. In userns mode they pass through exec by themselves.
fn inheritable_fds() -> Result<Vec<RawFd>> {
    let mut v = Vec::new();
    for e in std::fs::read_dir("/proc/self/fd").context("list our fds")? {
        let Ok(n) = e?.file_name().to_string_lossy().parse::<RawFd>() else {
            continue;
        };
        // SAFETY: F_GETFD only reads flags. The listing's own fd is
        // close-on-exec, and gone by now anyway (-1).
        if n >= 3 && unsafe { libc::fcntl(n, libc::F_GETFD) } == 0 {
            v.push(n);
        }
    }
    v.sort_unstable();
    Ok(v)
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

/// Run `f` as the caller: effective uid and gid `uid`/`gid`, no
/// supplementary groups, no capabilities. What the caller cannot reach, root
/// does not reach for them, and a socket connected meanwhile carries their
/// credentials, not root's, to whatever listens there. The saved uid stays 0
/// to come back.
fn as_caller<T>(uid: libc::uid_t, gid: libc::gid_t, f: impl FnOnce() -> T) -> Result<T> {
    const KEEP: u32 = u32::MAX; // -1: leave this id as it is
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
        if libc::setresuid(KEEP, 0, KEEP) != 0 || libc::setresgid(KEEP, 0, KEEP) != 0 {
            bail!("back to root: {}", std::io::Error::last_os_error());
        }
        Ok(r)
    }
}

fn set_timeouts(fd: &OwnedFd, t: Duration) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: t.as_secs() as _,
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
    let addr = UnixAddr::new(&path).with_context(|| {
        format!(
            "the helper socket {} is too long a path: set TMPDIR to a shorter directory",
            path.display()
        )
    })?;
    bind(l.as_raw_fd(), &addr).context("bind the helper socket")?;
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
        match sudo.try_wait() {
            Ok(None) => {}
            Ok(Some(st)) => bail!("sudo failed ({st}): the namespace was not created"),
            // Reaped by the kernel already (our caller ignores SIGCHLD).
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                bail!("sudo failed: the namespace was not created")
            }
            Err(e) => return Err(e.into()),
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let cred = getsockopt(&ctl, sockopt::PeerCredentials).context("SO_PEERCRED")?;
    // The helper connects as us (see `as_caller`).
    ensure!(
        cred.uid() == nix::unistd::getuid().as_raw(),
        "the helper socket was answered by uid {}, not on our behalf",
        cred.uid()
    );

    let inherit = inheritable_fds()?;
    ensure!(
        inherit.len() <= MAX_INHERIT,
        "{} inherited fds: through sudo at most {MAX_INHERIT} can be passed on",
        inherit.len()
    );
    let req = Request {
        fake_range: s.fake_range,
        // SAFETY: plain syscall.
        pgrp: unsafe { libc::getpgrp() },
        forwards: s.forwards.clone(),
        // SAFETY: plain syscalls, putting it back at once; no other thread
        // runs yet (the runtime comes later).
        umask: unsafe {
            let m = libc::umask(0);
            libc::umask(m);
            m
        },
        sigpipe_ignored: netns::sigpipe_was_ignored(),
        inherit,
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
    let fds: Vec<RawFd> = [0, 1, 2, cwd.as_raw_fd()]
        .into_iter()
        .chain(req.inherit.iter().copied())
        .collect();
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

fn helper(args: &[OsString]) -> Result<()> {
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

    // Never closed by us, only by the kernel when we exit: the client may
    // queue fds on it, and the last close releases them, where a socket with
    // SO_LINGER would keep root waiting. At exit lingering does not apply.
    let ctl = ManuallyDrop::new(seqpacket(SockFlag::empty())?);
    set_timeouts(&ctl, HELPER_TIMEOUT)?;
    let addr = UnixAddr::new(path.as_os_str())?;
    as_caller(sudo_uid, sudo_gid, || connect(ctl.as_raw_fd(), &addr))?.context("connect to proxytun")?;
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
    let status = std::fs::read_to_string(format!("/proc/{}/status", cred.pid())).unwrap_or_default();
    let who = match identity(sudo_uid, cred.uid(), cred.gid(), &status) {
        Ok(w) => w,
        Err(e) => return refuse(&ctl, e),
    };
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
    if let Err(e) = same_confinement(&own, &status) {
        return refuse(&ctl, e);
    }
    let caller = crate::procfs::proc_stat(cred.pid());
    let caller_pgrp = caller.map_or(-1, |s| s.pgrp);
    let limits = match limits_of(cred.pid()) {
        Ok(l) => l,
        Err(e) => return refuse(&ctl, e),
    };

    // The namespaces first, still empty: the program is forked into them
    // before anything the client sends reaches a process of ours. The
    // request and its fds go to the program, once it is the user; it passes
    // the request on to us as bytes, on a pipe, which carries no fds.
    if let Err(e) = netns::enter_namespace(false) {
        netns::send_error(&ctl, &e);
        return Err(e.err);
    }
    // sudo gave us a terminal session of its own (`use_pty`): when its
    // leader, sudo's monitor, exits after us, the terminal hangs up whatever
    // is still in it. The program leaves first and tells us on this pipe.
    // SAFETY: plain syscall.
    let (left, detach) = if caller.map(|s| s.session) != Some(unsafe { libc::getsid(0) }) {
        let (r, w) = pipe()?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    let (from_program, to_parent) = pipe()?;
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
        unsafe { libc::_exit(126) };
    }
    drop((detach, to_parent)); // EOF should the program side die
    let served = (|| -> Result<()> {
        if let Some(left) = left {
            let mut b = [0u8; 1];
            // SAFETY: plain read into a local buffer.
            unsafe { libc::read(left.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        }
        let req = match read_report(&from_program) {
            Ok(r) => r,
            Err(e) => return refuse(&ctl, e),
        };
        if let Err(e) = validate(&req, caller_pgrp) {
            return refuse(&ctl, e);
        }
        let ns = match netns::configure_namespace(req.fake_range, false, &req.forwards) {
            Ok(v) => v,
            Err(e) => {
                netns::send_error(&ctl, &e);
                return Err(e.err);
            }
        };
        // Join proxytun's group. Safe from the parent alone: the program
        // cannot exec (and so make setpgid fail) before the go-ahead, which
        // follows our report.
        // SAFETY: plain syscall.
        let joined = unsafe { libc::setpgid(pid, req.pgrp) } == 0 || crate::procfs::pgrp_of(pid) == Some(req.pgrp);
        let report = format!("pid={pid} pgrp={}", if joined { "joined" } else { "alone" });
        netns::send_ok(&ctl, &ns, &report)
    })();
    if served.is_err() {
        // Not waited for: it holds the user's fds, and its exit may block on
        // them.
        // SAFETY: plain syscall on our own child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    served
}

/// A close-on-exec pipe: (read end, write end).
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut p = [0; 2];
    // SAFETY: pipe2 fills both fds, owned right away.
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) })
}

/// The longest request: the environment and argv of a program, as one
/// message.
const REQUEST_MAX: usize = 1 << 20;

/// The program side's report: `R` and the request it got, or `E` and why it
/// got none. It runs as the user by then, who may stop it: waited for a
/// little longer than it waits for the client, no more.
fn read_report(from: &OwnedFd) -> Result<Request> {
    let deadline = std::time::Instant::now() + HELPER_TIMEOUT + Duration::from_secs(5);
    let mut got = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let wait = deadline.saturating_duration_since(std::time::Instant::now());
        let mut p = libc::pollfd {
            fd: from.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
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
    ensure!(
        field(own_status, "TracerPid:").as_deref() == Some("0"),
        "sudo runs its command traced (sudoers intercept or log_subcmds?)"
    );
    for name in ["Seccomp:", "Seccomp_filters:"] {
        ensure!(
            field(own_status, name) == field(caller_status, name),
            "sudo runs its command under a syscall filter of its own (sudoers intercept or log_subcmds?)"
        );
    }
    Ok(())
}

/// Did the drop to the user leave no capability, as `status` (our
/// /proc/self/status) shows? Unreadable (an fd limit of 0) counts as no.
fn capabilities_gone(status: Option<&str>) -> bool {
    let zero = |name: &str| {
        status
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix(name)))
            .is_some_and(|v| v.trim().trim_start_matches('0').is_empty())
    };
    zero("CapPrm:") && zero("CapEff:")
}

/// Take the caller's resource limits, as userns mode leaves them: PAM may
/// give root more (nproc, memlock), sudo less (no core dumps). A higher hard
/// limit root cannot restore (without CAP_SYS_RESOURCE: a container) stays
/// lower.
fn adopt_limits(limits: &[libc::rlimit]) -> std::result::Result<(), String> {
    for (r, l) in limits.iter().enumerate() {
        // SAFETY: plain syscalls on local structs.
        unsafe {
            if libc::setrlimit(r as _, l) == 0 {
                continue;
            }
            let mut now = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::getrlimit(r as _, &mut now);
            let lower = libc::rlimit {
                rlim_cur: l.rlim_cur.min(now.rlim_max),
                rlim_max: l.rlim_max.min(now.rlim_max),
            };
            if libc::setrlimit(r as _, &lower) != 0 {
                return Err(format!(
                    "applying your resource limits: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    Ok(())
}

/// What becomes of the session keyring the program would inherit, given its
/// description (`KEYCTL_DESCRIBE`: "type;uid;gid;perm;name") or why there is
/// none to read. pam_keyinit (RHEL's /etc/pam.d/sudo) may have given the
/// helper root's, with root's user keyring linked into it: replaced. The
/// caller's own (sudo without pam_keyinit) stays, as in userns mode. One we
/// cannot look at (keyctl filtered out, as Docker's default seccomp profile
/// does) might be root's: refused.
fn keyring_action(described: std::result::Result<String, i32>, uid: libc::uid_t) -> std::result::Result<bool, String> {
    match described {
        Ok(d) => Ok(d.split(';').nth(1).and_then(|o| o.parse::<libc::uid_t>().ok()) != Some(uid)),
        // A kernel without keyrings: no root's to reach either.
        Err(libc::ENOSYS) => Ok(false),
        Err(e @ (libc::EPERM | libc::EACCES)) => Err(format!(
            "cannot tell whose session keyring the program would get ({}); in a container, \
             allow keyctl in its seccomp profile",
            std::io::Error::from_raw_os_error(e)
        )),
        // Revoked, expired: a new one does no harm.
        Err(_) => Ok(true),
    }
}

/// A session keyring the user may have: see `keyring_action`. Runs as the
/// user already, so a new keyring is theirs.
fn own_session_keyring(uid: libc::uid_t) -> std::result::Result<(), String> {
    const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
    const KEYCTL_DESCRIBE: libc::c_long = 6;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    let mut buf = [0u8; 4096];
    // SAFETY: the kernel writes at most `buf.len()` bytes.
    let n = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_DESCRIBE,
            KEY_SPEC_SESSION_KEYRING,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    let described = if n < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        let text = &buf[..(n as usize).min(buf.len())];
        Ok(String::from_utf8_lossy(text.strip_suffix(&[0]).unwrap_or(text)).into_owned())
    };
    if !keyring_action(described, uid)? {
        return Ok(());
    }
    // SAFETY: a NULL name asks for a new anonymous keyring.
    let r = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        )
    };
    if r < 0 {
        return Err(format!(
            "leaving root's session keyring: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Write the report to the parent (see `read_report`) and close the pipe,
/// so it reads on at once whatever happens to us next.
fn tell(to_parent: OwnedFd, kind: u8, body: &[u8]) {
    let mut msg = Vec::with_capacity(1 + body.len());
    msg.push(kind);
    msg.extend_from_slice(body);
    let mut rest = &msg[..];
    while !rest.is_empty() {
        // SAFETY: plain write of our own buffer.
        let n = unsafe { libc::write(to_parent.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        rest = &rest[n as usize..];
    }
}

/// In the forked child, still root: leave sudo's session if asked
/// (`detach`), take the caller's limits, drop to the user (groups, gid, uid,
/// keyring; no capability may survive) and set no_new_privs, so no setuid
/// program can regain root in a network the user controls. Only then take
/// the request and the fds from the client: closing an fd of theirs can
/// block (SO_LINGER, a file on their FUSE mount), which must never happen to
/// root. Report the request to the parent, take the user's umask, stdio,
/// directory and environment, wait for the go-ahead, put the inherited fds
/// back at their numbers and become the program. Returns only on failure,
/// with the reason, or empty when the parent, still listening, got it.
fn become_program(
    who: &Identity,
    limits: &[libc::rlimit],
    detach: Option<OwnedFd>,
    ctl: &OwnedFd,
    to_parent: OwnedFd,
) -> String {
    let mut to_parent = Some(to_parent);
    let mut fail = |why: String| -> String {
        match to_parent.take() {
            Some(p) => {
                tell(p, b'E', why.as_bytes());
                String::new()
            }
            None => why,
        }
    };
    // SAFETY: plain syscalls; the helper is single-threaded, so the child
    // may use the environment and the allocator.
    unsafe {
        if let Some(w) = detach {
            if libc::setsid() < 0 {
                return fail(format!("leaving sudo's session: {}", std::io::Error::last_os_error()));
            }
            libc::write(w.as_raw_fd(), b"s".as_ptr().cast(), 1);
        }
        if let Err(e) = adopt_limits(limits) {
            return fail(e);
        }
        if libc::setgroups(who.groups.len(), who.groups.as_ptr()) != 0
            || libc::setresgid(who.gid, who.gid, who.gid) != 0
            || libc::setresuid(who.uid, who.uid, who.uid) != 0
        {
            return fail(format!(
                "dropping to uid {}: {}",
                who.uid,
                std::io::Error::last_os_error()
            ));
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        libc::getresuid(&mut r, &mut e, &mut s);
        if (r, e, s) != (who.uid, who.uid, who.uid) || libc::setuid(0) == 0 {
            return fail("privileges were not dropped".into());
        }
        if let Err(e) = own_session_keyring(who.uid) {
            return fail(e);
        }
        if !capabilities_gone(std::fs::read_to_string("/proc/self/status").ok().as_deref()) {
            return fail("capabilities survived the drop to the user, or cannot be checked".into());
        }
        // The network in here is the user's: a setuid program (sudo, su,
        // anything PAM authenticates over the network) must not regain
        // root in it.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        {
            return fail(format!("setting no_new_privs: {}", std::io::Error::last_os_error()));
        }
    }
    let mut buf = vec![0u8; REQUEST_MAX];
    let (n, fds) = match netns::recv_with_fds(ctl, &mut buf) {
        Ok(v) => v,
        Err(e) => return fail(format!("read the request: {e:#}")),
    };
    // Not closed on the way out, failing: at exit the kernel does it, and
    // lingering does not apply there.
    let fds: Vec<RawFd> = fds.into_iter().map(IntoRawFd::into_raw_fd).collect();
    let Some(req) = Request::decode(&buf[..n]) else {
        return fail("malformed request".into());
    };
    if fds.len() != 4 + req.inherit.len() {
        return fail(format!("expected {} fds", 4 + req.inherit.len()));
    }
    let env: Vec<CString> = match req.env.iter().map(|e| CString::new(e.as_bytes())).collect() {
        Ok(v) => v,
        Err(_) => return fail("environment entry contains NUL".into()),
    };
    // The program shares this socket and waits on it for the go-ahead for as
    // long as proxytun needs.
    if let Err(e) = set_timeouts(ctl, Duration::ZERO) {
        return fail(format!("{e:#}"));
    }
    if let Some(p) = to_parent.take() {
        tell(p, b'R', &buf[..n]);
    }
    drop(buf);
    let (stdio, cwd, inherit) = (&fds[..3], fds[3], &fds[4..]);
    // SAFETY: plain syscalls on fds we hold.
    unsafe {
        libc::umask(req.umask);
        for (i, &fd) in stdio.iter().enumerate() {
            if libc::dup2(fd, i as libc::c_int) < 0 {
                return format!("taking your stdio: {}", std::io::Error::last_os_error());
            }
        }
        // As the user: a directory it cannot enter is its problem, not
        // something root opens for it.
        if libc::fchdir(cwd) != 0 {
            return format!("entering the working directory: {}", std::io::Error::last_os_error());
        }
    }
    // The user's environment; execvp then searches the user's PATH.
    // SAFETY: single-threaded; the strings live in `env` until exec.
    unsafe {
        libc::clearenv();
        for e in &env {
            libc::putenv(e.as_ptr() as *mut _);
        }
    }
    netns::wait_go(ctl);
    // The inherited fds at the numbers they had in proxytun. Each is first
    // copied to the lowest free number that is no one's target (a target
    // may be held by one of them, or by ctl, done with now), staying under
    // the caller's fd limit as userns mode would; the copies close on exec.
    let targets: std::collections::HashSet<RawFd> = req.inherit.iter().copied().collect();
    let mut moved = Vec::new();
    for (&n, &fd) in req.inherit.iter().zip(inherit) {
        let mut from = 3;
        let m = loop {
            // SAFETY: plain syscalls on fds we hold.
            let m = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, from) };
            if m < 0 {
                return format!("passing on fd {n}: {}", std::io::Error::last_os_error());
            }
            if !targets.contains(&m) {
                break m;
            }
            unsafe { libc::close(m) };
            from = m + 1;
        };
        moved.push((n, m));
    }
    for (n, m) in moved {
        // SAFETY: as above.
        if unsafe { libc::dup2(m, n) } < 0 {
            return format!("passing on fd {n}: {}", std::io::Error::last_os_error());
        }
    }
    let code = netns::exec(&req.argv, req.sigpipe_ignored);
    unsafe { libc::_exit(code) }
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
            umask: 0o027,
            sigpipe_ignored: true,
            inherit: vec![3, 7, 250],
            argv: vec![
                "curl".into(),
                "".into(),
                "a b=c".into(),
                OsString::from_vec(b"\xc4\xe3".to_vec()),
            ],
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
            umask: 0,
            sigpipe_ignored: false,
            inherit: vec![],
            argv: vec!["true".into()],
            env: vec![],
        };
        let mut other_version = no_env.encode();
        assert_eq!(Request::decode(&no_env.encode()), Some(no_env));
        other_version[0] = b'2';
        assert_eq!(Request::decode(&other_version), None, "another version");
        assert_eq!(
            Request::decode(b"3\x0010.0.0.0/8\x001\0-\x0022\x000\0-\x000\0"),
            None,
            "no program"
        );
        assert_eq!(
            Request::decode(b"3\x0010.0.0.0/8\x001\0-\x0022\x000\0-\x005\0a\0"),
            None,
            "argv cut short"
        );
        assert_eq!(
            Request::decode(b"3\x0010.0.0.0/8\x001\0-\x009\x000\0-\x001\0true\0"),
            None,
            "umask not octal"
        );
        assert_eq!(
            Request::decode(b"3\x0010.0.0.0/8\x001\0-\x0022\0yes\0-\x001\0true\0"),
            None,
            "SIGPIPE neither 0 nor 1"
        );
        assert!(Request::decode(b"3\x0010.0.0.0/8\x001\0-\x0022\x001\0-\x001\0true\0").is_some());
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
    fn no_capability_may_survive_and_unreadable_means_unknown() {
        let st = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n";
        assert!(capabilities_gone(Some(st)));
        assert!(!capabilities_gone(Some(
            &st.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000400")
        )));
        assert!(!capabilities_gone(Some(
            &st.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000003fffffffff")
        )));
        // A fd limit of 0 leaves /proc unreadable: that proves nothing.
        assert!(!capabilities_gone(None));
        assert!(!capabilities_gone(Some("")));
    }

    #[test]
    fn only_the_callers_own_session_keyring_reaches_the_program() {
        let desc = |uid: u32| Ok(format!("keyring;{uid};{uid};3f030000;_ses"));
        assert_eq!(keyring_action(desc(1000), 1000), Ok(false), "the caller's: kept");
        assert_eq!(
            keyring_action(desc(0), 1000),
            Ok(true),
            "root's (pam_keyinit): replaced"
        );
        assert_eq!(keyring_action(desc(1001), 1000), Ok(true), "anyone else's: replaced");
        assert_eq!(keyring_action(Ok("garbage".into()), 1000), Ok(true));
        assert_eq!(keyring_action(Err(libc::ENOSYS), 1000), Ok(false), "no keyrings at all");
        assert_eq!(keyring_action(Err(libc::EKEYREVOKED), 1000), Ok(true));
        // keyctl filtered out (a container): it might be root's; refused.
        assert!(keyring_action(Err(libc::EPERM), 1000).unwrap_err().contains("seccomp"));
        assert!(keyring_action(Err(libc::EACCES), 1000).is_err());
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
