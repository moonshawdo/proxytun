//! Start the program inside its own network namespace.
//!
//! proxytun forks one child, which at once re-executes proxytun itself in
//! setup mode (`SETUP_ARG`): a fresh image holds none of our memory (proxy
//! credentials) and is dumpable again, which it must be to write its own
//! /proc/self/uid_map. The setup process unshares user, network and mount
//! namespaces (mapping our uid/gid to themselves), points `/etc/resolv.conf`
//! at our DNS address with a private bind mount, creates and configures the
//! TUN device and a listener for captured TCP, and hands both fds back over a
//! socketpair. It then waits for the go-ahead (proxytun serving the TUN) and
//! execs the program, which loses the namespace capabilities at exec because
//! its uid is not 0.

use crate::netcfg;
use anyhow::{anyhow, bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
};
use std::ffi::{CStr, CString, OsString};
use std::fmt::Display;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

pub const TUN_NAME: &CStr = c"tun0";
/// Packets only travel between the namespace's kernel and proxytun, never
/// over a real link: the bigger they are, the fewer we handle.
pub const MTU: u32 = 65520;

/// proxytun's own addresses, in the last /24 of `fake_ip_range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addrs {
    /// The TUN device's address: the program's source address, and where the
    /// TCP listener sits.
    pub tun: Ipv4Addr,
    /// The first of the `nat::NAT_ADDRS` source addresses (.2 to .17) of
    /// rewritten connections towards the listener.
    pub nat: Ipv4Addr,
    /// Where resolv.conf points (any address on port 53 works too).
    pub dns: Ipv4Addr,
}

impl Addrs {
    pub const PREFIX: u8 = 24;

    pub fn new(range: Ipv4Net) -> Self {
        let block = u32::from(range.broadcast()) & !0xff;
        Addrs {
            tun: Ipv4Addr::from(block + 1),
            nat: Ipv4Addr::from(block + 2),
            dns: Ipv4Addr::from(block + 53),
        }
    }
}

/// The resolv.conf the program sees: only our DNS server, keeping the host's
/// search domains and options, but for `ndots`. Our DNS answers every name
/// with an address, so the first name a resolver tries is the one it keeps:
/// with ndots 2 or more (Kubernetes has 5) that is `github.com` with a
/// search domain appended, never `github.com` itself. At the default of 1,
/// only names without a dot get a search domain first.
pub fn resolv_conf(host: &str, dns: Ipv4Addr) -> String {
    let mut out = format!("# proxytun: names resolve through its fake-ip DNS\nnameserver {dns}\n");
    for line in host.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("search" | "domain" | "sortlist") => {
                out.push_str(line);
                out.push('\n');
            }
            Some("options") => {
                let kept: Vec<&str> = words.filter(|w| !w.starts_with("ndots:")).collect();
                if !kept.is_empty() {
                    out.push_str(&format!("options {}\n", kept.join(" ")));
                }
            }
            _ => {}
        }
    }
    out
}

/// A private temporary directory, removed with everything in it on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    pub fn new_in(base: &Path) -> Result<Self> {
        let template = base.join("proxytun-XXXXXX");
        let mut raw = CString::new(template.as_os_str().as_encoded_bytes())?.into_bytes_with_nul();
        // SAFETY: a writable NUL-terminated template, as mkdtemp requires.
        if unsafe { libc::mkdtemp(raw.as_mut_ptr() as *mut libc::c_char) }.is_null() {
            bail!("mkdtemp {}: {}", template.display(), std::io::Error::last_os_error());
        }
        raw.pop();
        Ok(TempDir(PathBuf::from(OsString::from_vec(raw))))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// argv[1] that makes proxytun run as the namespace setup process.
pub const SETUP_ARG: &str = "__proxytun_setup";

/// What the setup process needs; passed on its command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Setup {
    pub argv: Vec<OsString>,
    pub fake_range: Ipv4Net,
    /// Host loopback listeners to bind inside (see hostports.rs).
    pub forwards: Vec<SocketAddr>,
}

/// `a,b,c`, or `-` for none (an empty argument is easy to lose).
pub fn join_list<T: Display>(items: &[T]) -> String {
    if items.is_empty() {
        return "-".into();
    }
    items.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")
}

/// The items `join_list` wrote; `None` if any does not parse.
pub fn split_list<T: FromStr>(s: &str) -> Option<Vec<T>> {
    if s == "-" {
        return Some(Vec::new());
    }
    s.split(',').map(|a| a.parse().ok()).collect()
}

impl Setup {
    /// `proxytun SETUP_ARG <ctl fd> <fake range> <forwards> -- argv...`
    fn to_args(&self, exe: &str, ctl: RawFd) -> Vec<OsString> {
        let mut a: Vec<OsString> = [
            exe.to_string(),
            SETUP_ARG.to_string(),
            ctl.to_string(),
            self.fake_range.to_string(),
            join_list(&self.forwards),
            "--".to_string(),
        ]
        .map(OsString::from)
        .into();
        a.extend(self.argv.iter().cloned());
        a
    }

    fn from_args(args: &[OsString]) -> Option<(Setup, RawFd)> {
        let [_, mode, ctl, range, forwards, dashes, argv @ ..] = args else {
            return None;
        };
        if mode != SETUP_ARG || dashes != "--" || argv.is_empty() {
            return None;
        }
        let setup = Setup {
            argv: argv.to_vec(),
            fake_range: range.to_str()?.parse().ok()?,
            forwards: split_list(forwards.to_str()?)?,
        };
        Some((setup, ctl.to_str()?.parse().ok()?))
    }
}

/// The started program, still waiting for `go`.
pub struct Child {
    pub pid: libc::pid_t,
    ctl: OwnedFd,
}

impl Child {
    pub fn new(pid: libc::pid_t, ctl: OwnedFd) -> Child {
        Child { pid, ctl }
    }

    /// Let the program run: its packets are being served now.
    pub fn go(&self) -> Result<()> {
        // SAFETY: plain write of one byte on a socket we own.
        if unsafe { libc::write(self.ctl.as_raw_fd(), b"G".as_ptr() as *const _, 1) } != 1 {
            bail!("starting the program: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Creating the namespace failed for lack of usable user namespaces (disabled,
/// limited to 0, or stripped of capabilities by an LSM): sudo may help.
#[derive(Debug)]
pub struct UsernsUnusable(pub String);

impl std::fmt::Display for UsernsUnusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "user namespaces are not usable here: {}", self.0)
    }
}

impl std::error::Error for UsernsUnusable {}

/// What a successful setup hands over.
pub struct Handover {
    pub tun: OwnedFd,
    /// Where captured TCP is rewritten to.
    pub listener: TcpListener,
    /// Host ports bound inside, each with its listener (a bind that failed,
    /// e.g. [::1] without IPv6, is simply missing).
    pub forwards: Vec<(SocketAddr, TcpListener)>,
    /// The rest of the report (the sudo helper's `pid=... pgrp=...`).
    pub report: String,
}

/// The most fds one SCM_RIGHTS message carries (the kernel's SCM_MAX_FD).
pub const SCM_MAX_FDS: usize = 253;

/// Send `msg` on `ctl` as one message, with `fds` (SCM_RIGHTS; none, no
/// control message at all).
pub fn send_with_fds(ctl: &OwnedFd, msg: &[u8], fds: &[RawFd]) -> Result<()> {
    let rights = [ControlMessage::ScmRights(fds)];
    let cmsgs: &[ControlMessage] = if fds.is_empty() { &[] } else { &rights };
    sendmsg::<()>(ctl.as_raw_fd(), &[IoSlice::new(msg)], cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

/// One message from `ctl` into `buf`, with the fds it carries (close-on-exec,
/// at most `SCM_MAX_FDS`). A message or fd list that did not fit is an error,
/// not something to act on in part.
pub fn recv_with_fds(ctl: &OwnedFd, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>)> {
    let mut cmsg = nix::cmsg_space!([RawFd; SCM_MAX_FDS]);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(ctl.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC)?;
    let mut fds = Vec::new();
    for c in msg.cmsgs().context("reading passed fds")? {
        if let ControlMessageOwned::ScmRights(r) = c {
            // SAFETY: the kernel just installed these fds for us.
            fds.extend(r.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
        }
    }
    ensure!(
        !msg.flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC),
        "message truncated"
    );
    Ok((msg.bytes, fds))
}

/// Read the setup's answer on `ctl`. `pid` is reaped on failure.
pub fn recv_setup(ctl: &OwnedFd, pid: Option<libc::pid_t>) -> Result<Handover> {
    let mut buf = vec![0u8; 16 * 1024];
    let (n, fds) = recv_with_fds(ctl, &mut buf).context("waiting for the namespace setup")?;
    let reply = String::from_utf8_lossy(&buf[..n]).into_owned();
    let ok = reply.strip_prefix("OK ").and_then(|rest| {
        let mut forwards = None;
        let mut report = Vec::new();
        for token in rest.split(' ') {
            match token.strip_prefix("fwd=") {
                Some(list) => forwards = Some(split_list(list)?),
                None => report.push(token),
            }
        }
        let forwards = forwards?;
        (fds.len() == 2 + forwards.len()).then_some((forwards, report.join(" ")))
    });
    match ok {
        Some((forwards, report)) => {
            let mut fds = fds.into_iter();
            let tun = fds.next().expect("counted");
            let listener = TcpListener::from(fds.next().expect("counted"));
            let forwards = forwards.into_iter().zip(fds.map(TcpListener::from)).collect();
            Ok(Handover {
                tun,
                listener,
                forwards,
                report,
            })
        }
        None => {
            if let Some(pid) = pid {
                reap(pid);
            }
            if let Some(why) = reply.strip_prefix("ERR userns ") {
                return Err(UsernsUnusable(why.to_string()).into());
            }
            match reply.strip_prefix("ERR ") {
                Some(why) => bail!("{why}"),
                None => bail!("namespace setup failed (the setup process exited)"),
            }
        }
    }
}

/// Report a failed setup on `ctl` (the "ERR" answer `recv_setup` reads).
pub fn send_error(ctl: &OwnedFd, e: &SetupError) {
    let msg = format!("ERR {}{:#}", if e.userns { "userns " } else { "" }, e.err);
    let _ = send_with_fds(ctl, msg.as_bytes(), &[]);
}

/// Hand the namespace over on `ctl`, with `report` appended for the reader.
pub fn send_ok(ctl: &OwnedFd, ns: &Namespace, report: &str) -> Result<()> {
    let bound: Vec<SocketAddr> = ns.forwards.iter().map(|(a, _)| *a).collect();
    let mut msg = format!("OK fwd={}", join_list(&bound));
    if !report.is_empty() {
        msg.push(' ');
        msg.push_str(report);
    }
    let mut fds = vec![ns.tun.as_raw_fd(), ns.listener.as_raw_fd()];
    fds.extend(ns.forwards.iter().map(|(_, l)| l.as_raw_fd()));
    send_with_fds(ctl, msg.as_bytes(), &fds).context("handing the namespace over")
}

/// Start the setup process for the program and wait for its namespace; the
/// program itself waits for `Child::go` before exec. Returns it with the TUN
/// device and the listener for captured TCP.
pub fn spawn(s: &Setup) -> Result<(Child, Handover)> {
    if s.argv.is_empty() {
        bail!("no program given");
    }
    let (ours, theirs) =
        socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC).context("socketpair")?;
    // Everything the child needs is prepared here: between fork and exec it
    // only makes async-signal-safe calls.
    let exe = c"/proc/self/exe";
    let args: Vec<CString> = s
        .to_args("proxytun", theirs.as_raw_fd())
        .into_iter()
        .map(|a| CString::new(a.into_vec()).context("argument contains NUL"))
        .collect::<Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let msg = b"proxytun: cannot re-execute itself for the namespace setup\n";
    let sigpipe = sigpipe_disposition(sigpipe_was_ignored());

    // SAFETY: the child only calls fcntl, signal, execv, write and _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            // Our end of the socketpair must survive the exec; theirs (CLOEXEC) goes.
            libc::fcntl(theirs.as_raw_fd(), libc::F_SETFD, 0);
            // The caller's SIGPIPE, for the setup process to find at its
            // start (and give the program) instead of our runtime's.
            libc::signal(libc::SIGPIPE, sigpipe);
            libc::execv(exe.as_ptr(), ptrs.as_ptr());
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::_exit(127);
        }
    }
    drop(theirs);
    let handover = recv_setup(&ours, Some(pid))?;
    Ok((Child { pid, ctl: ours }, handover))
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: plain syscall.
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// Entry point of the setup process (`proxytun SETUP_ARG ...`). Never
/// returns: it becomes the program, or exits with 125-127 on failure.
pub fn setup_main(args: &[OsString]) -> ! {
    let Some((s, ctl)) = Setup::from_args(args) else {
        eprintln!("proxytun: {SETUP_ARG} is internal to proxytun");
        std::process::exit(2);
    };
    // SAFETY: proxytun passed us this fd for exactly this purpose.
    let ctl = unsafe { OwnedFd::from_raw_fd(ctl) };
    // SAFETY: plain fcntl; the program must not inherit the socket.
    unsafe { libc::fcntl(ctl.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    // Run as root (proxytun started by root): the program stays root, so no
    // user namespace, which would confine its capabilities to the namespace.
    let userns = !nix::unistd::geteuid().is_root();
    let ns = match setup_namespace(s.fake_range, userns, &s.forwards) {
        Ok(v) => v,
        Err(e) => {
            send_error(&ctl, &e);
            std::process::exit(126);
        }
    };
    if send_ok(&ctl, &ns, "").is_err() {
        std::process::exit(126);
    }
    drop(ns);
    wait_go(&ctl);
    drop(ctl);
    std::process::exit(exec(&s.argv, sigpipe_was_ignored()))
}

/// Block until proxytun serves the TUN device; exit if it went away instead.
pub fn wait_go(ctl: &OwnedFd) {
    let mut go = [0u8; 1];
    // SAFETY: plain read into a local buffer.
    if unsafe { libc::read(ctl.as_raw_fd(), go.as_mut_ptr() as *mut _, 1) } != 1 {
        std::process::exit(125);
    }
}

/// A failed namespace setup; `userns` = the failure is a lack of usable user
/// namespaces, which sudo may get around.
pub struct SetupError {
    pub userns: bool,
    pub err: anyhow::Error,
}

/// EPERM / EACCES anywhere in the chain: a capability the user namespace
/// lacks, unless the host refused the step outright.
fn blames_userns(e: &anyhow::Error) -> bool {
    e.downcast_ref::<netcfg::HostRefused>().is_none()
        && e.chain().any(|c| {
            let code = c
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.raw_os_error())
                .or_else(|| c.downcast_ref::<nix::errno::Errno>().map(|e| *e as i32));
            matches!(code, Some(libc::EPERM | libc::EACCES))
        })
}

/// A namespace ready to serve, as created by the setup process.
pub struct Namespace {
    pub tun: OwnedFd,
    pub listener: TcpListener,
    pub forwards: Vec<(SocketAddr, TcpListener)>,
}

/// Create the namespace (in this process) with the TUN device, the listener
/// and the host-port listeners. With `userns`, inside a new user namespace
/// mapping our uid/gid to themselves (needs no privilege); without, as root.
pub fn setup_namespace(
    range: Ipv4Net,
    userns: bool,
    forwards: &[SocketAddr],
) -> std::result::Result<Namespace, SetupError> {
    enter_namespace(userns)?;
    configure_namespace(range, userns, forwards)
}

/// Move this process into new, still empty namespaces (see `setup_namespace`).
pub fn enter_namespace(userns: bool) -> std::result::Result<(), SetupError> {
    if userns {
        enter_user_namespace().map_err(|err| SetupError { userns: true, err })
    } else {
        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)
            .context("create network and mount namespaces")
            .map_err(|err| SetupError { userns: false, err })
    }
}

/// Fill the namespaces `enter_namespace` made: the TUN device, the listener
/// and the host-port listeners.
pub fn configure_namespace(
    range: Ipv4Net,
    userns: bool,
    forwards: &[SocketAddr],
) -> std::result::Result<Namespace, SetupError> {
    // A user namespace whose capabilities an LSM withholds (Ubuntu's AppArmor
    // restriction) fails here instead, with EPERM.
    let (tun, listener) = configure(range).map_err(|err| SetupError {
        userns: userns && blames_userns(&err),
        err,
    })?;
    // Bound now, while we may (ports below 1024 too). One that cannot be bound
    // (no IPv6 inside) is left out; proxytun lists what was.
    let forwards = forwards
        .iter()
        .filter_map(|a| Some((*a, netcfg::listen(*a).ok()?)))
        .collect();
    Ok(Namespace {
        tun,
        listener,
        forwards,
    })
}

fn enter_user_namespace() -> Result<()> {
    let (uid, gid) = (nix::unistd::getuid(), nix::unistd::getgid());
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)
        .map_err(|e| anyhow!("cannot create a user namespace: {e}"))?;
    // setgroups must be denied before an unprivileged gid_map write (the file
    // does not exist before Linux 3.19, nor does the rule).
    match std::fs::write("/proc/self/setgroups", "deny") {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e).context("write /proc/self/setgroups"),
        _ => {}
    }
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).context("write /proc/self/uid_map")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).context("write /proc/self/gid_map")?;
    Ok(())
}

fn configure(range: Ipv4Net) -> Result<(OwnedFd, TcpListener)> {
    let addrs = Addrs::new(range);
    private_resolv_conf(addrs.dns)?;
    netcfg::link_up(c"lo").context("bring lo up")?;
    let tun = netcfg::create_tun(TUN_NAME)?;
    netcfg::set_addr(TUN_NAME, addrs.tun, Addrs::PREFIX, MTU).context("configure tun0")?;
    netcfg::link_up(TUN_NAME)?;
    netcfg::default_route(TUN_NAME)?;
    raise_somaxconn();
    let listener = netcfg::listen(SocketAddrV4::new(addrs.tun, 0).into())?;
    Ok((tun, listener))
}

/// Before Linux 5.4 a new network namespace starts with somaxconn 128,
/// whatever the host has, and cuts our listen backlog of 4096 to it: a burst
/// of connections then waits out SYN retransmits. Only root may raise it
/// (root and sudo modes); in a user namespace this quietly does nothing.
fn raise_somaxconn() {
    const PATH: &str = "/proc/sys/net/core/somaxconn";
    let now: Option<u32> = std::fs::read_to_string(PATH).ok().and_then(|s| s.trim().parse().ok());
    if now.is_some_and(|n| n < netcfg::BACKLOG) {
        let _ = std::fs::write(PATH, netcfg::BACKLOG.to_string());
    }
}

/// Point /etc/resolv.conf at `dns` in our own mount namespace. The file is
/// written here, by whoever sets up the namespace (root, for sudo), never
/// taken from a path someone else chose. Mount events must not propagate
/// back to the host: see `propagation`.
fn private_resolv_conf(dns: Ipv4Addr) -> Result<()> {
    use nix::mount::{mount, MsFlags};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let host = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    // As root, never under $TMPDIR: a directory the user controls would let
    // them swap ours for a link to /etc between our creating and writing it.
    // In the sticky /tmp nobody but us can rename our directory.
    let base = if nix::unistd::geteuid().is_root() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    let dir = TempDir::new_in(&base)?;
    let file = dir.path().join("resolv.conf");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(&file)
        .context("create resolv.conf")?;
    f.write_all(resolv_conf(&host, dns).as_bytes())
        .context("write resolv.conf")?;
    // Through the fd, whatever the umask: readable by the program.
    f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | propagation(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default()),
        None::<&str>,
    )
    .context("cut mount propagation to the host")?;
    // The target may be a symlink (systemd-resolved, WSL): mount follows it.
    // The mount keeps the file alive after `dir` is removed.
    mount(
        Some(&file),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind-mount /etc/resolv.conf")
}

/// Was SIGPIPE ignored when this process image started, as whoever started
/// it left it? Rust's runtime ignores it for itself before `main`; only a
/// constructor, run before the runtime, still sees the caller's.
static SIGPIPE_WAS_IGNORED: AtomicBool = AtomicBool::new(false);

extern "C" fn note_sigpipe() {
    // SAFETY: reads the disposition into a local struct.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut old) == 0 {
            SIGPIPE_WAS_IGNORED.store(old.sa_sigaction == libc::SIG_IGN, Ordering::Relaxed);
        }
    }
}

#[used]
#[link_section = ".init_array"]
static NOTE_SIGPIPE: extern "C" fn() = note_sigpipe;

/// SIGPIPE as our caller left it: ignored (`trap '' PIPE`), or not.
pub fn sigpipe_was_ignored() -> bool {
    SIGPIPE_WAS_IGNORED.load(Ordering::Relaxed)
}

fn sigpipe_disposition(ignored: bool) -> libc::sighandler_t {
    if ignored {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    }
}

/// How our mounts relate to the host's, on kernel `release`: slave, so the
/// host's later mounts reach us (an automounted share, a USB disk) and ours
/// never reach the host. Before Linux 4.11 a mount propagated onto
/// /etc/resolv.conf (a VPN script binding its own there) would go on top of
/// ours, and the program would bypass our DNS; since, it goes underneath.
/// There: private, the host's later mounts staying out.
fn propagation(release: &str) -> nix::mount::MsFlags {
    match crate::procfs::parse_kernel(release) {
        Some(v) if v >= (4, 11) => nix::mount::MsFlags::MS_SLAVE,
        _ => nix::mount::MsFlags::MS_PRIVATE,
    }
}

/// Become the program. Undo what our runtime changed, as std::process::Command
/// does: Rust ignores SIGPIPE at startup, and an ignored disposition survives
/// exec, so it goes back to what the caller had (`sigpipe_ignored`, see
/// `sigpipe_was_ignored`); proxytun blocked some signals for its signalfd.
/// Other signals the caller ignored (nohup, `cmd &`) stay ignored by
/// themselves: dispositions survive both execs and proxytun installs its
/// own handlers only after the fork.
pub fn exec(argv: &[OsString], sigpipe_ignored: bool) -> i32 {
    let argv: Vec<CString> = match argv.iter().map(|a| CString::new(a.as_bytes())).collect() {
        Ok(v) => v,
        Err(_) => return 127, // checked by proxytun before we got here
    };
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: plain syscalls on prepared, NUL-terminated buffers.
    unsafe {
        libc::signal(libc::SIGPIPE, sigpipe_disposition(sigpipe_ignored));
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    eprintln!(
        "proxytun: cannot execute {:?}: {}",
        argv[0],
        std::io::Error::last_os_error()
    );
    127
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_addresses_sit_in_the_last_slash_24_of_the_fake_range() {
        let a = Addrs::new("198.18.0.0/15".parse().unwrap());
        assert_eq!(
            (a.tun, a.nat, a.dns),
            (
                Ipv4Addr::new(198, 19, 255, 1),
                Ipv4Addr::new(198, 19, 255, 2),
                Ipv4Addr::new(198, 19, 255, 53)
            )
        );
        let a = Addrs::new("10.20.0.0/22".parse().unwrap());
        assert_eq!(a.tun, Ipv4Addr::new(10, 20, 3, 1));
    }

    #[test]
    fn host_mounts_come_in_only_where_they_cannot_cover_our_resolv_conf() {
        use nix::mount::MsFlags;
        assert_eq!(propagation("6.18.54.1-microsoft-standard-WSL2"), MsFlags::MS_SLAVE);
        assert_eq!(propagation("4.11.0"), MsFlags::MS_SLAVE);
        assert_eq!(propagation("4.10.17"), MsFlags::MS_PRIVATE);
        assert_eq!(propagation("3.10.0-1160.el7.x86_64"), MsFlags::MS_PRIVATE, "CentOS 7");
        assert_eq!(propagation(""), MsFlags::MS_PRIVATE, "unknown: the safe one");
    }

    #[test]
    fn setup_arguments_round_trip() {
        let s = Setup {
            argv: vec!["curl".into(), "--".into(), "-x".into(), "a b".into()],
            fake_range: "198.18.0.0/15".parse().unwrap(),
            forwards: vec!["127.0.0.1:5432".parse().unwrap(), "[::1]:8080".parse().unwrap()],
        };
        let args = s.to_args("proxytun", 7);
        assert_eq!(Setup::from_args(&args), Some((s, 7)));
        let none = Setup {
            argv: vec!["true".into()],
            fake_range: "10.0.0.0/8".parse().unwrap(),
            forwards: vec![],
        };
        assert_eq!(Setup::from_args(&none.to_args("p", 3)), Some((none, 3)));
        assert_eq!(Setup::from_args(&["p".into(), SETUP_ARG.into()]), None, "truncated");
        let odd = Setup {
            argv: vec!["cat".into(), OsString::from_vec(b"\xc4\xe3.txt".to_vec())],
            fake_range: "10.0.0.0/8".parse().unwrap(),
            forwards: vec![],
        };
        assert_eq!(Setup::from_args(&odd.to_args("p", 3)), Some((odd, 3)), "not UTF-8");
    }

    #[test]
    fn lists_are_comma_separated_or_a_dash_for_none() {
        assert_eq!(join_list::<RawFd>(&[]), "-");
        assert_eq!(join_list(&[3, 7, 250]), "3,7,250");
        assert_eq!(split_list::<RawFd>("-"), Some(vec![]));
        assert_eq!(split_list::<RawFd>("3,7,250"), Some(vec![3, 7, 250]));
        for bad in ["", "3,", ",3", "3,,7", "3;7", "-,3"] {
            assert_eq!(split_list::<RawFd>(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn resolv_conf_keeps_search_and_options_but_only_our_nameserver() {
        let host = "# generated by WSL\nnameserver 172.25.32.1\nnameserver 8.8.8.8\nsearch corp.example lan\n\
                    options edns0 trust-ad\ndomain corp.example\n";
        let ours = resolv_conf(host, Ipv4Addr::new(198, 19, 255, 53));
        let lines: Vec<&str> = ours.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                "nameserver 198.19.255.53",
                "search corp.example lan",
                "options edns0 trust-ad",
                "domain corp.example"
            ]
        );
        // A Kubernetes pod's: with ndots 5, github.com would be tried as
        // github.com.default.svc.cluster.local first, and our DNS answers
        // that too. The other options stay.
        let pod = "nameserver 10.96.0.10\nsearch default.svc.cluster.local svc.cluster.local cluster.local\n\
                   options ndots:5 timeout:2\noptions ndots:3\n";
        let ours = resolv_conf(pod, Ipv4Addr::new(198, 19, 255, 53));
        let lines: Vec<&str> = ours.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                "nameserver 198.19.255.53",
                "search default.svc.cluster.local svc.cluster.local cluster.local",
                "options timeout:2"
            ]
        );
    }

    #[test]
    fn only_a_capability_the_user_namespace_lacks_sends_us_to_sudo() {
        let io = |code| anyhow::Error::new(std::io::Error::from_raw_os_error(code));
        // Refused inside the user namespace (Ubuntu's AppArmor restriction).
        assert!(blames_userns(&io(libc::EPERM).context("TUNSETIFF")));
        assert!(blames_userns(
            &anyhow::Error::new(nix::errno::Errno::EPERM).context("mount")
        ));
        // The host's own refusals, however deep: sudo must not get around them.
        assert!(!blames_userns(
            &io(libc::EACCES)
                .context(netcfg::HostRefused("open /dev/net/tun"))
                .context("configure")
        ));
        assert!(!blames_userns(&io(libc::ENOENT).context("TUNSETIFF")));
    }
}
