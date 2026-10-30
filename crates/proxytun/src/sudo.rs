//! sudo mode, for hosts without usable user namespaces (CentOS 7): a
//! short-lived root helper, started through sudo, creates the namespace and
//! starts the program as the user who ran proxytun, then exits.
//!
//! proxytun listens on a unix socket in a private (0700) directory and runs
//! `sudo -- <proxytun> HELPER_ARG <socket>` (sudo closes inherited fds, hence
//! the socket path). The helper, as root:
//!   * serves only the user sudo was run by: the socket's owner must be
//!     SUDO_UID, and the program's gid and groups are read from that process
//!     in /proc (kernel-provided), never from the request;
//!   * reads no config and opens no path the user chose: the request carries
//!     only the fake-ip range, the argv, the environment and four fds (stdin,
//!     stdout, stderr, working directory);
//!   * forks the program, puts it in proxytun's process group, and has it drop
//!     to the user (groups, gid, uid; no capability may survive), take the
//!     user's stdio, directory and environment, and wait for the go-ahead;
//!   * hands the TUN device and listener back and exits: from then on no
//!     process of ours runs as root.

use crate::netns::{self, Child, Setup, TempDir};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use nix::sys::socket::{
    accept4, bind, connect, getsockopt, listen, recvmsg, sendmsg, socket, sockopt, AddressFamily, Backlog,
    ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, UnixAddr,
};
use std::ffi::{CString, OsString};
use std::io::{IoSlice, IoSliceMut};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
    argv: Vec<String>,
    env: Vec<OsString>,
}

impl Request {
    /// NUL-separated: version, range, pgrp, argc, argv..., env...
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut field = |b: &[u8]| {
            out.extend_from_slice(b);
            out.push(0);
        };
        field(b"1");
        field(self.fake_range.to_string().as_bytes());
        field(self.pgrp.to_string().as_bytes());
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
        let argc: usize = text()?.parse().ok()?;
        let argv = (0..argc).map(|_| text()).collect::<Option<Vec<_>>>()?;
        if argv.is_empty() {
            return None;
        }
        let env = fields.map(|e| OsString::from_vec(e.to_vec())).collect();
        Some(Request {
            fake_range,
            pgrp,
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
fn identity(sudo_uid: Option<&str>, peer_uid: u32, peer_gid: u32, peer_status: &str) -> Result<Identity> {
    let sudo_uid: u32 = sudo_uid
        .ok_or_else(|| anyhow!("SUDO_UID is not set: run proxytun as a normal user, it calls sudo itself"))?
        .parse()
        .context("SUDO_UID is not a number")?;
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
/// waiting program, the TUN device, the listener, and whether the program
/// could join our process group (not when sudo gave it a terminal session
/// of its own: `use_pty`).
pub fn spawn(s: &Setup) -> Result<(Child, OwnedFd, TcpListener, bool)> {
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
    let (report, tun, listener) = netns::recv_setup(&ctl, None)?;
    let (pid, joined) = report
        .split_once(' ')
        .and_then(|(p, j)| Some((p.parse().ok()?, j == "joined")))
        .ok_or_else(|| anyhow!("bad report from the helper: {report:?}"))?;
    drop(dir);
    Ok((Child::new(pid, ctl), tun, listener, joined))
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

fn helper(args: &[String]) -> Result<()> {
    let [_, mode, path] = args else {
        bail!("{HELPER_ARG} is internal to proxytun");
    };
    ensure!(mode == HELPER_ARG, "{HELPER_ARG} is internal to proxytun");
    ensure!(
        nix::unistd::geteuid().is_root(),
        "the helper must run as root (through sudo)"
    );
    let ctl = seqpacket(SockFlag::empty())?;
    connect(ctl.as_raw_fd(), &UnixAddr::new(path.as_str())?).context("connect to proxytun")?;
    let cred = getsockopt(&ctl, sockopt::PeerCredentials).context("SO_PEERCRED")?;
    let status = std::fs::read_to_string(format!("/proc/{}/status", cred.pid())).unwrap_or_default();
    let who = identity(
        std::env::var("SUDO_UID").ok().as_deref(),
        cred.uid(),
        cred.gid(),
        &status,
    );
    let who = match who {
        Ok(w) => w,
        Err(e) => {
            netns::send_error(
                &ctl,
                &netns::SetupError {
                    userns: false,
                    err: anyhow!("sudo helper: {e:#}"),
                },
            );
            return Err(e);
        }
    };

    let mut buf = vec![0u8; 1 << 20];
    let mut cmsg = nix::cmsg_space!([RawFd; 4]);
    let (n, fds) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(ctl.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC)
            .context("read the request")?;
        let mut fds = Vec::new();
        for c in msg.cmsgs().context("reading passed fds")? {
            if let ControlMessageOwned::ScmRights(r) = c {
                // SAFETY: the kernel just installed these fds for us.
                fds.extend(r.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
            }
        }
        (msg.bytes, fds)
    };
    let req = Request::decode(&buf[..n]).ok_or_else(|| anyhow!("malformed request"))?;
    let [stdin, stdout, stderr, cwd]: [OwnedFd; 4] = fds.try_into().map_err(|_| anyhow!("expected 4 fds"))?;

    let (tun, listener) = match netns::setup_namespace(req.fake_range, false) {
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
        drop((tun, listener));
        let why = prepared.become_user(&who, [&stdin, &stdout, &stderr], &cwd, &ctl, &req.argv);
        // Only reached on failure; stderr is the user's by now, or ours.
        eprintln!("proxytun (sudo helper): {why}");
        unsafe { libc::_exit(126) };
    }
    // Join proxytun's group. Safe from the parent alone: the child cannot exec
    // (and so make setpgid fail) before the go-ahead, which follows our report.
    // SAFETY: plain syscall.
    let joined = unsafe { libc::setpgid(pid, req.pgrp) } == 0 || crate::witness::pgrp_of(pid) == Some(req.pgrp);
    netns::send_ok(
        &ctl,
        &tun,
        &listener,
        &format!("{pid} {}", if joined { "joined" } else { "alone" }),
    )?;
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
            argv: vec!["true".into()],
            env: vec![],
        };
        assert_eq!(Request::decode(&no_env.encode()), Some(no_env));
        assert_eq!(Request::decode(b"2\0x\0"), None, "unknown version");
        assert_eq!(Request::decode(b"1\x0010.0.0.0/8\x001\x000\0"), None, "no program");
        assert_eq!(
            Request::decode(b"1\x0010.0.0.0/8\x001\x005\0a\0"),
            None,
            "argv cut short"
        );
    }

    const STATUS: &str =
        "Name:\tproxytun\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t4 27 1000 \n";

    #[test]
    fn the_program_runs_as_the_user_sudo_was_run_by_with_their_groups() {
        assert_eq!(
            identity(Some("1000"), 1000, 1000, STATUS).unwrap(),
            Identity {
                uid: 1000,
                gid: 1000,
                groups: vec![4, 27, 1000]
            }
        );
        let no_groups = STATUS.replace("Groups:\t4 27 1000 ", "Groups:\t");
        assert_eq!(
            identity(Some("1000"), 1000, 1000, &no_groups).unwrap().groups,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn the_helper_refuses_anyone_but_the_sudo_caller() {
        let err = |r: Result<Identity>| r.unwrap_err().to_string();
        assert!(err(identity(None, 1000, 1000, STATUS)).contains("SUDO_UID"));
        assert!(err(identity(Some("1001"), 1000, 1000, STATUS)).contains("sudo was run by uid 1001"));
        assert!(err(identity(Some("0"), 0, 0, &STATUS.replace("1000", "0"))).contains("root"));
        // The pid behind the socket now belongs to someone else (or nobody).
        assert!(err(identity(
            Some("1000"),
            1000,
            1000,
            &STATUS.replace("Uid:\t1000", "Uid:\t1001")
        ))
        .contains("gone"));
        assert!(err(identity(Some("1000"), 1000, 1000, "")).contains("gone"));
    }
}
