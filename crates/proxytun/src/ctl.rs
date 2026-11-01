//! The control channel between proxytun and whoever builds the namespace (the
//! setup process; in sudo mode the root helper and the program side it
//! forks): one SOCK_SEQPACKET socket. The builder answers with one message,
//! `OK fwd=<host ports bound> [report]` with the TUN device, the capture
//! listener and the host-port listeners attached (SCM_RIGHTS), or
//! `ERR [userns ]<why>`; the program then waits on the same socket for
//! proxytun's one-byte go-ahead. In sudo mode proxytun's request goes the
//! other way on it first.

use anyhow::{bail, ensure, Context, Result};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::fmt::Display;
use std::io::{IoSlice, IoSliceMut};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::str::FromStr;

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

/// A failed namespace setup; `userns` = the failure is a lack of usable user
/// namespaces, which sudo may get around.
pub struct SetupError {
    pub userns: bool,
    pub err: anyhow::Error,
}

/// A namespace ready to serve, as created by the setup process.
pub struct Namespace {
    pub tun: OwnedFd,
    pub listener: TcpListener,
    pub forwards: Vec<(SocketAddr, TcpListener)>,
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

/// Read the setup's answer on `ctl`.
pub fn recv_setup(ctl: &OwnedFd) -> Result<Handover> {
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
            if reply.starts_with("OK ") {
                // Answered, so still there: waiting for the go-ahead.
                bail!(
                    "namespace setup answered wrongly: {reply:?}, fds attached: {}",
                    fds.len()
                );
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

/// Block until proxytun serves the TUN device; exit if it went away instead.
pub fn wait_go(ctl: &OwnedFd) {
    let mut go = [0u8; 1];
    // SAFETY: plain read into a local buffer.
    if unsafe { libc::read(ctl.as_raw_fd(), go.as_mut_ptr() as *mut _, 1) } != 1 {
        std::process::exit(125);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ok_without_the_fds_it_lists_is_refused_as_a_wrong_answer_not_an_exit() {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        let pair = || socketpair(AddressFamily::Unix, SockType::SeqPacket, None, SockFlag::SOCK_CLOEXEC).unwrap();
        let (ours, theirs) = pair();
        let (a, _b) = pair();
        // One fd where the TUN device and the listener make two.
        send_with_fds(&theirs, b"OK fwd=-", &[a.as_raw_fd()]).unwrap();
        let e = recv_setup(&ours).err().expect("refused").to_string();
        assert!(e.contains("answered wrongly") && e.ends_with("fds attached: 1"), "{e}");
        assert!(!e.contains("exited"), "{e}");
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
}
