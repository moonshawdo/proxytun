//! sudo mode, for hosts without usable user namespaces (CentOS 7): a
//! short-lived root helper, started through sudo, creates the namespace and
//! starts the program as the user who ran proxytun, then exits.
//!
//! proxytun listens on a unix socket in a private (0700) directory and runs
//! `sudo -- <proxytun> HELPER_ARG <socket>` (sudo closes inherited fds, hence
//! the socket path), with the first setuid-root sudo on PATH, never a
//! wrapper (`client::find_sudo`). The helper, as root:
//!   * runs only when started by sudo (real and effective uid 0), never setuid;
//!   * reaches the socket as the caller (effective uid and gid theirs, so
//!     whatever listens there sees them, not root), and serves only the
//!     process that ran sudo: the socket's creator must be one of its own
//!     ancestors (alive, so its pid cannot have been reused) and belong to
//!     SUDO_UID; the program's uid and gid are the socket's credentials
//!     (SO_PEERCRED) and its groups are read from that process in /proc
//!     (all kernel-provided), never from the request;
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
//!   * gives up after `helper::HELPER_TIMEOUT` (and a little) on a client,
//!     or a program side, that does not talk;
//!   * fills the namespaces, puts the program in proxytun's process group
//!     (or, when sudo gave it a terminal session of its own, `use_pty`, has
//!     it leave that session before it ends and hangs the program up),
//!     hands the TUN device and listener back and exits: from then on no
//!     process of ours runs as root. The program takes the user's umask,
//!     stdio, directory and environment, waits for the go-ahead, and puts
//!     the inherited fds back at their numbers.

mod client;
mod helper;
mod program;

pub use client::{find_sudo, spawn};
pub use helper::helper_main;

use crate::ctl::{join_list, split_list, SCM_MAX_FDS};
use anyhow::{ensure, Context, Result};
use ipnet::Ipv4Net;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::ffi::OsString;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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
        field(join_list(&self.forwards).as_bytes());
        field(format!("{:o}", self.umask).as_bytes());
        field(if self.sigpipe_ignored { b"1" } else { b"0" });
        field(join_list(&self.inherit).as_bytes());
        // The count is what tells `decode` where argv ends and the environment
        // begins: items of either may be empty or hold any byte but NUL.
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
        // Every field ends in NUL (see `encode`): drop the last one, split on the rest.
        let mut fields = b.strip_suffix(&[0])?.split(|&c| c == 0);
        // The fixed fields are UTF-8 text; argv and env are taken as raw bytes.
        let mut text = || std::str::from_utf8(fields.next()?).ok().map(str::to_owned);
        if text()? != "3" {
            return None;
        }
        let fake_range = text()?.parse().ok()?;
        let pgrp = text()?.parse().ok()?;
        let forwards = split_list(&text()?)?;
        let umask = libc::mode_t::from_str_radix(&text()?, 8).ok()?;
        let sigpipe_ignored = match text()?.as_str() {
            "1" => true,
            "0" => false,
            _ => return None,
        };
        let inherit = split_list(&text()?)?;
        let argc: usize = text()?.parse().ok()?;
        let argv: Vec<OsString> = (0..argc)
            .map(|_| fields.next().map(|a| OsString::from_vec(a.to_vec())))
            .collect::<Option<_>>()?;
        // `netns::exec` needs a program name in argv[0].
        if argv.is_empty() {
            return None;
        }
        // Whatever follows argv is the environment, `KEY=VALUE` each.
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

/// One SCM_RIGHTS message carries them all; four are stdio and the working
/// directory.
const MAX_INHERIT: usize = SCM_MAX_FDS - 4;

/// The longest request: the environment and argv of a program, as one
/// message.
const REQUEST_MAX: usize = 1 << 20;

fn set_timeouts(fd: &OwnedFd, t: Duration) -> Result<()> {
    // Blocking receives and sends on the socket (connect included) give up
    // after `t`; zero means wait forever. They belong to the socket, so every
    // fd sharing it (a forked child's too) sees the same ones.
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

    #[test]
    fn root_mode_is_refused_through_sudo_or_setuid() {
        assert_eq!(root_refusal(1000, 1000, true), None, "not root: nothing to refuse");
        assert_eq!(root_refusal(0, 0, false), None, "root itself");
        assert!(root_refusal(1000, 0, false).unwrap().contains("setuid"));
        assert!(root_refusal(0, 0, true).unwrap().contains("through sudo"));
    }
}
