//! sudo mode, proxytun's side, run as the user: the private socket, sudo
//! started on it, and the request and fds sent to the program side.

use super::{seqpacket, Request, HELPER_ARG, MAX_INHERIT};
use crate::ctl::{recv_setup, send_with_fds, Child, Handover, SETUP_TIMEOUT};
use crate::netns::{self, Setup, TempDir};
use anyhow::{anyhow, bail, ensure, Context, Result};
use nix::sys::socket::{accept4, bind, getsockopt, listen, sockopt, Backlog, SockFlag, UnixAddr};
use std::ffi::OsStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// The first `sudo` on `path` (a PATH value) that is setuid root, so sudo
/// itself. Wrappers that shadow it are passed over: devtoolset's (`scl
/// enable`) rewrites the command line (`--` becomes the command) and keeps
/// the user's environment (-E) for root.
pub fn find_sudo(path: &OsStr) -> Result<PathBuf> {
    let mut passed = Vec::new();
    for p in std::env::split_paths(path).map(|d| d.join("sudo")) {
        let Ok(m) = std::fs::metadata(&p) else { continue };
        if m.uid() == 0 && m.mode() & libc::S_ISUID != 0 {
            return Ok(p);
        }
        passed.push(p.display().to_string());
    }
    if passed.is_empty() {
        bail!("no sudo on PATH");
    }
    bail!(
        "no sudo on PATH is setuid root, so none is sudo itself (a wrapper?): {}",
        passed.join(", ")
    )
}

/// Have sudo start the helper and wait for the namespace. Returns the
/// waiting program, the namespace, and whether the program could join our
/// process group (not when sudo gave it a terminal session of its own:
/// `use_pty`).
pub fn spawn(s: &Setup) -> Result<(Child, Handover, bool)> {
    let dir = TempDir::new()?;
    let ctl = start_helper(&dir.path().join("ctl"))?;
    send_request(&ctl, s)?;
    let handover = recv_setup(&ctl, SETUP_TIMEOUT)?;
    let report = &handover.report;
    let value = |key: &str| report.split(' ').find_map(|t| t.strip_prefix(key));
    let pid = value("pid=")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("bad report from the helper: {report:?}"))?;
    let joined = value("pgrp=") == Some("joined");
    drop(dir);
    Ok((Child::new(pid, ctl), handover, joined))
}

/// Listen on `path`, have sudo start the helper on it and take the
/// helper's connection, made as us.
fn start_helper(path: &Path) -> Result<OwnedFd> {
    // Non-blocking: while waiting we must notice sudo giving up.
    let l = seqpacket(SockFlag::SOCK_NONBLOCK)?;
    let addr = UnixAddr::new(path).with_context(|| {
        format!(
            "the helper socket {} is too long a path: set TMPDIR to a shorter directory",
            path.display()
        )
    })?;
    bind(l.as_raw_fd(), &addr).context("bind the helper socket")?;
    listen(&l, Backlog::new(1)?).context("listen")?;
    let exe = std::env::current_exe().context("locate our own executable for sudo")?;
    let sudo = find_sudo(&std::env::var_os("PATH").unwrap_or_default())?;
    tracing::debug!("sudo: {}", sudo.display());
    // stdio stays ours: sudo asks for the password on the terminal.
    let mut sudo = std::process::Command::new(sudo)
        .arg("--")
        .arg(&exe)
        .arg(HELPER_ARG)
        .arg(path)
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
    Ok(ctl)
}

/// Send the request, with our stdio, working directory and inheritable
/// fds, on `ctl`.
fn send_request(ctl: &OwnedFd, s: &Setup) -> Result<()> {
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
    // SAFETY: open just returned it (not -1: checked above), and nothing
    // else owns it.
    let cwd = unsafe { OwnedFd::from_raw_fd(cwd) };
    let fds: Vec<RawFd> = [0, 1, 2, cwd.as_raw_fd()]
        .into_iter()
        .chain(req.inherit.iter().copied())
        .collect();
    send_with_fds(ctl, &req.encode(), &fds).context("send the request to the helper (environment too large?)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A setuid-root program of this host, to stand in for sudo.
    fn setuid_root() -> Option<PathBuf> {
        [
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/bin/su",
            "/usr/bin/passwd",
            "/usr/bin/mount",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & libc::S_ISUID != 0))
    }

    #[test]
    fn only_a_setuid_root_sudo_is_run_never_a_wrapper_ahead_of_it_on_path() {
        let Some(real) = setuid_root() else {
            eprintln!("SKIP: no setuid-root program on this host to stand in for sudo");
            return;
        };
        if nix::unistd::geteuid().is_root() {
            eprintln!("SKIP: as root, a setuid file of our own would be root's");
            return;
        }
        let t = TempDir::new().unwrap();
        let dir = |n: &str| {
            let d = t.path().join(n);
            std::fs::create_dir(&d).unwrap();
            d
        };
        // root's but not setuid, as devtoolset's wrapper script.
        let wrapper = dir("wrapper");
        symlink("/bin/sh", wrapper.join("sudo")).unwrap();
        // setuid, but ours: it makes nobody root.
        let ours = dir("ours");
        std::fs::write(ours.join("sudo"), "").unwrap();
        std::fs::set_permissions(ours.join("sudo"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        let none = dir("none");
        let real_dir = dir("real");
        symlink(&real, real_dir.join("sudo")).unwrap();

        let path = std::env::join_paths([&wrapper, &ours, &none, &real_dir]).unwrap();
        assert_eq!(find_sudo(&path).unwrap(), real_dir.join("sudo"));

        let path = std::env::join_paths([&wrapper, &ours, &none]).unwrap();
        let e = find_sudo(&path).unwrap_err().to_string();
        for passed in [wrapper.join("sudo"), ours.join("sudo")] {
            assert!(e.contains(passed.to_str().unwrap()), "{e}");
        }
        let path = std::env::join_paths([&none]).unwrap();
        assert_eq!(find_sudo(&path).unwrap_err().to_string(), "no sudo on PATH");
    }
}
