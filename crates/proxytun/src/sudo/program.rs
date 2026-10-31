//! sudo mode, the program side: the helper's forked child, which takes the
//! caller's limits, drops from root to the user, takes the request and the
//! fds from the client, reports the request to the helper and becomes the
//! program.

use super::{set_timeouts, Identity, Request, REQUEST_MAX};
use crate::ctl::{recv_with_fds, wait_go};
use crate::netns;
use std::ffi::CString;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

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
pub(super) fn become_program(
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
    let (n, fds) = match recv_with_fds(ctl, &mut buf) {
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
    wait_go(ctl);
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
}
