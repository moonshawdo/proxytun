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
use anyhow::{anyhow, bail, Context, Result};
use ipnet::Ipv4Net;
use nix::sched::{unshare, CloneFlags};
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
};
use std::ffi::{CStr, CString};
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

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
    /// Source address of rewritten connections towards the listener.
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
/// search domains and options.
pub fn resolv_conf(host: &str, dns: Ipv4Addr) -> String {
    let mut out = format!("# proxytun: names resolve through its fake-ip DNS\nnameserver {dns}\n");
    for line in host.lines() {
        if matches!(
            line.split_whitespace().next(),
            Some("search" | "domain" | "options" | "sortlist")
        ) {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A private temporary directory, removed with everything in it on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Result<Self> {
        let template = std::env::temp_dir().join("proxytun-XXXXXX");
        let mut raw = CString::new(template.as_os_str().as_encoded_bytes())?.into_bytes_with_nul();
        // SAFETY: a writable NUL-terminated template, as mkdtemp requires.
        if unsafe { libc::mkdtemp(raw.as_mut_ptr() as *mut libc::c_char) }.is_null() {
            bail!("mkdtemp {}: {}", template.display(), std::io::Error::last_os_error());
        }
        raw.pop();
        Ok(TempDir(PathBuf::from(String::from_utf8(raw)?)))
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
    pub argv: Vec<String>,
    pub fake_range: Ipv4Net,
    /// File to bind-mount over /etc/resolv.conf.
    pub resolv: PathBuf,
    /// Signals the program starts with ignored (they were ignored when we
    /// started).
    pub ignored: Vec<libc::c_int>,
}

impl Setup {
    /// `proxytun SETUP_ARG <ctl fd> <fake range> <resolv> <ignored,...> -- argv...`
    fn to_args(&self, exe: &str, ctl: RawFd) -> Vec<String> {
        let ignored: Vec<String> = self.ignored.iter().map(|s| s.to_string()).collect();
        let mut a = vec![
            exe.to_string(),
            SETUP_ARG.to_string(),
            ctl.to_string(),
            self.fake_range.to_string(),
            self.resolv.display().to_string(),
            ignored.join(","),
            "--".to_string(),
        ];
        a.extend(self.argv.iter().cloned());
        a
    }

    fn from_args(args: &[String]) -> Option<(Setup, RawFd)> {
        let [_, mode, ctl, range, resolv, ignored, dashes, argv @ ..] = args else {
            return None;
        };
        if mode != SETUP_ARG || dashes != "--" || argv.is_empty() {
            return None;
        }
        let ignored = if ignored.is_empty() {
            Vec::new()
        } else {
            ignored.split(',').map(|s| s.parse().ok()).collect::<Option<_>>()?
        };
        let setup = Setup {
            argv: argv.to_vec(),
            fake_range: range.parse().ok()?,
            resolv: PathBuf::from(resolv),
            ignored,
        };
        Some((setup, ctl.parse().ok()?))
    }
}

/// The started program, still waiting for `go`.
pub struct Child {
    pub pid: libc::pid_t,
    ctl: OwnedFd,
}

impl Child {
    /// Let the program run: its packets are being served now.
    pub fn go(&self) -> Result<()> {
        // SAFETY: plain write of one byte on a socket we own.
        if unsafe { libc::write(self.ctl.as_raw_fd(), b"G".as_ptr() as *const _, 1) } != 1 {
            bail!("starting the program: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

const OK: &[u8] = b"OK";

/// Start the setup process for the program and wait for its namespace; the
/// program itself waits for `Child::go` before exec. Returns it with the TUN
/// device and the listener for captured TCP.
pub fn spawn(s: &Setup) -> Result<(Child, OwnedFd, TcpListener)> {
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
        .map(|a| CString::new(a).context("argument contains NUL"))
        .collect::<Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let msg = b"proxytun: cannot re-execute itself for the namespace setup\n";

    // SAFETY: the child only calls fcntl, execv, write and _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            // Our end of the socketpair must survive the exec; theirs (CLOEXEC) goes.
            libc::fcntl(theirs.as_raw_fd(), libc::F_SETFD, 0);
            libc::execv(exe.as_ptr(), ptrs.as_ptr());
            libc::write(2, msg.as_ptr() as *const _, msg.len());
            libc::_exit(127);
        }
    }
    drop(theirs);

    let mut buf = vec![0u8; 4096];
    let mut cmsg = nix::cmsg_space!([RawFd; 2]);
    let (n, fds) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(ours.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC)
            .context("waiting for the namespace setup")?;
        let mut fds = Vec::new();
        for c in msg.cmsgs().context("reading passed fds")? {
            if let ControlMessageOwned::ScmRights(r) = c {
                // SAFETY: the kernel just installed these fds for us.
                fds.extend(r.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }));
            }
        }
        (msg.bytes, fds)
    };
    let reply = &buf[..n];
    if reply != OK || fds.len() != 2 {
        reap(pid);
        let why = String::from_utf8_lossy(reply.strip_prefix(b"ERR ").unwrap_or(reply));
        if why.is_empty() {
            bail!("namespace setup failed (the setup process exited)");
        }
        bail!("{why}");
    }
    let mut fds = fds.into_iter();
    let tun = fds.next().expect("two fds");
    let listener = TcpListener::from(fds.next().expect("two fds"));
    Ok((Child { pid, ctl: ours }, tun, listener))
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    // SAFETY: plain syscall.
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// Entry point of the setup process (`proxytun SETUP_ARG ...`). Never
/// returns: it becomes the program, or exits with 125-127 on failure.
pub fn setup_main(args: &[String]) -> ! {
    let Some((s, ctl)) = Setup::from_args(args) else {
        eprintln!("proxytun: {SETUP_ARG} is internal to proxytun");
        std::process::exit(2);
    };
    // SAFETY: proxytun passed us this fd for exactly this purpose.
    let ctl = unsafe { OwnedFd::from_raw_fd(ctl) };
    // SAFETY: plain fcntl; the program must not inherit the socket.
    unsafe { libc::fcntl(ctl.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    let (tun, listener) = match setup_namespace(&s) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("ERR {e:#}");
            let _ = sendmsg::<()>(
                ctl.as_raw_fd(),
                &[IoSlice::new(msg.as_bytes())],
                &[],
                MsgFlags::empty(),
                None,
            );
            std::process::exit(126);
        }
    };
    let fds = [tun.as_raw_fd(), listener.as_raw_fd()];
    if sendmsg::<()>(
        ctl.as_raw_fd(),
        &[IoSlice::new(OK)],
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::empty(),
        None,
    )
    .is_err()
    {
        std::process::exit(126);
    }
    drop((tun, listener));
    // Wait for proxytun to serve the TUN device; EOF means it went away.
    let mut go = [0u8; 1];
    // SAFETY: plain read into a local buffer.
    if unsafe { libc::read(ctl.as_raw_fd(), go.as_mut_ptr() as *mut _, 1) } != 1 {
        std::process::exit(125);
    }
    drop(ctl);
    std::process::exit(exec(&s.argv, &s.ignored))
}

fn setup_namespace(s: &Setup) -> Result<(OwnedFd, TcpListener)> {
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
    private_resolv_conf(&s.resolv)?;
    let addrs = Addrs::new(s.fake_range);

    netcfg::link_up(c"lo").context("bring lo up")?;
    let tun = netcfg::create_tun(TUN_NAME)?;
    netcfg::set_addr(TUN_NAME, addrs.tun, Addrs::PREFIX, MTU).context("configure tun0")?;
    netcfg::link_up(TUN_NAME)?;
    netcfg::default_route(TUN_NAME)?;
    let listener = netcfg::listen(SocketAddrV4::new(addrs.tun, 0))?;
    Ok((tun, listener))
}

/// Bind-mount `src` over /etc/resolv.conf in our own mount namespace. Mount
/// events must not propagate back to the host, hence MS_PRIVATE first.
fn private_resolv_conf(src: &Path) -> Result<()> {
    use nix::mount::{mount, MsFlags};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("make mounts private")?;
    // The target may be a symlink (systemd-resolved, WSL): mount follows it.
    mount(
        Some(src),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind-mount /etc/resolv.conf")
}

/// Become the program. Undo what our runtime changed, as std::process::Command
/// does: Rust ignores SIGPIPE at startup and an ignored disposition survives
/// exec; proxytun blocked some signals for its signalfd.
fn exec(argv: &[String], ignored: &[libc::c_int]) -> i32 {
    let argv: Vec<CString> = match argv.iter().map(|a| CString::new(a.as_str())).collect() {
        Ok(v) => v,
        Err(_) => return 127, // checked by proxytun before we got here
    };
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: plain syscalls on prepared, NUL-terminated buffers.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        for &sig in ignored {
            libc::signal(sig, libc::SIG_IGN);
        }
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
    fn setup_arguments_round_trip() {
        let s = Setup {
            argv: vec!["curl".into(), "--".into(), "-x".into(), "a b".into()],
            fake_range: "198.18.0.0/15".parse().unwrap(),
            resolv: "/tmp/proxytun-x/resolv.conf".into(),
            ignored: vec![libc::SIGHUP, libc::SIGINT],
        };
        let args = s.to_args("proxytun", 7);
        assert_eq!(Setup::from_args(&args), Some((s, 7)));
        let none = Setup {
            argv: vec!["true".into()],
            fake_range: "10.0.0.0/8".parse().unwrap(),
            resolv: "/r".into(),
            ignored: vec![],
        };
        assert_eq!(Setup::from_args(&none.to_args("p", 3)), Some((none, 3)));
        assert_eq!(Setup::from_args(&["p".into(), SETUP_ARG.into()]), None, "truncated");
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
    }
}
