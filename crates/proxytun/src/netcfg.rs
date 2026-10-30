//! Network configuration inside the namespace with plain ioctls (no `ip`
//! binary, no netlink): create the TUN device, give it an address and MTU,
//! bring links up, add the default route. Every call needs CAP_NET_ADMIN in
//! the user namespace owning the network namespace, which the namespace
//! creator has until it execs the program.

use anyhow::{bail, Context, Result};
use std::ffi::CStr;
use std::io::Error;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `_IOW('T', 202, int)`; not exported by the libc crate.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

fn ifreq(name: &CStr) -> libc::ifreq {
    // SAFETY: ifreq is plain old data; all-zero is a valid value.
    let mut r: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, s) in r.ifr_name.iter_mut().zip(name.to_bytes()) {
        *d = *s as libc::c_char;
    }
    r
}

fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_in and sockaddr are both 16 bytes; the kernel reads it
    // back as sockaddr_in because of sin_family.
    unsafe { std::mem::transmute(sin) }
}

/// A socket to issue interface ioctls on.
fn ctl_socket() -> Result<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned right away.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        bail!("socket: {}", Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ioctl(fd: &OwnedFd, req: libc::c_ulong, arg: *mut libc::c_void, what: &str) -> Result<()> {
    // SAFETY: `arg` points at the struct `req` expects (ifreq / rtentry).
    if unsafe { libc::ioctl(fd.as_raw_fd(), req as _, arg) } < 0 {
        // Kept as an io::Error: the caller tells permission problems apart.
        return Err(anyhow::Error::new(Error::last_os_error()).context(what.to_string()));
    }
    Ok(())
}

/// Create a TUN device (layer 3, no packet-info header). It is not
/// persistent: the kernel deletes it when the returned fd is closed.
pub fn create_tun(name: &CStr) -> Result<OwnedFd> {
    // SAFETY: plain syscall on a constant path; the fd is owned right away.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow::Error::new(Error::last_os_error()).context("open /dev/net/tun"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut r = ifreq(name);
    r.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    ioctl(&fd, TUNSETIFF, &mut r as *mut _ as *mut _, "TUNSETIFF")?;
    Ok(fd)
}

/// Bring a link up.
pub fn link_up(name: &CStr) -> Result<()> {
    let s = ctl_socket()?;
    let mut r = ifreq(name);
    ioctl(&s, libc::SIOCGIFFLAGS, &mut r as *mut _ as *mut _, "SIOCGIFFLAGS")?;
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    unsafe { r.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short };
    ioctl(&s, libc::SIOCSIFFLAGS, &mut r as *mut _ as *mut _, "SIOCSIFFLAGS")
        .with_context(|| format!("bring {name:?} up"))
}

/// Give a link an IPv4 address, netmask and MTU.
pub fn set_addr(name: &CStr, ip: Ipv4Addr, prefix: u8, mtu: u32) -> Result<()> {
    let s = ctl_socket()?;
    let mut r = ifreq(name);
    r.ifr_ifru.ifru_addr = sockaddr(ip);
    ioctl(&s, libc::SIOCSIFADDR, &mut r as *mut _ as *mut _, "SIOCSIFADDR")?;
    let mask = Ipv4Addr::from(u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0));
    r.ifr_ifru.ifru_netmask = sockaddr(mask);
    ioctl(&s, libc::SIOCSIFNETMASK, &mut r as *mut _ as *mut _, "SIOCSIFNETMASK")?;
    r.ifr_ifru.ifru_mtu = mtu as libc::c_int;
    ioctl(&s, libc::SIOCSIFMTU, &mut r as *mut _ as *mut _, "SIOCSIFMTU")
}

/// Route everything without a more specific route through `dev`.
pub fn default_route(dev: &CStr) -> Result<()> {
    let s = ctl_socket()?;
    // SAFETY: rtentry is plain old data; all-zero is a valid value.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = sockaddr(Ipv4Addr::UNSPECIFIED);
    rt.rt_flags = libc::RTF_UP;
    // The kernel only reads the name during the call.
    rt.rt_dev = dev.as_ptr() as *mut libc::c_char;
    ioctl(
        &s,
        libc::SIOCADDRT,
        &mut rt as *mut _ as *mut _,
        "SIOCADDRT (default route)",
    )
}

/// A TCP listener on `addr`, with a backlog large enough for bursts of
/// connections arriving through the TUN device (std listens with 128).
pub fn listen(addr: SocketAddrV4) -> Result<TcpListener> {
    let l = TcpListener::bind(addr).with_context(|| format!("bind {addr}"))?;
    // Calling listen() again on a listening socket only resizes its backlog.
    // SAFETY: plain syscall on a socket we own.
    if unsafe { libc::listen(l.as_raw_fd(), 4096) } < 0 {
        bail!("listen {addr}: {}", Error::last_os_error());
    }
    Ok(l)
}
