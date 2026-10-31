//! proxytun-core: the proxy side of proxytun, independent of how traffic is
//! captured. Copied from proxyhook (commit e0be192) and trimmed of everything
//! tied to ptrace: `config`/`policy` (rules), `balancer`/`health` (upstream
//! selection), `proxy` (SOCKS5/HTTP dialers), `net` (fake-ip pool and DNS
//! answers, relay routing), `sniff` (TLS SNI / HTTP Host).

pub mod balancer;
pub mod config;
pub mod health;
pub mod net;
pub mod policy;
pub mod proxy;
pub mod sniff;
pub mod throttle;
pub mod types;

#[cfg(test)]
pub(crate) mod testutil {
    use std::net::{SocketAddr, TcpListener};
    use std::os::fd::{FromRawFd, OwnedFd};

    /// An address that refuses connections *and cannot be taken by another
    /// test*: a socket that is bound but not listening. (Binding a listener and
    /// dropping it races with other tests picking the same ephemeral port.)
    pub(crate) struct Refused {
        pub addr: SocketAddr,
        fd: OwnedFd,
    }

    pub(crate) fn refused() -> Refused {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let len = std::mem::size_of::<libc::sockaddr_in>() as u32;
            assert_eq!(libc::bind(fd, &sa as *const _ as *const libc::sockaddr, len), 0);
            let mut out: libc::sockaddr_in = std::mem::zeroed();
            let mut olen = len;
            assert_eq!(
                libc::getsockname(fd, &mut out as *mut _ as *mut libc::sockaddr, &mut olen),
                0
            );
            let addr = SocketAddr::from(([127, 0, 0, 1], u16::from_be(out.sin_port)));
            Refused {
                addr,
                fd: OwnedFd::from_raw_fd(fd),
            }
        }
    }

    impl Refused {
        /// Start listening on the very same port ("the proxy came back up").
        pub(crate) fn into_listener(self) -> TcpListener {
            use std::os::fd::AsRawFd;
            assert_eq!(unsafe { libc::listen(self.fd.as_raw_fd(), 16) }, 0);
            let l = TcpListener::from(self.fd);
            l.set_nonblocking(true).unwrap();
            l
        }
    }
}
