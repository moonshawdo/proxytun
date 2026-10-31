//! Errors told apart by the OS error code (errno) in their chain; above all,
//! our own lack of resources, which is no fault of a proxy or the upstream.

/// Is `errno` anywhere in `e`'s chain?
pub(crate) fn is_errno(e: &anyhow::Error, errno: i32) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<std::io::Error>().and_then(|io| io.raw_os_error()) == Some(errno))
}

/// Did `e` happen for lack of our own resources (fds, buffers, memory,
/// local ports)? That is not the proxy's fault: it must not count against
/// its health. Short of fds or memory, every other proxy would fail the same
/// way; short of local ports, maybe not (they are counted per destination).
pub(crate) fn is_local_shortage(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .and_then(|io| io.raw_os_error())
            .is_some_and(|n| {
                matches!(
                    n,
                    libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EADDRNOTAVAIL
                )
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_out_of_our_own_fds_is_not_the_proxys_fault() {
        let io = |n| anyhow::Error::new(std::io::Error::from_raw_os_error(n)).context("connect to the proxy");
        assert!(is_local_shortage(&io(libc::EMFILE)));
        assert!(is_local_shortage(&io(libc::ENFILE)));
        assert!(is_local_shortage(&io(libc::EADDRNOTAVAIL)), "local ports used up");
        assert!(is_errno(&io(libc::EADDRNOTAVAIL), libc::EADDRNOTAVAIL));
        assert!(!is_errno(&io(libc::EMFILE), libc::EADDRNOTAVAIL));
        assert!(!is_local_shortage(&io(libc::ECONNREFUSED)));
        assert!(!is_local_shortage(&io(libc::ETIMEDOUT)));
    }
}
