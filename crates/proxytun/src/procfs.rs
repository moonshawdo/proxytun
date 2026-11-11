//! Parsing what proxytun reads from /proc: a process's parent, process group
//! and session (`/proc/<pid>/stat`), and the kernel release
//! (`/proc/sys/kernel/osrelease`).

/// The fields of /proc/<pid>/stat proxytun looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    pub ppid: libc::pid_t,
    pub pgrp: libc::pid_t,
    pub session: libc::pid_t,
}

pub fn proc_stat(pid: libc::pid_t) -> Option<ProcStat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// The process group of `pid`.
pub fn pgrp_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    proc_stat(pid).map(|s| s.pgrp)
}

/// "pid (comm) state ppid pgrp session ...": comm may hold spaces and
/// parentheses, so fields are counted from the last ')'.
fn parse_stat(stat: &str) -> Option<ProcStat> {
    // Past ") ": the state letter (skipped), then ppid, pgrp and session.
    let mut f = stat.get(stat.rfind(')')? + 2..)?.split_whitespace().skip(1);
    let mut next = || f.next()?.parse().ok();
    Some(ProcStat {
        ppid: next()?,
        pgrp: next()?,
        session: next()?,
    })
}

/// Parse "3.10.0-1160.el7.x86_64" -> (3, 10).
pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut it = release.split(|c: char| !c.is_ascii_digit());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgrp_is_read_past_a_command_name_with_spaces_and_parens() {
        assert_eq!(
            parse_stat("4242 (my (odd) prog) S 1 777 778 0 -1 4194560"),
            Some(ProcStat {
                ppid: 1,
                pgrp: 777,
                session: 778
            })
        );
        assert_eq!(parse_stat("garbage"), None);
        let me = std::process::id() as libc::pid_t;
        assert_eq!(pgrp_of(me), Some(unsafe { libc::getpgrp() }));
    }

    #[test]
    fn kernel_release_parsing() {
        assert_eq!(parse_kernel("3.10.0-1160.el7.x86_64"), Some((3, 10)));
        assert_eq!(parse_kernel("6.18.54.1-microsoft-standard-WSL2"), Some((6, 18)));
        assert_eq!(parse_kernel("5.4"), Some((5, 4)));
        assert_eq!(parse_kernel("garbage"), None);
        assert_eq!(parse_kernel(""), None);
    }
}
