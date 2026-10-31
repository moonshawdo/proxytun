//! `proxytun --doctor`: say plainly whether proxytun can work on this host and
//! how. Rather than guess from sysctls, it sets up exactly the namespace a run
//! would (with `true` as the program); when user namespaces are unusable it
//! reports the sudo mode instead, without running sudo. Meant to be run once on
//! a new host (especially CentOS 7) and pasted into a bug report.

use crate::hostports;
use crate::netns::{self, Setup, UsernsUnusable};
use proxytun_core::balancer::Node;
use proxytun_core::config::Config;
use proxytun_core::health;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

pub fn run_checks(cfg: &Config, no_sudo: bool) -> Vec<Check> {
    let mut out = vec![check_arch(), check_kernel(), check_tun_device()];
    out.extend(check_mode(cfg, no_sudo));
    out.push(check_yama());
    out.push(check_host_ports(cfg));
    out.extend(check_proxies(cfg));
    out
}

/// Print a report; returns the process exit code (1 if anything FAILed).
pub fn report(checks: &[Check]) -> i32 {
    let mut code = 0;
    for c in checks {
        let tag = match c.status {
            Status::Ok => " OK ",
            Status::Warn => "WARN",
            Status::Fail => {
                code = 1;
                "FAIL"
            }
        };
        println!("[{tag}] {:<20} {}", c.name, c.detail);
    }
    code
}

fn check_arch() -> Check {
    if cfg!(target_arch = "x86_64") {
        check("architecture", Status::Ok, "x86_64")
    } else {
        check("architecture", Status::Warn, "only x86-64 is tested")
    }
}

/// Parse "3.10.0-1160.el7.x86_64" -> (3, 10).
pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut it = release.split(|c: char| !c.is_ascii_digit());
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_kernel() -> Check {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    match parse_kernel(&rel) {
        Some((m, n)) if (m, n) >= (3, 10) => check("kernel", Status::Ok, rel),
        Some(_) => check("kernel", Status::Warn, format!("{rel}: older than 3.10 is untested")),
        None => check("kernel", Status::Warn, format!("cannot parse release {rel:?}")),
    }
}

fn check_tun_device() -> Check {
    match std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun") {
        Ok(_) => check("TUN device", Status::Ok, "/dev/net/tun can be opened"),
        Err(e) => check("TUN device", Status::Fail, format!("/dev/net/tun: {e}")),
    }
}

/// The sysctls that decide whether unprivileged user namespaces work.
fn userns_knobs() -> String {
    let knobs = [
        ("user.max_user_namespaces", "/proc/sys/user/max_user_namespaces"),
        (
            "kernel.unprivileged_userns_clone",
            "/proc/sys/kernel/unprivileged_userns_clone",
        ),
        (
            "kernel.apparmor_restrict_unprivileged_userns",
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        ),
    ];
    let found: Vec<String> = knobs
        .iter()
        .filter_map(|(name, path)| Some(format!("{name}={}", std::fs::read_to_string(path).ok()?.trim())))
        .collect();
    if found.is_empty() {
        "no user namespace sysctls (a kernel before 7.4 on CentOS 7 needs user_namespace.enable=1)".into()
    } else {
        found.join(", ")
    }
}

/// Set up a namespace for `true`, as a run would, and report the mode.
fn check_mode(cfg: &Config, no_sudo: bool) -> Vec<Check> {
    let Ok(range) = cfg.fake_ip_range.parse() else {
        return vec![check("namespace", Status::Fail, "bad fake_ip_range")];
    };
    let setup = Setup {
        argv: vec!["true".into()],
        fake_range: range,
        forwards: Vec::new(),
    };
    let root = nix::unistd::geteuid().is_root();
    // A caller that ignores SIGCHLD would have the kernel reap the trial
    // program unasked: waitpid would fail and leave a status of 0, a failed
    // trial passing for a good one. (The trial is `true`: nothing to keep.)
    // SAFETY: plain syscall.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    match netns::spawn(&setup).and_then(|(child, _ns)| {
        child.go()?;
        let mut status = 0;
        // SAFETY: plain syscall on our own child.
        unsafe { libc::waitpid(child.pid, &mut status, 0) };
        anyhow::ensure!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the trial program did not run (status {status})"
        );
        Ok(())
    }) {
        Ok(()) if root => vec![check(
            "namespace",
            Status::Ok,
            "running as root: network namespace + TUN work, the program stays root",
        )],
        Ok(()) => vec![check(
            "namespace",
            Status::Ok,
            "rootless: user namespace + network namespace + TUN work",
        )],
        Err(e) => match e.downcast_ref::<UsernsUnusable>() {
            Some(u) => {
                let mut out = vec![check("namespace", Status::Warn, format!("{u} ({})", userns_knobs()))];
                out.push(check_sudo(no_sudo));
                out
            }
            None => vec![check("namespace", Status::Fail, format!("{e:#}"))],
        },
    }
}

fn check_sudo(no_sudo: bool) -> Check {
    if no_sudo {
        return check(
            "sudo mode",
            Status::Fail,
            "--no-sudo given: without user namespaces nothing can run",
        );
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    match std::env::split_paths(&path)
        .map(|d| d.join("sudo"))
        .find(|p| p.is_file())
    {
        Some(p) => check(
            "sudo mode",
            Status::Ok,
            format!(
                "runs will ask {} to create the namespace (not run by --doctor)",
                p.display()
            ),
        ),
        None => check("sudo mode", Status::Fail, "no user namespaces and no sudo on PATH"),
    }
}

fn check_yama() -> Check {
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").map(|s| s.trim().to_string()) {
        Ok(v) if v == "0" => check(
            "gdb -p / strace -p",
            Status::Ok,
            "ptrace_scope=0: any of your processes",
        ),
        Ok(v) if v == "1" => check(
            "gdb -p / strace -p",
            Status::Ok,
            "ptrace_scope=1: only your own descendants, as without proxytun",
        ),
        Ok(v) => check(
            "gdb -p / strace -p",
            Status::Warn,
            format!("ptrace_scope={v}: attaching needs privileges; run the debugger inside proxytun instead"),
        ),
        Err(_) => check("gdb -p / strace -p", Status::Ok, "no Yama: any of your processes"),
    }
}

fn check_host_ports(cfg: &Config) -> Check {
    if !cfg.host_ports_forward {
        return check(
            "host ports",
            Status::Ok,
            "forwarding is off (host_ports_forward = false)",
        );
    }
    let fwd = hostports::scan(&cfg.host_ports_exclude);
    let mut list: Vec<String> = fwd.iter().take(10).map(|a| a.to_string()).collect();
    if fwd.len() > 10 {
        list.push(format!("and {} more", fwd.len() - 10));
    }
    check(
        "host ports",
        Status::Ok,
        format!(
            "{} loopback listener(s) reachable inside: {}",
            fwd.len(),
            list.join(", ")
        ),
    )
}

fn check_proxies(cfg: &Config) -> Vec<Check> {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return vec![check("upstream proxy", Status::Fail, format!("runtime: {e}"))],
    };
    cfg.proxies
        .iter()
        .map(|p| {
            let name = format!("{} {}", p.name, p.addr);
            let r = Node::new(p.clone()).and_then(|n| rt.block_on(health::probe(&n, Duration::from_secs(3))));
            match r {
                Ok(rtt) => check(
                    "upstream proxy",
                    Status::Ok,
                    format!("{name}: answers ({:.1} ms)", rtt.as_secs_f64() * 1000.0),
                ),
                Err(e) => check("upstream proxy", Status::Fail, format!("{name}: {e:#}")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_parsing() {
        assert_eq!(parse_kernel("3.10.0-1160.el7.x86_64"), Some((3, 10)));
        assert_eq!(parse_kernel("6.18.54.1-microsoft-standard-WSL2"), Some((6, 18)));
        assert_eq!(parse_kernel("5.4"), Some((5, 4)));
        assert_eq!(parse_kernel("garbage"), None);
        assert_eq!(parse_kernel(""), None);
    }

    #[test]
    fn report_exit_code_reflects_failures() {
        let ok = vec![check("a", Status::Ok, "x"), check("b", Status::Warn, "y")];
        assert_eq!(report(&ok), 0, "warnings alone do not fail");
        let bad = vec![check("a", Status::Ok, "x"), check("b", Status::Fail, "y")];
        assert_eq!(report(&bad), 1);
    }
}
