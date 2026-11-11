//! `proxytun --doctor`: say plainly whether proxytun can work on this host and
//! how. Rather than guess from sysctls, it sets up exactly the namespace a run
//! would (with `true` as the program); when user namespaces are unusable it
//! reports the sudo mode instead, without running sudo. Meant to be run once on
//! a new host (especially CentOS 7) and pasted into a bug report.

use crate::ctl::UsernsUnusable;
use crate::netns::{self, Setup};
use crate::procfs::parse_kernel;
use crate::{app, hostports};
use anyhow::Result;
use proxytun_core::balancer::Node;
use proxytun_core::config::Config;
use proxytun_core::health;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

/// Check the host for a run with the config at `path` and `--proxy` (`proxy`)
/// and print the report; returns the process exit code. A config that does
/// not load is a failed check of its own.
pub fn main(path: &Path, proxy: Option<&str>, no_sudo: bool) -> Result<i32> {
    let proxy = app::take_proxy_override(proxy);
    let (cfg, problem) = match app::load_config(path, proxy.as_deref()) {
        Ok(c) => (c, None),
        // Still check the host, with the default settings and no proxy.
        Err(e) => {
            // A valid config needs a proxy: parse one with a placeholder, then
            // drop it so that no proxy is probed.
            let mut c = Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n")?;
            c.proxies.clear();
            (c, Some(format!("{e:#}")))
        }
    };
    let mut checks = Vec::new();
    if let Some(p) = problem {
        checks.push(Check {
            name: "config",
            status: Status::Fail,
            detail: p,
        });
    }
    checks.extend(run_checks(&cfg, no_sudo));
    Ok(report(&checks))
}

fn run_checks(cfg: &Config, no_sudo: bool) -> Vec<Check> {
    let mut out = vec![check_arch(), check_kernel(), check_tun_device()];
    out.extend(check_mode(cfg, no_sudo));
    out.push(check_yama());
    out.push(check_host_ports(cfg));
    out.extend(check_proxies(cfg));
    out
}

/// Print a report; returns the process exit code (1 if anything FAILed).
fn report(checks: &[Check]) -> i32 {
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
    // Not every kernel has each of these (some are distribution additions):
    // only those present are shown.
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
    // The trial: the namespace a run would get, the go-ahead, and `true` must
    // then exit 0.
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
            // No user namespaces: a run would fall back to sudo; can it?
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
    // The sudo a run would use.
    match crate::sudo::find_sudo(&std::env::var_os("PATH").unwrap_or_default()) {
        Ok(p) => check(
            "sudo mode",
            Status::Ok,
            format!(
                "runs will ask {} to create the namespace (not run by --doctor)",
                p.display()
            ),
        ),
        Err(e) => check("sudo mode", Status::Fail, format!("no user namespaces and {e}")),
    }
}

fn check_yama() -> Check {
    // proxytun does not trace the program, so whether a debugger may attach to
    // it is up to Yama's ptrace_scope alone.
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
            // As the health checker would judge it.
            let within = Duration::from_millis(cfg.health.timeout_ms);
            let r = Node::new(p.clone()).and_then(|n| rt.block_on(health::probe(&n, within)));
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
    fn proxies_are_judged_with_the_health_probe_timeout() {
        // Takes the connection (the kernel does) and never greets.
        let mute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = Config::parse(&format!(
            "[[proxies]]\nname=\"m\"\ntype=\"socks5\"\naddr=\"{}\"\n[health]\ntimeout_ms = 200\n",
            mute.local_addr().unwrap()
        ))
        .unwrap();
        let start = std::time::Instant::now();
        let checks = check_proxies(&cfg);
        let took = start.elapsed();
        assert!(
            matches!(
                checks[..],
                [Check {
                    status: Status::Fail,
                    ..
                }]
            ),
            "{:?}",
            checks.len()
        );
        assert!(
            took < Duration::from_secs(2),
            "the configured 200 ms, not a fixed timeout: {took:?}"
        );
    }

    #[test]
    fn report_exit_code_reflects_failures() {
        let ok = vec![check("a", Status::Ok, "x"), check("b", Status::Warn, "y")];
        assert_eq!(report(&ok), 0, "warnings alone do not fail");
        let bad = vec![check("a", Status::Ok, "x"), check("b", Status::Fail, "y")];
        assert_eq!(report(&bad), 1);
    }
}
