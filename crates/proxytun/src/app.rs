//! Wiring: config -> namespace + program (waiting) -> async side (TUN loop,
//! relay, health, signals) -> let the program run -> wait for its whole tree.
//!
//! The namespace is set up by a fresh proxytun process (see netns.rs) before
//! the tokio runtime starts.

use crate::capture::{self, Shared, Stats};
use crate::nat::Nat;
use crate::netns::{self, Addrs, Setup, UsernsUnusable};
use crate::witness::{self, Witness};
use crate::{hostports, sudo};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use proxytun_core::config::{url_has_credentials, Config};
use proxytun_core::health;
use proxytun_core::net::fakeip::FakePool;
use proxytun_core::net::relay::build_live;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub struct Args {
    pub config: PathBuf,
    pub proxy: Option<String>,
    pub no_sudo: bool,
    pub no_host_ports: bool,
    pub argv: Vec<String>,
}

/// Read an environment variable that may hold a secret, then destroy it: the
/// value bytes are overwritten in place (the kernel serves
/// /proc/<pid>/environ straight from that memory, so merely unsetting the
/// variable would leave the secret readable there) and the variable is removed
/// so the program we start does not inherit it. Must run before other threads
/// exist.
fn take_env_secret(name: &str) -> Option<String> {
    let value = std::env::var(name).ok().filter(|v| !v.is_empty());
    let c = std::ffi::CString::new(name).ok()?;
    unsafe {
        let p = libc::getenv(c.as_ptr());
        if !p.is_null() {
            std::ptr::write_bytes(p, 0, libc::strlen(p));
        }
    }
    std::env::remove_var(name);
    value
}

/// Load the config and apply the `--proxy` / `PROXYTUN_PROXY` override.
pub fn load_config(path: &Path, proxy_override: Option<&str>) -> Result<Config> {
    let mut cfg = match Config::load(path) {
        Ok(c) => c,
        // With an explicit proxy a config file is optional.
        Err(_) if proxy_override.is_some() && !path.exists() => {
            Config::parse("[proxy]\ntype = \"socks5\"\naddr = \"127.0.0.1:1\"\n")?
        }
        Err(e) => return Err(e),
    };
    if let Some(w) = cfg.permission_warning(path) {
        tracing::warn!("{w}");
    }
    for key in &cfg.ignored_keys {
        tracing::warn!(%key, "config key has no effect in proxytun (a typo, or a proxyhook-only setting); ignored");
    }
    if let Some(url) = proxy_override {
        cfg.override_proxy(url)?;
    }
    Ok(cfg)
}

pub fn run(args: Args) -> Result<i32> {
    // The program's name only: its arguments may hold secrets (curl -u user:pass).
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        program = args.argv.first().map_or("", String::as_str),
        "starting"
    );
    // Our memory holds proxy credentials (config, $PROXYTUN_PROXY). Without
    // this, any process of the same user - including the program we are about
    // to run - could read them from /proc/<our pid>/environ or /proc/<pid>/mem.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let env_proxy = take_env_secret("PROXYTUN_PROXY");
    if args.proxy.as_deref().is_some_and(url_has_credentials) {
        tracing::warn!(
            "--proxy carries credentials, which any local user can read from `ps` / /proc/<pid>/cmdline; \
             put them in the config file (mode 600) or in $PROXYTUN_PROXY instead"
        );
    }
    let proxy_override = args.proxy.clone().or(env_proxy);
    // Before any thread exists (see `exit_signal_fd`).
    let ignored = ignored_signals(&[libc::SIGHUP, libc::SIGUSR1, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM]);
    let exit_sigs: Vec<libc::c_int> = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM]
        .into_iter()
        .filter(|s| !ignored.contains(s))
        .collect();
    let exit_fd = exit_signal_fd(&exit_sigs);
    // Still single-threaded, signals blocked, not yet a subreaper: see witness.rs.
    let witness = match exit_fd {
        Some(_) => Witness::start(&exit_sigs)
            .inspect_err(|e| {
                tracing::warn!("{e:#}; a signal sent to the whole process group may reach the program twice")
            })
            .ok()
            .map(Arc::new),
        None => None,
    };
    let cfg = load_config(&args.config, proxy_override.as_deref()).context("load config")?;
    // A load from a missing file only succeeds through the --proxy fallback.
    if args.config.exists() {
        tracing::info!(path = %args.config.display(), "config loaded");
    } else {
        tracing::info!(path = %args.config.display(), "no config file; using the defaults and the proxy from --proxy / $PROXYTUN_PROXY");
    }

    let fake_net: Ipv4Net = cfg.fake_ip_range.parse().context("parse fake_ip_range")?;
    let addrs = Addrs::new(fake_net);
    let pool = FakePool::with_reserved_tail(fake_net, 256);
    let upstream_dns = cfg.upstream_dns_addr()?;
    let live = Arc::new(build_live(&cfg)?);

    // Orphans of the program's tree are re-parented to us, so we can wait for
    // all of it (as proxyhook does).
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    let setup = Setup {
        argv: args.argv.clone(),
        fake_range: fake_net,
        forwards: if cfg.host_ports_forward && !args.no_host_ports {
            hostports::scan(&cfg.host_ports_exclude)
        } else {
            Vec::new()
        },
    };
    let (child, ns) = match netns::spawn(&setup) {
        Err(e) if e.is::<UsernsUnusable>() => {
            if args.no_sudo {
                return Err(e.context("--no-sudo forbids falling back to sudo"));
            }
            tracing::warn!("{e}; asking sudo to create the namespace (--no-sudo refuses)");
            let (child, ns, joined) = sudo::spawn(&setup)?;
            if !joined {
                tracing::warn!(
                    "sudo started the program in a terminal session of its own (sudoers `use_pty`?): \
                     Ctrl+C on this terminal will not reach it"
                );
            }
            (child, ns)
        }
        r => r?,
    };
    let netns::Handover {
        tun,
        listener,
        forwards,
        ..
    } = ns;
    if !forwards.is_empty() {
        let list: Vec<String> = forwards.iter().map(|(a, _)| a.to_string()).collect();
        tracing::info!("host ports reachable inside: {}", list.join(", "));
    }
    let main_pid = Arc::new(AtomicI32::new(child.pid));
    let SocketAddr::V4(listen) = listener.local_addr()? else {
        anyhow::bail!("the capture listener is not IPv4");
    };

    let sh = Arc::new(Shared {
        addrs,
        listen,
        nat: Mutex::new(Nat::default()),
        pool,
        upstream_dns,
        live: RwLock::new(live.clone()),
        stats: Stats::default(),
        last_id: AtomicU64::new(0),
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let health_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    {
        let (sh, main_pid, health_task, cfg_path, proxy_override) = (
            sh.clone(),
            main_pid.clone(),
            health_task.clone(),
            args.config.clone(),
            proxy_override.clone(),
        );
        let health_cfg = cfg.health.clone();
        rt.block_on(async move {
            listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(listener)?;
            let tun_sh = sh.clone();
            tokio::spawn(async move {
                if let Err(e) = capture::run_tun(tun, tun_sh).await {
                    tracing::error!("{e:#}; the program has no network from now on");
                }
            });
            tokio::spawn(capture::run_relay(listener, sh.clone()));
            for (addr, l) in forwards {
                l.set_nonblocking(true)?;
                tokio::spawn(hostports::serve(
                    tokio::net::TcpListener::from_std(l)?,
                    addr,
                    sh.clone(),
                ));
            }
            tokio::spawn(capture::run_sweeper(sh.clone()));
            *health_task.lock().unwrap() = Some(health::spawn(live.registry.nodes.clone(), health_cfg));
            spawn_signal_handlers(sh, cfg_path, proxy_override, health_task);
            if let Some(fd) = exit_fd {
                spawn_exit_signal_task(fd, main_pid, witness);
            }
            Ok::<_, anyhow::Error>(())
        })?;
    }
    tracing::info!(tun = %addrs.tun, dns = %addrs.dns, "namespace up");
    child.go()?;

    let code = wait_tree(child.pid, &main_pid);
    rt.shutdown_background();
    Ok(code)
}

/// Wait until every process of the program's tree is gone (we are their
/// subreaper) and return the program's own exit code: its status, or 128 +
/// the signal that killed it.
fn wait_tree(main: libc::pid_t, main_pid: &AtomicI32) -> i32 {
    let mut code = 1;
    loop {
        let mut status = 0;
        // SAFETY: plain syscall.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return code; // ECHILD: nobody left
        }
        if pid == main {
            code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            };
            main_pid.store(0, Ordering::SeqCst);
            tracing::info!(code, "program exited");
        }
    }
}

/// Which of `sigs` are ignored right now. A caller that ignores a signal
/// (`cmd &` in a script ignores SIGINT/SIGQUIT, nohup ignores SIGHUP) means the
/// program should start with it ignored too, as it would if run directly.
fn ignored_signals(sigs: &[libc::c_int]) -> Vec<libc::c_int> {
    sigs.iter()
        .copied()
        .filter(|&s| unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(s, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
        })
        .collect()
}

/// SIGINT, SIGQUIT and SIGTERM are read from a signalfd rather than through a
/// tokio handler: whether to forward one depends on who sent it (`ssi_code`),
/// which tokio does not report. They are blocked here, before any thread
/// exists, so every thread inherits the mask (netns.rs unblocks them again for
/// the program). Signals the caller ignores are left ignored and not handled.
fn exit_signal_fd(sigs: &[libc::c_int]) -> Option<OwnedFd> {
    if sigs.is_empty() {
        return None;
    }
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in sigs {
            libc::sigaddset(&mut set, s);
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            tracing::warn!("signalfd: {}", std::io::Error::last_os_error());
            return None;
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        Some(OwnedFd::from_raw_fd(fd))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ExitSignal {
    /// Exit now with this code. The program's tree keeps running, cut off
    /// from the network (the TUN device goes with us).
    Exit(i32),
    /// The program got it too; nothing to do.
    Leave,
    /// Pass it on to the program unless it got it too (see `already_delivered`).
    Forward,
}

/// SIGINT / SIGQUIT / SIGTERM never stop proxytun while the main program runs:
/// the program decides, and proxytun exits when its tree is gone. `code` is
/// the sender's si_code; `terms` counts SIGTERMs so far.
fn on_exit_signal(sig: libc::c_int, code: i32, program_running: bool, terms: u32) -> ExitSignal {
    // Nobody left to decide (e.g. only a background child keeps us waiting),
    // or a second SIGTERM: whoever sent it wants us gone.
    if !program_running || (sig == libc::SIGTERM && terms >= 2) {
        return ExitSignal::Exit(128 + sig);
    }
    // Sent by the kernel: the terminal's Ctrl+C / Ctrl+\ signals the whole
    // foreground group, the program included.
    if code == libc::SI_KERNEL {
        return ExitSignal::Leave;
    }
    // From a process: `kill <proxytun>`, or `kill -- -<group>` / `kill %1` /
    // systemd, which look the same from here.
    ExitSignal::Forward
}

/// Did a signal from a process reach the program as well as us? It did if
/// it was sent to our whole group (the witness has it) and the program is
/// still in that group.
fn already_delivered(witness_saw: bool, program_pgrp: Option<libc::pid_t>, our_pgrp: libc::pid_t) -> bool {
    witness_saw && program_pgrp == Some(our_pgrp)
}

/// How long to wait before asking the witness: a group-wide signal is
/// delivered to the members one after another, and we may run first.
const WITNESS_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

fn spawn_exit_signal_task(fd: OwnedFd, main_pid: Arc<AtomicI32>, witness: Option<Arc<Witness>>) {
    tokio::spawn(async move {
        // SAFETY: an OwnedFd stays open and is the same fd for as long as the
        // AsyncFd owns it.
        let afd = match unsafe { tokio::io::unix::AsyncFd::register(fd) } {
            Ok(a) => a,
            Err(e) => return tracing::warn!("cannot watch the signalfd: {e}"),
        };
        let mut terms = 0;
        loop {
            let Ok(mut ready) = afd.readable().await else { return };
            // SAFETY: a plain C struct of integers, filled by read().
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::signalfd_siginfo>();
            let n = unsafe { libc::read(afd.as_raw_fd(), &mut info as *mut _ as *mut libc::c_void, size) };
            if n != size as isize {
                ready.clear_ready(); // EAGAIN: drained
                continue;
            }
            let sig = info.ssi_signo as libc::c_int;
            if sig == libc::SIGTERM {
                terms += 1;
            }
            let pid = main_pid.load(Ordering::SeqCst);
            let action = on_exit_signal(sig, info.ssi_code, pid > 0, terms);
            if let ExitSignal::Exit(code) = action {
                tracing::info!(sig, code, "exiting on a signal");
                std::process::exit(code)
            }
            let witness = witness.clone();
            tokio::spawn(async move {
                tokio::time::sleep(WITNESS_DELAY).await;
                let saw = witness.as_ref().is_some_and(|w| w.saw(sig));
                // SAFETY: plain syscall.
                let ours = unsafe { libc::getpgrp() };
                if action == ExitSignal::Forward && !already_delivered(saw, witness::pgrp_of(pid), ours) {
                    tracing::debug!(sig, pid, "forwarding the signal to the program");
                    unsafe { libc::kill(pid, sig) };
                }
                if let Some(w) = witness {
                    w.clear();
                }
            });
        }
    });
}

/// SIGHUP reloads rules and proxy groups, SIGUSR1 dumps statistics. SIGINT,
/// SIGQUIT and SIGTERM: see `spawn_exit_signal_task`.
fn spawn_signal_handlers(
    sh: Arc<Shared>,
    cfg_path: PathBuf,
    proxy_override: Option<String>,
    health_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut hup), Ok(mut usr1)) = (signal(SignalKind::hangup()), signal(SignalKind::user_defined1())) else {
        tracing::warn!("cannot install signal handlers");
        return;
    };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = hup.recv() => {
                    match load_config(&cfg_path, proxy_override.as_deref()).and_then(|c| build_live(&c).map(|l| (c, l))) {
                        Ok((c, live)) => {
                            let nodes = live.registry.nodes.clone();
                            *sh.live.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(live);
                            let mut slot = health_task.lock().unwrap();
                            if let Some(h) = slot.take() { h.abort(); }
                            *slot = Some(health::spawn(nodes, c.health.clone()));
                            tracing::info!("configuration reloaded (rules, localnet, proxies, groups; fake_ip_range and upstream_dns need a restart)");
                        }
                        Err(e) => tracing::error!("reload failed, keeping the old configuration: {e:#}"),
                    }
                }
                _ = usr1.recv() => capture::log_stats(&sh),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const SI_USER: i32 = 0;

    #[test]
    fn exit_signals_are_left_to_the_running_program() {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            // Ctrl+C / Ctrl+\ on the terminal: the program got it too.
            assert_eq!(on_exit_signal(sig, libc::SI_KERNEL, true, 1), ExitSignal::Leave);
            // kill(2) from some process: maybe only we got it.
            assert_eq!(on_exit_signal(sig, SI_USER, true, 1), ExitSignal::Forward);
            // Main program gone (a background child keeps us waiting): exit,
            // or Ctrl+C would do nothing at all.
            assert_eq!(on_exit_signal(sig, SI_USER, false, 1), ExitSignal::Exit(128 + sig));
            assert_eq!(
                on_exit_signal(sig, libc::SI_KERNEL, false, 1),
                ExitSignal::Exit(128 + sig)
            );
        }
        assert_eq!(
            on_exit_signal(libc::SIGTERM, SI_USER, true, 2),
            ExitSignal::Exit(143),
            "second SIGTERM"
        );
        assert_eq!(
            on_exit_signal(libc::SIGINT, SI_USER, true, 2),
            ExitSignal::Forward,
            "only SIGTERM counts"
        );
    }

    #[test]
    fn a_signal_is_only_held_back_when_the_program_shares_our_group() {
        // Sent to the group, and the program is in it: it has its own copy.
        assert!(already_delivered(true, Some(7), 7));
        // Sent to proxytun alone.
        assert!(!already_delivered(false, Some(7), 7));
        // Sent to our group, but the program moved to its own (setsid, a
        // shell's job control): the group signal never reached it.
        assert!(!already_delivered(true, Some(9), 7));
        // Program already gone: nothing to hold back for.
        assert!(!already_delivered(true, None, 7));
    }
}
