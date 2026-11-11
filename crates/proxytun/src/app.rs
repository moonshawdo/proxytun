//! Wiring: config -> namespace + program (waiting) -> async side (TUN loop,
//! relay, health, signals) -> let the program run -> wait for its whole tree.
//!
//! The namespace is set up by a fresh proxytun process (see netns.rs) before
//! the tokio runtime starts.

use crate::ctl::{self, UsernsUnusable};
use crate::nat::Nat;
use crate::netns::{self, Addrs, Setup};
use crate::signals::{self, Exit};
use crate::state::{self, Shared};
use crate::witness::Witness;
use crate::{accept, capture, hostports, sudo};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use proxytun_core::config::proxy_url::url_has_credentials;
use proxytun_core::config::{Config, HealthCfg};
use proxytun_core::health;
use proxytun_core::live::build_live;
use proxytun_core::net::fakeip::FakePool;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;

pub struct Args {
    pub config: PathBuf,
    pub proxy: Option<String>,
    pub no_sudo: bool,
    pub no_host_ports: bool,
    pub argv: Vec<std::ffi::OsString>,
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
    // getenv points into the environment block itself, not a copy: zero the
    // value's bytes there (`value` above is our own copy).
    unsafe {
        let p = libc::getenv(c.as_ptr());
        if !p.is_null() {
            std::ptr::write_bytes(p, 0, libc::strlen(p));
        }
    }
    std::env::remove_var(name);
    value
}

/// The `--proxy` / `$PROXYTUN_PROXY` override, kept from everyone else: our
/// memory holds proxy credentials (config, $PROXYTUN_PROXY), which any
/// process of the same user - the program we start included - could
/// otherwise read from /proc/<our pid>/environ or /proc/<pid>/mem. Must run
/// before other threads exist.
pub fn take_proxy_override(cli: Option<&str>) -> Option<String> {
    // Non-dumpable: our /proc/<pid> files (environ, mem) become root's, and
    // processes of the same user can no longer ptrace us.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let env_proxy = take_env_secret("PROXYTUN_PROXY");
    if cli.is_some_and(url_has_credentials) {
        tracing::warn!(
            "--proxy carries credentials, which any local user can read from `ps` / /proc/<pid>/cmdline; \
             put them in the config file (mode 600) or in $PROXYTUN_PROXY instead"
        );
    }
    cli.map(String::from).or(env_proxy)
}

/// Load the config and apply the `--proxy` / `PROXYTUN_PROXY` override.
/// With one, the file need not exist nor name any proxy, and is checked
/// only once the override is in.
pub fn load_config(path: &Path, proxy_override: Option<&str>) -> Result<Config> {
    let mut cfg = match proxy_override {
        None => Config::load(path)?,
        Some(_) if !path.exists() => Config::parse_unchecked("")?,
        Some(_) => Config::load_unchecked(path)?,
    };
    if let Some(w) = cfg.permission_warning(path) {
        tracing::warn!("{w}");
    }
    for key in &cfg.ignored_keys {
        tracing::warn!(%key, "config key has no effect in proxytun (a typo, or an unknown setting); ignored");
    }
    if let Some(url) = proxy_override {
        cfg.override_proxy(url)?;
    }
    Ok(cfg)
}

pub fn run(args: Args) -> Result<Exit> {
    // The program's name only: its arguments may hold secrets (curl -u user:pass).
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        program = %args.argv.first().map(|a| a.to_string_lossy()).unwrap_or_default(),
        "starting"
    );
    let proxy_override = take_proxy_override(args.proxy.as_deref());
    // Before any thread exists (see `signals::exit_signal_fd`).
    let ignored = signals::ignored_signals(&[libc::SIGHUP, libc::SIGUSR1, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM]);
    // The exit signals we take over: those the caller does not ignore (an
    // ignored one stays ignored, for the program too).
    let exit_sigs: Vec<libc::c_int> = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM]
        .into_iter()
        .filter(|s| !ignored.contains(s))
        .collect();
    let exit_fd = signals::exit_signal_fd(&exit_sigs);
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
    // `witness` goes to the signal task; `wait_tree` lets the witness go once
    // the program is reaped.
    let tree_witness = witness.clone();
    let cfg = load_config(&args.config, proxy_override.as_deref()).context("load config")?;
    // A load from a missing file only succeeds through the --proxy fallback.
    if args.config.exists() {
        tracing::info!(path = %args.config.display(), "config loaded");
    } else {
        tracing::info!(path = %args.config.display(), "no config file; using the defaults and the proxy from --proxy / $PROXYTUN_PROXY");
    }

    // proxytun's own addresses take the top /24 of fake_ip_range; the fake-ip
    // pool hands out the rest.
    let fake_net: Ipv4Net = cfg.fake_ip_range.parse().context("parse fake_ip_range")?;
    let addrs = Addrs::new(fake_net);
    let pool = FakePool::with_reserved_tail(fake_net, Addrs::RESERVED);
    // Non-A queries are forwarded from the host side, so the host's own
    // resolv.conf (not the namespace's) names the upstream.
    let host_resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let upstream_dns = cfg.upstream_dns_addr(&host_resolv)?;
    let from = if cfg.upstream_dns.is_some() {
        "upstream_dns"
    } else {
        "the host's /etc/resolv.conf"
    };
    tracing::info!(%upstream_dns, "non-A DNS queries go to {from}");
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
    let (child, ns) = spawn_program(&setup, args.no_sudo)?;
    // Only after the fork, so the program keeps the original open-file limit.
    let relays = relay_capacity(raise_fd_limit(), ns.forwards.len());
    // A caller that ignores SIGCHLD (that survives exec) would have the kernel
    // reap our children unasked, the program's exit status with them. The
    // program, forked already and waiting for the go-ahead, keeps the
    // caller's setting.
    // SAFETY: plain syscall.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let ctl::Handover {
        tun,
        listener,
        forwards,
        ..
    } = ns;
    // Shared with the sweeper, which writes resets to the programs.
    let tun = Arc::new(tun);
    if !forwards.is_empty() {
        let list: Vec<String> = forwards.iter().map(|(a, _)| a.to_string()).collect();
        tracing::info!("host ports reachable inside: {}", list.join(", "));
    }
    // The program's pid, set to 0 by `wait_tree` once it is reaped: from then
    // on the signal task forwards nothing and exits on the next signal.
    let main_pid = Arc::new(AtomicI32::new(child.pid));
    let SocketAddr::V4(listen) = listener.local_addr()? else {
        anyhow::bail!("the capture listener is not IPv4");
    };

    let sh = Arc::new(Shared::new(
        listen,
        Nat::new(addrs.nat, crate::nat::NAT_ADDRS),
        pool,
        upstream_dns,
        live,
        relays,
    ));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // Blocking work is resolving host names for direct rules
        // (getaddrinfo, seconds on a slow resolver; at most
        // relay::MAX_LOOKUPS at once). Each thread counts against the user's
        // process limit, which the program shares; the default would allow
        // 512.
        .max_blocking_threads(64)
        .build()
        .context("build tokio runtime")?;
    // The async side (spawned from inside the runtime, as tokio::spawn needs),
    // then the TUN thread: both must be serving before the program runs.
    rt.block_on(async {
        let prober = start_services(&sh, &tun, listener, forwards, cfg.health.clone())?;
        spawn_signal_handlers(sh.clone(), args.config.clone(), proxy_override, prober);
        if let Some(fd) = exit_fd {
            signals::spawn_exit_signal_task(fd, main_pid.clone(), witness);
        }
        Ok::<_, anyhow::Error>(())
    })?;
    // The packet loop has a thread of its own; `handle` lets it run DNS work
    // on the runtime.
    let (tun_sh, handle) = (sh.clone(), rt.handle().clone());
    std::thread::Builder::new()
        .name("tun".into())
        .spawn(move || {
            if let Err(e) = capture::run_tun(tun, tun_sh, handle) {
                tracing::error!("{e:#}; the program has no network from now on");
            }
        })
        .context("start the TUN thread")?;
    tracing::info!(tun = %addrs.tun, dns = %addrs.dns, "namespace up");
    // Everything is serving: let the program exec.
    child.go()?;

    let exit = signals::wait_tree(child.pid, &main_pid, tree_witness.as_deref());
    // Don't wait for blocking tasks still running (a slow host name lookup),
    // as dropping the runtime would.
    rt.shutdown_background();
    Ok(exit)
}

/// Start the program in its namespace, waiting for the go-ahead: through a
/// user namespace of our own, or where that is unusable, through sudo and
/// its root helper (unless `no_sudo`).
fn spawn_program(setup: &Setup, no_sudo: bool) -> Result<(ctl::Child, ctl::Handover)> {
    match netns::spawn(setup) {
        Err(e) if e.is::<UsernsUnusable>() => {
            if no_sudo {
                return Err(e.context("--no-sudo forbids falling back to sudo"));
            }
            tracing::warn!("{e}; asking sudo to create the namespace (--no-sudo refuses)");
            let (child, ns, joined) = sudo::spawn(setup)?;
            if !joined {
                tracing::warn!(
                    "sudo started the program in a terminal session of its own (sudoers `use_pty`?): \
                     it now runs in a session of its own without a controlling terminal: proxytun \
                     passes Ctrl+C and Ctrl+\\ on to it, but job control (Ctrl+Z) and window size \
                     changes do not reach it, and programs that open /dev/tty (password prompts of \
                     ssh, git, sudo) fail"
                );
            }
            Ok((child, ns))
        }
        // Started, or failed for a reason other than user namespaces: sudo
        // would not help.
        r => r,
    }
}

/// Serve the namespace, on the runtime: the relay's and the host ports'
/// accept loops, the sweeper, and health probes of the proxies. Returns the
/// prober, which SIGHUP replaces.
fn start_services(
    sh: &Arc<Shared>,
    tun: &Arc<OwnedFd>,
    listener: std::net::TcpListener,
    forwards: Vec<(SocketAddr, std::net::TcpListener)>,
    health_cfg: HealthCfg,
) -> Result<tokio::task::JoinHandle<()>> {
    // tokio's from_std leaves non-blocking mode to us: a blocking accept
    // would stall a runtime worker.
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    tokio::spawn(accept::run_relay(listener, sh.clone()));
    // One accept loop per host port bound inside the namespace.
    for (addr, l) in forwards {
        l.set_nonblocking(true)?;
        tokio::spawn(hostports::serve(
            tokio::net::TcpListener::from_std(l)?,
            addr,
            sh.clone(),
        ));
    }
    tokio::spawn(capture::run_sweeper(tun.clone(), sh.clone()));
    Ok(health::spawn(sh.live().registry.nodes.clone(), health_cfg))
}

/// Every relayed connection holds two fds, and the usual soft limit is 1024.
/// Raised to the hard limit only now: the program already has the original
/// (inherited, or in sudo mode read from us by the helper).
/// Raise our open-file limit as far as it goes; returns the soft limit.
fn raise_fd_limit() -> u64 {
    let mut l = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // The kernel's ceiling for any open-file limit.
    let nr_open = std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    // SAFETY: plain syscalls on a local struct.
    unsafe {
        // Unreadable: assume the usual soft limit.
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) != 0 {
            return 1024;
        }
        if let Some(to) = fd_target(l, nr_open) {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &to) != 0 {
                tracing::warn!(
                    soft = l.rlim_cur,
                    hard = l.rlim_max,
                    "cannot raise our open-file limit: {}",
                    std::io::Error::last_os_error()
                );
            }
            // Read back what is in effect now (unchanged if setrlimit failed).
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut l);
        }
    }
    tracing::info!(
        soft = l.rlim_cur,
        hard = l.rlim_max,
        "open-file limit: two per relayed connection"
    );
    l.rlim_cur
}

/// How many connections may be relayed at once with `soft` open files: two
/// fds each, once the rest is set aside: some 64 fixed ones (the TUN device,
/// the listener, the runtime, health probes), the `host_ports` listeners,
/// and as many DNS forwards and host name lookups as may run at once; but
/// at most half a small limit. `MAX_RELAYS` at most. Beyond it a connection
/// is reset at once (`relays_refused`), instead of waiting in the accept
/// queue for an fd, or failing its dial.
fn relay_capacity(soft: u64, host_ports: usize) -> usize {
    let rest = 64 + host_ports + proxytun_core::net::dns::MAX_FORWARDS + proxytun_core::net::relay::MAX_LOOKUPS;
    let reserve = (rest as u64).min(soft / 2);
    let n = (soft.saturating_sub(reserve) / 2).clamp(1, state::MAX_RELAYS as u64) as usize;
    if n < state::MAX_RELAYS {
        tracing::warn!(
            soft,
            "the open-file limit allows {n} connections relayed at once, not {}: raise the hard limit \
             (`ulimit -Hn`, limits.conf) for more",
            state::MAX_RELAYS
        );
    }
    n
}

/// The limits to set, if any: the soft one up to the hard one, both no
/// higher than fs.nr_open (a hard limit above it, left from before the
/// sysctl was lowered, makes every setrlimit fail).
fn fd_target(now: libc::rlimit, nr_open: Option<libc::rlim_t>) -> Option<libc::rlimit> {
    let max = nr_open.map_or(now.rlim_max, |n| now.rlim_max.min(n));
    (max > now.rlim_cur || max < now.rlim_max).then_some(libc::rlimit {
        rlim_cur: max,
        rlim_max: max,
    })
}

/// SIGHUP reloads rules and proxy groups, replacing `prober` (the health
/// probes) with one for the new proxies; SIGUSR1 dumps statistics. SIGINT,
/// SIGQUIT and SIGTERM: see `signals::spawn_exit_signal_task`.
fn spawn_signal_handlers(
    sh: Arc<Shared>,
    cfg_path: PathBuf,
    proxy_override: Option<String>,
    mut prober: tokio::task::JoinHandle<()>,
) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut hup), Ok(mut usr1)) = (signal(SignalKind::hangup()), signal(SignalKind::user_defined1())) else {
        tracing::warn!("cannot install signal handlers");
        return;
    };
    // The counters at the previous dump, for rates.
    let mut prev = state::Snapshot::zero();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = hup.recv() => {
                    // Load the file (the --proxy override still applies) and build the new
                    // state in full before swapping anything in.
                    match load_config(&cfg_path, proxy_override.as_deref()).and_then(|c| build_live(&c).map(|l| (c, l))) {
                        Ok((c, live)) => {
                            let nodes = live.registry.nodes.clone();
                            // New connections get the new state; those being relayed
                            // keep the `Live` they started with.
                            *sh.live.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(live);
                            // Probe the new proxies: the old prober holds the old nodes.
                            prober.abort();
                            prober = health::spawn(nodes, c.health.clone());
                            tracing::info!("configuration reloaded (rules, localnet, proxies, groups; fake_ip_range and upstream_dns need a restart)");
                        }
                        Err(e) => tracing::error!("reload failed, keeping the old configuration: {e:#}"),
                    }
                }
                _ = usr1.recv() => state::log_stats(&sh, &mut prev),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_cap_follows_the_open_file_limit() {
        // Room for everything else at its worst: 64 fixed, the host ports,
        // 256 DNS forwards, 32 lookups. Then two per relay.
        let rest = 64 + 256 + 32;
        // CentOS 7's default hard limit.
        assert_eq!(relay_capacity(4096, 0), (4096 - rest) / 2);
        // 1024, with a hundred host ports: forwards and lookups at their
        // most still find fds.
        assert_eq!(relay_capacity(1024, 100), (1024 - rest - 100) / 2);
        assert_eq!(relay_capacity(1 << 20, 250), crate::state::MAX_RELAYS);
        // A small limit: half for the rest at most.
        assert_eq!(relay_capacity(64, 4), 16);
        assert_eq!(relay_capacity(0, 0), 1);
    }

    #[test]
    fn our_fd_limit_goes_as_high_as_the_kernel_lets_it() {
        let l = |cur, max| libc::rlimit {
            rlim_cur: cur,
            rlim_max: max,
        };
        let got = |t: Option<libc::rlimit>| t.map(|t| (t.rlim_cur, t.rlim_max));
        assert_eq!(got(fd_target(l(1024, 4096), Some(1 << 20))), Some((4096, 4096)));
        assert_eq!(got(fd_target(l(4096, 4096), Some(1 << 20))), None, "nothing to do");
        // A hard limit above fs.nr_open: setrlimit refuses anything that keeps it.
        assert_eq!(
            got(fd_target(l(1024, 1 << 21), Some(1 << 19))),
            Some((1 << 19, 1 << 19))
        );
        assert_eq!(
            got(fd_target(l(1024, 4096), None)),
            Some((4096, 4096)),
            "nr_open unreadable"
        );
    }
}
