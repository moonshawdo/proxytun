//! Wiring: config -> namespace + program (waiting) -> async side (TUN loop,
//! relay, health, signals) -> let the program run -> wait for its whole tree.
//!
//! The namespace is set up by a fresh proxytun process (see netns.rs) before
//! the tokio runtime starts.

use crate::capture::{self, Shared};
use crate::nat::Nat;
use crate::netns::{self, Addrs, Setup, UsernsUnusable};
use crate::witness::Witness;
use crate::{hostports, procfs, sudo};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use proxytun_core::config::proxy_url::url_has_credentials;
use proxytun_core::config::Config;
use proxytun_core::health;
use proxytun_core::live::build_live;
use proxytun_core::net::fakeip::FakePool;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

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
        tracing::warn!(%key, "config key has no effect in proxytun (a typo, or a proxyhook-only setting); ignored");
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
    let tree_witness = witness.clone();
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
                     it now runs in a session of its own without a controlling terminal: proxytun \
                     passes Ctrl+C and Ctrl+\\ on to it, but job control (Ctrl+Z) and window size \
                     changes do not reach it, and programs that open /dev/tty (password prompts of \
                     ssh, git, sudo) fail"
                );
            }
            (child, ns)
        }
        r => r?,
    };
    let relays = relay_capacity(raise_fd_limit(), ns.forwards.len());
    // A caller that ignores SIGCHLD (that survives exec) would have the kernel
    // reap our children unasked, the program's exit status with them. The
    // program, forked already and waiting for the go-ahead, keeps the
    // caller's setting.
    // SAFETY: plain syscall.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let netns::Handover {
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
    let main_pid = Arc::new(AtomicI32::new(child.pid));
    let SocketAddr::V4(listen) = listener.local_addr()? else {
        anyhow::bail!("the capture listener is not IPv4");
    };

    let sh = Arc::new(Shared::new(
        listen,
        Nat::new(addrs.nat, crate::nat::NAT_ADDRS),
        pool,
        upstream_dns,
        live.clone(),
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
    let health_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    {
        let (sh, main_pid, health_task, cfg_path, proxy_override, sweep_tun) = (
            sh.clone(),
            main_pid.clone(),
            health_task.clone(),
            args.config.clone(),
            proxy_override.clone(),
            tun.clone(),
        );
        let health_cfg = cfg.health.clone();
        rt.block_on(async move {
            listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(listener)?;
            tokio::spawn(capture::run_relay(listener, sh.clone()));
            for (addr, l) in forwards {
                l.set_nonblocking(true)?;
                tokio::spawn(hostports::serve(
                    tokio::net::TcpListener::from_std(l)?,
                    addr,
                    sh.clone(),
                ));
            }
            tokio::spawn(capture::run_sweeper(sweep_tun, sh.clone()));
            *health_task.lock().unwrap() = Some(health::spawn(live.registry.nodes.clone(), health_cfg));
            spawn_signal_handlers(sh, cfg_path, proxy_override, health_task);
            if let Some(fd) = exit_fd {
                spawn_exit_signal_task(fd, main_pid, witness);
            }
            Ok::<_, anyhow::Error>(())
        })?;
    }
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
    child.go()?;

    let exit = wait_tree(child.pid, &main_pid, tree_witness.as_deref());
    rt.shutdown_background();
    Ok(exit)
}

/// How proxytun ends: as the program did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    /// Killed by this signal.
    Signal(libc::c_int),
}

/// End the process as `exit` says. Killed by a signal, the program has us
/// end by the same one, as timeout(1) and sudo do: a shell sees WIFSIGNALED
/// (bash stops a loop on Ctrl+C only then), and a service stopped with
/// SIGTERM counts as stopped, not failed. Without a core dump of ours.
pub fn finish(exit: Exit) -> ! {
    let sig = match exit {
        Exit::Code(c) => std::process::exit(c),
        Exit::Signal(sig) => sig,
    };
    // SAFETY: plain syscalls on our own process.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        libc::signal(sig, libc::SIG_DFL);
        let set = crate::sys::sigset(&[sig]);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
    }
    // A signal whose default is not to end a process (SIGCHLD, SIGWINCH).
    std::process::exit(128 + sig)
}

/// Wait until every process of the program's tree is gone (we are their
/// subreaper) and return how the program itself ended. Once it has, the
/// witness is let go: should it be our child too (we are a pid namespace's
/// init, or were made a subreaper), it is part of what we wait for.
fn wait_tree(main: libc::pid_t, main_pid: &AtomicI32, witness: Option<&Witness>) -> Exit {
    let (mut main, mut exit) = (Some(main), Exit::Code(1));
    loop {
        let mut status = 0;
        // SAFETY: plain syscall.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return exit; // ECHILD: nobody left
        }
        // Once only: its pid may be reused by a later child of the tree.
        if main == Some(pid) {
            main = None;
            exit = if libc::WIFEXITED(status) {
                Exit::Code(libc::WEXITSTATUS(status))
            } else {
                Exit::Signal(libc::WTERMSIG(status))
            };
            main_pid.store(0, Ordering::SeqCst);
            tracing::info!(?exit, "program exited");
            if let Some(w) = witness {
                w.stop();
            }
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
        let set = crate::sys::sigset(sigs);
        let fd = libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            tracing::warn!("signalfd: {}", std::io::Error::last_os_error());
            return None;
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        Some(OwnedFd::from_raw_fd(fd))
    }
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
    let nr_open = std::fs::read_to_string("/proc/sys/fs/nr_open")
        .ok()
        .and_then(|s| s.trim().parse().ok());
    // SAFETY: plain syscalls on a local struct.
    unsafe {
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
    let n = (soft.saturating_sub(reserve) / 2).clamp(1, capture::MAX_RELAYS as u64) as usize;
    if n < capture::MAX_RELAYS {
        tracing::warn!(
            soft,
            "the open-file limit allows {n} connections relayed at once, not {}: raise the hard limit \
             (`ulimit -Hn`, limits.conf) for more",
            capture::MAX_RELAYS
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

#[derive(Debug, PartialEq, Eq)]
enum ExitSignal {
    /// End now, by the signal received. The program's tree keeps running,
    /// cut off from the network (the TUN device goes with us).
    Exit,
    /// From the terminal, to our whole foreground group: pass it on only if
    /// the program is not in that group (see `forward_to`).
    Terminal,
    /// From a process: pass it on unless it got it too.
    Forward,
}

/// SIGINT / SIGQUIT / SIGTERM never stop proxytun while the main program runs:
/// the program decides, and proxytun exits when its tree is gone. `code` is
/// the sender's si_code; `terms` counts SIGTERMs so far.
fn on_exit_signal(sig: libc::c_int, code: i32, program_running: bool, terms: u32) -> ExitSignal {
    // Nobody left to decide (e.g. only a background child keeps us waiting),
    // or a second SIGTERM: whoever sent it wants us gone.
    if !program_running || (sig == libc::SIGTERM && terms >= 2) {
        return ExitSignal::Exit;
    }
    // Sent by the kernel: the terminal's Ctrl+C / Ctrl+\ signals the whole
    // foreground group, the program included if it is still in it.
    if code == libc::SI_KERNEL {
        return ExitSignal::Terminal;
    }
    // From a process: `kill <proxytun>`, or `kill -- -<group>` / `kill %1` /
    // systemd, which look the same from here.
    ExitSignal::Forward
}

/// Where to pass on a signal we got, if anywhere (a pid, or minus a process
/// group). Sent to our whole group (`to_group`: by the terminal, or the
/// witness has it), the program has it too if it is still in that group.
/// From the terminal (`terminal`: Ctrl+C) while the program leads a group of
/// its own (sudo's `use_pty` gave it a session of its own), that whole group
/// gets it, as the terminal would have done: a pipeline or a child is no
/// less interrupted there. A group signal from a process may have reached
/// every process already (systemd signals each one of a service): the
/// program alone gets the copy we pass on. Sent to proxytun alone: the
/// program.
fn forward_to(
    to_group: bool,
    terminal: bool,
    program: libc::pid_t,
    program_pgrp: Option<libc::pid_t>,
    our_pgrp: libc::pid_t,
) -> Option<libc::pid_t> {
    match program_pgrp {
        Some(p) if to_group && p == our_pgrp => None,
        Some(p) if terminal && p == program => Some(-p),
        _ => Some(program),
    }
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
            if action == ExitSignal::Exit {
                tracing::info!(sig, "exiting on a signal");
                finish(Exit::Signal(sig))
            }
            let (witness, main_pid) = (witness.clone(), main_pid.clone());
            tokio::spawn(async move {
                tokio::time::sleep(WITNESS_DELAY).await;
                // Reaped meanwhile: the pid may already be someone else's.
                if main_pid.load(Ordering::SeqCst) != pid {
                    return;
                }
                let terminal = action == ExitSignal::Terminal;
                // Asking the witness blocks (a second at most): not on a
                // runtime worker.
                let saw = match (&witness, terminal) {
                    (Some(w), false) => {
                        let w = w.clone();
                        tokio::task::spawn_blocking(move || w.saw(sig)).await.unwrap_or(false)
                    }
                    _ => false,
                };
                // SAFETY: plain syscall.
                let ours = unsafe { libc::getpgrp() };
                if let Some(to) = forward_to(terminal || saw, terminal, pid, procfs::pgrp_of(pid), ours) {
                    tracing::debug!(sig, to, "forwarding the signal to the program");
                    unsafe { libc::kill(to, sig) };
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
            assert_eq!(on_exit_signal(sig, libc::SI_KERNEL, true, 1), ExitSignal::Terminal);
            // kill(2) from some process: maybe only we got it.
            assert_eq!(on_exit_signal(sig, SI_USER, true, 1), ExitSignal::Forward);
            // Main program gone (a background child keeps us waiting): exit,
            // or Ctrl+C would do nothing at all.
            assert_eq!(on_exit_signal(sig, SI_USER, false, 1), ExitSignal::Exit);
            assert_eq!(on_exit_signal(sig, libc::SI_KERNEL, false, 1), ExitSignal::Exit);
        }
        assert_eq!(
            on_exit_signal(libc::SIGTERM, SI_USER, true, 2),
            ExitSignal::Exit,
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
        // Program 50; our group 7. (to_group, terminal, ...)
        // Sent to the group, and the program is in it: it has its own copy.
        assert_eq!(forward_to(true, false, 50, Some(7), 7), None);
        assert_eq!(forward_to(true, true, 50, Some(7), 7), None);
        // Sent to proxytun alone.
        assert_eq!(forward_to(false, false, 50, Some(7), 7), Some(50));
        // Ctrl+C, the program leading a group of its own (sudo's use_pty):
        // that whole group gets it, its pipeline too.
        assert_eq!(forward_to(true, true, 50, Some(50), 7), Some(-50));
        // A group signal from a process (systemd's, one to each process):
        // the others may have theirs already; the program alone.
        assert_eq!(forward_to(true, false, 50, Some(50), 7), Some(50));
        // Moved into someone else's group: the program alone.
        assert_eq!(forward_to(true, true, 50, Some(9), 7), Some(50));
        // Program already gone: nothing to hold back for.
        assert_eq!(forward_to(true, false, 50, None, 7), Some(50));
        // Sent to proxytun alone, the program leading its own group: only it.
        assert_eq!(forward_to(false, false, 50, Some(50), 7), Some(50));
    }

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
        assert_eq!(relay_capacity(1 << 20, 250), crate::capture::MAX_RELAYS);
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
