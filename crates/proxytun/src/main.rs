//! proxytun: run one program, and every process it starts, inside a private
//! network namespace whose only way out is a TUN device served by proxytun;
//! its TCP goes to a SOCKS5/HTTP proxy with domain names preserved. No ptrace,
//! so strace and gdb keep working.

mod app;
mod capture;
mod doctor;
mod hostports;
mod nat;
mod netcfg;
mod netns;
mod packet;
mod sudo;
mod witness;

use anyhow::{ensure, Context, Result};
use app::Args;
use clap::{ArgAction, Parser, ValueEnum};
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Parser, Debug)]
#[command(
    name = "proxytun",
    version,
    about = "Run one program through a SOCKS5/HTTP proxy via a private TUN namespace, domain names preserved",
    after_help = "Examples:\n  \
                  proxytun -c proxytun.toml curl https://example.com\n  \
                  proxytun -c proxytun.toml strace -f -e trace=network curl https://example.com\n  \
                  proxytun -v --log-file proxytun.log -c proxytun.toml curl https://example.com\n\
                  \n\
                  proxytun's own options go before the program; everything from the program\n\
                  name on is passed to it unchanged. A `--` before the program is optional.\n\
                  \n\
                  Environment:\n  \
                  PROXYTUN_PROXY  Upstream proxy URL, as --proxy but hidden from `ps`\n  \
                  PROXYTUN_LOG    Log filter when no -q, -v or --log-level is given: a level,\n                  \
                  or per-module filters (proxytun=info,proxytun::capture=trace)"
)]
struct Cli {
    /// Path to the TOML config.
    #[arg(short, long, default_value = "proxytun.toml")]
    config: PathBuf,

    /// Upstream proxy URL, overriding the config (socks5://host:port or
    /// http://[user:pass@]host:port). Also read from $PROXYTUN_PROXY.
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Never fall back to sudo: fail if user namespaces are not usable.
    #[arg(long)]
    no_sudo: bool,

    /// Do not forward the host's loopback listeners into the namespace.
    #[arg(long)]
    no_host_ports: bool,

    /// Check this host (namespaces, TUN, sudo, proxies, host ports) and exit.
    #[arg(long)]
    doctor: bool,

    /// Log errors only (same as --log-level error).
    #[arg(short, long, conflicts_with_all = ["verbose", "log_level"])]
    quiet: bool,

    /// Log more: -v for debug, -vv for trace (every captured connection's packets).
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "log_level")]
    verbose: u8,

    /// Log level, default info (or $PROXYTUN_LOG, see below).
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<LogLevel>,

    /// Append the log to this file (created with mode 600) instead of writing
    /// it to stderr. The program's own output is left alone.
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// The program to run and its arguments, e.g. `curl -c jar https://x`
    // Parsing stops at the program name, so its own options (`-c` there) are
    // not taken for ours, as with proxychains and graftcp.
    #[arg(trailing_var_arg = true, required_unless_present = "doctor")]
    argv: Vec<std::ffi::OsString>,
}

impl Cli {
    /// The log filter: a level option, else $PROXYTUN_LOG (`env`), else info.
    /// A bare level applies to proxytun only (both of its crates), never to
    /// its libraries.
    fn log_filter(&self, env: Option<String>) -> String {
        let level = match (self.quiet, self.verbose, self.log_level) {
            (true, ..) => Some(LogLevel::Error),
            (_, 0, l) => l,
            (_, 1, _) => Some(LogLevel::Debug),
            _ => Some(LogLevel::Trace),
        };
        let spec = match level {
            Some(l) => l
                .to_possible_value()
                .expect("no skipped variants")
                .get_name()
                .to_owned(),
            None => env.filter(|s| !s.is_empty()).unwrap_or_else(|| "info".into()),
        };
        if spec.parse::<LevelFilter>().is_ok() {
            format!("proxytun={spec},proxytun_core={spec}")
        } else {
            spec
        }
    }
}

/// stderr for our log lines, which never blocks and never fails: a reader
/// that stalls (Ctrl+S, a pipe nobody reads) must not freeze every relay
/// with it, nor one that is gone (`2>&1 | head`, a hung-up terminal) turn
/// each log line into a panic. A line that cannot be written at once is
/// dropped. Pipes and terminals get a description of their own, opened
/// non-blocking (the program shares the one on fd 2: switching that would
/// change it for the program too); where that open is refused (someone
/// else's terminal, after `su`), fd 2 is written only while poll says it
/// takes more, a pipe's atomic 4 KiB at a time; sockets (the journal) are
/// sent to without waiting; anything else (a file) is written as it is.
#[derive(Clone, Copy)]
struct LogSink {
    fd: std::os::fd::RawFd,
    socket: bool,
    /// Blocking: poll before each write.
    gated: bool,
}

impl LogSink {
    fn stderr() -> LogSink {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat fills a local struct.
        let kind = if unsafe { libc::fstat(2, &mut st) } == 0 {
            st.st_mode & libc::S_IFMT
        } else {
            0
        };
        let sink = |fd, socket, gated| LogSink { fd, socket, gated };
        if kind == libc::S_IFSOCK {
            return sink(2, true, false);
        }
        if kind == libc::S_IFIFO || kind == libc::S_IFCHR {
            let flags = libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
            // SAFETY: plain open; the fd is ours for good (logging lasts as
            // long as the process).
            let fd = unsafe { libc::open(c"/proc/self/fd/2".as_ptr(), flags) };
            return if fd >= 0 {
                sink(fd, false, false)
            } else {
                sink(2, false, true)
            };
        }
        sink(2, false, false)
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut rest = buf;
        while !rest.is_empty() {
            let mut chunk = rest;
            if self.gated {
                let mut p = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: a local pollfd.
                if unsafe { libc::poll(&mut p, 1, 0) } != 1 || p.revents & libc::POLLOUT == 0 {
                    break; // full: the rest is dropped
                }
                chunk = &rest[..rest.len().min(libc::PIPE_BUF)];
            }
            // SAFETY: plain writes of our own buffer.
            let n = unsafe {
                if self.socket {
                    libc::send(
                        self.fd,
                        chunk.as_ptr().cast(),
                        chunk.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                } else {
                    libc::write(self.fd, chunk.as_ptr().cast(), chunk.len())
                }
            };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if n <= 0 {
                break; // full, or nobody reading: the rest is dropped
            }
            rest = &rest[n as usize..];
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging(filter: &str, file: Option<&Path>) -> Result<()> {
    let filter = EnvFilter::try_new(filter).with_context(|| format!("bad log filter {filter:?}"))?;
    // A write that fails is not reported on stderr in turn: that would panic
    // when stderr is what failed.
    let fmt = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .log_internal_errors(false);
    match file {
        // Only our own writer moves: stderr stays as it was, and std opens the
        // file close-on-exec, so the program inherits neither.
        Some(path) => {
            // Not through a link, and only into a file of our own: in /tmp,
            // someone else may have created it first, readable by them, or as
            // a FIFO nobody reads, which would block a plain open forever.
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .with_context(|| format!("open log file {}", path.display()))?;
            let meta = f.metadata()?;
            ensure!(
                meta.is_file() && meta.uid() == nix::unistd::geteuid().as_raw(),
                "log file {} is not a regular file of yours",
                path.display()
            );
            fmt.with_ansi(false).with_writer(Arc::new(f)).init();
        }
        None => {
            let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
            let sink = LogSink::stderr();
            fmt.with_ansi(color).with_writer(move || sink).init();
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mode = std::env::args_os().nth(1);
    if mode.as_deref() == Some(std::ffi::OsStr::new(sudo::HELPER_ARG)) {
        // The root helper, run through sudo (it checks that itself).
        sudo::helper_main(&std::env::args_os().collect::<Vec<_>>());
    }
    // Everything else, the namespace setup included, must not run as root
    // through sudo or setuid.
    if let Some(why) = sudo::root_refusal_here() {
        eprintln!("proxytun: {why}");
        std::process::exit(2);
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new(netns::SETUP_ARG)) {
        // The process that sets up the namespace and becomes the program.
        netns::setup_main(&std::env::args_os().collect::<Vec<_>>());
    }
    let cli = Cli::parse();
    init_logging(
        &cli.log_filter(std::env::var("PROXYTUN_LOG").ok()),
        cli.log_file.as_deref(),
    )?;
    // A panic (a thread the kernel would not give us, say) belongs in the log
    // file too; without one, the usual report on stderr is enough.
    if cli.log_file.is_some() {
        let report = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            tracing::error!("panic: {info}");
            report(info);
        }));
    }

    if cli.doctor {
        let proxy = app::take_proxy_override(cli.proxy.as_deref());
        let (cfg, problem) = match app::load_config(&cli.config, proxy.as_deref()) {
            Ok(c) => (c, None),
            // Still check the host, with the default settings and no proxy.
            Err(e) => {
                let mut c = proxytun_core::config::Config::parse("[proxy]\ntype=\"socks5\"\naddr=\"127.0.0.1:1\"\n")?;
                c.proxies.clear();
                (c, Some(format!("{e:#}")))
            }
        };
        let mut checks = Vec::new();
        if let Some(p) = problem {
            checks.push(doctor::Check {
                name: "config",
                status: doctor::Status::Fail,
                detail: p,
            });
        }
        checks.extend(doctor::run_checks(&cfg, cli.no_sudo));
        std::process::exit(doctor::report(&checks));
    }

    let to_file = cli.log_file.is_some();
    let exit = app::run(Args {
        config: cli.config,
        proxy: cli.proxy,
        no_sudo: cli.no_sudo,
        no_host_ports: cli.no_host_ports,
        argv: cli.argv,
    })
    // Returning the error prints it to stderr; a log file needs its own copy.
    .inspect_err(|e| {
        if to_file {
            tracing::error!("{e:#}");
        }
    })?;
    app::finish(exit);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("proxytun").chain(args.iter().copied()))
    }

    #[test]
    fn options_after_the_program_name_belong_to_the_program() {
        for args in [
            &["-c", "my.toml", "curl", "-c", "jar", "-V", "--proxy", "x", "https://x"][..],
            &[
                "-c",
                "my.toml",
                "--",
                "curl",
                "-c",
                "jar",
                "-V",
                "--proxy",
                "x",
                "https://x",
            ][..],
        ] {
            let cli = parse(args).unwrap();
            assert_eq!(cli.config, PathBuf::from("my.toml"), "{args:?}");
            assert_eq!(cli.proxy, None, "{args:?}: --proxy after the program is the program's");
            assert_eq!(
                cli.argv,
                ["curl", "-c", "jar", "-V", "--proxy", "x", "https://x"],
                "{args:?}"
            );
        }
    }

    #[test]
    fn our_options_go_before_the_program_and_it_is_required() {
        let cli = parse(&["--proxy", "socks5://h:1", "curl"]).unwrap();
        assert_eq!(cli.proxy.as_deref(), Some("socks5://h:1"));
        assert_eq!(cli.argv, ["curl"]);
        // `--` still lets a program whose name starts with '-' through.
        assert_eq!(parse(&["--", "-odd", "a"]).unwrap().argv, ["-odd", "a"]);
        assert!(parse(&[]).is_err(), "nothing to run");
        assert!(
            parse(&["--doctor"]).unwrap().argv.is_empty(),
            "--doctor needs no program"
        );
        assert!(
            parse(&["--proxi", "x", "curl"]).is_err(),
            "a mistyped option is not a program"
        );
    }

    #[test]
    fn log_level_comes_from_our_options_then_the_environment() {
        let filter = |args: &[&str], env: Option<&str>| parse(args).unwrap().log_filter(env.map(String::from));
        assert_eq!(filter(&["curl"], None), "proxytun=info,proxytun_core=info");
        assert_eq!(filter(&["-q", "curl"], None), "proxytun=error,proxytun_core=error");
        assert_eq!(filter(&["-v", "curl"], None), "proxytun=debug,proxytun_core=debug");
        assert_eq!(filter(&["-vv", "curl"], None), "proxytun=trace,proxytun_core=trace");
        assert_eq!(
            filter(&["--log-level", "off", "curl"], None),
            "proxytun=off,proxytun_core=off"
        );
        // An option on the command line beats a filter left in the environment.
        assert_eq!(
            filter(&["-q", "curl"], Some("trace")),
            "proxytun=error,proxytun_core=error"
        );
        // A bare level must not switch on our libraries' logs (hickory, tokio);
        // anything else is a filter for experts and used as written.
        assert_eq!(filter(&["curl"], Some("debug")), "proxytun=debug,proxytun_core=debug");
        let modules = "proxytun=info,proxytun::capture=trace";
        assert_eq!(filter(&["curl"], Some(modules)), modules);
        assert_eq!(filter(&["curl"], Some("")), "proxytun=info,proxytun_core=info");
        for args in [
            &["curl"][..],
            &["-q", "curl"],
            &["-vv", "curl"],
            &["--log-level", "warn", "curl"],
        ] {
            let f = filter(args, None);
            assert!(EnvFilter::try_new(&f).is_ok(), "{f}");
        }
    }

    #[test]
    fn help_lists_every_option_and_environment_variable() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        let cmd = Cli::command();
        for arg in cmd.get_arguments().filter(|a| !a.is_positional()) {
            let flag = format!("--{}", arg.get_long().unwrap());
            assert!(help.contains(&flag), "{flag} missing from --help");
        }
        for var in ["PROXYTUN_PROXY", "PROXYTUN_LOG"] {
            assert!(
                help.contains(&format!("  {var}  ")),
                "{var} missing from --help:\n{help}"
            );
        }
        cmd.debug_assert();
    }

    #[test]
    fn log_options_are_ours_only_before_the_program() {
        let cli = parse(&["-v", "--log-file", "x.log", "curl", "-v", "-q", "--log-file", "y"]).unwrap();
        assert_eq!((cli.verbose, cli.quiet), (1, false));
        assert_eq!(cli.log_file, Some(PathBuf::from("x.log")));
        assert_eq!(cli.argv, ["curl", "-v", "-q", "--log-file", "y"]);
        // One way to set the level at a time.
        assert!(parse(&["-q", "-v", "curl"]).is_err());
        assert!(parse(&["-q", "--log-level", "info", "curl"]).is_err());
        assert!(parse(&["-v", "--log-level", "info", "curl"]).is_err());
        assert!(parse(&["--log-level", "loud", "curl"]).is_err());
    }
}
