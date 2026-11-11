//! proxytun: run one program, and every process it starts, inside a private
//! network namespace whose only way out is a TUN device served by proxytun;
//! its TCP goes to a SOCKS5/HTTP proxy with domain names preserved. No ptrace,
//! so strace and gdb keep working.

mod accept;
mod app;
mod capture;
mod ctl;
mod doctor;
mod hostports;
mod logging;
mod nat;
mod netcfg;
mod netns;
mod packet;
mod procfs;
mod signals;
mod state;
mod sudo;
mod sys;
mod witness;

use anyhow::Result;
use app::Args;
use clap::{ArgAction, Parser, ValueEnum};
use std::path::PathBuf;
use tracing_subscriber::filter::LevelFilter;

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
                  or per-module filters (proxytun=info,proxytun::capture=trace,proxytun::accept=trace)"
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

    /// Log more: -v for debug, -vv for trace (each captured SYN, the connection that takes it, dropped packets).
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
        // At most one of -q, -v / -vv and --log-level is set (clap rejects
        // the combinations); None when none is.
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

fn main() -> Result<()> {
    // argv[1] may name an internal role, each a fresh run of this binary:
    // the sudo root helper, or the namespace setup process. Neither returns.
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
    logging::init_logging(
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
        std::process::exit(doctor::main(&cli.config, cli.proxy.as_deref(), cli.no_sudo)?);
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
    // Never returns: exit with the program's code, or by the signal that
    // killed it.
    signals::finish(exit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::filter::EnvFilter;

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
