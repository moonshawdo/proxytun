//! End-to-end tests: run the real `proxytun` binary (real namespaces, real TUN
//! device) around real programs and watch what a mock proxy receives.
//!
//! The decisive assertion everywhere is the one the whole tool exists for: the
//! proxy must see a DOMAIN, not the fake IP.
//!
//! Tests skip (loudly) when the host cannot create the namespace or a helper
//! program (curl, python3, dig) is missing.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_proxytun");
const BODY: &str = "hello-from-origin";

// ------------------------------------------------------------- fixtures --

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    /// SOCKS5 ATYP (1 = IPv4, 3 = domain), or 0 for an HTTP CONNECT.
    atyp: u8,
    host: String,
    port: u16,
}

struct Mock {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.seen().into_iter().map(|s| s.host).collect();
        v.sort();
        v
    }
}

/// `*.test` domains and the documentation address 203.0.113.9 lead to the
/// local origin server; anything else is refused by the mock proxies.
fn mappable(host: &str) -> bool {
    host.ends_with(".test") || host == "203.0.113.9"
}

fn start_mock(origin_port: u16, http: bool) -> Mock {
    start_mock_on("127.0.0.1:0", origin_port, http)
}

fn start_mock_on(bind: &str, origin_port: u16, http: bool) -> Mock {
    let l = TcpListener::bind(bind).unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let seen = seen2.clone();
            std::thread::spawn(move || {
                let _ = if http {
                    serve_connect(c, origin_port, seen)
                } else {
                    serve_socks(c, origin_port, seen)
                };
            });
        }
    });
    Mock { addr, seen }
}

/// A SOCKS5 proxy that records requests.
fn start_mock_proxy(origin_port: u16) -> Mock {
    start_mock(origin_port, false)
}

fn serve_socks(mut c: TcpStream, origin_port: u16, seen: Arc<Mutex<Vec<Seen>>>) -> std::io::Result<()> {
    let mut b = [0u8; 262];
    let n = c.read(&mut b)?;
    if n < 3 {
        return Ok(());
    }
    c.write_all(&[5, 0])?;
    let mut h = [0u8; 4];
    c.read_exact(&mut h)?;
    let (host, atyp) = match h[3] {
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l)?;
            let mut d = vec![0u8; l[0] as usize];
            c.read_exact(&mut d)?;
            (String::from_utf8_lossy(&d).into_owned(), 3)
        }
        1 => {
            let mut d = [0u8; 4];
            c.read_exact(&mut d)?;
            (Ipv4Addr::from(d).to_string(), 1)
        }
        a => (format!("atyp{a}"), a),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p)?;
    let port = u16::from_be_bytes(p);
    seen.lock().unwrap().push(Seen {
        atyp,
        host: host.clone(),
        port,
    });
    if !mappable(&host) {
        c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    }
    let Ok(up) = TcpStream::connect(("127.0.0.1", origin_port)) else {
        c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Ok(());
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    bridge(c, up);
    Ok(())
}

/// An HTTP proxy that only does CONNECT and records `host:port`.
fn serve_connect(mut c: TcpStream, origin_port: u16, seen: Arc<Mutex<Vec<Seen>>>) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b)? == 0 {
            return Ok(());
        }
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let authority = head.split_whitespace().nth(1).unwrap_or_default().to_string();
    let (host, port) = authority.rsplit_once(':').unwrap_or((&authority, "0"));
    seen.lock().unwrap().push(Seen {
        atyp: 0,
        host: host.to_string(),
        port: port.parse().unwrap_or(0),
    });
    if !mappable(host) {
        c.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")?;
        return Ok(());
    }
    let up = TcpStream::connect(("127.0.0.1", origin_port))?;
    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    bridge(c, up);
    Ok(())
}

fn bridge(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let (mut a, mut b) = (a, b);
    let _ = std::io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

fn read_head(c: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Minimal HTTP/1.0 origin on `bind`: `GET /big/<n>` returns n pattern bytes,
/// `POST` returns a checksum of the body, anything else returns BODY.
fn start_origin_on(bind: &str) -> u16 {
    let l = TcpListener::bind(bind).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let Some(head) = read_head(&mut c) else { return };
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                if head.starts_with("POST") {
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_string())
                        })
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; len];
                    if c.read_exact(&mut body).is_err() {
                        return;
                    }
                    let sum = checksum(&body);
                    let _ = write!(
                        c,
                        "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{sum}",
                        sum.to_string().len()
                    );
                } else if let Some(n) = path.strip_prefix("/big/").and_then(|n| n.parse::<usize>().ok()) {
                    let _ = write!(c, "HTTP/1.0 200 OK\r\nContent-Length: {n}\r\n\r\n");
                    let _ = c.write_all(&pattern(n));
                } else {
                    let _ = write!(c, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{BODY}", BODY.len());
                }
            });
        }
    });
    port
}

fn start_origin() -> u16 {
    start_origin_on("127.0.0.1:0")
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Order-sensitive, so a reordered or duplicated chunk is caught too.
fn checksum(b: &[u8]) -> u64 {
    b.iter()
        .fold(0u64, |h, &x| h.wrapping_mul(1_000_003).wrapping_add(x as u64))
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Skip when the host cannot create proxytun's namespace at all.
fn namespaces_work() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OK.get_or_init(|| {
        let out = Command::new(BIN)
            .args(["--proxy", "socks5://127.0.0.1:1", "--", "true"])
            .env("PROXYTUN_LOG", "error")
            .output()
            .expect("run proxytun");
        if !out.status.success() {
            eprintln!(
                "SKIP: proxytun cannot set up its namespace on this host; end-to-end tests cannot run: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        out.status.success()
    })
}

macro_rules! require {
    ($($tool:expr),*) => {{
        if !namespaces_work() { return; }
        $( if !have($tool) { eprintln!("SKIP: {} not installed", $tool); return; } )*
    }};
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Prefix of the directories the tests make in $TMPDIR, followed by our pid.
const TMP_PREFIX: &str = "proxytun-test-";

/// A directory of our own for one test, created by us (0700), never one
/// someone else made first under the name: we write scripts there and run
/// them. Leftovers of earlier runs are removed first, as far as we may.
fn tmp_dir(name: &str) -> PathBuf {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(sweep_old_tmp_dirs);
    let d = std::env::temp_dir().join(format!("{TMP_PREFIX}{}-{name}", std::process::id()));
    match std::fs::DirBuilder::new().mode(0o700).create(&d) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Asked for again this run (a helper's own directory).
            let m = std::fs::symlink_metadata(&d).unwrap();
            assert!(
                m.is_dir() && m.uid() == unsafe { libc::geteuid() },
                "{} was not made by us",
                d.display()
            );
        }
        Err(e) => panic!("create {}: {e}", d.display()),
    }
    d
}

/// Remove what earlier test runs (ours, their process gone) left in
/// $TMPDIR. Best effort: the CentOS 7 simulation leaves files of other uids
/// in directories we cannot empty.
fn sweep_old_tmp_dirs() {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(TMP_PREFIX))
            .and_then(|rest| rest.split('-').next())
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        let ours = e
            .path()
            .symlink_metadata()
            .is_ok_and(|m| m.is_dir() && m.uid() == unsafe { libc::geteuid() });
        if ours && pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Write a config pointing at `proxy`, with `top` (top-level keys) and `rules`.
fn write_cfg_kind(dir: &Path, kind: &str, proxy: SocketAddr, top: &str, rules: &str) -> PathBuf {
    let p = dir.join("cfg.toml");
    std::fs::write(
        &p,
        format!(
            "{top}\n[[proxies]]\nname=\"mock\"\ntype=\"{kind}\"\naddr=\"{proxy}\"\n\
             [[groups]]\nname=\"default\"\nmembers=[\"mock\"]\n{rules}\n"
        ),
    )
    .unwrap();
    p
}

fn write_cfg(dir: &Path, proxy: SocketAddr, top: &str, rules: &str) -> PathBuf {
    write_cfg_kind(dir, "socks5", proxy, top, rules)
}

fn run(cfg: &Path, extra: &[&str], argv: &[&str], env: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.arg("-c").arg(cfg).args(extra).arg("--").args(argv);
    run_cmd(cmd, env)
}

/// Run `cmd` (proxytun, or something that starts it) with a clean proxy
/// environment plus `env`, and capture everything.
fn run_cmd(mut cmd: Command, env: &[(&str, &str)]) -> Out {
    for k in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "PROXYTUN_PROXY",
    ] {
        cmd.env_remove(k);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.env("PROXYTUN_LOG", "debug");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // A process group of its own: on a timeout, all it started goes with it.
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd.spawn().expect("spawn proxytun");
    let (tx, rx) = std::sync::mpsc::channel();
    let pipes: [(usize, Box<dyn Read + Send>); 2] = [
        (0, Box::new(child.stdout.take().unwrap())),
        (1, Box::new(child.stderr.take().unwrap())),
    ];
    for (i, mut pipe) in pipes {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = pipe.read_to_string(&mut s);
            let _ = tx.send((i, s));
        });
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let code = loop {
        if let Some(st) = child.try_wait().unwrap() {
            // Killed by a signal: minus its number, as Python has it.
            break st
                .code()
                .unwrap_or_else(|| -std::os::unix::process::ExitStatusExt::signal(&st).unwrap_or(1));
        }
        if Instant::now() > deadline {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            break -999;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Until both pipes close. Something that left the group (a session of
    // its own) may still hold them: not for ever.
    let mut got = [String::new(), String::new()];
    let until = Instant::now() + Duration::from_secs(if code == -999 { 2 } else { 60 });
    for _ in 0..2 {
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok((i, s)) => got[i] = s,
            Err(_) => break,
        }
    }
    let [stdout, stderr] = got;
    Out { code, stdout, stderr }
}

impl Out {
    fn dump(&self) -> String {
        format!(
            "exit={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// An address that refuses connections and cannot be grabbed by a parallel test:
/// bound but not listening (binding a listener and dropping it races).
fn refused_addr() -> (std::os::fd::OwnedFd, SocketAddr) {
    use std::os::fd::FromRawFd;
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
        (
            std::os::fd::OwnedFd::from_raw_fd(fd),
            SocketAddr::from(([127, 0, 0, 1], u16::from_be(out.sin_port))),
        )
    }
}

/// This host's address on its outward interface (not loopback), if any.
fn host_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?; // no packet is sent
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

// ---------------------------------------------------------------- tests --

#[test]
fn curl_a_domain_reaches_the_proxy_as_a_domain() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("domain");
    // No sniffing: the domain must come from the fake-IP mapping alone, not
    // from the Host header.
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let out = run(
        &cfg,
        &[],
        &["curl", "-sS", "--max-time", "20", "http://site.test/"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    assert_eq!(
        mock.seen(),
        [Seen {
            atyp: 3,
            host: "site.test".into(),
            port: 80
        }],
        "the proxy must get the DOMAIN, not the fake IP\n{}",
        out.dump()
    );
    // Every line about the connection names it, with the recovered target.
    assert!(
        out.stderr.contains(r#"conn{id=1 target=Domain("site.test", 80)}"#),
        "{}",
        out.dump()
    );
}

#[test]
fn an_http_proxy_gets_connect_with_the_domain() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock(origin, true);
    let dir = tmp_dir("http-connect");
    let cfg = write_cfg_kind(&dir, "http", mock.addr, "", "");
    let out = run(
        &cfg,
        &[],
        &["curl", "-sS", "--max-time", "20", "http://web.test:8080/"],
        &[],
    );
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    assert_eq!(
        mock.seen(),
        [Seen {
            atyp: 0,
            host: "web.test".into(),
            port: 8080
        }],
        "{}",
        out.dump()
    );
}

#[test]
fn literal_ip_is_sent_as_ip() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("literal");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    let out = run(
        &cfg,
        &[],
        &["curl", "-sS", "--max-time", "20", "http://203.0.113.9/"],
        &[],
    );
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    assert_eq!(
        mock.seen(),
        [Seen {
            atyp: 1,
            host: "203.0.113.9".into(),
            port: 80
        }]
    );
}

#[test]
fn the_whole_process_tree_is_captured_and_waited_for() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("tree");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    // A grandchild that outlives the program still runs inside, and proxytun
    // waits for it.
    let script = "curl -s http://a.test/ >/dev/null; (sleep 1; curl -s http://b.test/ >/dev/null) & exit 0";
    let out = run(&cfg, &[], &["sh", "-c", script], &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(mock.hosts(), ["a.test", "b.test"], "{}", out.dump());
}

#[test]
fn the_exit_code_survives_a_caller_that_ignores_sigchld() {
    require!("python3");
    let dir = tmp_dir("sigchld-ignored");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // SIG_IGN survives exec: the kernel would reap proxytun's children unasked
    // and the program's status would be lost. The program itself still gets
    // the caller's setting.
    let mut cmd = Command::new("python3");
    cmd.arg("-c").arg(
        "import os, signal, sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); \
         os.execv(sys.argv[1], sys.argv[1:])",
    );
    cmd.args([BIN, "-c", cfg.to_str().unwrap(), "--", "python3", "-c"])
        .arg("import signal, sys; print(signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN); sys.exit(7)");
    let out = run_cmd(cmd, &[]);
    assert_eq!(out.code, 7, "{}", out.dump());
    assert_eq!(out.stdout, "True\n", "{}", out.dump());
}

#[test]
fn host_mounts_made_later_reach_the_program_and_ours_never_leave() {
    require!("unshare", "mount");
    let dir = tmp_dir("propagation");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    std::fs::create_dir_all(dir.join("m")).unwrap();
    // A host (root, with shared mounts) where a share is mounted after
    // proxytun started (autofs, a USB disk): the program must see it; and
    // the resolv.conf proxytun mounts for the program must stay inside.
    let script = r#"
        mount -t tmpfs none "$D/m" && mount --make-shared "$D/m"
        "$BIN" -c "$D/cfg.toml" -- sh -c '
            touch "$D/ready"; while [ ! -e "$D/go" ]; do sleep 0.05; done; cat "$D/m/sub/file"
            grep nameserver /etc/resolv.conf' &
        until [ -e "$D/ready" ]; do sleep 0.05; done
        mkdir "$D/m/sub" && mount -t tmpfs none "$D/m/sub" && echo late-mount > "$D/m/sub/file"
        echo "nameserver 127.0.0.53" > "$D/host-resolv" && mount --bind "$D/host-resolv" /etc/resolv.conf
        touch "$D/go"; wait $!; echo "code $?"
        grep -c 198.19.255.53 /etc/resolv.conf"#;
    let mut cmd = Command::new("unshare");
    cmd.args(["-Urm", "--propagation", "shared", "sh", "-c", script]);
    let out = run_cmd(cmd, &[("BIN", BIN), ("D", dir.to_str().unwrap())]);
    let lines: Vec<&str> = out.stdout.lines().collect();
    // A host tool binding its own resolv.conf meanwhile (a VPN script) does
    // not cover ours: since Linux 4.11 a propagated mount goes underneath.
    assert_eq!(
        lines,
        ["late-mount", "nameserver 198.19.255.53", "code 0", "0"],
        "{}",
        out.dump()
    );
}

#[test]
fn as_a_pid_namespaces_init_or_a_subreaper_proxytun_still_ends_with_the_program() {
    require!("unshare", "python3");
    let dir = tmp_dir("init");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // In a container without an init (`docker run` without --init), and
    // under a wrapper that made itself a subreaper: orphans, our signal
    // witness among them, come to us, and we wait for all of them.
    let mut cmd = Command::new("unshare");
    cmd.args([
        "-Urpf",
        "--mount-proc",
        BIN,
        "-c",
        cfg.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "exit 7",
    ]);
    let out = run_cmd(cmd, &[]);
    assert_eq!(out.code, 7, "{}", out.dump());
    let mut cmd = Command::new("python3");
    cmd.args([
        "-c",
        "import ctypes, os, sys; ctypes.CDLL(None).prctl(36, 1, 0, 0, 0); os.execv(sys.argv[1], sys.argv[1:])",
        BIN,
        "-c",
        cfg.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        "exit 7",
    ]);
    let out = run_cmd(cmd, &[]);
    assert_eq!(out.code, 7, "{}", out.dump());
}

/// Runs argv[3:] (proxytun and its arguments) with stderr on a pipe that,
/// as argv[2] says, nobody reads ("stalled") or nobody has open ("gone").
const PY_STDERR: &str = r#"
import fcntl, os, subprocess, sys
mode, argv = sys.argv[1], sys.argv[2:]
r, w = os.pipe()
fcntl.fcntl(w, 1031, 4096)  # F_SETPIPE_SZ: one page, full after a few lines
if mode == "gone":
    os.close(r)
p = subprocess.Popen(argv, stderr=w, stdout=subprocess.PIPE)
os.close(w)
try:
    out, _ = p.communicate(timeout=40)
    print("rc", p.returncode)
    sys.stdout.write(out.decode())
except subprocess.TimeoutExpired:
    p.kill()
    print("rc timeout")
"#;

#[test]
fn a_stalled_or_vanished_stderr_stops_neither_the_program_nor_proxytun() {
    require!("python3", "curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("stderr");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    std::fs::write(dir.join("stderr.py"), PY_STDERR).unwrap();
    // Each connection logs a dozen lines at trace level: a pipe nobody reads
    // is full after a few connections, and a terminal on Ctrl+S, or a reader gone
    // (`2>&1 | head`, a closed ssh session), are no different for us.
    let prog = "for i in $(seq 40); do curl -s --max-time 5 http://log.test/ || echo fail; echo; done; exit 7";
    for mode in ["stalled", "gone"] {
        let mut cmd = Command::new("python3");
        cmd.arg(dir.join("stderr.py"))
            .arg(mode)
            .args([BIN, "-vv", "-c", cfg.to_str().unwrap(), "--", "sh", "-c"])
            .arg(format!("({prog}) 2>/dev/null"));
        let out = run_cmd(cmd, &[]);
        assert!(out.stdout.starts_with("rc 7\n"), "{mode}\n{}", out.dump());
        assert_eq!(out.stdout.matches(BODY).count(), 40, "{mode}\n{}", out.dump());
    }
}

#[test]
fn exit_codes_are_propagated() {
    require!();
    let dir = tmp_dir("exit");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    assert_eq!(run(&cfg, &[], &["sh", "-c", "exit 7"], &[]).code, 7);
    // Killed by a signal, the program has proxytun end by the same one: a
    // shell or service manager sees what it would without proxytun.
    for sig in [libc::SIGKILL, libc::SIGTERM, libc::SIGINT, libc::SIGSEGV] {
        let out = run(&cfg, &[], &["sh", "-c", &format!("kill -{sig} $$")], &[]);
        assert_eq!(out.code, -sig, "{}", out.dump());
    }
    let out = run(&cfg, &[], &["/nonexistent/program"], &[]);
    assert_eq!(out.code, 127, "{}", out.dump());
    assert!(out.stderr.contains("cannot execute"), "{}", out.dump());
}

#[test]
fn the_program_sees_only_our_dns_and_the_host_keeps_its_own() {
    require!();
    let host_before = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let dir = tmp_dir("resolv");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let out = run(&cfg, &[], &["sh", "-c", "cat /etc/resolv.conf; id -u"], &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    let nameservers: Vec<&str> = out.stdout.lines().filter(|l| l.starts_with("nameserver")).collect();
    assert_eq!(nameservers, ["nameserver 198.19.255.53"], "{}", out.dump());
    let uid = out.stdout.lines().last().unwrap();
    assert_eq!(uid, current_uid().to_string(), "the program keeps our uid");
    assert_eq!(
        std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
        host_before,
        "the host's resolv.conf is untouched"
    );
}

fn current_uid() -> u32 {
    let out = Command::new("id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// Ask for `name` over UDP (connect+send, and sendto) and TCP, each to a
/// different, real-looking server; print the answers.
const PY_DNS: &str = r#"
import socket, struct, sys
def query(name):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)
def first_a(resp):
    # answers follow the question; the first A record's last 4 bytes
    return socket.inet_ntoa(resp[-4:])
name = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.connect(("8.8.8.8", 53)); s.send(query(name)); print("udp-connect", first_a(s.recv(512)))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(query(name), ("9.9.9.9", 53)); data, src = s.recvfrom(512)
print("udp-sendto", first_a(data), src[0])
t = socket.create_connection(("1.1.1.1", 53), timeout=5)
q = query(name); t.sendall(struct.pack(">H", len(q)) + q)
n = struct.unpack(">H", t.recv(2))[0]; r = b""
while len(r) < n: r += t.recv(n - len(r))
print("tcp", first_a(r))
"#;

#[test]
fn dns_to_any_server_over_udp_or_tcp_gets_a_fake_ip() {
    require!("python3");
    let dir = tmp_dir("dns");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let out = run(&cfg, &[], &["python3", "-c", PY_DNS, "any.test"], &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    let lines: Vec<Vec<&str>> = out.stdout.lines().map(|l| l.split(' ').collect()).collect();
    assert_eq!(lines.len(), 3, "{}", out.dump());
    let ip: Ipv4Addr = lines[0][1].parse().unwrap();
    assert!(
        "198.18.0.0/15".parse::<ipnet::Ipv4Net>().unwrap().contains(&ip),
        "a fake IP: {ip}"
    );
    assert!(
        lines.iter().all(|l| l[1] == ip.to_string()),
        "one name, one fake IP:\n{}",
        out.dump()
    );
    assert_eq!(lines[1][2], "9.9.9.9", "the reply comes from the server asked");
}

#[test]
fn dig_works_against_the_fake_dns() {
    require!("dig");
    let dir = tmp_dir("dig");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let out = run(
        &cfg,
        &[],
        &[
            "sh",
            "-c",
            "dig +short a.test; dig +short +tcp @9.9.9.9 a.test; dig +short AAAA a.test",
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "two A answers, no AAAA:\n{}", out.dump());
    assert_eq!(lines[0], lines[1]);
    assert!(lines[0].starts_with("198.18."), "{}", out.dump());
}

const PY_UDP: &str = r#"
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.connect(("1.2.3.4", 443)); t = time.time()
s.send(b"quic?")
try:
    s.recv(100); print("got data")
except ConnectionRefusedError:
    print("refused %.2f" % (time.time() - t))
except socket.timeout:
    print("timeout")
"#;

#[test]
fn other_udp_fails_fast() {
    require!("python3");
    let dir = tmp_dir("udp");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let out = run(&cfg, &[], &["python3", "-c", PY_UDP], &[]);
    let line = out.stdout.trim();
    let secs: f64 = line
        .strip_prefix("refused ")
        .unwrap_or_else(|| panic!("expected ECONNREFUSED:\n{}", out.dump()))
        .parse()
        .unwrap();
    assert!(secs < 1.0, "{}", out.dump());
}

#[test]
fn large_transfers_are_intact_both_ways() {
    require!("curl", "sh");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("large");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    const N: usize = 48 << 20;
    let down = dir.join("down.bin");
    let up = dir.join("up.bin");
    let payload = pattern(N + 7);
    std::fs::write(&up, &payload).unwrap();
    let script = format!(
        "curl -sS --max-time 50 -o {} http://big.test/big/{N} && \
         curl -sS --max-time 50 --data-binary @{} -H 'Content-Type: application/octet-stream' http://up.test/",
        down.display(),
        up.display()
    );
    let out = run(&cfg, &[], &["sh", "-c", &script], &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    let got = std::fs::read(&down).unwrap();
    assert_eq!(got.len(), N);
    assert!(got == pattern(N), "download corrupted");
    assert_eq!(out.stdout, checksum(&payload).to_string(), "upload corrupted");
}

#[test]
fn many_parallel_connections_all_succeed() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("parallel");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    let out = run(
        &cfg,
        &[],
        &[
            "curl",
            "-s",
            "--parallel",
            "--parallel-max",
            "100",
            "--max-time",
            "30",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\n",
            "http://c[1-300].test/",
        ],
        &[],
    );
    let ok = out.stdout.lines().filter(|l| *l == "200").count();
    assert_eq!(ok, 300, "{}", out.dump());
    assert_eq!(mock.seen().len(), 300);
}

#[test]
fn localnet_and_direct_rules_reach_the_host_without_the_proxy() {
    require!("curl");
    let Some(ip) = host_ip() else {
        eprintln!("SKIP: no non-loopback IPv4 address on this host");
        return;
    };
    let origin = start_origin_on("0.0.0.0:0");
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("direct");
    let url = format!("http://{ip}:{origin}/");
    for (top, rules) in [
        (format!("localnet = [\"{ip}/32\"]"), String::new()),
        (
            "localnet = []".to_string(),
            format!("[[rules]]\nmatch=\"ip-cidr\"\nvalue=\"{ip}/32\"\naction=\"direct\""),
        ),
    ] {
        let cfg = write_cfg(&dir, mock.addr, &top, &rules);
        let out = run(&cfg, &[], &["curl", "-sS", "--max-time", "20", &url], &[]);
        assert_eq!(out.stdout, BODY, "{top} {rules}\n{}", out.dump());
    }
    assert!(mock.seen().is_empty(), "direct never touches the proxy");
}

#[test]
fn block_rules_and_a_dead_proxy_fail_closed() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("block");
    let cfg = write_cfg(
        &dir,
        mock.addr,
        "",
        "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"blocked.test\"\naction=\"block\"",
    );
    let out = run(
        &cfg,
        &[],
        &["curl", "-sS", "--max-time", "10", "http://x.blocked.test/"],
        &[],
    );
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(mock.seen().is_empty());

    // The proxy dead: the connection fails, and is not made directly
    // instead. The target is one a direct dial would reach (an origin on the
    // host's own address, which the namespace routes through us), so that
    // it would show.
    let (_dead, dead_addr) = refused_addr();
    let cfg = write_cfg(&dir, dead_addr, "", "");
    let host = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|u| u.connect("192.0.2.1:9").and_then(|_| u.local_addr()))
        .map(|a| a.ip())
        .ok()
        .filter(|ip| !ip.is_loopback() && ip.is_ipv4());
    let url = match host {
        Some(ip) => format!("http://{ip}:{}/", start_origin_on(&format!("{ip}:0"))),
        None => {
            eprintln!("note: no non-loopback IPv4 address here; a direct fallback could not show");
            "http://site.test/".to_string()
        }
    };
    let out = run(&cfg, &[], &["curl", "-sS", "--max-time", "10", &url], &[]);
    assert_ne!(out.code, 0, "never silently direct\n{}", out.dump());
    assert!(!out.stdout.contains(BODY), "reached directly\n{}", out.dump());
}

#[test]
fn proxyhook_only_and_misspelt_config_keys_are_warned_about() {
    require!();
    let dir = tmp_dir("keys");
    let cfg = write_cfg(
        &dir,
        "127.0.0.1:1".parse().unwrap(),
        "verify_peer_uid = true\nsnif = false",
        "",
    );
    let out = run(&cfg, &[], &["true"], &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    for key in ["verify_peer_uid", "snif"] {
        assert!(
            out.stderr.contains(&format!("key={key}")) && out.stderr.contains("has no effect"),
            "{key}\n{}",
            out.dump()
        );
    }
}

// ------------------------------------------------- lifecycle and signals --

struct ChildGuard(std::process::Child);

impl std::ops::Deref for ChildGuard {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Kills a process on drop (one proxytun leaves behind on purpose).
struct PidGuard(i32);

impl Drop for PidGuard {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

fn alive(pid: i32) -> bool {
    // A zombie is not alive; /proc/<pid>/stat field 3 is its state.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z')))
}

fn spawn_bg(cfg: &Path, argv: &[&str]) -> (ChildGuard, Arc<Mutex<String>>) {
    let mut cmd = Command::new(BIN);
    cmd.arg("-c").arg(cfg).arg("--").args(argv);
    for k in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        cmd.env_remove(k);
    }
    cmd.env("PROXYTUN_LOG", "info");
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut se = child.stderr.take().unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let l2 = log.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = se.read(&mut buf) {
            if n == 0 {
                break;
            }
            l2.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    (ChildGuard(child), log)
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn sighup_reloads_the_proxy_and_sigusr1_prints_stats() {
    require!("curl", "bash");
    let origin = start_origin();
    let (a, b) = (start_mock_proxy(origin), start_mock_proxy(origin));
    let dir = tmp_dir("reload");
    let cfg = write_cfg(&dir, a.addr, "", "");
    let (go1, done1, go2, done2, go3) = (
        dir.join("go1"),
        dir.join("done1"),
        dir.join("go2"),
        dir.join("done2"),
        dir.join("go3"),
    );
    for f in [&go1, &done1, &go2, &done2, &go3] {
        let _ = std::fs::remove_file(f);
    }
    let script = format!(
        "while [ ! -f {go1} ]; do sleep 0.05; done; curl -sS -m 20 -o /dev/null http://first.test/; touch {done1}; \
         while [ ! -f {go2} ]; do sleep 0.05; done; curl -sS -m 20 -o /dev/null http://second.test/; touch {done2}; \
         while [ ! -f {go3} ]; do sleep 0.05; done",
        go1 = go1.display(),
        done1 = done1.display(),
        go2 = go2.display(),
        done2 = done2.display(),
        go3 = go3.display(),
    );
    let (mut child, log) = spawn_bg(&cfg, &["bash", "-c", &script]);
    let pid = child.id() as i32;

    std::fs::write(&go1, "").unwrap();
    wait_for("first request", || done1.exists());
    assert_eq!((a.seen().len(), b.seen().len()), (1, 0));

    // Point the config at proxy B and reload.
    write_cfg(&dir, b.addr, "", "");
    unsafe { libc::kill(pid, libc::SIGHUP) };
    wait_for("reload message", || {
        log.lock().unwrap().contains("configuration reloaded")
    });

    unsafe { libc::kill(pid, libc::SIGUSR1) };
    wait_for("stats dump", || log.lock().unwrap().contains("proxy stats"));
    {
        let l = log.lock().unwrap();
        let stats = l.lines().find(|l| l.contains(" stats ")).unwrap_or_default();
        for field in [
            "fake_ips=",
            "nat_entries=",
            "connections=1",
            "dns_queries=",
            "udp_refused=",
            "relayed_up=",
            "relayed_down=",
            "dns_forward_failed=",
            "tun_packets_in=",
            "tun_bytes_out=",
            "dropped_no_flow=",
            "dropped_table_full=",
        ] {
            assert!(stats.contains(field), "{field} missing from: {stats}");
        }
        let rates = l
            .lines()
            .find(|l| l.contains("rates since the previous stats"))
            .unwrap_or_default();
        for field in [
            "seconds=",
            "connections_per_s=",
            "tun_packets_in_per_s=",
            "down_mb_per_s=",
        ] {
            assert!(rates.contains(field), "{field} missing from: {rates}");
        }
    }

    std::fs::write(&go2, "").unwrap();
    wait_for("second request", || done2.exists());
    assert_eq!(
        (a.seen().len(), b.seen().len()),
        (1, 1),
        "second request must use the reloaded proxy"
    );

    // A broken config must be rejected and the old one kept.
    std::fs::write(&cfg, "garbage = [").unwrap();
    unsafe { libc::kill(pid, libc::SIGHUP) };
    wait_for("reload failure message", || {
        log.lock().unwrap().contains("reload failed")
    });

    std::fs::write(&go3, "").unwrap(); // let the program finish
    let st = child.wait().unwrap();
    assert!(st.success(), "{}", log.lock().unwrap());
}

#[test]
fn proxy_override_flag_replaces_the_config_proxy() {
    require!("curl");
    let origin = start_origin();
    let (wrong, right) = (start_mock_proxy(origin), start_mock_proxy(origin));
    let dir = tmp_dir("override");
    let cfg = write_cfg(&dir, wrong.addr, "", "");
    let flag = format!("socks5://{}", right.addr);
    let out = run(
        &cfg,
        &["--proxy", &flag],
        &["curl", "-sS", "-m", "20", "http://ov.test/"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!((wrong.seen().len(), right.seen().len()), (0, 1));

    // The environment variable works too, and no config file is then required.
    let missing = dir.join("does-not-exist.toml");
    let out = run(
        &missing,
        &[],
        &["curl", "-sS", "-m", "20", "http://ov2.test/"],
        &[("PROXYTUN_PROXY", flag.as_str())],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(right.seen().len(), 2);
    assert!(out.stderr.contains("no config file"), "{}", out.dump());

    // A file with rules only, the proxy coming from the environment; one
    // whose rules send traffic to a group of its own: all through the
    // override (the file alone would be refused, or name proxies we skip).
    let rules = dir.join("rules-only.toml");
    std::fs::write(
        &rules,
        "[[rules]]\nmatch=\"domain\"\nvalue=\"skip.test\"\naction=\"block\"\n",
    )
    .unwrap();
    let out = run(
        &rules,
        &[],
        &["curl", "-sS", "-m", "20", "http://ov3.test/"],
        &[("PROXYTUN_PROXY", flag.as_str())],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    let grouped = dir.join("grouped.toml");
    std::fs::write(
        &grouped,
        format!(
            "[[proxies]]\nname=\"hk1\"\ntype=\"socks5\"\naddr=\"{}\"\n[[groups]]\nname=\"default\"\nmembers=[\"hk1\"]\n\
             [[groups]]\nname=\"hk\"\nmembers=[\"hk1\"]\n\
             [[rules]]\nmatch=\"domain-suffix\"\nvalue=\"test\"\naction=\"proxy\"\ngroup=\"hk\"\n",
            wrong.addr
        ),
    )
    .unwrap();
    let out = run(
        &grouped,
        &["--proxy", &flag],
        &["curl", "-sS", "-m", "20", "http://ov4.test/"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(
        out.stderr.contains("rules for group(s) hk use it too"),
        "{}",
        out.dump()
    );
    assert_eq!((wrong.seen().len(), right.seen().len()), (0, 4));
}

#[test]
fn proxy_credentials_are_not_handed_to_the_program() {
    require!("sh");
    let dir = tmp_dir("creds");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let url = "socks5://alice:s3cret@127.0.0.1:1";
    // The variable that configured proxytun must not reach the program it runs.
    let out = run(
        &cfg,
        &[],
        &["sh", "-c", "echo \"[${PROXYTUN_PROXY+set}]\""],
        &[("PROXYTUN_PROXY", url)],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(out.stdout.trim(), "[]", "not even an empty variable\n{}", out.dump());
    assert!(
        !out.stdout.contains("s3cret") && !out.stderr.contains("s3cret"),
        "password leaked\n{}",
        out.dump()
    );

    // Unsetting is not enough: /proc/<pid>/environ is served from the original
    // memory. The program must not find the secret in its parent's files either.
    // proxytun is non-dumpable, so its /proc files belong to root, not to the
    // user the program runs as (checked directly: Yama may hide /proc/<pid>/mem
    // anyway, and CentOS 7 has no Yama).
    let probe = "for f in environ cmdline; do cat /proc/$PPID/$f 2>/dev/null | tr '\\0' '\\n'; done; \
                 cat /proc/$PPID/mem >/dev/null 2>&1 && echo MEM-READ\"ABLE\"; \
                 ls /proc/$PPID/fd >/dev/null 2>&1 && echo FD-READ\"ABLE\"; \
                 echo owner=$(stat -c %u /proc/$PPID/environ); echo done";
    let out = run(&cfg, &[], &["sh", "-c", probe], &[("PROXYTUN_PROXY", url)]);
    assert!(out.stdout.contains("done"), "{}", out.dump());
    assert!(
        !out.stdout.contains("s3cret"),
        "secret readable from /proc/$PPID\n{}",
        out.dump()
    );
    assert!(!out.stdout.contains("MEM-READABLE"), "{}", out.dump());
    assert!(!out.stdout.contains("FD-READABLE"), "{}", out.dump());
    assert!(
        !out.stdout.contains(&format!("owner={}\n", current_uid())),
        "proxytun's /proc files belong to the program's user\n{}",
        out.dump()
    );

    // Credentials on the command line are visible in `ps`: warn about it.
    let out = run(&cfg, &["--proxy", url], &["true"], &[]);
    assert!(out.stderr.contains("can read from"), "{}", out.dump());
    assert!(
        !out.stderr.contains("s3cret"),
        "the warning must not echo the password\n{}",
        out.dump()
    );
}

#[test]
fn the_program_starts_with_default_signal_dispositions() {
    require!("sh", "yes", "head");
    let dir = tmp_dir("signals");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // Rust sets SIGPIPE to "ignore" in proxytun itself; that must not leak
    // into the program (an ignored disposition survives exec).
    let out = run(
        &cfg,
        &[],
        &["sh", "-c", "grep -E '^Sig(Ign|Blk)' /proc/self/status"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    let field = |name: &str| -> u64 {
        let line = out.stdout.lines().find(|l| l.starts_with(name)).unwrap();
        u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
    };
    assert_eq!(
        field("SigIgn:") & (1 << (libc::SIGPIPE - 1)),
        0,
        "SIGPIPE ignored\n{}",
        out.dump()
    );
    assert_eq!(field("SigBlk:"), 0, "signals blocked\n{}", out.dump());

    // The visible effect: a writer into a closed pipe dies quietly, as usual.
    let out = run(&cfg, &[], &["sh", "-c", "yes | head -1; echo exit=$?"], &[]);
    assert_eq!(out.stdout, "y\nexit=0\n", "{}", out.dump());
    assert!(!out.stderr.contains("Broken pipe"), "{}", out.dump());
}

/// Counts the signal named in argv[1]: exits 3 after exactly one, 4 if a
/// duplicate arrived (the group signal plus a forwarded copy), 1 if none came.
/// argv[2] is how the program takes it: "handler" (main thread), "thread" (a
/// handler, but only a worker thread leaves the signal unblocked), "sigwait"
/// (blocked everywhere and taken with sigtimedwait), or "ownpgrp" (a handler,
/// after moving to a process group of its own).
const PY_SIGNAL: &str = r#"
import os, signal, sys, threading, time
sig = getattr(signal, sys.argv[1])
style = sys.argv[2] if len(sys.argv) > 2 else "handler"
n = [0]
if style == "sigwait":
    signal.pthread_sigmask(signal.SIG_BLOCK, [sig])
    print("ready", flush=True)
    if signal.sigtimedwait([sig], 30) is None:
        print("not interrupted", flush=True)
        sys.exit(1)
    n[0] = 1
    while signal.sigtimedwait([sig], 0.5) is not None:  # a duplicate
        n[0] += 1
else:
    def on_sig(s, frame):
        n[0] += 1
    signal.signal(sig, on_sig)
    if style == "ownpgrp":
        os.setpgrp()
    if style == "thread":
        threading.Thread(target=time.sleep, args=(60,), daemon=True).start()
        signal.pthread_sigmask(signal.SIG_BLOCK, [sig])
    print("ready", flush=True)
    deadline = time.time() + 30
    while n[0] == 0 and time.time() < deadline:
        time.sleep(0.02)
    if n[0] == 0:
        print("not interrupted", flush=True)
        sys.exit(1)
    time.sleep(0.5)  # a duplicate would land in this window
print("handled %d" % n[0], flush=True)
sys.exit(3 if n[0] == 1 else 4)
"#;

/// Start proxytun running `python3 script args..` in a process group of its
/// own (as a shell job would be), wait until the program says "ready", deliver
/// a signal with `deliver`, and return (exit code, stdout).
fn interrupt_run(script: &Path, args: &[&str], deliver: impl FnOnce(i32)) -> (Option<i32>, String) {
    use std::os::unix::process::CommandExt;
    let dir = script.parent().unwrap();
    let cfg = write_cfg(dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let mut cmd = Command::new(BIN);
    cmd.arg("-c")
        .arg(&cfg)
        .args(["--", "python3", script.to_str().unwrap()])
        .args(args);
    cmd.process_group(0).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = ChildGuard(cmd.spawn().unwrap());
    let pid = child.id() as i32;
    let mut out = child.stdout.take().unwrap();
    let collected = Arc::new(Mutex::new(String::new()));
    let c2 = collected.clone();
    std::thread::spawn(move || {
        let mut b = [0u8; 256];
        while let Ok(n) = out.read(&mut b) {
            if n == 0 {
                break;
            }
            c2.lock().unwrap().push_str(&String::from_utf8_lossy(&b[..n]));
        }
    });
    wait_for("program ready", || collected.lock().unwrap().contains("ready"));
    deliver(pid);
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(Instant::now() < deadline, "proxytun did not exit after the signal");
        std::thread::sleep(Duration::from_millis(20));
    };
    std::thread::sleep(Duration::from_millis(100));
    let text = collected.lock().unwrap().clone();
    (status.code(), text)
}

#[test]
fn ctrl_c_reaches_the_program_and_lets_it_clean_up() {
    require!("python3");
    let dir = tmp_dir("sigint");
    let script = dir.join("int.py");
    std::fs::write(&script, PY_SIGNAL).unwrap();

    // Like Ctrl+C or `kill %1`: the whole group gets SIGINT from a process.
    let (code, out) = interrupt_run(&script, &["SIGINT"], |pgid| unsafe {
        libc::kill(-pgid, libc::SIGINT);
    });
    assert!(
        out.contains("handled 1"),
        "exactly one SIGINT, not a forwarded duplicate\n{out}"
    );
    assert_eq!(
        code,
        Some(3),
        "program's own exit code, not killed with proxytun\n{out}"
    );

    // `kill -INT <proxytun pid>`: forwarded to the program.
    let (code, out) = interrupt_run(&script, &["SIGINT"], |pid| unsafe {
        libc::kill(pid, libc::SIGINT);
    });
    assert!(out.contains("handled 1"), "{out}");
    assert_eq!(code, Some(3), "{out}");
}

#[test]
fn a_group_signal_is_not_duplicated_however_the_program_takes_it() {
    require!("python3");
    let dir = tmp_dir("sigthread");
    let script = dir.join("sig.py");
    std::fs::write(&script, PY_SIGNAL).unwrap();
    for (sig, n) in [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)] {
        // proxyhook could not avoid a duplicate for "sigwait" (nothing to see
        // through ptrace); the witness sees every group signal.
        for style in ["thread", "sigwait"] {
            let (code, out) = interrupt_run(&script, &[sig, style], |pgid| unsafe {
                libc::kill(-pgid, n);
            });
            assert!(
                out.contains("handled 1"),
                "{sig} {style}: got a forwarded duplicate\n{out}"
            );
            assert_eq!(code, Some(3), "{sig} {style}\n{out}");
        }
    }
}

#[test]
fn a_group_signal_is_forwarded_to_a_program_that_left_the_group() {
    require!("python3");
    let dir = tmp_dir("sigpgrp");
    let script = dir.join("sig.py");
    std::fs::write(&script, PY_SIGNAL).unwrap();
    // The group signal reaches proxytun (and the witness) but not the program.
    let (code, out) = interrupt_run(&script, &["SIGTERM", "ownpgrp"], |pgid| unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    });
    assert!(out.contains("handled 1"), "{out}");
    assert_eq!(code, Some(3), "{out}");
}

/// Runs proxytun on a pseudo-terminal as the foreground job and presses
/// Ctrl+C on it: the kernel's tty driver sends SIGINT to the whole group.
const PY_PTY_CTRL_C: &str = r#"
import fcntl, os, pty, select, subprocess, sys, termios, time
argv = sys.argv[1:]
master, slave = pty.openpty()
def own_tty():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
p = subprocess.Popen(argv, stdin=slave, stdout=slave,
                     start_new_session=True, preexec_fn=own_tty)
os.close(slave)
out = b""
def pump(secs):
    global out
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                d = os.read(master, 4096)
            except OSError:
                return
            if not d:
                return
            out += d
        elif p.poll() is not None:
            return
end = time.time() + 15
while b"ready" not in out and time.time() < end and p.poll() is None:
    pump(0.1)
os.write(master, b"\x03")
try:
    code = p.wait(10)
except subprocess.TimeoutExpired:
    p.kill()
    code = "timeout"
pump(0.3)
print("exit", code)
print(out.decode(errors="replace"))
"#;

#[test]
fn ctrl_c_on_a_terminal_is_not_forwarded_even_to_a_sigwait_program() {
    require!("python3");
    let dir = tmp_dir("sigpty");
    let (prog, driver) = (dir.join("sig.py"), dir.join("press_ctrl_c.py"));
    std::fs::write(&prog, PY_SIGNAL).unwrap();
    std::fs::write(&driver, PY_PTY_CTRL_C).unwrap();
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    for style in ["handler", "sigwait"] {
        let out = Command::new("python3")
            .arg(&driver)
            .args([BIN, "-c", cfg.to_str().unwrap(), "--", "python3"])
            .arg(&prog)
            .args(["SIGINT", style])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("handled 1"), "{style}\n{text}");
        assert!(text.starts_with("exit 3"), "{style}\n{text}");
    }
}

#[test]
fn sigterm_reaches_the_program_exactly_once() {
    require!("python3");
    let dir = tmp_dir("sigterm");
    let script = dir.join("term.py");
    std::fs::write(&script, PY_SIGNAL).unwrap();
    // `kill <proxytun pid>`: only proxytun gets it, so it is forwarded.
    let (code, out) = interrupt_run(&script, &["SIGTERM"], |pid| unsafe {
        libc::kill(pid, libc::SIGTERM);
    });
    assert!(out.contains("handled 1"), "{out}");
    assert_eq!(code, Some(3), "{out}");
    // systemd / `kill -- -<pgid>`: the program already has it, no second copy.
    let (code, out) = interrupt_run(&script, &["SIGTERM"], |pgid| unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    });
    assert!(out.contains("handled 1"), "{out}");
    assert_eq!(code, Some(3), "{out}");
}

#[test]
fn pkill_proxytun_reaches_the_program_exactly_once() {
    require!("python3", "pkill");
    let dir = tmp_dir("pkill");
    let script = dir.join("term.py");
    std::fs::write(&script, PY_SIGNAL).unwrap();
    // pkill (killall, pidof) by name: proxytun, not its signal witness,
    // which would make it look like a group signal the program has too.
    let (code, out) = interrupt_run(&script, &["SIGTERM"], |pid| {
        let st = Command::new("pkill")
            .args(["-TERM", "-g", &pid.to_string(), "proxytun"])
            .status()
            .unwrap();
        assert!(st.success(), "pkill found nothing");
    });
    assert!(out.contains("handled 1"), "{out}");
    assert_eq!(code, Some(3), "{out}");
}

/// SigIgn mask of the program, from its /proc status.
fn ignored_mask(out: &str) -> u64 {
    let hex = out
        .lines()
        .find_map(|l| l.strip_prefix("SigIgn:"))
        .expect("SigIgn line")
        .trim();
    u64::from_str_radix(hex, 16).unwrap()
}

#[test]
fn signals_ignored_by_the_caller_stay_ignored_in_the_program() {
    use std::os::unix::process::CommandExt;
    require!();
    let dir = tmp_dir("sigign");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let bit = |sig: i32| 1u64 << (sig - 1);
    // What `cmd &` in a script (SIGINT, SIGQUIT) and nohup (SIGHUP) do.
    let mut cmd = Command::new(BIN);
    cmd.arg("-c").arg(&cfg).args(["--", "cat", "/proc/self/status"]);
    // `trap '' PIPE` too (SIGPIPE, which Rust's runtime ignores for itself
    // before proxytun can see how its caller left it).
    unsafe {
        cmd.pre_exec(|| {
            for s in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGPIPE] {
                libc::signal(s, libc::SIG_IGN);
            }
            Ok(())
        });
    }
    let out = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
    let ign = ignored_mask(&out);
    for (name, sig) in [
        ("SIGINT", libc::SIGINT),
        ("SIGQUIT", libc::SIGQUIT),
        ("SIGHUP", libc::SIGHUP),
        ("SIGPIPE", libc::SIGPIPE),
    ] {
        assert!(ign & bit(sig) != 0, "{name} must stay ignored\n{out}");
    }
    // And nothing is ignored that the caller did not ignore.
    let out = Command::new(BIN)
        .arg("-c")
        .arg(&cfg)
        .args(["--", "cat", "/proc/self/status"])
        .output()
        .unwrap();
    let ign = ignored_mask(&String::from_utf8(out.stdout).unwrap());
    for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM, libc::SIGPIPE] {
        assert!(ign & bit(sig) == 0, "signal {sig} ignored without reason");
    }
}

#[test]
fn ctrl_c_stops_proxytun_once_the_main_program_has_exited() {
    use std::os::unix::process::CommandExt;
    require!();
    let dir = tmp_dir("sigorphan");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let mut cmd = Command::new(BIN);
    cmd.arg("-c")
        .arg(&cfg)
        .args(["--", "sh", "-c", "sleep 30 & echo ready $!"]);
    cmd.process_group(0).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = ChildGuard(cmd.spawn().unwrap());
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
    let orphan: i32 = line.trim().strip_prefix("ready ").unwrap().parse().unwrap();
    let _orphan = PidGuard(orphan);
    std::thread::sleep(Duration::from_millis(300)); // sh is gone, sleep is not
    assert!(
        child.try_wait().unwrap().is_none(),
        "still waiting for the background child"
    );
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(Instant::now() < deadline, "Ctrl+C did nothing: proxytun keeps waiting");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGINT),
        "ended by the signal, as the program would have been\n{status:?}"
    );
    // Unlike proxyhook, the tree is not killed (DESIGN.md 5): it keeps
    // running, cut off from the network.
    assert!(alive(orphan), "the background child must survive proxytun");
}

/// Connects to `net.test` every 0.2 s and appends ok/fail to argv[1].
const PY_NET_PROBE: &str = r#"
import os, socket, sys, time
log = open(sys.argv[1], "a", buffering=1)
print("ready", os.getpid(), flush=True)
while True:
    try:
        s = socket.create_connection(("net.test", 80), timeout=1)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        log.write("ok\n" if s.recv(100) else "fail\n")
        s.close()
    except OSError:
        log.write("fail\n")
    time.sleep(0.2)
"#;

#[test]
fn a_killed_proxytun_leaves_the_program_running_but_without_network() {
    require!("python3");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("killed");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    let log = dir.join("net.log");
    let _ = std::fs::remove_file(&log);
    let mut cmd = Command::new(BIN);
    cmd.arg("-c")
        .arg(&cfg)
        .args(["--", "python3", "-c", PY_NET_PROBE])
        .arg(&log);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = ChildGuard(cmd.spawn().unwrap());
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
    let prog: i32 = line.trim().strip_prefix("ready ").unwrap().parse().unwrap();
    let _prog = PidGuard(prog);
    let lines = || std::fs::read_to_string(&log).unwrap_or_default();
    wait_for("a proxied connection", || lines().contains("ok"));

    unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    child.wait().unwrap();
    let before = lines().lines().count();
    wait_for("attempts after proxytun died", || lines().lines().count() >= before + 3);
    assert!(alive(prog), "the program keeps running");
    let after: Vec<String> = lines().lines().skip(before + 1).map(String::from).collect();
    assert!(
        after.iter().all(|l| l == "fail"),
        "no way out without proxytun: {after:?}"
    );
}

// ------------------------------------------- what ptrace tools now allow --

#[test]
fn a_static_binary_is_captured() {
    require!("cc");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("static");
    let src = dir.join("get.c");
    std::fs::write(
        &src,
        r#"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int e = getaddrinfo(argv[1], "80", &hints, &ai);
    if (e) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e)); return 2; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(s, ai->ai_addr, ai->ai_addrlen)) { perror("connect"); return 3; }
    char req[256]; snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", argv[1]);
    if (write(s, req, strlen(req)) < 0) return 4;
    char buf[4096]; int n;
    while ((n = read(s, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    return 0;
}
"#,
    )
    .unwrap();
    let bin = dir.join("get-static");
    let cc = Command::new("cc")
        .args(["-static", "-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .unwrap();
    if !cc.status.success() {
        eprintln!("SKIP: cannot link statically: {}", String::from_utf8_lossy(&cc.stderr));
        return;
    }
    let file = Command::new("file")
        .arg(&bin)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    if let Ok(f) = file {
        assert!(f.contains("statically linked"), "{f}");
    }
    // sniff off: the domain must come from DNS, not from the Host header.
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let out = run(&cfg, &[], &[bin.to_str().unwrap(), "static.test"], &[]);
    assert!(out.stdout.ends_with(BODY), "{}", out.dump());
    assert_eq!(mock.hosts(), ["static.test"]);
}

#[test]
fn a_program_started_with_an_empty_environment_is_still_captured() {
    require!("curl", "env");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("envclear");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    // A grandchild exec'd with no environment at all: no LD_PRELOAD, nothing
    // that a preload-based proxifier could rely on.
    let curl = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v curl"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let script = format!("exec env -i {} -sS --max-time 20 http://bare.test/", curl.trim());
    let out = run(&cfg, &[], &["sh", "-c", &script], &[("LD_PRELOAD", "")]);
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    assert_eq!(mock.hosts(), ["bare.test"]);
}

#[test]
fn strace_runs_inside() {
    require!("strace", "curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("strace-in");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let out = run(
        &cfg,
        &[],
        &[
            "strace",
            "-f",
            "-e",
            "trace=connect",
            "curl",
            "-sS",
            "--max-time",
            "20",
            "http://st.test/",
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    assert!(
        out.stderr.contains("connect(") && out.stderr.contains("198.18."),
        "strace saw the connect to the fake IP\n{}",
        out.dump()
    );
    assert_eq!(mock.hosts(), ["st.test"]);
}

#[test]
fn strace_runs_outside_around_proxytun() {
    require!("strace", "curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("strace-out");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let trace = dir.join("trace.txt");
    let out = Command::new("strace")
        .args(["-f", "-e", "trace=connect", "-o"])
        .arg(&trace)
        .arg(BIN)
        .arg("-c")
        .arg(&cfg)
        .args(["--", "curl", "-sS", "--max-time", "20", "http://so.test/"])
        .env_remove("http_proxy")
        .env_remove("HTTP_PROXY")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), BODY);
    let t = std::fs::read_to_string(&trace).unwrap();
    assert!(t.contains("198.18."), "the program's connect is in the trace\n{t}");
    assert_eq!(mock.hosts(), ["so.test"]);
}

#[test]
fn gdb_runs_inside_and_stops_at_connect() {
    require!("gdb", "curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("gdb-in");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let out = run(
        &cfg,
        &[],
        &[
            "gdb",
            "-batch",
            "-nx",
            "-ex",
            "set breakpoint pending on",
            "-ex",
            "break connect",
            "-ex",
            "run",
            // curl connects more than once (a unix socket first): stop at the
            // first, then let it run to the end.
            "-ex",
            "bt 1",
            "-ex",
            "delete",
            "-ex",
            "continue",
            "--args",
            "curl",
            "-sS",
            "--max-time",
            "20",
            "http://gd.test/",
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(
        out.stdout.contains("Breakpoint 1,"),
        "gdb stopped at connect\n{}",
        out.dump()
    );
    assert!(out.stdout.contains(BODY), "{}", out.dump());
    assert_eq!(mock.hosts(), ["gd.test"]);
}

#[test]
fn ltrace_runs_inside() {
    require!("ltrace", "curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("ltrace-in");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let out = run(
        &cfg,
        &[],
        &[
            "ltrace",
            "-f",
            "-e",
            "curl_easy_perform",
            "curl",
            "-sS",
            "--max-time",
            "20",
            "http://lt.test/",
        ],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(
        out.stderr.contains("curl_easy_perform"),
        "ltrace traced the library call\n{}",
        out.dump()
    );
    assert!(out.stdout.contains(BODY), "{}", out.dump());
    assert_eq!(mock.hosts(), ["lt.test"]);
}

#[test]
fn gdb_attaches_from_outside_to_a_running_program() {
    require!("gdb", "sh");
    let dir = tmp_dir("gdb-p");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let pidfile = dir.join("pid");
    let _ = std::fs::remove_file(&pidfile);
    let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
    let (_child, _log) = spawn_bg(&cfg, &["sh", "-c", &script]);
    wait_for("the program's pid", || {
        std::fs::read_to_string(&pidfile).is_ok_and(|s| s.ends_with('\n'))
    });
    let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
    std::thread::sleep(Duration::from_millis(200)); // sh has exec'd sleep
                                                    // The test process is an ancestor of the program, which a Yama
                                                    // ptrace_scope of 1 requires (with or without proxytun).
    let out = Command::new("gdb")
        .args(["-batch", "-nx", "-p", &pid, "-ex", "info inferiors", "-ex", "detach"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains(&format!("process {pid}")), "{text}");
}

/// Opens `n` connections and holds them (proxytun runs out of fds on the
/// way), drops them, then makes one ordinary request.
const PY_FD_PRESSURE: &str = r#"
import socket, struct, sys, time, urllib.request
held = []
for i in range(int(sys.argv[1])):
    s = socket.create_connection(("203.0.113.1", 80), timeout=10)
    held.append(s)
# Just before they dial out (5 s of sniffing): TXT lookups, forwarded
# upstream, which answers each after a second. Each forward holds an fd.
time.sleep(4.6)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(int(sys.argv[2])):
    q = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
    u.sendto(q, ("8.8.8.8", 53))
time.sleep(3)
for s in held:
    s.close()
# Once the leftovers (connections still in the accept queue) are through,
# the proxy must serve again: never marked down.
for attempt in range(10):
    time.sleep(1)
    try:
        body = urllib.request.urlopen("http://after.test/", timeout=10).read().decode()
        print("final:", body, flush=True)
        break
    except Exception as e:
        last = e
else:
    print("final: failed", last, flush=True)
"#;

#[test]
fn proxytun_uses_its_whole_fd_limit_and_blames_no_proxy_for_running_out() {
    require!("python3");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("fd-pressure");
    // The held connections go to a literal IP, so proxytun sniffs them, for
    // 5 s: they are more than its fds, each keeps its accepted one while
    // proxytun waits for its first bytes, and the dials that follow find none
    // left. Probes every second meanwhile find none either.
    let cfg = write_cfg(
        &dir,
        mock.addr,
        "sniff_timeout_ms = 5000",
        "[health]\ninterval_secs = 1",
    );
    // Our soft limit goes up to the hard one; the program keeps its own.
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(
        "ulimit -Sn 100; exec \"$BIN\" -c \"$CFG\" -- \
         sh -c 'ulimit -Sn; awk \"/Max open files/ {print (\\$4 == \\$5)}\" /proc/$PPID/limits'",
    );
    let out = run_cmd(cmd, &[("BIN", BIN), ("CFG", cfg.to_str().unwrap())]);
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(
        out.stdout,
        "100\n1\n",
        "program: 100; proxytun: soft = hard\n{}",
        out.dump()
    );
    assert!(out.stderr.contains("open-file limit"), "and says so\n{}", out.dump());

    // With no room to raise it, the relay cap follows the limit: 24 at once
    // for 64 fds; more are reset at once, not left to run proxytun out of
    // fds. No host ports: each would hold an fd, and how many listeners the
    // host has varies.
    let prog = dir.join("pressure.py");
    std::fs::write(&prog, PY_FD_PRESSURE).unwrap();
    let pressure = |cfg: &Path, held: &str, lookups: &str| {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("ulimit -n 64; exec \"$BIN\" --no-host-ports -c \"$CFG\" -- python3 \"$PROG\" \"$HELD\" \"$LOOKUPS\"");
        run_cmd(
            cmd,
            &[
                ("BIN", BIN),
                ("CFG", cfg.to_str().unwrap()),
                ("PROG", prog.to_str().unwrap()),
                ("HELD", held),
                ("LOOKUPS", lookups),
            ],
        )
    };
    let out = pressure(&cfg, "50", "0");
    assert!(
        out.stderr.contains("allows 24 connections relayed at once"),
        "{}",
        out.dump()
    );
    assert!(out.stderr.contains("refusing new ones"), "{}", out.dump());
    assert!(
        !out.stderr.contains("lack of local resources"),
        "never out of fds\n{}",
        out.dump()
    );
    assert!(out.stdout.contains(&format!("final: {BODY}")), "{}", out.dump());

    // Fds run out anyway, here to a burst of lookups forwarded upstream
    // while the held connections dial out. Neither the proxy nor the
    // upstream resolver (which answers, a second late) is to blame: it must
    // not be marked down, and once it is over the next request must go
    // through it.
    let dns = start_slow_dns(Duration::from_secs(1));
    let cfg = write_cfg(
        &dir,
        mock.addr,
        &format!("sniff_timeout_ms = 5000\nupstream_dns = \"{dns}\""),
        "[health]\ninterval_secs = 1",
    );
    let out = pressure(&cfg, "20", "150");
    assert!(
        out.stderr.contains("dial failed for lack of local resources"),
        "fds did run out\n{}",
        out.dump()
    );
    assert!(
        out.stderr.matches("dial failed for lack of local resources").count() <= 2,
        "said now and then, not for every connection\n{}",
        out.dump()
    );
    assert!(!out.stderr.contains("marked DOWN"), "{}", out.dump());
    // accept fails again at once while connections wait: said once in a
    // while, not every 20 ms.
    assert!(out.stderr.matches("relay accept:").count() <= 2, "{}", out.dump());
    // Nor is the upstream resolver blamed for the lookup we could not forward.
    assert!(
        out.stderr.contains("dns: cannot forward for lack of local resources"),
        "{}",
        out.dump()
    );
    assert!(
        !out.stderr.contains("upstream resolver did not answer"),
        "{}",
        out.dump()
    );
    assert!(out.stdout.contains(&format!("final: {BODY}")), "{}", out.dump());
}

// ------------------------------------------------ sudo mode (CentOS 7) --

/// A resolver on the host that answers every query (as NXDOMAIN) after
/// `delay`.
fn start_slow_dns(delay: Duration) -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let mut reply = buf[..n].to_vec();
            if reply.len() < 12 {
                continue;
            }
            reply[2] |= 0x80; // a response
            reply[3] = (reply[3] & 0xf0) | 3; // NXDOMAIN
            let sock = sock.try_clone().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let _ = sock.send_to(&reply, from);
            });
        }
    });
    addr
}

/// A stand-in for sudo. Installed setuid in a user namespace where we are
/// root, it really makes its caller root there. Like sudo it resets the
/// environment, closes inherited fds, records the caller in SUDO_UID, adds
/// 022 to the umask and gives the command root's resource limits. On
/// request it also does what some sudo setups do to their command: a root
/// session keyring (pam_keyinit), a syscall filter or a tracer (intercept,
/// log_subcmds), lower limits (no core dumps).
const C_FAKE_SUDO: &str = r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (getenv("FAKE_SUDO_FAIL")) { fprintf(stderr, "fake sudo: authentication failure\n"); return 1; }
    int new_pgrp = getenv("FAKE_SUDO_NEW_PGRP") != NULL, new_session = getenv("FAKE_SUDO_SETSID") != NULL;
    int to_root = getenv("FAKE_SUDO_CHDIR") != NULL, use_pty = getenv("FAKE_SUDO_USE_PTY") != NULL;
    int low_limits = getenv("FAKE_SUDO_LOW_LIMITS") != NULL, keyring = getenv("FAKE_SUDO_KEYRING") != NULL;
    int filter = getenv("FAKE_SUDO_SECCOMP") != NULL, trace = getenv("FAKE_SUDO_TRACE") != NULL;
    char uid[32], gid[32];
    const char *forced = getenv("FAKE_SUDO_UID");
    if (forced) snprintf(uid, sizeof uid, "%s", forced); else snprintf(uid, sizeof uid, "%u", getuid());
    snprintf(gid, sizeof gid, "%u", getgid());
    if (argc < 3 || strcmp(argv[1], "--") != 0) { fprintf(stderr, "fake sudo: usage: sudo -- cmd\n"); return 1; }
    clearenv();
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("SUDO_UID", uid, 1);
    setenv("SUDO_GID", gid, 1);
    for (int fd = 3; fd < 1024; fd++) close(fd);
    /* Like sudo variants that give the command a group, or (use_pty) a whole
       session, of its own. */
    if (new_pgrp) setpgid(0, 0);
    if (new_session) setsid();
    /* Like sudo with `runcwd` in sudoers, or -D. */
    if (to_root && chdir("/") != 0) return 1;
    /* Like sudo's default `umask 0022`, and pam_limits giving root its own
       limits (here: more open files, within the hard limit). */
    umask(umask(0) | 022);
    struct rlimit files;
    getrlimit(RLIMIT_NOFILE, &files);
    files.rlim_cur = files.rlim_max < 4096 ? files.rlim_max : 4096;
    if (setrlimit(RLIMIT_NOFILE, &files)) { perror("fake sudo: setrlimit"); return 1; }
    /* Like sudo's use_pty: a monitor in a session of its own, with a new pty
       as controlling terminal, runs the command in the pty's foreground group.
       When the command exits, so does the monitor, the session leader: the
       pty hangs up whatever is still in that group. */
    if (use_pty) {
        int m = posix_openpt(O_RDWR | O_NOCTTY);
        if (m < 0 || grantpt(m) || unlockpt(m)) { perror("fake sudo: pty"); return 1; }
        pid_t monitor = fork();
        if (monitor > 0) {
            int st;
            waitpid(monitor, &st, 0);
            return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
        }
        setsid();
        int s = open(ptsname(m), O_RDWR);
        if (s < 0) { perror("fake sudo: open pty"); _exit(1); }
        pid_t cmd = fork();
        if (cmd > 0) {
            int st;
            setpgid(cmd, cmd);
            tcsetpgrp(s, cmd);
            waitpid(cmd, &st, 0);
            _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
        }
        setpgid(0, 0);
        while (tcgetpgrp(s) != getpid()) usleep(1000);
        close(s);
        close(m);
    }
    if (setgroups(0, NULL) || setresgid(0, 0, 0) || setresuid(0, 0, 0)) { perror("fake sudo"); return 1; }
    if (low_limits) {
        struct rlimit core, nofile;
        getrlimit(RLIMIT_CORE, &core);
        getrlimit(RLIMIT_NOFILE, &nofile);
        core.rlim_cur = 0;
        nofile.rlim_cur = 300;
        if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_NOFILE, &nofile)) { perror("fake sudo: limits"); return 1; }
    }
    if (keyring && syscall(SYS_keyctl, 1 /* JOIN_SESSION_KEYRING */, "fake-sudo-root") < 0) {
        perror("fake sudo: keyctl"); return 1;
    }
    if (filter) {
        struct sock_filter allow[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
        struct sock_fprog prog = { 1, allow };
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("fake sudo: seccomp"); return 1; }
    }
    if (trace) {
        pid_t cmd = fork();
        if (cmd > 0) {
            int st;
            while (waitpid(cmd, &st, 0) == cmd && WIFSTOPPED(st)) {
                int sig = WSTOPSIG(st) == SIGTRAP ? 0 : WSTOPSIG(st);
                ptrace(PTRACE_CONT, cmd, 0, sig);
            }
            return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
        }
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) { perror("fake sudo: ptrace"); _exit(1); }
    }
    execv(argv[2], argv + 2);
    perror("fake sudo: exec");
    return 127;
}
"#;

/// A directory holding the fake `sudo`, built once.
fn fake_sudo_dir() -> Option<PathBuf> {
    static DIR: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tmp_dir("fake-sudo");
        let src = dir.join("sudo.c");
        std::fs::write(&src, C_FAKE_SUDO).unwrap();
        let bin = dir.join("sudo");
        let ok = Command::new("cc")
            .arg("-o")
            .arg(&bin)
            .arg(&src)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return None;
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o4755)).unwrap();
        // Everything inside the namespace runs as uids we do not own: let
        // them into our per-test directories.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        Some(dir)
    })
    .clone()
}

/// Can we build a CentOS-7-like world: a user namespace with subordinate
/// uids where nested user namespaces are forbidden?
fn centos7_simulation_works() -> bool {
    static OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OK.get_or_init(|| {
        let ok = have("cc")
            && have("setpriv")
            && Command::new("unshare")
                .args(["--user", "--map-auto", "--map-root-user", "--", "true"])
                .status()
                .is_ok_and(|s| s.success());
        if !ok {
            eprintln!(
                "SKIP: cannot simulate a host without user namespaces (needs cc, setpriv, newuidmap and /etc/subuid)"
            );
        }
        ok
    })
}

macro_rules! require_centos7 {
    ($($tool:expr),*) => {{
        require!($($tool),*);
        if !centos7_simulation_works() { return; }
    }};
}

/// Run proxytun like on CentOS 7: in a user namespace where nested user
/// namespaces are forbidden (max_user_namespaces = 0), as uid 1000 with
/// groups 1000 and 1001 (`as_user`) or as root, with our fake sudo on PATH.
fn run_like_centos7(cfg: &Path, extra: &[&str], argv: &[&str], as_user: bool, env: &[(&str, &str)]) -> Out {
    let sudo_dir = fake_sudo_dir().expect("fake sudo builds");
    let mut cmd = Command::new("unshare");
    cmd.args(["--user", "--map-auto", "--map-root-user", "--", "sh", "-c"]);
    let drop = if as_user {
        "setpriv --reuid=1000 --regid=1000 --groups=1000,1001 --"
    } else {
        ""
    };
    cmd.arg(format!(
        "echo 0 > /proc/sys/user/max_user_namespaces && PATH=\"$0:$PATH\" exec {drop} \"$@\""
    ));
    cmd.arg(&sudo_dir)
        .arg(BIN)
        .arg("-c")
        .arg(cfg)
        .args(extra)
        .arg("--")
        .args(argv);
    run_cmd(cmd, env)
}

/// A test directory that uids other than ours (inside the namespace) can use.
fn shared_dir(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp_dir(name);
    // Sticky, as /tmp is: the other uids may add files, but not replace or
    // remove ours (scripts we run among them).
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o1777)).unwrap();
    d
}

#[test]
fn without_user_namespaces_sudo_sets_up_and_the_program_runs_as_the_user() {
    require_centos7!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = shared_dir("sudo-ok");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let script = "id -u; id -G; grep -E '^Cap(Eff|Prm)' /proc/self/status; grep nameserver /etc/resolv.conf; \
                  sleep 0.3; echo parent=$(cat /proc/$(cut -d' ' -f4 /proc/$$/stat)/comm); \
                  curl -sS --max-time 20 http://sudo.test/";
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", script], true, &[]);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("asking sudo"), "{}", out.dump());
    assert_eq!(lines[0], "1000", "the user's uid, not root's\n{}", out.dump());
    assert_eq!(lines[1], "1000 1001", "the user's own groups\n{}", out.dump());
    assert_eq!(lines[2], "CapPrm:\t0000000000000000", "{}", out.dump());
    assert_eq!(lines[3], "CapEff:\t0000000000000000", "{}", out.dump());
    assert_eq!(lines[4], "nameserver 198.19.255.53", "{}", out.dump());
    assert_eq!(lines[5], "parent=proxytun", "the root helper is gone\n{}", out.dump());
    assert!(out.stdout.ends_with(BODY), "{}", out.dump());
    assert_eq!(mock.hosts(), ["sudo.test"]);
}

#[test]
fn the_users_environment_and_directory_survive_sudo() {
    require_centos7!();
    let dir = shared_dir("sudo-env");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let mut cmd = Command::new("unshare");
    let sudo_dir = fake_sudo_dir().unwrap();
    // Start from the test directory with a variable sudo would reset.
    cmd.current_dir(&dir);
    cmd.args(["--user", "--map-auto", "--map-root-user", "--", "sh", "-c"]);
    cmd.arg("echo 0 > /proc/sys/user/max_user_namespaces && PATH=\"$0:$PATH\" exec setpriv --reuid=1000 --regid=1000 --groups=1000 -- \"$@\"");
    cmd.arg(&sudo_dir)
        .arg(BIN)
        .arg("-c")
        .arg(&cfg)
        .args(["--", "sh", "-c", "echo $MARK; pwd; echo $HOME"]);
    // FAKE_SUDO_CHDIR: a sudo that changes directory (runcwd, -D) must not
    // move the program.
    let out = run_cmd(
        cmd,
        &[("MARK", "kept"), ("HOME", "/home/someone"), ("FAKE_SUDO_CHDIR", "1")],
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        lines,
        ["kept", dir.to_str().unwrap(), "/home/someone"],
        "{}",
        out.dump()
    );
}

#[test]
fn no_sudo_refuses_when_user_namespaces_are_unusable() {
    require_centos7!();
    let dir = shared_dir("no-sudo");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    let out = run_like_centos7(&cfg, &["--no-sudo"], &["sh", "-c", &touch], true, &[]);
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("user namespaces are not usable"), "{}", out.dump());
    assert!(out.stderr.contains("--no-sudo"), "{}", out.dump());
    assert!(!marker.exists(), "the program must not run");
}

#[test]
fn a_failed_sudo_is_reported_and_nothing_runs() {
    require_centos7!();
    let dir = shared_dir("sudo-fail");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", &touch], true, &[("FAKE_SUDO_FAIL", "1")]);
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("sudo failed"), "{}", out.dump());
    assert!(!marker.exists(), "the program must not run");
}

#[test]
fn the_helper_serves_only_the_user_sudo_was_run_by() {
    require_centos7!();
    let dir = shared_dir("sudo-wrong-uid");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    // sudo claims another caller than the owner of proxytun's socket. The
    // helper reaches the socket with that caller's file permissions, so it
    // cannot even connect to proxytun's private directory.
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", &touch], true, &[("FAKE_SUDO_UID", "1234")]);
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("connect to proxytun: EACCES"), "{}", out.dump());
    assert!(!marker.exists(), "the program must not run");
}

#[test]
fn root_gets_a_namespace_without_sudo_and_stays_root() {
    require_centos7!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = shared_dir("root");
    let cfg = write_cfg(&dir, mock.addr, "sniff = false", "");
    let script = "id -u; grep '^CapEff' /proc/self/status; curl -sS --max-time 20 http://root.test/";
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", script], false, &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines[0], "0", "{}", out.dump());
    assert_ne!(
        lines[1],
        "CapEff:\t0000000000000000",
        "root keeps its capabilities\n{}",
        out.dump()
    );
    assert!(!out.stderr.contains("sudo"), "{}", out.dump());
    assert!(out.stdout.ends_with(BODY), "{}", out.dump());
    assert_eq!(mock.hosts(), ["root.test"]);
}

#[test]
fn the_program_joins_proxytuns_process_group_whatever_sudo_does() {
    require_centos7!();
    let dir = shared_dir("sudo-pgrp");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // The program's group, and its parent's (proxytun, once the helper is gone).
    let script = "sleep 0.3; P=$(cut -d' ' -f4 /proc/$$/stat); \
                  echo $(cut -d' ' -f5 /proc/$$/stat) $(cut -d' ' -f5 /proc/$P/stat)";
    // sudo putting its command into a group of its own: the program still
    // joins ours, so terminal and group signals reach it.
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", script], true, &[("FAKE_SUDO_NEW_PGRP", "1")]);
    assert_eq!(out.code, 0, "{}", out.dump());
    let groups: Vec<&str> = out.stdout.split_whitespace().collect();
    assert_eq!(groups.len(), 2, "{}", out.dump());
    assert_eq!(
        groups[0],
        groups[1],
        "program and proxytun share a process group\n{}",
        out.dump()
    );
    assert!(!out.stderr.contains("session of its own"), "{}", out.dump());

    // A session of its own (sudo's use_pty) cannot be undone: say so.
    let out = run_like_centos7(&cfg, &[], &["true"], true, &[("FAKE_SUDO_SETSID", "1")]);
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("session of its own"), "{}", out.dump());
}

/// Run `root` as root, then `user` as uid 1000 (groups 1000, 1001), each with
/// `sh -c`, in the CentOS-7-like world: `$BIN` is proxytun, `$D` is `dir`,
/// and our fake sudo is on PATH.
fn sh_like_centos7(dir: &Path, root: &str, user: &str) -> Out {
    let sudo_dir = fake_sudo_dir().expect("fake sudo builds");
    let mut cmd = Command::new("unshare");
    // Not whatever the test runner's stdin is: a socket there would answer
    // a mistaken setup entry and keep it waiting.
    cmd.stdin(Stdio::null());
    cmd.args(["--user", "--map-auto", "--map-root-user", "--", "sh", "-c"]);
    cmd.arg(format!(
        "echo 0 > /proc/sys/user/max_user_namespaces && PATH=\"$SUDO_DIR:$PATH\" && {root} && \
         exec setpriv --reuid=1000 --regid=1000 --groups=1000,1001 -- sh -c \"$USER_SCRIPT\""
    ));
    run_cmd(
        cmd,
        &[
            ("BIN", BIN),
            ("D", dir.to_str().unwrap()),
            ("SUDO_DIR", sudo_dir.to_str().unwrap()),
            ("USER_SCRIPT", user),
        ],
    )
}

#[test]
fn proxytun_refuses_root_through_sudo_or_a_setuid_copy() {
    require_centos7!();
    let dir = shared_dir("refuse-root");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // A copy installed setuid root, as an admin might to spare users sudo.
    let root = "cp \"$BIN\" \"$D/suid\" && chmod 4755 \"$D/suid\"";
    // With a sudoers rule for proxytun, any of these would give the user a
    // root program: the normal command line, the namespace setup entry
    // (fd 0 named as its socket), a setuid copy, and that copy
    // playing helper with a SUDO_UID of the user's choosing.
    let user = "\
        sudo -- \"$BIN\" -c \"$D/cfg.toml\" -- touch \"$D/ran\"; echo sudo=$?; \
        sudo -- \"$BIN\" __proxytun_setup 0 198.18.0.0/15 - -- touch \"$D/ran\"; echo setup=$?; \
        \"$D/suid\" -c \"$D/cfg.toml\" -- touch \"$D/ran\"; echo suid=$?; \
        SUDO_UID=1000 SUDO_GID=1000 \"$D/suid\" __proxytun_root_setup \"$D/ctl\"; echo suid-helper=$?";
    let out = sh_like_centos7(&dir, root, user);
    let codes: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        codes,
        ["sudo=2", "setup=2", "suid=2", "suid-helper=1"],
        "{}",
        out.dump()
    );
    assert_eq!(
        out.stderr.matches("refuses to run as root through sudo").count(),
        2,
        "{}",
        out.dump()
    );
    assert!(
        out.stderr.contains("must not be installed setuid root"),
        "{}",
        out.dump()
    );
    assert!(
        out.stderr.contains("the helper must be started by sudo"),
        "{}",
        out.dump()
    );
    assert!(!dir.join("ran").exists(), "nothing may run");
}

#[test]
fn under_sudo_a_setuid_program_cannot_regain_root() {
    require_centos7!();
    let dir = shared_dir("sudo-nnp");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // The network in there is the user's; our fake sudo, setuid root, stands
    // for any setuid program that would trust it.
    let script = "sudo -- \"$(command -v id)\" -u || echo refused";
    let out = run_like_centos7(&cfg, &[], &["sh", "-c", script], true, &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(out.stdout.trim(), "refused", "{}", out.dump());
}

/// A client of the root helper that is not proxytun: it runs sudo itself
/// and then misbehaves, or is merely slow, as `case` says.
const PY_HELPER_CLIENT: &str = r#"
import os, socket, struct, subprocess, sys, time
binary, d, case = sys.argv[1:4]
path = os.path.join(d, "ctl-" + case)
helper = ["sudo", "--", binary, "__proxytun_root_setup", path]

def listener():
    l = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    l.bind(path)
    l.listen(1)
    return l

def again(n):
    """Start over with a fresh socket path, for the n-th try."""
    global path, helper
    path = os.path.join(d, f"ctl-{case}-{n}")
    helper = ["sudo", "--", binary, "__proxytun_root_setup", path]

def hostile_end():
    """The receiving end of a socketpair with fds in flight inside it whose
    last close blocks for 20 s: a socket with SO_LINGER and unsent data, and
    its peer, which never reads."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    a = socket.create_connection(srv.getsockname())
    b, _ = srv.accept()
    a.setblocking(False)
    try:
        while True:
            a.send(b"x" * 65536)
    except BlockingIOError:
        pass
    a.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 20))
    x, y = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    socket.send_fds(x, [b"in flight"], [a.fileno(), b.fileno()])
    for s in (a, b, srv, x):
        s.close()  # in flight still: not the last
    return y

def send_and_exit(c, y):
    """Send `y` on `c`, drop our copy at once and exit. Our close follows the
    send so closely that the copy sent is the last (we must have closed ours,
    the caller, before). Should we still be late, the receiver gone already,
    ours is the last and we linger instead: our output goes nowhere and
    nobody waits for us."""
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.dup2(null, 2)
    try:
        socket.send_fds(c, [b"junk\0"], [y.fileno()])
    except OSError:
        os._exit(0)  # the helper hung up first: ours is the only copy
    y.close()
    os._exit(0)

# A helper that would block on them does so only if its copy is the last,
# which depends on timing (our sender's close against its own): five tries.
TRIES = 5

if case == "queued":
    # Queued on the connection, never read: the helper turns down a socket
    # that is not the sudo caller's and hangs up.
    worst = 0
    for n in range(TRIES):
        again(n)
        y = hostile_end()
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            l = listener()
            os.write(w, b"x")
            c, _ = l.accept()
            send_and_exit(c, y)
        y.close()
        os.read(r, 1)
        start = time.monotonic()
        rc = subprocess.call(helper)
        worst = max(worst, time.monotonic() - start)
    print(f"rc={rc} after {worst:.0f}s", flush=True)
    sys.exit()

if case == "stranger":
    # The socket belongs to our child, not to the process that ran sudo.
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        l = listener()
        os.write(w, b"x")
        c, _ = l.accept()
        uid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        print("peer uid:", uid, flush=True)
        print("got:", c.recv(4096).decode(errors="replace"), flush=True)
        os._exit(0)
    os.read(r, 1)
    rc = subprocess.call(helper)
    os.waitpid(pid, 0)
    print(f"rc={rc}", flush=True)
    sys.exit()

if case == "linger":
    # With a malformed request: the program side, not root, gets them.
    worst = 0
    for n in range(TRIES):
        again(n)
        y = hostile_end()
        l = listener()
        p = subprocess.Popen(helper)
        c, _ = l.accept()
        start = time.monotonic()
        r, w = os.pipe()
        if os.fork() == 0:
            os.read(r, 1)
            send_and_exit(c, y)
        y.close()
        os.write(w, b"x")
        got = c.recv(4096)[:2].decode(errors="replace")
        rc = p.wait(timeout=90)
        worst = max(worst, time.monotonic() - start)
    print("got:", got, flush=True)
    print(f"rc={rc} after {worst:.0f}s", flush=True)
    sys.exit()
l = listener()
p = subprocess.Popen(helper)
c, _ = l.accept()
start = time.monotonic()
if case == "silent":
    rc = p.wait(timeout=30)
    print(f"rc={rc} after {time.monotonic() - start:.0f}s", flush=True)
    sys.exit()
rng, pgrp, inherit = {
    "range": ("10.0.0.0/30", os.getpgrp(), "-"),
    "pgrp": ("198.18.0.0/15", 1, "-"),
    # Claims an inherited fd 9 but sends none.
    "fds": ("198.18.0.0/15", os.getpgrp(), "9"),
    "late": ("198.18.0.0/15", os.getpgrp(), "-"),
}[case]
marker = os.path.join(d, "ran-" + case)
fields = ["3", rng, str(pgrp), "-", "22", "0", inherit, "2", "touch", marker, "PATH=/usr/bin:/bin"]
cwd = os.open(d, os.O_PATH)
socket.send_fds(c, [b"".join(f.encode() + b"\0" for f in fields)], [0, 1, 2, cwd])
print("got:", c.recv(4096)[:2].decode(errors="replace"), flush=True)
print(f"rc={p.wait()}", flush=True)
if case == "late":
    # Longer than the helper waits for us: the program still waits.
    time.sleep(12)
    c.send(b"G")
    for _ in range(50):
        if os.path.exists(marker):
            break
        time.sleep(0.1)
    print("ran" if os.path.exists(marker) else "did not run", flush=True)
"#;

#[test]
fn the_helper_trusts_neither_the_socket_nor_the_request() {
    require_centos7!("python3");
    let dir = shared_dir("helper-client");
    std::fs::write(dir.join("client.py"), PY_HELPER_CLIENT).unwrap();
    let cases = ["stranger", "range", "pgrp", "fds", "linger", "queued", "silent", "late"];
    let user = format!(
        "for c in {}; do python3 \"$D/client.py\" \"$BIN\" \"$D\" $c > \"$D/out-$c\" 2>&1 & done; wait",
        cases.join(" ")
    );
    let out = sh_like_centos7(&dir, "true", &user);
    assert_eq!(out.code, 0, "{}", out.dump());
    let got = |c: &str| std::fs::read_to_string(dir.join(format!("out-{c}"))).unwrap();
    let all = || cases.map(|c| format!("--- {c} ---\n{}", got(c))).join("\n");
    // A socket that is not the sudo caller's own (someone else's proxytun, or
    // anything listening) sees the user connecting, not root, and is told
    // nothing.
    assert!(got("stranger").contains("peer uid: 1000\n"), "{}", all());
    assert!(got("stranger").contains("got: \n"), "{}", all());
    assert!(got("stranger").ends_with("rc=1\n"), "{}", all());
    assert!(
        got("stranger").contains("the socket was not created by the process that ran sudo"),
        "{}",
        all()
    );

    // Requests proxytun would never send.
    assert!(
        got("range").contains("fake-ip range 10.0.0.0/30 out of bounds"),
        "{}",
        all()
    );
    assert!(
        got("range").contains("got: ER\n") && got("range").ends_with("rc=1\n"),
        "{}",
        all()
    );
    assert!(got("pgrp").contains("process group 1 is not the caller's"), "{}", all());
    assert!(
        got("pgrp").contains("got: ER\n") && got("pgrp").ends_with("rc=1\n"),
        "{}",
        all()
    );
    assert!(got("fds").contains("expected 5 fds"), "{}", all());
    assert!(got("fds").ends_with("rc=1\n"), "{}", all());
    // Whatever fds a client sends, root never holds them: closing them (the
    // socket lingers for 20 s) cannot keep it, and sudo, waiting.
    assert!(got("linger").contains("malformed request"), "{}", all());
    assert!(got("linger").contains("got: ER\n"), "{}", all());
    let secs = |c: &str| -> u64 {
        got(c)
            .lines()
            .last()
            .and_then(|l| l.strip_prefix("rc=1 after "))
            .and_then(|s| s.strip_suffix('s'))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("{}", all()))
    };
    assert!(secs("linger") < 5, "{}", all());
    // Nor when they are only queued on the connection, and the helper ends
    // it without reading (here: turning down a stranger's socket).
    assert!(
        got("queued").contains("the socket was not created by the process that ran sudo"),
        "{}",
        all()
    );
    assert!(secs("queued") < 5, "{}", all());
    // A client that never talks does not keep root waiting.
    assert!((5..=15).contains(&secs("silent")), "{}", all());
    // That limit is for talking to root only: the program, the helper gone,
    // waits for the go-ahead as long as proxytun takes.
    assert!(got("late").ends_with("got: OK\nrc=0\nran\n"), "{}", all());
    for c in ["range", "pgrp", "fds"] {
        assert!(!dir.join(format!("ran-{c}")).exists(), "{c}: nothing may run");
    }
}

/// Join a session keyring named argv[1], then run argv[2:].
const PY_JOIN_KEYRING: &str = r#"
import ctypes, os, sys
if ctypes.CDLL(None, use_errno=True).syscall(250, 1, sys.argv[1].encode()) < 0:  # keyctl JOIN (x86_64)
    sys.exit("keyctl: %d" % ctypes.get_errno())
os.execvp(sys.argv[2], sys.argv[2:])
"#;

/// Print the name of our session keyring.
const PY_SESSION_KEYRING: &str = r#"
import ctypes
buf = ctypes.create_string_buffer(4096)
n = ctypes.CDLL(None).syscall(250, 6, -3, buf, 4096)  # keyctl DESCRIBE @s (x86_64)
print(buf.value.decode().split(";")[-1] if n > 0 else "none")
"#;

/// Run argv[1:] under a syscall filter that fails keyctl with EPERM, as
/// Docker's default seccomp profile does. Needs CAP_SYS_ADMIN (no
/// no_new_privs, so that sudo still works under it).
const PY_NO_KEYCTL: &str = r#"
import ctypes, os, struct, sys
ins = lambda code, k, jt=0, jf=0: struct.pack("HBBI", code, jt, jf, k)
prog = ins(0x20, 0) + ins(0x15, 250, 0, 1) + ins(0x06, 0x00050001) + ins(0x06, 0x7fff0000)
buf = ctypes.create_string_buffer(prog)
class Fprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
fp = Fprog(len(prog) // 8, ctypes.addressof(buf))
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(22, 2, ctypes.byref(fp), 0, 0) != 0:  # PR_SET_SECCOMP, FILTER
    sys.exit("seccomp: %d" % ctypes.get_errno())
os.execvp(sys.argv[1], sys.argv[1:])
"#;

#[test]
fn the_callers_own_session_keyring_reaches_the_program_in_either_mode() {
    require_centos7!("python3");
    let dir = shared_dir("sudo-own-keyring");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    std::fs::write(dir.join("join.py"), PY_JOIN_KEYRING).unwrap();
    std::fs::write(dir.join("session.py"), PY_SESSION_KEYRING).unwrap();
    // Without sudo (user namespaces), as the reference.
    let mut cmd = Command::new("python3");
    cmd.arg(dir.join("join.py"))
        .args(["callers-own", BIN, "-c", dir.join("cfg.toml").to_str().unwrap(), "--"])
        .arg("python3")
        .arg(dir.join("session.py"));
    let plain = run_cmd(cmd, &[]);
    assert_eq!(
        (plain.code, plain.stdout.as_str()),
        (0, "callers-own\n"),
        "{}",
        plain.dump()
    );
    // Through sudo (without pam_keyinit) the same: not a fresh, empty one.
    let user = "python3 \"$D/join.py\" callers-own \"$D/pt\" -c \"$D/cfg.toml\" -- python3 \"$D/session.py\"";
    let out = sh_like_centos7(&dir, "cp \"$BIN\" \"$D/pt\"", user);
    assert!(out.stderr.contains("asking sudo"), "{}", out.dump());
    assert_eq!((out.code, out.stdout.as_str()), (0, "callers-own\n"), "{}", out.dump());
    // With pam_keyinit's root keyring in between, a fresh one of the user's.
    let out = sh_like_centos7(&dir, "cp \"$BIN\" \"$D/pt\"", &format!("FAKE_SUDO_KEYRING=1 {user}"));
    assert_eq!((out.code, out.stdout.as_str()), (0, "_ses\n"), "{}", out.dump());
}

#[test]
fn without_keyctl_the_helper_cannot_check_the_keyring_and_refuses() {
    require_centos7!("python3");
    let dir = shared_dir("sudo-no-keyctl");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    std::fs::write(dir.join("no-keyctl.py"), PY_NO_KEYCTL).unwrap();
    let marker = dir.join("ran");
    // A container's filter, the caller's and so the helper's too: the
    // program might be left with root's session keyring, unseen.
    let sudo_dir = fake_sudo_dir().unwrap();
    let mut cmd = Command::new("unshare");
    cmd.stdin(Stdio::null());
    cmd.args(["--user", "--map-auto", "--map-root-user", "--", "sh", "-c"]);
    cmd.arg(
        "echo 0 > /proc/sys/user/max_user_namespaces && PATH=\"$SUDO_DIR:$PATH\" exec python3 \"$D/no-keyctl.py\" \
         setpriv --reuid=1000 --regid=1000 --groups=1000 -- \"$BIN\" -c \"$CFG\" -- touch \"$MARK\"",
    );
    let out = run_cmd(
        cmd,
        &[
            ("BIN", BIN),
            ("D", dir.to_str().unwrap()),
            ("CFG", cfg.to_str().unwrap()),
            ("MARK", marker.to_str().unwrap()),
            ("SUDO_DIR", sudo_dir.to_str().unwrap()),
        ],
    );
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("asking sudo"), "{}", out.dump());
    assert!(
        out.stderr.contains("cannot tell whose session keyring"),
        "{}",
        out.dump()
    );
    assert!(!marker.exists(), "the program must not run");
}

#[test]
fn the_helper_refuses_a_sudo_that_traces_or_filters_its_command() {
    require_centos7!();
    let dir = shared_dir("sudo-confined");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    // sudoers `intercept` / `log_subcmds`: the program would run with root
    // watching (and able to stop) its every exec.
    for (how, says) in [("FAKE_SUDO_SECCOMP", "syscall filter"), ("FAKE_SUDO_TRACE", "traced")] {
        let out = run_like_centos7(&cfg, &[], &["sh", "-c", &touch], true, &[(how, "1")]);
        assert_ne!(out.code, 0, "{how}\n{}", out.dump());
        assert!(out.stderr.contains(says), "{how}\n{}", out.dump());
        assert!(!marker.exists(), "{how}: the program must not run");
    }
}

#[test]
fn a_tmpdir_too_long_for_the_helper_socket_says_so() {
    require_centos7!();
    let dir = shared_dir("sudo-long-tmpdir");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let long = dir.join("t".repeat(100));
    std::fs::create_dir(&long).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let out = run_like_centos7(&cfg, &[], &["true"], true, &[("TMPDIR", long.to_str().unwrap())]);
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(
        out.stderr.contains("set TMPDIR to a shorter directory"),
        "{}",
        out.dump()
    );
}

#[test]
fn a_refused_tun_device_is_reported_not_handed_to_sudo() {
    require_centos7!();
    let dir = shared_dir("tun-refused");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let sudo_dir = fake_sudo_dir().unwrap();
    let mut cmd = Command::new("unshare");
    cmd.stdin(Stdio::null());
    // User namespaces work here; only the device is off-limits to the user,
    // as with an admin's mode 0600 or a container's device cgroup. Root
    // must not be asked to open it instead.
    cmd.args(["--user", "--map-auto", "--map-root-user", "--mount", "--", "sh", "-c"]);
    cmd.arg(
        "touch \"$D/no-tun\" && chmod 600 \"$D/no-tun\" && mount --bind \"$D/no-tun\" /dev/net/tun && \
         PATH=\"$SUDO_DIR:$PATH\" exec setpriv --reuid=1000 --regid=1000 --groups=1000 -- \
         \"$BIN\" -c \"$D/cfg.toml\" -- true",
    );
    let out = run_cmd(
        cmd,
        &[
            ("BIN", BIN),
            ("D", dir.to_str().unwrap()),
            ("SUDO_DIR", sudo_dir.to_str().unwrap()),
        ],
    );
    assert_ne!(out.code, 0, "{}", out.dump());
    assert!(
        out.stderr.contains("open /dev/net/tun: Permission denied"),
        "{}",
        out.dump()
    );
    assert!(!out.stderr.contains("asking sudo"), "{}", out.dump());
}

#[test]
fn the_log_file_is_never_someone_elses_nor_a_link() {
    require_centos7!();
    let dir = shared_dir("log-file");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // Another user got there first, with a file anyone may write and they
    // may read; or a link to wherever.
    // (A copy of proxytun: the user cannot reach our build directory.)
    let root = "touch \"$D/theirs\" && chmod 666 \"$D/theirs\" && mkfifo -m 666 \"$D/fifo\" && cp \"$BIN\" \"$D/pt\"";
    let user = "ln -s \"$D/own\" \"$D/link\"; \
        \"$D/pt\" -v -c \"$D/cfg.toml\" --log-file \"$D/theirs\" -- true; echo theirs=$?; \
        \"$D/pt\" -v -c \"$D/cfg.toml\" --log-file \"$D/link\" -- true; echo link=$?; \
        timeout 10 \"$D/pt\" -v -c \"$D/cfg.toml\" --log-file \"$D/fifo\" -- true; echo fifo=$?";
    let out = sh_like_centos7(&dir, root, user);
    let codes: Vec<&str> = out.stdout.lines().collect();
    // (A FIFO nobody reads: refused at once, not waited on.)
    assert_eq!(codes, ["theirs=1", "link=1", "fifo=1"], "{}", out.dump());
    assert!(out.stderr.contains("is not a regular file of yours"), "{}", out.dump());
    // ELOOP, worded differently by glibc and musl.
    assert!(out.stderr.contains("(os error 40)"), "{}", out.dump());
    assert_eq!(
        std::fs::metadata(dir.join("theirs")).unwrap().len(),
        0,
        "nothing logged to them"
    );
    assert!(!dir.join("own").exists(), "nothing created through the link");
}

#[test]
fn under_sudo_the_program_keeps_the_users_limits_umask_and_fds() {
    require_centos7!("bash");
    let dir = shared_dir("sudo-parity");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    std::fs::write(dir.join("five"), "inherited\n").unwrap();
    for n in 20..=60 {
        std::fs::write(dir.join(format!("f{n}")), format!("{n},")).unwrap();
    }
    // What the program sees of its process: sudo gives root other limits
    // (more, or fewer: no core dumps, fewer fds), another umask and session
    // keyring, and closes inherited fds; none of that may reach the program.
    // Two inherited fds sit right under the fd limit, where they must stay;
    // a band of them (each its own file) covers the numbers that are free
    // while they are put in place, so none may end up on another's number.
    std::fs::write(
        dir.join("parity.sh"),
        r#"ulimit -Sn 777; ulimit -Sc 1024; umask 002; trap '' PIPE; exec 775<"$D/five" 776>&1
for n in $(seq 20 60); do eval "exec $n<\"\$D/f$n\""; done
exec "$PT" -c "$D/cfg.toml" -- bash -c 'ulimit -Sn; ulimit -Hn; ulimit -Sc; umask; cat <&775; echo to-776 >&776;
  for n in $(seq 20 60); do cat <&$n; done; echo; grep -c fake-sudo-root /proc/keys; grep SigIgn /proc/self/status;
  ls /proc/self/fd | sort -n | tr "\n" " "'
"#,
    )
    .unwrap();
    // Without sudo (user namespaces), as the reference.
    let mut cmd = Command::new("bash");
    cmd.arg(dir.join("parity.sh"));
    let plain = run_cmd(cmd, &[("PT", BIN), ("D", dir.to_str().unwrap())]);
    assert_eq!(plain.code, 0, "{}", plain.dump());
    assert!(!plain.stderr.contains("asking sudo"), "{}", plain.dump());
    let lines: Vec<&str> = plain.stdout.lines().collect();
    assert_eq!(lines.len(), 10, "{}", plain.dump());
    assert_eq!(lines[0], "777", "{}", plain.dump());
    let band: Vec<String> = (20..=60).map(|n| n.to_string()).collect();
    assert_eq!(
        lines[2..],
        [
            "1024".to_string(),
            "0002".into(),
            "inherited".into(),
            "to-776".into(),
            format!("{},", band.join(",")),
            "0".into(),
            lines[8].to_string(),
            format!("0 1 2 3 {} 775 776 ", band.join(" ")),
        ],
        "{}",
        plain.dump()
    );
    assert_ne!(
        ignored_mask(lines[8]) & (1 << (libc::SIGPIPE - 1)),
        0,
        "SIGPIPE stays ignored\n{}",
        plain.dump()
    );
    // Through sudo, the same. (A copy of proxytun: the user cannot reach our
    // build directory.)
    let out = sh_like_centos7(
        &dir,
        "cp \"$BIN\" \"$D/pt\"",
        "FAKE_SUDO_LOW_LIMITS=1 FAKE_SUDO_KEYRING=1 PT=\"$D/pt\" bash \"$D/parity.sh\"",
    );
    assert_eq!(out.code, 0, "{}", out.dump());
    assert!(out.stderr.contains("asking sudo"), "{}", out.dump());
    assert_eq!(out.stdout, plain.stdout, "{}", out.dump());
}

#[test]
fn arguments_and_environment_need_not_be_utf8() {
    require_centos7!();
    let dir = shared_dir("not-utf8");
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // As with GBK file names and directories (in $PWD, or $TMPDIR, where
    // proxytun makes its own) on CentOS 7: the program gets the very bytes,
    // in either mode.
    std::fs::write(
        dir.join("odd.sh"),
        r#"BAD=$(printf '\377'); export BAD
TMPDIR="$D/$(printf '\304\343')"; mkdir -p -m 1777 "$TMPDIR"; export TMPDIR
exec "$PT" -c "$D/cfg.toml" -- sh -c 'printf "%s|%s" "$1" "$BAD" | od -An -tx1 | tr -d " \n"' sh "$(printf '\304\343')"
"#,
    )
    .unwrap();
    let mut cmd = Command::new("sh");
    cmd.arg(dir.join("odd.sh"));
    let plain = run_cmd(cmd, &[("PT", BIN), ("D", dir.to_str().unwrap())]);
    assert_eq!((plain.code, plain.stdout.as_str()), (0, "c4e37cff"), "{}", plain.dump());
    let out = sh_like_centos7(&dir, "cp \"$BIN\" \"$D/pt\"", "PT=\"$D/pt\" sh \"$D/odd.sh\"");
    assert!(out.stderr.contains("asking sudo"), "{}", out.dump());
    assert_eq!((out.code, out.stdout.as_str()), (0, "c4e37cff"), "{}", out.dump());
}

#[test]
fn under_sudo_use_pty_the_program_survives_sudo_and_still_gets_ctrl_c() {
    require_centos7!("python3");
    let dir = shared_dir("sudo-use-pty");
    std::fs::write(dir.join("sig.py"), PY_SIGNAL).unwrap();
    std::fs::write(dir.join("press_ctrl_c.py"), PY_PTY_CTRL_C).unwrap();
    write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // sudo's pty session ends right after the helper: the program must have
    // left it, and is then out of our foreground group, so the terminal's
    // Ctrl+C reaches it only through us.
    let user = "FAKE_SUDO_USE_PTY=1 python3 \"$D/press_ctrl_c.py\" \"$D/pt\" -c \"$D/cfg.toml\" -- \
                python3 \"$D/sig.py\" SIGINT handler";
    let out = sh_like_centos7(&dir, "cp \"$BIN\" \"$D/pt\"", user);
    // (The fake sudo really made a pty session of its own.)
    assert!(out.stderr.contains("session of its own"), "{}", out.dump());
    assert!(out.stdout.contains("handled 1"), "{}", out.dump());
    assert!(out.stdout.starts_with("exit 3"), "{}", out.dump());

    // Ctrl+C reaches the whole pipeline there, not only its shell: else
    // `sleep` would go on, and proxytun with it, waiting for it.
    let user = "FAKE_SUDO_USE_PTY=1 python3 \"$D/press_ctrl_c.py\" \"$D/pt\" -c \"$D/cfg.toml\" -- \
                sh -c 'echo ready; sleep 30 | cat'";
    let out = sh_like_centos7(&dir, "cp \"$BIN\" \"$D/pt\"", user);
    assert!(out.stdout.starts_with("exit -2"), "{}", out.dump());
}

#[test]
fn as_root_the_namespace_files_never_go_to_tmpdir() {
    require_centos7!();
    let dir = shared_dir("root-tmpdir");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // Under a directory someone else controls, the resolv.conf root writes
    // could be swapped for a link mid-way: root uses /tmp whatever $TMPDIR
    // says (here: nowhere at all).
    let out = run_like_centos7(&cfg, &[], &["true"], false, &[("TMPDIR", "/nonexistent")]);
    assert_eq!(out.code, 0, "{}", out.dump());
}

// ------------------------------------------------ host ports and doctor --

/// Does this host have IPv6 on loopback?
fn have_ipv6_loopback() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

#[test]
fn the_hosts_loopback_listeners_are_reachable_inside() {
    require!("curl");
    let mock = start_mock_proxy(1); // must stay untouched
    let dir = tmp_dir("hostports");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    let lo = start_origin_on("127.0.0.1:0");
    let any = start_origin_on("0.0.0.0:0");
    let mut urls = vec![format!("http://127.0.0.1:{lo}/"), format!("http://127.0.0.1:{any}/")];
    if have_ipv6_loopback() {
        let v6 = start_origin_on("[::1]:0");
        urls.push(format!("http://[::1]:{v6}/"));
    } else {
        eprintln!("SKIP (part): no IPv6 on loopback");
    }
    let mut argv = vec!["curl", "-sS", "--max-time", "10"];
    argv.extend(urls.iter().map(String::as_str));
    let out = run(&cfg, &[], &argv, &[]);
    assert_eq!(out.code, 0, "{}", out.dump());
    assert_eq!(out.stdout, BODY.repeat(urls.len()), "{}", out.dump());
    assert!(
        mock.seen().is_empty(),
        "the host's own ports never go through the proxy"
    );
    assert!(out.stderr.contains("host ports reachable inside:"), "{}", out.dump());
    assert!(out.stderr.contains("routing to the host's own port"), "{}", out.dump());
}

#[test]
fn excluded_ports_and_no_host_ports_leave_the_port_to_the_program() {
    require!("curl", "python3");
    let dir = tmp_dir("hostports-off");
    let port = start_origin_on("127.0.0.1:0");
    // The program listens on the same port itself, then talks to it.
    let script = format!(
        "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); \
         s.bind(('127.0.0.1', {port})); s.listen(); print('own listener ok')"
    );
    for (top, extra) in [
        (format!("host_ports_exclude = [{port}]"), &[][..]),
        (String::new(), &["--no-host-ports"][..]),
    ] {
        let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), &top, "");
        let out = run(&cfg, extra, &["python3", "-c", &script], &[]);
        assert_eq!(out.stdout.trim(), "own listener ok", "{top} {extra:?}\n{}", out.dump());
        let out = run(
            &cfg,
            extra,
            &["curl", "-sS", "--max-time", "5", &format!("http://127.0.0.1:{port}/")],
            &[],
        );
        assert_ne!(out.code, 0, "not forwarded: {top} {extra:?}\n{}", out.dump());
    }
}

#[test]
fn a_port_opened_after_start_is_not_forwarded() {
    require!("curl", "sh");
    let dir = tmp_dir("hostports-late");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let (go, port_file) = (dir.join("go"), dir.join("port"));
    let _ = std::fs::remove_file(&go);
    let script = format!(
        // Succeeds only if the late port is NOT reachable inside.
        "while [ ! -f {go} ]; do sleep 0.05; done; ! curl -sS --max-time 5 http://127.0.0.1:$(cat {pf})/",
        go = go.display(),
        pf = port_file.display()
    );
    let (mut child, _log) = spawn_bg(&cfg, &["sh", "-c", &script]);
    std::thread::sleep(Duration::from_millis(300)); // proxytun has scanned
    let port = start_origin_on("127.0.0.1:0");
    std::fs::write(&port_file, port.to_string()).unwrap();
    std::fs::write(&go, "").unwrap();
    let st = child.wait().unwrap();
    assert!(st.success(), "a listener opened after start-up was reachable inside");
}

#[test]
fn doctor_reports_rootless_mode_and_each_proxy() {
    require!();
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("doctor");
    let (_dead, dead) = refused_addr();
    let cfg = dir.join("doctor.toml");
    std::fs::write(
        &cfg,
        format!(
            "[[proxies]]\nname=\"good\"\ntype=\"socks5\"\naddr=\"{}\"\n[[proxies]]\nname=\"dead\"\ntype=\"socks5\"\naddr=\"{dead}\"\n\
             [[groups]]\nname=\"default\"\nmembers=[\"good\",\"dead\"]\n",
            mock.addr
        ),
    )
    .unwrap();
    let out = Command::new(BIN).arg("-c").arg(&cfg).arg("--doctor").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("[ OK ] namespace") && text.contains("rootless"), "{text}");
    assert!(
        text.contains("[ OK ] upstream proxy") && text.contains("good"),
        "{text}"
    );
    assert!(
        text.contains("[FAIL] upstream proxy") && text.contains("dead"),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(1), "a dead proxy fails the doctor\n{text}");

    // Credentials on the command line: the doctor says so too.
    let out = Command::new(BIN)
        .args(["--doctor", "--proxy", "socks5://u:secret@127.0.0.1:1"])
        .arg("-c")
        .arg(dir.join("none.toml"))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--proxy carries credentials"), "{err}");
}

#[test]
fn doctor_is_not_fooled_by_a_caller_that_ignores_sigchld() {
    require!("python3");
    let dir = tmp_dir("doctor-sigchld");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    // The trial program cannot even start (no `true` on PATH): the doctor must
    // say so, even with the kernel reaping its children unasked.
    let mut cmd = Command::new("python3");
    cmd.arg("-c").arg(
        "import os, signal, sys; signal.signal(signal.SIGCHLD, signal.SIG_IGN); \
         os.execve(sys.argv[1], sys.argv[1:], {'PATH': '/nonexistent'})",
    );
    cmd.args([BIN, "-c", cfg.to_str().unwrap(), "--doctor"]);
    let out = run_cmd(cmd, &[]);
    assert!(out.stdout.contains("[FAIL] namespace"), "{}", out.dump());
    assert!(out.stdout.contains("did not run"), "{}", out.dump());
}

#[test]
fn doctor_reports_the_sudo_mode_without_running_sudo() {
    require_centos7!();
    let mock = start_mock_proxy(1);
    let dir = shared_dir("doctor-sudo");
    let cfg = write_cfg(&dir, mock.addr, "", "");
    // A fake sudo that would fail loudly if --doctor ran it.
    let out = run_like_centos7(&cfg, &["--doctor"], &[], true, &[("FAKE_SUDO_FAIL", "1")]);
    assert!(out.stdout.contains("[WARN] namespace"), "{}", out.dump());
    assert!(out.stdout.contains("max_user_namespaces=0"), "{}", out.dump());
    assert!(out.stdout.contains("[ OK ] sudo mode"), "{}", out.dump());
    assert!(
        !out.stderr.contains("fake sudo"),
        "--doctor must not run sudo\n{}",
        out.dump()
    );
    assert_eq!(out.code, 0, "{}", out.dump());

    let out = run_like_centos7(&cfg, &["--doctor", "--no-sudo"], &[], true, &[]);
    assert!(out.stdout.contains("[FAIL] sudo mode"), "{}", out.dump());
    assert_eq!(out.code, 1, "{}", out.dump());
}

#[test]
fn a_program_dialing_our_proxy_itself_does_not_go_through_it_twice() {
    require!("curl");
    let Some(ip) = host_ip() else {
        eprintln!("SKIP: no non-loopback IPv4 address on this host");
        return;
    };
    let origin = start_origin();
    // On a real address: a loopback proxy would be reached through the host
    // ports instead of the relay.
    let mock = start_mock_on("0.0.0.0:0", origin, false);
    let proxy = SocketAddr::new(ip.into(), mock.addr.port());
    let dir = tmp_dir("direct-to-proxies");
    // The program uses our proxy through its own option, not its environment.
    let argv = [
        "curl",
        "-sS",
        "--max-time",
        "10",
        "-x",
        &format!("socks5h://{proxy}"),
        "http://twice.test/",
    ];

    let cfg = write_cfg(&dir, proxy, "sniff = false", "");
    let out = run(&cfg, &[], &argv, &[]);
    assert_eq!(out.stdout, BODY, "{}", out.dump());
    let once = Seen {
        atyp: 3,
        host: "twice.test".into(),
        port: 80,
    };
    assert_eq!(mock.seen(), [once], "one trip through the proxy\n{}", out.dump());

    // Switched off: the connection to the proxy is itself sent to the proxy.
    let cfg = write_cfg(&dir, proxy, "sniff = false\ndirect_to_proxies = false", "");
    let out = run(&cfg, &[], &argv, &[]);
    let nested = Seen {
        atyp: 1,
        host: ip.to_string(),
        port: proxy.port(),
    };
    assert_eq!(mock.seen()[1..], [nested], "proxied to itself\n{}", out.dump());
}

// ------------------------------------------------------- observability --

/// The `closed` lines of a log, as maps of their `key=value` fields.
fn closed_lines(log: &str) -> Vec<std::collections::HashMap<String, String>> {
    log.lines()
        .filter(|l| l.contains(" closed"))
        .map(|l| {
            l.split_whitespace()
                .filter_map(|w| w.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .collect()
}

#[test]
fn every_connection_ends_with_a_summary_line_at_the_default_level() {
    require!("curl");
    let origin = start_origin();
    let mock = start_mock_proxy(origin);
    let dir = tmp_dir("closed");
    let cfg = write_cfg(
        &dir,
        mock.addr,
        "sniff = false",
        "[[rules]]\nmatch=\"domain-suffix\"\nvalue=\"blocked.test\"\naction=\"block\"",
    );
    let script =
        "curl -sS --max-time 10 -o /dev/null http://ok.test/; curl -s --max-time 10 http://x.blocked.test/; true";
    let out = run(&cfg, &["--log-level", "info"], &["sh", "-c", script], &[]);
    let closed = closed_lines(&out.stderr);
    assert_eq!(closed.len(), 2, "one line per connection\n{}", out.dump());
    let ok = &closed[0];
    assert_eq!(ok.get("via").map(String::as_str), Some("mock"), "{}", out.dump());
    let down: u64 = ok["down"].parse().unwrap();
    assert!(down >= BODY.len() as u64, "bytes from the origin are counted: {down}");
    assert!(ok["up"].parse::<u64>().unwrap() > 0, "the request bytes are counted");
    for k in ["ms", "dial_ms"] {
        assert!(ok[k].parse::<u64>().is_ok(), "{k}\n{}", out.dump());
    }
    assert!(out.stderr.contains("closed: blocked by a rule"), "{}", out.dump());

    // A proxy that is down: the failure is visible without -v.
    let (_dead, dead) = refused_addr();
    let cfg = write_cfg(&dir, dead, "sniff = false", "");
    let out = run(
        &cfg,
        &["--log-level", "info"],
        &["curl", "-s", "--max-time", "10", "http://down.test/"],
        &[],
    );
    let closed = closed_lines(&out.stderr);
    assert_eq!(closed.len(), 1, "{}", out.dump());
    assert!(
        out.stderr
            .lines()
            .any(|l| l.contains("closed: ") && l.contains("down.test")),
        "the closing line names the failure\n{}",
        out.dump()
    );
}

#[test]
fn dns_queries_are_logged_and_a_dead_upstream_warns_once() {
    require!("dig");
    let dir = tmp_dir("dns-log");
    let (_dead, dead) = refused_addr(); // nothing answers UDP there either
    let cfg = write_cfg(
        &dir,
        "127.0.0.1:1".parse().unwrap(),
        &format!("upstream_dns = \"{dead}\""),
        "",
    );
    let script = "dig +short +tries=1 +time=5 A a.test; dig +short +tries=1 +time=5 MX b.test; \
                  dig +short +tries=1 +time=5 MX c.test; true";
    let out = run(&cfg, &[], &["sh", "-c", script], &[]);
    assert!(
        out.stderr
            .lines()
            .any(|l| l.contains("dns: A -> fake ip") && l.contains("a.test")),
        "{}",
        out.dump()
    );
    assert_eq!(
        out.stderr
            .lines()
            .filter(|l| l.contains("dns: forwarding upstream"))
            .count(),
        2,
        "{}",
        out.dump()
    );
    let warns = out
        .stderr
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("did not answer"))
        .count();
    assert_eq!(warns, 1, "warned once, the rest at debug\n{}", out.dump());
}

#[test]
fn the_tun_loop_runs_on_its_own_named_thread() {
    require!("sh");
    let dir = tmp_dir("tun-thread");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    let (child, _log) = spawn_bg(&cfg, &["sleep", "5"]);
    let pid = child.id();
    let names = || -> Vec<String> {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|d| {
                d.filter_map(|t| std::fs::read_to_string(t.ok()?.path().join("comm")).ok())
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    wait_for("the tun thread", || names().iter().any(|n| n == "tun"));
}
