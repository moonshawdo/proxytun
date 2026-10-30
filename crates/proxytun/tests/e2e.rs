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
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
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

fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("proxytun-e2e-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
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
    let mut child = cmd.spawn().expect("spawn proxytun");
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let code = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st.code().unwrap_or(-1);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break -999;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code,
        stdout: t_out.join().unwrap(),
        stderr: t_err.join().unwrap(),
    }
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
fn exit_codes_are_propagated() {
    require!();
    let dir = tmp_dir("exit");
    let cfg = write_cfg(&dir, "127.0.0.1:1".parse().unwrap(), "", "");
    assert_eq!(run(&cfg, &[], &["sh", "-c", "exit 7"], &[]).code, 7);
    assert_eq!(run(&cfg, &[], &["sh", "-c", "kill -9 $$"], &[]).code, 128 + 9);
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

    let (_dead, dead_addr) = refused_addr();
    let cfg = write_cfg(&dir, dead_addr, "", "");
    let out = run(
        &cfg,
        &[],
        &["curl", "-sS", "--max-time", "10", "http://site.test/"],
        &[],
    );
    assert_ne!(out.code, 0, "never silently direct\n{}", out.dump());
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
        ] {
            assert!(stats.contains(field), "{field} missing from: {stats}");
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
p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
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
    unsafe {
        cmd.pre_exec(|| {
            for s in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
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
    assert_eq!(status.code(), Some(130), "{status:?}");
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
