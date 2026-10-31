//! Performance benchmarks: proxytun against the same client reaching the
//! same proxy (or the same local service) without it. Ignored by default; run
//! with
//!
//!     cargo test --release --test bench -- --ignored --nocapture --test-threads=1
//!
//! Needs curl and python3. The origin server and the SOCKS5 proxy are threads
//! of this process (with large buffers), so the client side is what is
//! measured. Results: docs/PERFORMANCE.md.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Instant;

const BIN: &str = env!("CARGO_BIN_EXE_proxytun");
/// Bytes per download.
const DOWNLOAD: u64 = 1 << 30;
const ROUNDS: usize = 3;
const BUF: usize = 256 * 1024;

/// An HTTP origin: `GET /bytes/N` answers N bytes, anything else "ok".
fn start_origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || serve_origin(c));
        }
    });
    addr
}

fn serve_origin(mut c: TcpStream) {
    let mut req = Vec::new();
    let mut b = [0u8; 1024];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&b[..n]),
        }
    }
    let path = String::from_utf8_lossy(&req)
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let len: u64 = path.strip_prefix("/bytes/").and_then(|n| n.parse().ok()).unwrap_or(2);
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n");
    if c.write_all(head.as_bytes()).is_err() {
        return;
    }
    if len == 2 {
        let _ = c.write_all(b"ok");
        return;
    }
    let chunk = vec![b'x'; BUF];
    let mut left = len;
    while left > 0 {
        let n = left.min(BUF as u64) as usize;
        if c.write_all(&chunk[..n]).is_err() {
            return;
        }
        left -= n as u64;
    }
}

/// A SOCKS5 proxy (no authentication) that sends every request to `origin`.
fn start_proxy(origin: SocketAddr) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = serve_socks(c, origin);
            });
        }
    });
    addr
}

fn serve_socks(mut c: TcpStream, origin: SocketAddr) -> std::io::Result<()> {
    let mut g = [0u8; 2];
    c.read_exact(&mut g)?;
    let mut methods = vec![0u8; g[1] as usize];
    c.read_exact(&mut methods)?;
    c.write_all(&[5, 0])?;
    let mut h = [0u8; 4];
    c.read_exact(&mut h)?;
    let rest = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        _ => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l)?;
            l[0] as usize + 2
        }
    };
    let mut skip = vec![0u8; rest];
    c.read_exact(&mut skip)?;
    let up = TcpStream::connect(origin)?;
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    c.set_nodelay(true)?;
    up.set_nodelay(true)?;
    let (mut c2, mut up2) = (c.try_clone()?, up.try_clone()?);
    let t = std::thread::spawn(move || pipe(&mut c2, &mut up2));
    pipe(&mut { up }, &mut c);
    let _ = t.join();
    Ok(())
}

fn pipe(from: &mut TcpStream, to: &mut TcpStream) {
    let mut b = vec![0u8; BUF];
    loop {
        match from.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&b[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// Run `argv`, through proxytun (`proxy`: its --proxy) or not, and return its
/// stdout. proxytun logs at its default level, to nowhere.
fn run(proxy: Option<SocketAddr>, argv: &[&str]) -> String {
    let mut cmd = match proxy {
        Some(p) => {
            let mut c = Command::new(BIN);
            c.arg("--proxy").arg(format!("socks5://{p}")).arg("--").args(argv);
            c
        }
        None => {
            let mut c = Command::new(argv[0]);
            c.args(&argv[1..]);
            c
        }
    };
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
    let out = cmd.stderr(Stdio::null()).output().expect("run");
    assert!(out.status.success(), "{argv:?}: {:?}", out.status);
    String::from_utf8(out.stdout).unwrap()
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd}"))
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Median and range of `xs`.
fn summary(mut xs: Vec<f64>) -> (f64, f64, f64) {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (xs[xs.len() / 2], xs[0], xs[xs.len() - 1])
}

fn mb(bytes_per_s: f64) -> f64 {
    bytes_per_s / 1e6
}

/// curl's download speed in bytes/s.
fn curl_speed(proxy: Option<SocketAddr>, extra: &[&str], url: &str) -> f64 {
    let mut argv = vec!["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}"];
    argv.extend_from_slice(extra);
    argv.push(url);
    run(proxy, &argv).trim().parse().unwrap()
}

#[test]
#[ignore]
fn throughput() {
    assert!(have("curl"), "needs curl");
    let origin = start_origin();
    let proxy = start_proxy(origin);
    let url = format!("http://bench.test/bytes/{DOWNLOAD}");
    let host_url = format!("http://{origin}/bytes/{DOWNLOAD}");
    let socks = format!("{proxy}");
    let mut rows = Vec::new();
    for (name, with, without) in [
        (
            "captured (TUN) vs curl --socks5-hostname",
            Box::new(|| curl_speed(Some(proxy), &[], &url)) as Box<dyn Fn() -> f64>,
            Box::new(|| curl_speed(None, &["--socks5-hostname", &socks], &url)) as Box<dyn Fn() -> f64>,
        ),
        (
            "host port vs the port itself",
            Box::new(|| curl_speed(Some(proxy), &[], &host_url)),
            Box::new(|| curl_speed(None, &[], &host_url)),
        ),
    ] {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..ROUNDS {
            a.push(mb(with()));
            b.push(mb(without()));
        }
        rows.push((name, summary(a), summary(b)));
    }
    println!("\n1 GiB download, MB/s (median, min..max of {ROUNDS})");
    for (name, (a, a0, a1), (b, b0, b1)) in rows {
        println!(
            "  {name}: proxytun {a:.0} ({a0:.0}..{a1:.0}), without {b:.0} ({b0:.0}..{b1:.0}), ratio {:.0}%",
            100.0 * a / b
        );
    }
}

/// N sequential HTTP requests, each on a new connection, to the origin via
/// `argv[1]`: "socks" (SOCKS5 handshake to the proxy at argv[2]) or "plain"
/// (connect to bench.test:80, resolved once). Prints the mean ms each.
const PY_CONNECTIONS: &str = r#"
import socket, struct, sys, time
mode, n = sys.argv[1], int(sys.argv[3])
if mode == "plain":
    target = (socket.gethostbyname("bench.test"), 80)
else:
    host, port = sys.argv[2].rsplit(":", 1)
    target = (host, int(port))
req = b"GET / HTTP/1.0\r\nHost: bench.test\r\n\r\n"
start = time.perf_counter()
for _ in range(n):
    s = socket.create_connection(target)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if mode == "socks":
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        name = b"bench.test"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", 80))
        s.recv(10)
    s.sendall(req)
    while s.recv(65536):
        pass
    s.close()
print((time.perf_counter() - start) / n * 1000)
"#;

#[test]
#[ignore]
fn connection_setup() {
    assert!(have("python3"), "needs python3");
    let origin = start_origin();
    let proxy = start_proxy(origin);
    let n = "1000";
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        a.push(
            run(Some(proxy), &["python3", "-c", PY_CONNECTIONS, "plain", "-", n])
                .trim()
                .parse()
                .unwrap(),
        );
        b.push(
            run(None, &["python3", "-c", PY_CONNECTIONS, "socks", &proxy.to_string(), n])
                .trim()
                .parse()
                .unwrap(),
        );
    }
    let ((a, a0, a1), (b, b0, b1)) = (summary(a), summary(b));
    println!("\n{n} sequential short connections, ms each (median, min..max of {ROUNDS})");
    println!("  proxytun {a:.3} ({a0:.3}..{a1:.3}), SOCKS5 handshake by the client {b:.3} ({b0:.3}..{b1:.3}), extra {:.3} ms", a - b);
}

/// N sequential A queries for distinct names to the resolver in
/// /etc/resolv.conf (proxytun's fake DNS inside). Prints queries per second.
const PY_DNS: &str = r#"
import socket, struct, sys, time
n = int(sys.argv[1])
ns = [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")][0]
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect((ns, 53))
start = time.perf_counter()
for i in range(n):
    name = b"".join(bytes([len(p)]) + p for p in [b"h%d" % i, b"bench", b"test"]) + b"\0"
    u.send(struct.pack(">HHHHHH", i & 0xffff, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1))
    u.recv(512)
print(n / (time.perf_counter() - start))
"#;

#[test]
#[ignore]
fn fake_dns() {
    assert!(have("python3"), "needs python3");
    let origin = start_origin();
    let proxy = start_proxy(origin);
    let mut q = Vec::new();
    for _ in 0..ROUNDS {
        q.push(
            run(Some(proxy), &["python3", "-c", PY_DNS, "20000"])
                .trim()
                .parse()
                .unwrap(),
        );
    }
    let (m, lo, hi) = summary(q);
    println!("\n20000 sequential A queries to the fake DNS: {m:.0} per second ({lo:.0}..{hi:.0})");
}

#[test]
#[ignore]
fn start_and_exit() {
    let origin = start_origin();
    let proxy = start_proxy(origin);
    let mut t = Vec::new();
    for _ in 0..10 {
        let start = Instant::now();
        run(Some(proxy), &["true"]);
        t.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let (m, lo, hi) = summary(t);
    println!("\nproxytun -- true, ms (median, min..max of 10): {m:.1} ({lo:.1}..{hi:.1})");
}
