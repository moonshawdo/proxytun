# proxytun

[简体中文](../README.md) · **English**

Sends **a given program and all of its child processes** through a SOCKS5 / HTTP proxy and **carries domain names all the way to the proxy**, so Clash, sing-box and the like can route by domain.
It does not use ptrace, so **strace, gdb and ltrace work as usual**; it runs as an ordinary user and also supports CentOS 7.

```bash
proxytun -c proxytun.toml curl https://example.com
proxytun --proxy socks5://172.25.32.1:7897 git clone https://github.com/user/repo
proxytun --proxy socks5://172.25.32.1:7897 strace -f -e trace=network ./my-static-binary
proxytun --proxy socks5://172.25.32.1:7897 gdb --args ./my-program
```

## Why it exists

| Existing approach | Problem |
|---|---|
| proxychains-ng (LD_PRELOAD) | No effect on statically linked programs; a program that clears `LD_PRELOAD` when it starts a child process escapes |
| proxyhook / graftcp (ptrace) | A process can have only one tracer at a time, so it cannot be used together with strace / gdb / ltrace |
| tun2proxy `--unshare` | Depends on the `unshare` command from a recent util-linux and on unprivileged user namespaces; CentOS 7 has neither. All TCP goes through the proxy; loopback services on the local machine are not handled |
| Global TUN / transparent proxy | Needs root, and takes over the whole machine's traffic |

proxytun puts the program in a **private network namespace** whose only exit is a TUN device held by proxytun. A namespace is a process attribute, inherited through the kernel on fork/exec,
regardless of how the program is linked, its environment variables or debuggers:

```
proxytun (host network, ordinary user)
  ├─ TCP on the TUN  → rewrite addresses, hand to a listening socket inside the namespace (kernel TCP stack) → rules → proxy / direct / drop
  ├─ UDP on the TUN  → port 53: fake-ip DNS; others: ICMP port unreachable (QUIC falls back to TCP)
  └─ the program (private network + mount namespace, original user identity) and all its child processes
```

1. The program asks DNS (the namespace's `/etc/resolv.conf` points to the fake DNS, and queries sent to port 53 of any IP are intercepted too) → gets a fake IP (`198.18.0.0/15`); proxytun remembers `fake IP ↔ domain`.
2. The program connects to the fake IP → the packet comes out of the TUN → proxytun looks the domain back up → hands it to the proxy as SOCKS5 `ATYP=3` or HTTP `CONNECT host:port`.
3. When the program connects straight to a literal IP, `ip-cidr` rules apply; on ports 80/443/8443 the domain is also recovered from the TLS SNI / HTTP Host of the first packet.

How it works (with a primer, flow diagrams and a description of each module): [docs/ARCHITECTURE.md](ARCHITECTURE_en.md). Design trade-offs: [docs/DESIGN.md](DESIGN_en.md).

## Features

- **Domain names preserved**: the proxy receives the domain, not the fake IP; when the program connects straight to a literal IP, IP rules apply, and the domain is recovered from the first packet where possible.
- **The whole process tree**: children, grandchildren, programs exec'd after `env -i` clears the environment, statically linked programs — all are in the namespace.
- **Debugging tools work**: `proxytun -- strace -f ...`, `proxytun -- gdb ...`, `proxytun -- ltrace ...`; also `strace -f proxytun -- ...`, or `gdb -p` from outside.
- **No root needed**: unprivileged user namespaces are used directly when available; when not (CentOS 7), a short-lived privileged helper is started through `sudo` automatically. The program still runs as you (uid, gid, supplementary groups), and no root process remains afterwards.
- **All DNS taken over**: UDP and TCP, `/etc/resolv.conf` and a hard-coded `8.8.8.8` are all answered by the fake DNS; AAAA, HTTPS and SVCB get an empty local answer so they cannot bypass the fake IP; MX/TXT and the like are forwarded from the host to the upstream.
- **Rules and load balancing** (from proxyhook): `domain-suffix` / `domain-keyword` / `domain` / `ip-cidr` / `final`, actions `proxy` / `direct` / `block`;
  6 balancing strategies, active health checks, failover, disconnect when none is available (**never a silent direct connection**). A target refused by the proxy does not count as a proxy failure.
- **Local services reachable**: at startup, TCP ports listening on the host's loopback addresses are forwarded into the namespace, and the program connects to `127.0.0.1:5432` as usual.
- **Behaves as if run directly**: exit status (including death by signal), Ctrl+C, `kill` and ignored signals all behave the program's own way; a proxy the program configures itself is not proxied a second time.
- **Leaves no trace**: the TUN is not persistent and the namespaces are anonymous; the kernel reclaims them on exit (including a crash or `kill -9`). The host's interfaces, routes and `resolv.conf` are untouched. If proxytun exits unexpectedly, the program loses the network; it does not bypass the proxy and connect directly.
- **Operations**: `--doctor` self-check; `SIGHUP` hot reload; `SIGUSR1` prints stats; log levels and a log file (as in proxyhook); `--proxy` / `PROXYTUN_PROXY` override the proxy address.

## Tech stack

| Layer | Choice |
|---|---|
| Language | Rust 2021 (developed and tested on Rust 1.99; older versions unverified), Linux x86-64 |
| Traffic capture | Network + mount namespaces (plus a user namespace when available), a TUN device, user-space address rewriting, connections terminated by the kernel TCP stack; networking configured with ioctl, no dependency on the `ip` command or netlink |
| Async | `tokio` (relay, DNS, health probes, signals); TUN I/O on a dedicated `tun` thread |
| DNS messages | `hickory-proto` 0.24 |
| System calls | `nix`, `libc` |
| Other | `ipnet`, `clap`, `serde` + `toml` (+ `serde_ignored` to report misspelled keys), `tracing` + `tracing-subscriber`, `anyhow` |
| Without user namespaces | A privileged helper started by sudo hands fds back over a unix socket with `SCM_RIGHTS` |
| Release | musl static binary; runs as is on CentOS 7 and other old systems |

## Build requirements

- Rust stable (developed and tested on 1.99; installing with `rustup` is recommended).
- A native build needs only `cargo` and a C linker (`cc`).
- A **static build** (for CentOS 7 and other old systems) also needs the musl target: `rustup target add x86_64-unknown-linux-musl`.
- For the extra tools the tests need, see [Testing](#testing).

## Building

```bash
# Development / local use
cargo build --release            # output: target/release/proxytun

# Static build; runs on x86-64 Linux with any glibc version (including CentOS 7)
./scripts/build-static.sh        # output: dist/proxytun-x86_64-linux-musl
```

> **Do not copy a binary built with `cargo build --release` on a recent distribution to CentOS 7**: it links newer glibc symbols and does not start on glibc 2.17.
> Use the static build above.

## Usage

### Quick start

```bash
# 1. Check whether this machine meets the requirements and which mode will be used (always run this first on a new machine)
proxytun --doctor --proxy socks5://172.25.32.1:7897

# 2. With a config file
proxytun -c proxytun.toml curl -I https://example.com

# 3. Or give only the proxy address (no config file needed)
proxytun --proxy socks5://172.25.32.1:7897 curl -I https://example.com
PROXYTUN_PROXY=http://user:pass@10.0.0.5:8080 proxytun git ls-remote https://github.com/user/repo

# 4. See where each connection went and which exit it used
proxytun -v -c proxytun.toml curl https://example.com

# 5. Write logs to a file and leave only the program's own output on the terminal
proxytun --log-file ~/proxytun.log -c proxytun.toml curl https://example.com
```

proxytun's own options go **before** the program name; every argument from the program name on is passed to the program unchanged, so in `proxytun -c proxytun.toml curl -c cookies.txt https://x`
the second `-c` belongs to curl. A `--` before the program name is also accepted, with the same effect.

proxytun's exit status is the program's exit status; when the program is killed by a signal, proxytun ends with the same signal (as `timeout` and sudo do: Ctrl+C in a shell loop stops the loop,
and systemd does not count stopping the service as a failure), without leaving a core. As long as any process in the program's process tree is still running, proxytun keeps running.

### Command-line options

| Option | Description |
|---|---|
| `-c, --config <FILE>` | Config file, default `proxytun.toml`. With `--proxy` it may be absent, or may contain only rules and no proxies |
| `--proxy <URL>` | Overrides all proxies in the config: `socks5://[user:pass@]IP:port` (`socks5h://` is the same) or `http://[user:pass@]IP:port`; the host must be an IP (write `@ : /` in the password as `%40 %3A %2F`). The environment variable `PROXYTUN_PROXY` works too. Rules that name another group use it as well (warned at startup and on every hot reload). **With a password, use the environment variable or the config file**: any local user can see command-line arguments with `ps`, and proxytun warns about it |
| `--no-sudo` | Fail when user namespaces are unavailable, instead of calling sudo |
| `--no-host-ports` | Do not forward the host's loopback listening ports into the namespace |
| `--doctor` | Run the self-check and exit; exit status 1 if there is a FAIL |
| `-q, --quiet` | Log only at error level (same as `--log-level error`) |
| `-v` / `-vv` | Log at debug / trace level |
| `--log-level <LEVEL>` | `off`, `error`, `warn`, `info` (default), `debug`, `trace`; only one of this, `-q` and `-v` may be used |
| `--log-file <PATH>` | Append logs to this file (mode 600 when created) instead of stderr; the program's own output is unaffected. Symbolic links are not followed; an existing file must be a regular file you own |

### Config file

An annotated example: [proxytun.toml](../proxytun.toml) (only the required `[[proxies]]`; most other keys are given as comments with their defaults). **Every key (default, allowed values, hot-reloadable or not, common errors)
is described in [docs/CONFIG.md](CONFIG_en.md)**. The format is the same as proxyhook's, and a `proxyhook.toml` works as is (widen `fake_ip_range` if it is narrower than /22). Highlights:

```toml
# Top-level keys must come before any [table] (TOML rule)
fake_ip_range = "198.18.0.0/15"  # the last /24 is reserved for the namespace itself, so at least /22
# upstream_dns = "1.1.1.1:53"    # upstream for non-A queries; default: the first nameserver in the host's /etc/resolv.conf
localnet = ["192.168.0.0/16"]    # these literal IPs go direct from the host, rules not consulted; default empty
direct_to_proxies = true         # when the program itself connects to a proxy below, go direct instead of looping through a proxy
sniff = true                     # recover the domain of literal-IP connections from TLS SNI / HTTP Host
sniff_ports = [80, 443, 8443]
host_ports_forward = true        # forward the host's loopback listeners into the namespace
host_ports_exclude = []          # ports the program will listen on itself
retries = 2                      # how many more exits to try when a proxy handshake fails
connect_timeout_ms = 10000       # connect timeout to a proxy / direct / host port; on a proxy timeout try the next member, with none left send RST to the program
handshake_timeout_ms = 10000     # timeout of each step of the proxy handshake: SOCKS5 greeting and auth, waiting for the proxy's reply to the request / CONNECT

[[proxies]]
name = "clash"
type = "socks5"                  # or "http"
addr = "172.25.32.1:7897"        # must be an IP; proxytun connects to it from the host, 127.0.0.1 means the host

[[rules]]                        # top to bottom, the first match wins
match = "domain-suffix"
value = "cn"
action = "direct"

[[rules]]
match = "final"
action = "proxy"                 # may add group = "<group name>"
```

About rules:

- Domain rules (`domain*`) apply when the program **resolved a domain through the fake DNS** (or sniffing recovered the domain); `ip-cidr` applies when the program **connects straight to a literal IP**.
- A literal IP covered by an `ip-cidr` rule is not replaced by a sniffed domain; the IP rule decides.
- When no rule matches and there is no `final`, the `default` group is used (**not** a direct connection by default).
- For a domain target, `direct` means proxytun resolves the real IP with the host's system resolver and connects to it (the program only ever gets the fake IP).
- If the config file contains a proxy password and is readable by group or others, startup suggests `chmod 600`; misspelled keys are warned about and ignored.

Common setups (full versions in [CONFIG.md section 9](CONFIG_en.md#9-examples)):

| Scenario | How |
|---|---|
| Only one proxy | Write a single `[[proxies]]`; or no config file, just `--proxy` |
| Config file without passwords, fit for version control | Only rules in the config file; the proxy goes in `PROXYTUN_PROXY=http://user:pass@...` |
| LAN and Chinese domains direct, everything else through the proxy | `localnet` lists the LAN ranges; rules such as `match = "domain-suffix"`, `value = "cn"`, `action = "direct"`, and last `final` → `proxy` |
| Several proxies, use the fastest; some sites on a fixed exit | `[[groups]]` with `strategy = "least-latency"`; a second group with `strategy = "hash"`, pointed to by a rule's `group` |
| Block some domains | `action = "block"` |
| The program must listen on a port already taken on the host | `host_ports_exclude = [port]` |

### Multiple proxies and load balancing

```toml
[[proxies]]
name = "hk"
type = "socks5"
addr = "10.0.0.1:1080"
weight = 3                       # used only by weighted-round-robin, 1~1000

[[proxies]]
name = "jp"
type = "http"
addr = "10.0.0.2:8080"
username = "u"
password = "p"

[[groups]]
name = "default"                 # default is required; rules without a group use it
strategy = "least-latency"
members = ["hk", "jp"]

[[groups]]
name = "sticky"
strategy = "hash"                # the same domain always uses the same exit
members = ["hk", "jp"]
```

| Strategy | Behavior |
|---|---|
| `round-robin` | Take turns in order (default) |
| `random` | Random (seeded from `/dev/urandom`, different on every start and hot reload) |
| `least-conn` | The one with the fewest active connections; ties rotate |
| `least-latency` | The one with the lowest probe latency to the proxy (EWMA); rotate while there are no samples yet |
| `weighted-round-robin` | Take turns in proportion to `weight` |
| `hash` | Consistent hashing on the target host; when an exit goes down, only the hosts it served move |

Health checks: every `health.interval_secs` seconds all proxies are probed concurrently (a TCP connect; for SOCKS5 also a greeting including authentication); `fail_threshold` consecutive failures mark a proxy DOWN,
and one successful probe after that brings it back. A failed proxy reply falls into one of three classes: clearly a problem with the target (SOCKS5 0x03–0x06, HTTP 502/504, timeout waiting for the proxy's reply to the request) — disconnect at once, not a proxy failure, no retry;
unclear, or the proxy's own rules (SOCKS5 0x01/0x02, HTTP 403/500/503 etc., and a SOCKS5 proxy closing right after accepting the request) — retry on another member, but not a proxy failure;
a problem with the proxy itself (cannot connect or connect timeout, SOCKS5 greeting / auth timeout or rejection, SOCKS5 0x07/0x08, HTTP 405/407, HTTP proxy closing before replying) — a proxy failure, and switch member. Details: [ARCHITECTURE section 7](architecture/operations_en.md).

### Run modes

| Situation | How the namespaces are created | The program's identity |
|---|---|---|
| Unprivileged user namespaces available (most recent distributions, WSL2) | By proxytun itself, no privileges needed | You (uid/gid mapped to yourself) |
| Not available (CentOS 7 default, `max_user_namespaces=0`, AppArmor restrictions) | `sudo` is called to start the privileged helper | You (including supplementary groups), all capabilities cleared |
| proxytun run after logging in as root | Directly (no user namespace) | root (full capabilities) |

In sudo mode the privileged helper does one thing only, creating the namespaces, and exits as soon as they exist; no root process remains afterwards. Its security boundary (it serves only the process that ran sudo,
takes identities only from the kernel, re-checks every field of a request, never receives your fds as root, fully drops privileges for the program and sets `no_new_privs` first, etc.) is described in
[ARCHITECTURE section 5](architecture/privilege_en.md). The helper refuses to run when sudoers sets a SELinux `ROLE`/`TYPE` for the command or enables `intercept` / `log_subcmds`,
or when the container's seccomp profile forbids keyctl.

proxytun refuses to run as root through sudo, doas, pkexec or setuid (the privileged helper is the only exception): even if sudoers allows only proxytun, that does not yield a root program.
For root mode, log in as root (or `su -`) and run it. **Grant proxytun only through sudo**; do not let ordinary users run it as root through ksu, userhelper/consolehelper, `systemd-run --uid=0`
and the like: these leave no recognizable trace, and proxytun takes them for a real root. `--no-sudo` disables the fallback to sudo.

sudo runs proxytun's own executable as root, so it must live where only root can write (an ordinary user who can modify it can run arbitrary code as root). For passwordless use, allow only the privileged helper:

```bash
sudo install -o root -g root -m 0755 dist/proxytun-x86_64-linux-musl /usr/local/bin/proxytun
# visudo -f /etc/sudoers.d/proxytun
alice ALL=(root) NOPASSWD: /usr/local/bin/proxytun __proxytun_root_setup *
```

### Reaching local services

`127.0.0.1` inside the namespace is isolated. **At startup** proxytun scans the TCP ports listening on the host once, and opens them in the namespace at the same addresses:

| On the host | In the namespace |
|---|---|
| `127.x.x.x:P` | The same address |
| `0.0.0.0:P` | `127.0.0.1:P` |
| `[::1]:P` | `[::1]:P` |
| `[::]:P` | `127.0.0.1:P` and `[::1]:P` |

- Port 53 is not forwarded (DNS must be answered by the fake DNS).
- Ports opened on the host after startup are not visible; restart the program when needed.
- If the program wants to listen on the same port itself, that fails (`EADDRINUSE`); exclude the port with `host_ports_exclude`, or use `--no-host-ports`.

### Debugging tools

```bash
proxytun -c proxytun.toml strace -f -e trace=network ./prog          # strace inside the namespace
strace -f -o trace.txt proxytun -c proxytun.toml ./prog              # strace outside, following proxytun too
proxytun -c proxytun.toml gdb --args ./prog                          # gdb inside the namespace
gdb -p <program's pid>                                               # attach from outside
proxytun -c proxytun.toml ltrace -f ./prog
```

`gdb -p` / `strace -p` from outside have the same limits as without proxytun: with Yama `ptrace_scope=1` (the Ubuntu and WSL2 default) you can attach only to your own descendants;
`--doctor` reports the current setting.

### Runtime control

| Action | Effect |
|---|---|
| Ctrl+C (the terminal sends it to the whole foreground process group) | The program handles it; proxytun does not forward it again and exits after the program does. When the program is in a group of its own (sudo `use_pty`), proxytun forwards it to the program's whole process group, and other processes in the pipeline get it too |
| `kill <proxytun pid>`, `pkill proxytun`, `killall proxytun` (sent only to proxytun) | Forwarded to the program, exactly once (the witness process is named `signal-witness` and is not matched by these commands) |
| `kill %1`, `kill -- -<pgid>`, systemd sending to each process | The program already got it; not forwarded again (decided with a "witness process"). When the program is not in proxytun's process group (sudo `use_pty`), sending to each process gives it two copies |
| A second `SIGTERM` (however long after the first); or Ctrl+C when the main program has exited and only background children remain | proxytun ends at once with that signal |
| `kill -HUP <pid>` | Reloads rules, localnet, `direct_to_proxies`, proxies and groups, `retries`, `connect_timeout_ms`, `handshake_timeout_ms`, sniffing and health-check settings; on a config error the old config is kept |
| `kill -USR1 <pid>` | Prints stats: number of fake IPs, NAT table size, connections, traffic, DNS queries, drops by reason, each proxy's health and latency |
| proxytun is `kill -9`'d or crashes | The program **is not killed**; it keeps running but without network (the TUN is gone with proxytun), and does not bypass the proxy to connect directly |

Signals ignored at startup (`nohup`, `cmd &` in a script, `trap '' PIPE`) stay ignored in the program (in sudo mode this always holds for SIGPIPE; for other signals it depends on whether sudo leaves the original disposition to the command). Changing `fake_ip_range`, `upstream_dns` or host port forwarding needs a restart.
Details and edge cases of signal handling: [ARCHITECTURE section 6](architecture/lifecycle_en.md).

### Logging

| Level | Option | Content |
|---|---|---|
| `off` | `--log-level off` | No output (startup errors are still printed to the terminal) |
| `error` | `-q` | Problems that need attention: config reload failed, NAT table full, fake IP pool full |
| `warn` | `--log-level warn` | Degraded but still working: switching to sudo mode, proxy DOWN, dial failed and node switched, not enough fds, config file permissions, `--proxy` with a password, misspelled config keys |
| `info` | default | Startup and exit (version, program name, forwarded host ports, how it exited), two lines per connection (routing result, closing summary), proxy recovery, successful reload, `SIGUSR1` stats |
| `debug` | `-v` | Every DNS query (`dns: A -> fake ip`, `dns: forwarding upstream`, upstream time), sniffing results, proxy retry reasons that do not count against health (target refused, proxy disconnected) |
| `trace` | `-vv` | Every SYN on the TUN and the address it is rewritten with, so a connection can be followed from its SYN to its end |

- Without a level option, the environment variable `PROXYTUN_LOG` is read: either a level, or per module, e.g. `proxytun=info,proxytun::capture=trace,proxytun::accept=trace` (SYNs on the TUN, and which connection picked each one up). Command-line options take precedence.
- **Following a connection**: each connection has an increasing number, written as `conn{id=… target=…}` in the log. At the default level each connection gets two lines (time, level and module name omitted below):

  ```
  conn{id=1 target=Domain("example.com", 443)}: routing decision=Proxy { group: "default" }
  conn{id=1 target=Domain("example.com", 443)}: closed ms=812 dial_ms=35 via=clash up=812 down=153204
  ```

  `ms` is the connection's lifetime; `dial_ms` the time spent establishing the outbound connection (through a proxy: connecting to the proxy, the handshake up to the proxy's reply that the target is connected, and retries on other members; direct: including resolving the domain); `via` the proxy node used (`direct` / `host` mean direct / host port);
  `up` and `down` the bytes in each direction. A failure is written as `closed: <reason>`, a connection stopped by a rule as `closed: blocked by a rule`. The log does not record which process started the connection.
- **Writing to stderr never blocks and never fails**: when the reader stalls (Ctrl+S, a pipe nobody reads), log lines that do not fit are dropped; when the reader closes (`2>&1 | head`, terminal disconnected), logs are lost;
  proxytun and the program keep running. For complete logs use `--log-file`.
- **`--log-file` and the program's output**: only proxytun's own logs go to the file; the program inherits stdin/stdout/stderr unchanged and does not inherit the log file.
  The file is appended to and created with mode 600 (at `info` level it records every domain visited).

### When the program configures its own proxy

The proxy that `http_proxy` / `https_proxy` / `all_proxy` in the program's environment point to is connected to directly, not proxied a second time: for `IP:port`, connections to it go direct;
for a host name, connections to "hostname:port" are handled as `direct`. Without a port, `http://` or no scheme covers both 80 and 1080 (curl and git use 1080; pip, Go, wget, npm and apt use 80), `https://` means 443, `socks5://` and the like 1080.
When the program connects straight to one of the proxies in `[[proxies]]` (`curl -x`), that goes direct too (`direct_to_proxies`, on by default). A proxy on the host's loopback
(e.g. `http_proxy=http://127.0.0.1:7890`) works through host port forwarding as long as it was listening at startup. proxytun does not rewrite or remove these environment variables.

### Using it on CentOS 7

1. Build the static binary with `scripts/build-static.sh` on a newer machine, copy it to CentOS 7, and install it to `/usr/local/bin` as described in [Run modes](#run-modes).
2. First run `proxytun --doctor --proxy socks5://proxy-ip:port`. CentOS 7 has no unprivileged user namespaces by default, so it should report that sudo mode will be used.
3. Proxy something for real to confirm the whole chain works:
   ```bash
   proxytun --proxy socks5://proxy-ip:port getent hosts example.com      # should give 198.18.x.x
   proxytun -v --proxy socks5://proxy-ip:port curl -sI https://example.com
   ```
   If curl returns normally and the log has `asking sudo` and `target=Domain("example.com", 443)`, sudo mode works and the proxy receives the domain.

**Verification status**: sudo mode was run on a development machine simulating CentOS 7 with "an outer user namespace + `max_user_namespaces=0` + a setuid fake sudo", and everything passed;
**a real CentOS 7 machine** (3.10 kernel, real sudo 1.8.23, SELinux) has not been verified yet. For step-by-step verification see [docs/CENTOS7.md](CENTOS7_en.md); results are welcome.

## Testing

```bash
cargo test                                         # unit tests + end-to-end tests
cargo test --target x86_64-unknown-linux-musl      # the same tests against the static build
cargo test --release --test bench -- --ignored --nocapture --test-threads=1   # benchmarks
```

- **Unit tests** cover all pure logic: config validation and overrides, the rule engine, the fake IP pool (LRU, pinning, reclaim interval), load balancing strategies, health checks, SOCKS5 / HTTP handshake bytes and failure classification,
  DNS answers and forwarding checks, sniffing, packet parsing and address rewriting (including checksums), the NAT table's state machine and batched sweep, the sudo helper's request encoding and validation, signal-forwarding decisions, computing the relay limit.
- **End-to-end tests** run `curl`, `python3`, `dig`, `strace`, `gdb`, `ltrace` and others with real namespaces and a TUN; built-in mock SOCKS5 / HTTP proxies record whether the proxy actually received a domain or an IP.
  Covered: domain preservation, literal IPs and sniffing, every DNS path (including a hard-coded `8.8.8.8` and DNS over TCP), rules, localnet, host port forwarding, debuggers, exit status and signals
  (real Ctrl+C on a pty, `kill`, `pkill`, signals to a whole group, `sigwait` programs, ignored signals), running as pid 1 or as a subreaper, stderr stalled or closed,
  fd exhaustion, mount propagation, hot reload, `--doctor`, and **sudo mode simulating CentOS 7** (user identity, resource limits, umask, inherited fds, session keyring,
  refusing a traced or filtered sudo, a malicious helper client).
- End-to-end tests need `curl`, `python3`, `cc`, `strace`, `gdb`, `ltrace`, `dig`, `pkill`, `mount`, `unshare` (util-linux); the sudo-mode tests and one stderr test
  also need `newuidmap` (the uidmap package), `setpriv`, an `unshare` that supports `--map-auto` (util-linux ≥ 2.38) and a range in `/etc/subuid`. If the host cannot create proxytun's namespaces, all end-to-end tests SKIP.
  When something is missing, the affected tests print `SKIP` (visible only with `-- --nocapture`) and count as passed.
- Test directories are in `$TMPDIR/proxytun-test-<pid>-*` and are kept until the next run, which deletes them where it can (only this user's, whose original process has exited), so a failure can be inspected.

### Performance

Benchmarks on the local loopback, comparing "through proxytun" with "without proxytun" using the same client (Intel i5-8265U, WSL2, kernel 6.18):

| Test | proxytun | Without proxytun |
|---|---|---|
| 1 GiB download, captured on the TUN, through a SOCKS5 proxy | **about 1130 MB/s** | about 2050 MB/s (curl connects to the proxy itself) |
| 1 GiB download, host port forwarding | **about 1190 MB/s** | about 4060 MB/s (direct to the local port) |
| Short connections, per connection | **+0.53 ms** | |
| Fake DNS, sequential A queries | **about 4500/s** | |
| `proxytun -- true` from start to exit | **about 90 ms** | |

Single-connection throughput is capped by the `tun` thread (about 95% CPU while downloading) at about 1 GB/s, far above the speed of real proxies and networks. Methodology, more data and analysis: [docs/PERFORMANCE.md](PERFORMANCE_en.md).

## Not supported

**Platform and processes**
- Built and tested only on **Linux x86-64** (gnu and musl static).
- Needs a TUN device (`/dev/net/tun`). If the administrator restricted it (mode 0600, the container's device cgroup), proxytun fails rather than using sudo to get around it; in a container, add `--device /dev/net/tun`.
- **setuid programs**: `sudo`, `su`, `ping` and the like cannot gain privileges inside. In user namespace mode, root-owned files show up as `nobody`; in sudo mode the program carries `no_new_privs`.
- **sudo's `use_pty`** (on by default in Ubuntu 22.04+, Debian 12 and sudo ≥ 1.9.14; off by default in CentOS 7): in sudo mode the program runs in its own session, without a controlling terminal:
  proxytun forwards Ctrl+C and Ctrl+\ to it, but Ctrl+Z job control and window size changes do not reach it, and programs that open `/dev/tty` (e.g. password prompts) fail. proxytun warns about it.
- **Abstract unix sockets** are isolated per network namespace (X11 falls back to the `/tmp/.X11-unix` path and is usually unaffected); unix sockets bound to file paths are unaffected.
- sudo is the only privilege-escalation method recognized for starting the privileged helper; if the container's seccomp profile forbids keyctl, sudo mode refuses to run.

**Network**
- Only **TCP** is proxied. UDP other than DNS (including QUIC) gets port unreachable at once; SOCKS5 `UDP ASSOCIATE` is not supported.
- **ICMP** is dropped; ping does not work.
- **IPv6** is not supported: the namespace has no IPv6 route, AAAA queries return empty, and connections to literal IPv6 addresses get "network unreachable" at once.
- **DoH / DoT** cannot be intercepted; resolving through the unix socket of systemd-resolved / nscd (`resolve` in `nsswitch.conf`) also gets the real IP. For these, the domain can only be recovered by first-packet sniffing,
  and sniffing does not work for: connections that really use ECH, ports not in `sniff_ports`, protocols where the server sends first. `/etc/hosts` works as usual.
- **HTTPS / SVCB (type 65 / 64) DNS records** always get an empty local answer; the program gets no ECH keys or IP hints.
- The `resolv.conf` the program sees has `options ndots:N` removed (everything else is kept).
- Proxy protocols: only SOCKS5 (no auth / username and password, `CONNECT` only) and HTTP `CONNECT` (Basic auth). No SOCKS4, no TLS to the proxy, no proxy chains.
  The proxy address must be an IP. SOCKS5 domain names are at most 255 bytes.
- Host port forwarding forwards only TCP, and only ports already listening at startup.

**Features**
- Hot reload (`SIGHUP`) does not change `fake_ip_range`, `upstream_dns` or host port forwarding.
- Fake IP mappings are not written to disk; they are lost on restart.
- The NAT table holds at most about 1.03 million entries (including those kept for 75 s after closing), i.e. a sustained rate of about 13,800 new connections per second; at most 8192 connections are relayed at once (fewer with a low fd limit).
  Beyond that, new connections get an RST at once instead of hanging in retries.
- Several edge cases of signals (two SIGTERMs within 50 ms, etc.): see [ARCHITECTURE section 6](architecture/lifecycle_en.md).
- **A real CentOS 7 machine** has not been verified yet; see above.

## Project layout

```
crates/proxytun-core/  proxy side: config, rules, load balancing and health checks, SOCKS5/HTTP handshakes, fake IP pool and fake DNS, sniffing, relay
crates/proxytun/       capture side and the binary: namespaces and TUN, address rewriting, sudo helper, witness process, host ports, self-check, command line
  tests/e2e.rs         end-to-end tests (real namespaces, TUN, debuggers, sudo mode simulating CentOS 7)
  tests/bench.rs       benchmarks
scripts/               build-static.sh static build
docs/                  ARCHITECTURE.md architecture index (the chapters are in architecture/), CONFIG.md config reference,
                       PERFORMANCE.md performance tests, DESIGN.md design decisions, CENTOS7.md CentOS 7 verification steps;
                       English versions are the *_en.md files alongside (this README is docs/README_en.md)
proxytun.toml          annotated example config
```

## Troubleshooting

| Symptom | What to check |
|---|---|
| `user namespaces are not usable here` followed by `sudo failed` | No unprivileged user namespaces, and sudo did not succeed either: make sure you can sudo, or set up a passwordless rule as in [Run modes](#run-modes); `--doctor` explains why |
| `open /dev/net/tun: Permission denied` | The administrator restricted the TUN device (sudo is not tried in this case); in a container add `--device /dev/net/tun` |
| `proxytun refuses to run as root through sudo` | Do not `sudo proxytun`: run it as yourself; proxytun calls sudo itself when it needs to |
| sudo mode reports `security context` / `traced` / `syscall filter` / `session keyring` | sudoers sets `ROLE`/`TYPE` or enables `intercept` / `log_subcmds`, or the container forbids keyctl: remove those settings, or allow keyctl in the container's seccomp profile |
| `the helper socket ... is too long a path` | `$TMPDIR` is too long; use a shorter directory |
| `no healthy proxy available` | The proxies are marked DOWN: check the proxy addresses and connectivity; `kill -USR1` shows each proxy's state |
| A connection fails | `closed: <reason>` at info level; `-v` shows how the proxy retries went |
| Slow | The `closed` line: a large `dial_ms` means connecting to the proxy, the proxy connecting to the target, or the direct connection is slow (`-v` shows whether members were switched); a small `dial_ms` with a large `ms` and few bytes means the proxy or the target transfers slowly |
| Throughput does not go up | The rate line of `kill -USR1`; if the thread named `tun` in `top -H -p <pid>` is near 100%, proxytun's own limit (about 1 GB/s) is reached; otherwise the bottleneck is the proxy |
| Domains do not resolve / resolve slowly | The `dns:` lines of `-v`; `dns_forward_failed` in the stats (warned the first time the upstream does not answer); check `upstream_dns` |
| The proxy sees an IP instead of a domain | The program did not go through the fake DNS (DoH, hard-coded IP, resolving through nscd / systemd-resolved): is the port in `sniff_ports`? Is the address a private address, or covered by an `ip-cidr` rule (neither is sniffed)? |
| The program cannot reach the local `127.0.0.1:P` | Was the service started after proxytun? Is the port in `host_ports_exclude`, or is `--no-host-ports` in use? The startup log lists the forwarded ports |
| Listening inside the namespace fails with `EADDRINUSE` | A service on the host has the same port and was forwarded in: exclude it with `host_ports_exclude` |
| Connections hang | The drop counters in the stats: `dropped_no_flow` (TCP packets with no matching connection), `dropped_table_full` (NAT table full), `relays_refused` (the limit of concurrently relayed connections is reached; a warning at startup states the limit; with CentOS 7's default fd limit of 4096 it is about 1870), `dropped_dns_busy` (1024 DNS queries already in flight), `dropped_unparsed` (IPv6, fragments), `dropped_other_proto` (ICMP etc.) |

## License

GPL-2.0 (the code comes from proxyhook).
