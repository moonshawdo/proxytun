# proxytun configuration

[简体中文](CONFIG.md) · **English**

This document goes through every key in the config file: what it does, type, default, range, whether it can be hot-reloaded, and how it relates to other settings.
For an annotated example see [proxytun.toml](../proxytun.toml); for command-line options and log options see [README](README_en.md#command-line-options);
for the mechanisms behind each setting see [ARCHITECTURE.md](ARCHITECTURE_en.md).

- [1. Quick reference](#1-quick-reference)
- [2. File, validation and loading](#2-file-validation-and-loading)
- [3. Top-level keys](#3-top-level-keys)
- [4. `[health]` health checks](#4-health-health-checks)
- [5. `[[proxies]]` upstream proxies](#5-proxies-upstream-proxies)
- [6. `[[groups]]` proxy groups and load balancing](#6-groups-proxy-groups-and-load-balancing)
- [7. `[[rules]]` routing rules](#7-rules-routing-rules)
- [8. Command-line and environment overrides](#8-command-line-and-environment-overrides)
- [9. Examples](#9-examples)
- [10. Common errors](#10-common-errors)

## 1. Quick reference

"Hot reload" means the change takes effect after `kill -HUP <proxytun pid>`; "restart" means proxytun must be run again.

| Key | Type | Default | Range | Takes effect after |
|---|---|---|---|---|
| `fake_ip_range` | string, IPv4 CIDR | `"198.18.0.0/15"` | prefix /8–/22 | restart |
| `upstream_dns` | string, `IP:port` | the first nameserver in the host's `/etc/resolv.conf` that is an IP, port 53 | must be an IP, not a hostname | restart |
| `localnet` | array of CIDR strings | `[]` | IPv4 CIDR (IPv6 is accepted but never matches) | hot reload |
| `direct_to_proxies` | bool | `true` | | hot reload |
| `sniff` | bool | `true` | | hot reload |
| `sniff_ports` | array of ports | `[80, 443, 8443]` | 0–65535 | hot reload |
| `sniff_skip_domains` | array of strings | `["cloudflare-ech.com"]` | domain suffixes | hot reload |
| `sniff_override_destination` | bool | `true` | | hot reload |
| `sniff_timeout_ms` | integer (ms) | `300` | 1–10000 | hot reload |
| `host_ports_forward` | bool | `true` | | restart |
| `host_ports_exclude` | array of ports | `[]` | 0–65535 | restart |
| `retries` | integer | `2` | ≥ 0 | hot reload |
| `connect_timeout_ms` | integer (ms) | `10000` | 100–60000 | hot reload |
| `handshake_timeout_ms` | integer (ms) | `10000` | 100–60000 | hot reload |
| `[health] interval_secs` | integer (s) | `10` | 1–3600 | hot reload |
| `[health] fail_threshold` | integer | `3` | 1–100 | hot reload |
| `[health] timeout_ms` | integer (ms) | `10000` | 100–60000 | hot reload |
| `[[proxies]]` `name` | string | none (required) | unique | hot reload |
| `[[proxies]]` `type` | `"socks5"` / `"http"` | none (required) | | hot reload |
| `[[proxies]]` `addr` | string, `IP:port` | none (required) | must be an IP | hot reload |
| `[[proxies]]` `username` / `password` | string | none | ≤ 255 bytes each | hot reload |
| `[[proxies]]` `weight` | integer | `1` | 1–1000 | hot reload |
| `[[groups]]` `name` | string | none (required) | unique; a `default` group is required | hot reload |
| `[[groups]]` `strategy` | enum | `"round-robin"` | see section 6 | hot reload |
| `[[groups]]` `members` | array of strings | none (required) | non-empty, all defined proxy names | hot reload |
| `[[rules]]` `match` | enum | none (required) | see section 7 | hot reload |
| `[[rules]]` `value` | string | `""` | required except for `final` | hot reload |
| `[[rules]]` `action` | `"proxy"` / `"direct"` / `"block"` | none (required) | | hot reload |
| `[[rules]]` `group` | string | `"default"` | only with `action = "proxy"` | hot reload |

## 2. File, validation and loading

**Location.** By default proxytun reads `proxytun.toml` in the current directory; `-c <file>` gives another path. With `--proxy` or `PROXYTUN_PROXY`, the config file may be missing
(every other setting then takes its default), or may contain only rules and no proxies (see section 8); with no proxy given and no config file found, proxytun exits with an error.

**Compatible with proxyhook.** The format is the same as `proxyhook.toml`, which can be used as is. proxyhook keys that proxytun has no use for (`verify_peer_uid`, `block_quic`,
`dns_udp_unconnected`, `splice`) get a warn at startup and are ignored. The only incompatibility is the prefix range of `fake_ip_range` (see 3.1).

**TOML order.** Top-level keys (all keys in section 3) must come before the first `[table]` / `[[table]]`. A key written after a table is taken as a field of that table.

**Unknown keys get a warning and are ignored.** A misspelled key (such as `sniff_port`, `proxies.0.usrname`) logs a warn at startup
(`config key has no effect in proxytun (a typo, or a proxyhook-only setting); ignored`), and the setting keeps its default.

**Whole-file validation.** At startup and on hot reload the whole file is validated once; any invalid item is an error (see section 10), and the file never takes effect partially.
An error at startup makes proxytun exit, and the target program never runs; an error on hot reload keeps the old config running, with `reload failed` in the log.

**File permissions.** If the file contains a proxy password and grants any permission bit to group or others (`mode & 077` is not 0), startup warns and suggests `chmod 600`. Note: the proxied program runs as the same user as proxytun,
so it can always read this file; to keep the password from it, use the environment variable `PROXYTUN_PROXY` instead (section 8).

**Hot reload (`kill -HUP <proxytun pid>`).**

| Takes effect on hot reload | Needs a restart |
|---|---|
| `[[rules]]`, `localnet`, `direct_to_proxies`, `[[proxies]]` / `[proxy]`, `[[groups]]`, `retries`, `connect_timeout_ms`, `handshake_timeout_ms`, all `sniff*`, all of `[health]` | `fake_ip_range`, `upstream_dns`, `host_ports_forward`, `host_ports_exclude` |

- Established connections are unaffected; new connections use the new config.
- After a reload every proxy's health state and stats start over (all are treated as healthy), and health checks restart immediately under the new `[health]`.
- A `--proxy` / `PROXYTUN_PROXY` given at startup still overrides the config's proxies after a reload.
- The listening sockets for host port forwarding are created once, when the namespace is built; a reload does not change them.

## 3. Top-level keys

### 3.1 fake-ip and DNS

#### `fake_ip_range`

When the program resolves a domain name, proxytun's fake DNS assigns it a "fake IP" from this range. The program then connects to that fake IP, proxytun maps it back to the original domain name and hands the **domain name** to the proxy.
This is how domain names are kept all the way to the proxy (see [Core flows](architecture/flow_en.md)).

- Type: IPv4 CIDR string; default `"198.18.0.0/15"`; prefix length /8–/22; changing it needs a restart.
- **The last /24 is reserved for the namespace itself**: in the default `198.19.255.0/24`, `.1` is the TUN device, `.53` is the fake DNS, and `.2`–`.17` are the source addresses used for address rewriting.
  Hence the prefix must be at least /22 (proxyhook allowed up to /30; a range narrower than /22 must be widened, and the error message says so).
- The remaining addresses go to domain names. There are at most 2^20 (about 1.05 million) mappings, however large the range; DNS answers have a TTL of 60 seconds. When addresses run out, the least recently used mapping is reclaimed
  among those that no connection is using and that were last answered or used more than 120 seconds ago; when none can be reclaimed, the new query gets `SERVFAIL`, and a mapping in use is never overwritten. Mappings live only in memory and are lost on restart.
- **Choosing a range: it must not overlap any address the program really needs to reach.** The default 198.18.0.0/15 is the benchmarking range reserved by RFC 2544 and never appears on the public internet; it usually needs no change.
- IPv4 only. The program's AAAA queries get an empty answer, and it falls back to IPv4.

#### `upstream_dns`

DNS queries that proxytun does not fake itself are forwarded unchanged from the host to this address.

- Type: `"IP:port"` string; default: the first nameserver in the host's `/etc/resolv.conf` that parses as an IP (IPv6 link-local addresses with `%iface` are skipped), port 53; `127.0.0.1:53` if there is none, as in glibc; must be an IP address; changing it needs a restart.
- Queries go out from the host, so local resolvers on the host such as `127.0.0.53` (systemd-resolved) work too.
- How each kind of query is handled:

  | Query | Handling |
  |---|---|
  | `A` | Answered with a fake IP (`localhost` and `*.localhost` get `127.0.0.1`; the root `.` gets an empty answer) |
  | `AAAA`, `HTTPS` (65), `SVCB` (64) | Answered empty locally (NOERROR, no records), so the program uses the IPv4 fake IP |
  | Others (`MX`, `TXT`, `PTR`, `SRV` …) and non-`IN` classes | Forwarded to `upstream_dns`: UDP queries over UDP, TCP queries over TCP, 3-second timeout |

- **Forwarding is a direct connection, not through the proxy**, and is plaintext DNS. If your network cannot reach external DNS directly, use an internal DNS server instead, for example `"192.168.1.1:53"`.
- Unrelated to `direct` rules: domain names for `direct` are resolved by proxytun with the host's system resolver (`getaddrinfo`), not through this.
- Queries the program sends to port 53 of **any** IP (UDP and TCP) are answered by the fake DNS, including programs that hard-code `8.8.8.8`; the namespace's `/etc/resolv.conf`
  is also replaced with one that points only at the fake DNS (the host's `search` / `domain` / `options` are kept, `ndots` is dropped).

### 3.2 Direct ranges

#### `localnet`

Connections whose destination address falls in these ranges are connected directly from the host by proxytun: no sniffing, no `[[rules]]`, no proxy. Same purpose as proxychains' `localnet`.

- Type: array of CIDR strings; default `[]`; hot-reloadable. IPv6 ranges pass validation, but the namespace has only IPv4, so they never match.
- Applies only to **literal IP** destinations (the program connected to an IP directly, without resolving through the fake DNS). Domain names resolved through the fake DNS follow the rules.
- Why it is empty by default: `127.0.0.0/8` in the namespace is the namespace's own loopback; a program connecting to `127.0.0.1` never reaches proxytun at all (for the host's local services see 3.4).
- To keep the LAN off the proxy, add it here, for example `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]`.
- Difference from an `ip-cidr` + `direct` rule: both are connected directly from the host by proxytun; `localnet` is checked before sniffing and rules, and once it matches nothing else is looked at.

#### `direct_to_proxies`

When the program itself connects to one of the proxies in `[[proxies]]` (its own proxy settings, `curl -x`), the connection goes directly to that IP + port instead of making a second trip through the proxy.

- Type: bool; default `true`; hot-reloadable.
- Only that port is let through: other ports on the same host follow the rules as usual. This is the difference from `localnet`.
- With `--proxy` / `PROXYTUN_PROXY`, the overriding proxy is covered too.

**Proxies in the program's environment.** Regardless of `direct_to_proxies`, the proxies named by the program's environment variables `http_proxy` / `https_proxy` / `all_proxy` (either case)
are also connected to directly, to avoid "a proxy inside a proxy":

- If the value is `IP:port`, connections to that address go direct; if it is a hostname, connections to that "hostname:port" are handled as `direct`.
- Without a port: `http://` and values without a scheme register both 80 and 1080 (curl and git use 1080; pip, Go, wget, npm and apt use 80),
  `socks5://` and the like get 1080, and `https://` gets 443.
- proxytun does not rewrite or remove these environment variables.

### 3.3 Sniffing (recovering the domain name from the first packet)

When the program bypasses proxytun's fake DNS and connects to a literal IP directly (Chrome's secure DNS / DoH, hard-coded IPs, `/etc/hosts`, resolution over the unix socket of nscd /
systemd-resolved), proxytun first peeks at the first data the program sends and recovers the domain name from the SNI of a TLS ClientHello or from the HTTP `Host` header.
It only peeks and consumes nothing; the byte stream between the program and the server is unchanged.

**No sniffing** in these cases: the destination is already a domain name; the port is not in `sniff_ports`; the destination is a private, loopback, link-local or CGNAT (100.64.0.0/10) address
(such addresses are connected to on purpose); the destination address is covered by an `ip-cidr` rule (the IP rule you wrote wins); the destination is in `localnet` or is the program's own proxy.

#### `sniff`

- Type: bool; default `true`; hot-reloadable. Master switch; with `false` none of the settings below have any effect.

#### `sniff_ports`

- Type: array of port numbers; default `[80, 443, 8443]`; hot-reloadable.
- proxytun waits for the first packet only on these destination ports; other ports see no delay at all.
- Do not list ports of "server speaks first" protocols (SMTP 25, SSH 22, FTP 21, etc.): the client sends nothing before it receives the server's greeting, so every connection waits out `sniff_timeout_ms` for nothing.

#### `sniff_skip_domains`

- Type: array of strings; default `["cloudflare-ech.com"]`; hot-reloadable.
- When the sniffed name equals one of these or is a subdomain of one, the name is not used and the original IP is kept. Comparison is case-insensitive; as with the `value` of a `domain-suffix` rule,
  `*.example.com` or `.example.com` also works and is normalized to `example.com` (matching both `example.com` and its subdomains).
- Purpose: on connections that really use ECH (Encrypted ClientHello), the plaintext SNI carries only the provider's "public name", not the real destination.

#### `sniff_override_destination`

- Type: bool; default `true`; hot-reloadable.
- `true`: the sniffed domain name is used both for rule matching and as the destination sent to the proxy, so the proxy can route by domain name and resolve it itself.
- `false`: the domain name is used only for rule matching; the proxy still gets the original IP.

#### `sniff_timeout_ms`

- Type: integer, milliseconds; default `300`; range 1–10000; hot-reloadable.
- The longest wait for the first packet; on timeout the original IP is kept. It only affects the connect time of connections to literal IPs on `sniff_ports`.

### 3.4 The host's local services

`127.0.0.1` in the namespace is the namespace's own loopback, isolated from the host. At startup proxytun scans once for TCP ports on the host listening on loopback or wildcard addresses (`0.0.0.0`, `[::]`) and opens them on the namespace's loopback addresses;
the program's connections to those addresses are forwarded to the host (mapping table in [README](README_en.md#reaching-local-services)).

#### `host_ports_forward`

- Type: bool; default `true`; changing it needs a restart. The command-line option `--no-host-ports` is equivalent to `false`.
- At most 250 addresses at a time (`[::]:P` counts as two), the excess is listed in a warn; port 53 is not forwarded (DNS must be answered by the fake DNS); listeners are forwarded whichever user owns them.
- Ports opened on the host after startup are not seen; restart if you need them.

#### `host_ports_exclude`

- Type: array of port numbers; default `[]`; changing it needs a restart.
- Ports not to forward. Use it when the program itself needs to listen on the same port number in the namespace; otherwise it gets `EADDRINUSE`.

### 3.5 Retries

#### `retries`

- Type: non-negative integer; default `2`; hot-reloadable.
- When the handshake with a proxy fails, the maximum number of other group members to retry with. Total attempts = `retries` + 1, and never more than the number of healthy members in the group. `0` means no switching.
- Retries happen only in the handshake phase: at that point not one byte of the program's data has been sent, so retrying is safe.
- Retried on another member: the proxy cannot be reached, connect timeout (`connect_timeout_ms`, see 3.6), greeting timeout (`handshake_timeout_ms`, see 3.6), the proxy replies "general failure" or an access-control denial (SOCKS5 0x01, 0x02; HTTP 403, 500, 503, etc.),
  a SOCKS5 proxy accepts the request and then just disconnects (this is what `ssh -D` does when it cannot reach the target), local ephemeral ports exhausted.
- Not retried: the proxy explicitly replies that the target refused or is unreachable (SOCKS5 0x03–0x06, HTTP 502, 504), or the proxy timed out waiting for the target (`handshake_timeout_ms`; another proxy would give the same result).
  Running out of local fds / memory, or a target domain name that is empty or longer than 255 bytes (SOCKS5 cannot encode it), also fails at once.
- When all attempts fail, the program's connection is closed with an RST; **there is no fallback to a direct connection**.

### 3.6 Connect and handshake timeouts

An upstream proxy may have long timeouts of its own (for example it waits a long time when connecting to the target), so each of proxytun's waits on an upstream proxy defaults to 10 seconds:

| Waiting for | Timeout | A timeout counts against |
|---|---|---|
| The TCP connection to the proxy | `connect_timeout_ms`, default 10 s | The proxy: counts toward health; another group member is tried |
| Reads and writes of the SOCKS5 greeting and authentication | `handshake_timeout_ms`, default 10 s | The proxy: counts toward health; another group member is tried |
| The proxy's reply after the SOCKS5 request / HTTP CONNECT is sent (the proxy is connecting to the target) | `handshake_timeout_ms`, default 10 s | The target: does not count toward health; no retry on another proxy |
| Health probes (connect + SOCKS5 greeting), and the proxy checks of `proxytun --doctor` | `[health] timeout_ms`, default 10 s | The proxy |

Once connected (handshake complete), relay reads and writes have no timeout and a connection is never cut however long it idles; dead links are detected by TCP keepalive.
So a connection through a proxy waits at worst `connect_timeout_ms` + 2 × `handshake_timeout_ms` (30 seconds by default) for each member it tries; switching members per `retries` restarts the clock,
so the worst case is (`retries` + 1) × that time (90 seconds with the default `retries = 2` and at least 3 healthy members in the group).

#### `connect_timeout_ms`

- Type: integer, milliseconds; default `10000`; range 100–60000; hot-reloadable (applies to connections made afterwards).
- The longest proxytun waits when making an outgoing TCP connection, of all three kinds: to a proxy, direct (`direct` rules, `localnet`, `direct_to_proxies`), and to a local service via host port forwarding.
- On timeout the program gets an RST and sees the connection reset at once instead of hanging: left to the kernel's own SYN retries it would take about 2 minutes, holding a relay slot the whole time
  (as happens when a service on the host is stuck or its accept queue is full).
- A timeout connecting to a proxy is the proxy's fault: it counts toward health (`[health] fail_threshold` consecutive failures mark it DOWN), and another group member is tried per `retries`.
- It covers only the connect step (when the target of a `direct` rule is a domain name, this includes the time to resolve it with the system resolver).
- Set too low, connections to remote proxies fail often; with only local proxies it can be lowered so failures surface faster.

#### `handshake_timeout_ms`

- Type: integer, milliseconds; default `10000`; range 100–60000; hot-reloadable (applies to connections made afterwards).
- For a connection through a proxy, the longest each handshake step may wait after the TCP connection to the proxy is up. The two steps are timed separately; a slow first step does not eat into the second step's time:
  1. SOCKS5 greeting and authentication (HTTP proxies have no such step). A timeout is the proxy's fault: it counts toward health, and another group member is tried per `retries`.
  2. Waiting for the proxy's reply after the SOCKS5 request or HTTP CONNECT is sent. The proxy replies only once it has connected to the target, so this is really a wait on the proxy connecting to the target;
     a timeout is the target's fault: it does not count toward the proxy's health, and no other proxy is tried (another proxy would have to wait just as long).
- On timeout the program gets an RST. Raise it when the upstream proxy's timeout for connecting to targets is longer than 10 seconds and you want to wait for it to finish; lower it to make unreachable targets fail faster.

## 4. `[health]` health checks

proxytun actively probes each proxy at regular intervals and combines that with the results of real connections to decide whether a proxy is usable.

```toml
[health]
interval_secs = 10
fail_threshold = 3
timeout_ms = 10000
```

| Key | Default | Range | Notes |
|---|---|---|---|
| `interval_secs` | `10` | 1–3600 | Interval between two probe rounds. One round runs immediately at startup; each round probes all proxies concurrently |
| `fail_threshold` | `3` | 1–100 | Number of consecutive failures that marks a proxy DOWN. Both failed active probes and the proxy's own failures on real connections count; target problems and local resource shortages do not |
| `timeout_ms` | `10000` | 100–60000 | Timeout of a single probe (`proxytun --doctor` also uses it to check proxies). Set too low, it marks healthy proxies DOWN |

- What a probe does: establishes a TCP connection to the proxy; for a SOCKS5 proxy it also performs the same greeting as a real connection (including username/password authentication), and a rejection or no acceptable method counts as a failure;
  for an HTTP proxy only the TCP connection is made. It measures the hop to the proxy, not from the proxy to the target.
- Probe round-trip times are averaged with exponential weighting (a new sample weighs 0.3), for use by the `least-latency` strategy.
- A proxy marked DOWN is no longer selected, so it returns to healthy only when a health probe succeeds (it also recovers when a connection started before it was marked DOWN later succeeds or gets an answer from the proxy).
- When all members of a group are DOWN, connections through that group fail at once (`no healthy proxy available`); they do not go direct.
- When local resources run short (open files, memory, ephemeral ports), probes are skipped and not counted as failures.
- Logs: a health probe that marks a proxy DOWN logs a warn (`proxy marked DOWN`); a proxy marked DOWN by failures of real connections only gets the `dial failed` warn of that connection; recovery logs an info, a single failed probe logs a debug. `kill -USR1 <proxytun pid>` prints each proxy's state and counters.

## 5. `[[proxies]]` upstream proxies

Each `[[proxies]]` table defines one upstream proxy. At least one is required (or one given with `--proxy` / `PROXYTUN_PROXY`).

```toml
[[proxies]]
name = "hk"
type = "socks5"
addr = "10.0.0.1:1080"
username = "user"     # optional
password = "pass"     # optional
weight = 3            # optional, used only by weighted-round-robin
```

| Key | Required | Notes |
|---|---|---|
| `name` | yes | Unique name, referenced by `members` of `[[groups]]` |
| `type` | yes | `"socks5"`: sends the domain name to the proxy in SOCKS5 domain-name form (ATYP=3); supports no authentication and username/password authentication. `"http"`: sends `CONNECT domain:port`, with `Proxy-Authorization: Basic` when a username is set |
| `addr` | yes | The proxy's `IP:port`; IPv6 is written `"[::1]:1080"`. **Must be an IP address**; proxytun does not resolve proxy hostnames. proxytun connects to it from the host, so `127.0.0.1` means the host itself |
| `username` / `password` | no | At most 255 bytes each (a SOCKS5 protocol limit) |
| `weight` | no | 1–1000, default 1. Used only by the `weighted-round-robin` strategy |

- Not supported: TLS to the proxy (HTTPS proxies), SOCKS4, chaining through multiple proxies.
- Passwords always show as `***` in logs and error messages.
- **Legacy form `[proxy]`**: a single proxy; `name` may be omitted (default `"default"`); equivalent to one `[[proxies]]`. With no `[[groups]]`, a `default` group containing only it is added as well.
  When `[[proxies]]` is also present, `[proxy]` is ignored.

## 6. `[[groups]]` proxy groups and load balancing

A group puts several proxies together and picks an exit for each connection according to its strategy. Rules hand traffic to a group by its name.

```toml
[[groups]]
name = "default"
strategy = "least-latency"
members = ["hk", "jp"]
```

| Key | Required | Notes |
|---|---|---|
| `name` | yes | Unique name. **A group named `default` is required**: `proxy` rules without `group`, and connections that match no rule, all use it |
| `strategy` | no | Default `"round-robin"`; values in the table below |
| `members` | yes | Non-empty; each item must be a defined proxy `name`. The same proxy may appear in several groups |

With no `[[groups]]` at all, a `default` group is generated automatically, containing all proxies, with strategy `round-robin`.

Each selection is made only among members that are "healthy and not yet tried for this connection":

| `strategy` | Behavior | When to use |
|---|---|---|
| `round-robin` | Takes turns in order | Default; proxies of similar capacity |
| `random` | Random: seeded from `/dev/urandom` at each startup and hot reload | Frequent short runs (only a few connections each): `round-robin` starts from the first member on every run, `random` spreads the load |
| `least-conn` | The member with the fewest active connections currently relayed through it; takes turns on ties | Many long-lived connections, widely varying connection durations |
| `least-latency` | The member with the lowest latency (weighted average) measured by health checks; takes turns while there are no measurements yet | Proxies in different locations, and you want the fastest. In a group mixing SOCKS5 and HTTP it favors HTTP (the SOCKS5 probe has one extra greeting round trip) |
| `weighted-round-robin` | Takes turns in proportion to `weight` | Proxies with different bandwidth |
| `hash` | Consistent hashing on the target host (domain name or IP, without port), so the same host always uses the same proxy; when a proxy goes down, only the hosts it was responsible for move to other proxies | Sites that need a fixed exit IP (login sessions, risk control) |

## 7. `[[rules]]` routing rules

Rules decide whether each TCP connection goes through a proxy, connects directly or is blocked. **Top to bottom, the first matching rule wins.**

```toml
[[rules]]
match  = "domain-suffix"
value  = "openai.com"
action = "proxy"
group  = "sticky"     # optional, default "default"
```

| Key | Required | Notes |
|---|---|---|
| `match` | yes | Match type, see the table below |
| `value` | required except for `final` | The value to match; `final` needs none |
| `action` | yes | `"proxy"`, `"direct"` or `"block"` |
| `group` | no | Only with `action = "proxy"`; must be a defined group; when omitted, the `default` group is used |

### 7.1 Match types

| `match` | Matches against | Matches when | Example (`value`) |
|---|---|---|---|
| `domain-suffix` | domain name | equals `value` or ends with `.value` | `example.com` matches `example.com`, `a.b.example.com`, not `badexample.com` |
| `domain-keyword` | domain name | contains `value` as a substring | `google` matches `www.google.com`, `googleapis.com` |
| `domain` | domain name | identical to `value` | `api.example.com` matches only itself |
| `ip-cidr` | literal IP | falls within the range | `192.168.0.0/16`, `2001:db8::/32`; a single address is written with `/32` or `/128` |
| `final` | any connection | always | Usually placed last as the catch-all |

- Domain name comparison is case-insensitive. A `domain-suffix` `value` may also be written `*.example.com` or `.example.com`; it is normalized to `example.com`.
  Internationalized domain names are written in punycode form (`xn--…`).
- An `ip-cidr` `value` must carry a prefix length; `1.2.3.4` alone is an error. IPv6 ranges pass validation, but the namespace has only IPv4, so they never match.

### 7.2 Actions

| `action` | Behavior |
|---|---|
| `proxy` | Handed to the group named by `group` (default `default`), which picks an exit per section 6; on failure retried per `retries`; on final failure the program gets an RST |
| `direct` | proxytun connects to the target directly from the host, not through a proxy. When the target is a domain name, it is resolved to the real IP with the host's system resolver (the program only has the fake IP); at most 32 resolutions run at once, and beyond that the connection fails immediately |
| `block` | The connection is closed immediately |

### 7.3 How a connection is decided

1. **Capture phase** (TUN thread):
   - UDP port 53: handed to the fake DNS; rules are not consulted.
   - Other UDP: answered with ICMP port unreachable, so the program fails at once (QUIC falls back to TCP).
   - TCP: addresses are rewritten and the connection is handed to the listening socket in the namespace, where the relay takes over.
2. **Relay phase**:
   - Destination port 53: handed to the fake DNS as TCP DNS.
   - Destination is a fake IP: mapped back to the domain name, which becomes the target.
   - Destination is a literal IP that is in `localnet` or is the program's own proxy (an `IP:port` from the environment variables, a `[[proxies]]` entry under `direct_to_proxies`): connected directly from the host,
     no sniffing, rules not consulted.
   - Destination is a literal IP and the port is in `sniff_ports`: the domain name is sniffed per 3.3.
   - Destination is a "hostname:port" from the program's proxy environment variables: connected directly.
   - Otherwise `[[rules]]` are matched in order, and the first match wins.
   - **When no rule matches, the connection goes through a proxy via the `default` group; it never goes direct.**

Which kinds of rules are consulted depends on what the target is:

- **Target is a domain name** (the program resolved it through the fake DNS, or sniffing recovered a domain name): only `domain-*` rules and `final`. proxytun never resolves a domain name in order to match `ip-cidr`.
- **Target is a literal IP** (the program bypassed the fake DNS, and no domain name was sniffed): only `ip-cidr` rules and `final`.

## 8. Command-line and environment overrides

| Method | Effect |
|---|---|
| `--proxy <URL>` | Replaces all `[[proxies]]` / `[proxy]` and `[[groups]]` in the config with this one proxy: it becomes the proxy named `default`, in the `default` group. The rest of the config (rules, `localnet`, sniffing, etc.) is unchanged |
| `PROXYTUN_PROXY=<URL>` | Same as `--proxy`; when both are given, `--proxy` wins. Zeroed in memory and removed from the environment right after it is read, so the program cannot inherit it. Use it, not `--proxy`, when there is a password (any local user can see command-line arguments in `ps`) |

- URL format: `socks5://[user:password@]IP:port` (`socks5h://` is the same) or `http://[user:password@]IP:port`. The host part must also be an IP.
  Write `@`, `:`, `/` in the username or password as `%40`, `%3A`, `%2F`.
- With an override, the config file is parsed first and validated after the override is applied, so the config file may be missing, or may contain only rules and no proxies.
- The override replaces all proxies; rules that named another group (`group = "hk"`) also go through this proxy, with one warn at startup and one on each hot reload.
- The log level and log file can only be set on the command line (`-q`, `-v`, `--log-level`, `--log-file`, `PROXYTUN_LOG`), not in the config file; see the "Logging" section of the README.
  `--no-sudo` is likewise command-line only; `--no-host-ports` corresponds to `host_ports_forward = false` in the config file.

## 9. Examples

### 9.1 Minimal config

```toml
[[proxies]]
name = "clash"
type = "socks5"
addr = "127.0.0.1:7890"
```

All TCP connections go through this proxy, with domain names passed to it unchanged; the host's local services stay reachable. `127.0.0.1` means the host (proxytun connects to the proxy from the host).

### 9.2 Rules only, proxy from the environment

```toml
# rules.toml: contains no proxies or passwords, safe to put under version control
[[rules]]
match = "domain-suffix"
value = "corp.example"
action = "direct"
```

```bash
PROXYTUN_PROXY=http://user:pass@10.0.0.5:8080 proxytun -c rules.toml git fetch
```

Domain names under `corp.example` are connected directly from the host; everything else goes through `PROXYTUN_PROXY`.

### 9.3 LAN and domestic sites direct, everything else through the proxy

```toml
localnet = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

[[proxies]]
name = "clash"
type = "socks5"
addr = "127.0.0.1:7890"

[[rules]]
match = "domain-suffix"
value = "cn"
action = "direct"

[[rules]]
match = "domain-keyword"
value = "baidu"
action = "direct"

[[rules]]
match = "final"
action = "proxy"
```

### 9.4 Several proxies: the fastest by default, a fixed exit for some sites, ad domains blocked

```toml
retries = 2

[health]
interval_secs = 10
fail_threshold = 3
timeout_ms = 2000

[[proxies]]
name = "hk"
type = "socks5"
addr = "10.0.0.1:1080"

[[proxies]]
name = "jp"
type = "http"
addr = "10.0.0.2:8080"
username = "u"
password = "p"

[[groups]]
name = "default"
strategy = "least-latency"
members = ["hk", "jp"]

[[groups]]
name = "sticky"
strategy = "hash"
members = ["hk", "jp"]

[[rules]]
match = "domain-suffix"
value = "openai.com"
action = "proxy"
group = "sticky"

[[rules]]
match = "domain-keyword"
value = "adservice"
action = "block"
```

There is no `final` at the end: unmatched connections go to the `default` group. The file contains a password; remember `chmod 600`.

### 9.5 The program needs to listen in the namespace on a port already in use on the host

```toml
host_ports_exclude = [8080]

[[proxies]]
name = "clash"
type = "socks5"
addr = "127.0.0.1:7890"
```

When a service on the host listens on port 8080, that port is forwarded into the namespace by default; exclude it when the program itself needs to listen on 8080.

### 9.6 Migrating from proxyhook

`proxyhook.toml` can usually be used as is. The only things to watch:

- A `fake_ip_range` narrower than /22 must be widened (proxytun takes the last /24).
- `127.0.0.0/8` in `localnet` has no effect in proxytun (host loopback services are handled by host port forwarding) and can be removed.
- `verify_peer_uid`, `block_quic`, `dns_udp_unconnected`, `splice` get a warning and are ignored.
- When `upstream_dns` is not set, the default is the host's nameserver, not `1.1.1.1:53`.
- When `[health] timeout_ms` is not set, it defaults to 10 seconds (proxyhook: 3 seconds); a value that is set is used as is.

## 10. Common errors

Config errors at startup or on hot reload, with their messages and causes:

| Error message | Cause |
|---|---|
| `parsing config toml` | TOML syntax error, a missing required field (`missing field`), wrong type or integer range (such as `retries = -1`), a misspelled enum value (such as `strategy = "rr"`, which reports `unknown variant`) |
| `reading config proxytun.toml` | The config file does not exist, and there is no `--proxy` / `PROXYTUN_PROXY` |
| `no upstream proxy configured (add [[proxies]] or [proxy])` | No proxy is defined at all, and there is no `--proxy` / `PROXYTUN_PROXY` |
| `every [[proxies]] entry needs a name` | A `[[proxies]]` lacks `name` |
| `duplicate proxy name '…'` / `duplicate group name '…'` | Duplicate name |
| `proxy '…': bad addr "…" (want ip:port)` | `addr` is not `IP:port`, for example it is a hostname |
| `proxy '…': weight must be between 1 and 1000` | `weight` out of range |
| `proxy '…': username/password longer than 255 bytes` | Username or password too long |
| `group '…' has no members` / `group '…': unknown proxy '…'` | The group has no members, or references a proxy that does not exist |
| ``no group named 'default' (rules without `group` use it)`` | `[[groups]]` is present but there is no `default` group |
| `health.interval_secs must be between 1 and 3600` etc. | A `[health]` value is out of range |
| `sniff_timeout_ms must be between 1 and 10000` | Same as above |
| `connect_timeout_ms must be between 100 and 60000` / `handshake_timeout_ms must be between 100 and 60000` | Same as above |
| `bad fake_ip_range …` / `fake_ip_range prefix must be between /8 and /22 …` | Not an IPv4 CIDR, or the prefix length is out of range (a range narrower than /22 in a proxyhook config must be widened) |
| `bad upstream_dns …` | Not `IP:port` |
| `bad localnet entry …` | Not a valid CIDR |
| `rule #N: bad ip-cidr …` | The `ip-cidr` value is not a CIDR (for example the `/32` is missing) |
| ``rule #N: `value` is required for …`` (… is the internal name of the rule type, such as `DomainSuffix`) | A `domain-suffix` / `domain-keyword` / `domain` rule lacks `value` (an `ip-cidr` rule without `value` reports `bad ip-cidr` above) |
| ``rule #N: `group` only applies to action = "proxy"`` | A `direct` / `block` rule has `group` |
| `rule #N: unknown group '…'` | References a group that does not exist |
| `unsupported proxy scheme …` | The scheme of `--proxy` / `PROXYTUN_PROXY` is not `socks5`, `socks5h` or `http` |
| `proxy url "…" needs a scheme (socks5:// or http://)` | `--proxy` / `PROXYTUN_PROXY` lacks `socks5://` or `http://` |
| `bad percent-escape in proxy url credentials` | A malformed `%XX` escape in the username or password of the proxy URL |
| `proxy url credentials are not valid UTF-8` | The username or password in the proxy URL is not UTF-8 after `%XX` decoding |
| `seeding the random strategy from /dev/urandom` | A group uses the `random` strategy but `/dev/urandom` cannot be read (no `/dev`, fds exhausted): startup or this reload is refused; there is no fallback to a fixed seed |
