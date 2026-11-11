# proxytun performance

[简体中文](PERFORMANCE.md) · **English**

This document gives proxytun's benchmark method, results and analysis. The benchmark is in [crates/proxytun/tests/bench.rs](../crates/proxytun/tests/bench.rs) and can be reproduced.

## Conclusions

- **Throughput**: a single-connection download captured through the TUN runs at about **1.1 GB/s**, about 55% of the same client downloading directly through the same proxy; host port forwarding runs at about 1.2 GB/s.
  This is the ceiling on local loopback with a proxy that is not the bottleneck; real proxies and networks are usually far below it and never hit it.
- **The bottleneck is the tun thread**: TCP processing in the namespace lands on the thread that writes the TUN, and single-connection throughput is limited by it; about 90% of its time is in kernel mode.
  TUN checksum offload was tried: only about 10% faster, not merged (4.8).
- **Connection setup**: each new connection costs about **0.5 ms** more than the client doing the SOCKS5 handshake itself.
- **Fake DNS**: about 4500 sequential queries per second (about 0.22 ms per round trip).
- **Startup**: `proxytun -- true` takes about 90 ms (creating the namespace, the TUN and the witness process).

## 1. Test environment

| Item | Value |
|---|---|
| CPU | Intel Core i5-8265U (4 cores, 8 threads, 1.6 GHz) |
| Memory | 11 GiB |
| System | WSL2, kernel 6.18 |
| Build | `cargo test --release` (`opt-level = 3`, thin LTO, `codegen-units = 1`) |
| Clients | curl 8.5.0, Python 3.12 |
| proxytun | user namespace mode, default log level (info), log written to `/dev/null` |

## 2. Method

The origin server and the SOCKS5 proxy are both threads of the test process itself (256 KiB buffers); all traffic stays on local loopback, so what is measured is the overhead on the client side.
Each test is compared with "the same client doing the same thing without proxytun":

| Test | Through proxytun | Baseline |
|---|---|---|
| `throughput`: download through the TUN | `proxytun --proxy socks5://PROXY -- curl http://bench.test/bytes/1073741824` (1 GiB) | `curl --socks5-hostname PROXY http://bench.test/bytes/1073741824` (curl connects to the proxy itself) |
| `throughput`: host port forwarding | `proxytun --proxy socks5://PROXY -- curl http://127.0.0.1:ORIGIN_PORT/bytes/1073741824` (the origin listens on the host and is forwarded into the namespace) | `curl http://127.0.0.1:ORIGIN_PORT/bytes/1073741824` |
| `connection_setup`: connection setup | Python sends 1000 HTTP requests sequentially, a new connection each time (the domain is resolved only once) | The same Python script, doing its own SOCKS5 handshake on each new connection |
| `fake_dns`: fake DNS | Python in the namespace sends 20000 A queries sequentially, a new domain each time | None (fake DNS exists only in proxytun) |
| `start_and_exit`: startup | Total time of `proxytun --proxy ... -- true` | None |

Download, connection setup and fake DNS run 3 rounds each and startup runs 10 times; the median is reported, with min–max in parentheses. To run (needs curl and python3):

```bash
cargo test --release --test bench -- --ignored --nocapture --test-threads=1
```

## 3. Results

### 3.1 Throughput (1 GiB single-connection download, MB/s)

| Path | proxytun | Without proxytun | Ratio |
|---|---|---|---|
| Captured through the TUN, via the SOCKS5 proxy | **1131** (1122–1143) | 2047 (2035–2122) | 55% |
| Host port forwarding | **1194** (1068–1272) | 4062 (2766–4146) | 29% |

### 3.2 Connection setup (1000 sequential short connections, ms per connection)

| | Per connection |
|---|---|
| proxytun | **1.885** (1.864–1.892) |
| Client doing its own SOCKS5 handshake | 1.352 (1.314–1.382) |
| Extra overhead | **about 0.53 ms** |

### 3.3 Fake DNS and startup

| Test | Result |
|---|---|
| 20000 sequential A queries | **4476 queries/s** (3993–4721), about 0.22 ms per round trip |
| `proxytun --proxy ... -- true` (10 runs) | **87.6 ms** (71.8–116.5) |

## 4. Analysis

### 4.1 The throughput ceiling is the tun thread

A connection through the TUN travels an extra leg compared with connecting to the proxy directly: program → namespace kernel → TUN → rewritten by the tun thread → written back to the TUN → kernel → capture listener → relay → proxy.
The namespace's TCP processing (receiving packets, ACKs, windows) all happens inside the tun thread's `write` calls, and this single thread is the bottleneck (during a download the thread named `tun` uses about 95% CPU, visible in `top -H`).
Split by utime / stime from `/proc/<pid>/task/<tid>/stat`, the tun thread spends about 8% in user mode and about 88% in kernel mode during a download: proxytun's own packet parsing and rewriting is only a small part;
the time goes mainly into the `read` / `write` system calls, that is, the kernel copying each packet of about 64 KB out and back in, and doing the protocol stack processing for the namespace's TCP connection on this thread.
So proxytun's single-connection ceiling is about 1 GB/s, independent of the proxy's speed.

This ceiling is reachable only on local loopback with a proxy that is not the bottleneck; a proxy over a real network is usually far below it, so optimizations such as multi-queue TUN were not done (section 5).

### 4.2 Host port forwarding

Host port forwarding skips the TUN's address rewriting but adds a relay copy: listening socket in the namespace → proxytun → service on the host. A direct connection on loopback runs at about 4 GB/s,
through proxytun about 1.2 GB/s, which is enough for local services (databases, development servers).

### 4.3 Why not zero-copy (splice)

`splice(2)` moves the data inside the kernel and saves the user-space copy; when proxytun was implemented it was compared with a plain copy (same machine, 2 GiB download):

| Path | splice | Plain copy (64 KiB buffer) | Without proxytun |
|---|---|---|---|
| Connections captured through the TUN | about 800 MB/s | about 1070 MB/s | about 2100 MB/s |
| Host port forwarding | about 2700 MB/s | about 1350 MB/s | about 4100 MB/s |

On the TUN path plain copy is about a third faster: the bottleneck is already the thread that writes the TUN, and splice's pipe operations only add to its load. On host port forwarding splice is twice as fast,
but 1.35 GB/s is already enough for local services, and keeping splice just for it is not worth it.

### 4.4 Relay buffer size

Each relayed connection has a 64 KiB buffer per direction (128 KiB as soon as it is established). Comparison made during implementation, 3 GB downloaded through the TUN: 64 KiB about 990 MB/s, 32 KiB about 915 (−8%),
16 KiB about 750 (−24%), 8 KiB about 545 (−45%). 64 KiB was kept by the criterion "throughput drops by no more than 5%"; with at most 8192 connections relayed at once, buffers take at most about 1 GiB.

### 4.5 Per-connection overhead

The extra 0.5 ms or so comes from: an extra TCP handshake in the namespace (program ↔ capture listener, rewritten by the tun thread), accept, lookups in the NAT table and the fake IP pool, rule evaluation,
and two log lines per connection at the default info level. Connections are dominated by round trips on the proxy side; in real environments this 0.5 ms is usually negligible.

### 4.6 Scale limits

| Item | Limit | Basis |
|---|---|---|
| Sustained new connections | about 13,800 per second | the NAT table has about 1.03 million keys; closed connections are kept for 75 seconds |
| Concurrently relayed connections | 8192 (fewer when the fd limit is low) | two fds and two 64 KiB buffers each |
| NAT table memory | about 200–280 MB when full | about 1.03 million entries |
| Fake IP mapping memory | about 280 MB for 1 million entries (worst case about 2.3 GB for very long domains containing escape characters) | mapping limit 2^20 (about 1.05 million) entries |
| NAT table sweep | at most 4096 entries per lock hold (about 1 ms) | when many expire at once they are swept in batches, so the tun thread does not stall and drop packets |

### 4.7 What is not on the hot path

- The tun thread forwards TCP packets without allocating or copying: packet parsing, address rewriting and the incremental checksum are all done in place on the read buffer; a new connection's SYN allocates only when the NAT table grows,
  and replying with RST or ICMP and dispatching DNS queries also allocate.
- An ordinary data packet does a single NAT table lookup; only the program's SYN (creating an entry), the listener side's SYN-ACK and an RST from either side change an entry.
- System files are read only at startup or on a signal; rule matching lowercases once per connection, and suffix matching does not allocate.
- Warnings that would repeat at packet rate (table full, fds exhausted) are rate-limited to one per 10 seconds.

### 4.8 The checksum offload experiment

The loopback interface does not compute TCP checksums, while TUN has no checksum offload by default. The experiment added `IFF_VNET_HDR` when creating the TUN and enabled `TUN_F_CSUM` with `TUNSETOFFLOAD`:
each packet gets a 10-byte virtio header in front; for a packet with the `NEEDS_CSUM` flag only the pseudo-header partial sum is fixed up, the header is passed along unchanged when forwarding, and the receiving kernel no longer verifies the checksum.
The offload did take effect (`ethtool -k tun0` in the namespace shows `tx-checksumming: on`), and the end-to-end tests all passed on gnu and musl.
Same machine, same time window, 1 GiB downloaded through the TUN (median of 3 rounds per run):

| Version | Per-run medians (MB/s) | Relative to without proxytun | tun thread CPU |
|---|---|---|---|
| Original | 1109, 1119, 1116, 1075 | 54%–57% | 96% |
| Checksum offload | 1154, 1226, 1232 | 56%–59% | 94% |

Throughput rose only about 8%–10%, and the tun thread stayed saturated: checksumming is only a small part of its kernel-mode time (4.1). Not merged: the gain is small, yet every packet on the hot path gets an extra layer of header handling,
and it was never verified on a real CentOS 7 machine; the throughput of real networks and proxies comes nowhere near this ceiling.

## 5. Optimizations not done

| Optimization | Why not |
|---|---|
| Multi-queue TUN | The ceiling of a single TUN receive/send loop is about 1 GB/s, far above real proxy throughput; a single connection would still use only one queue |
| TUN checksum offload | Tried (4.8): only about 10% faster, not worth the added complexity |
| splice in the relay | See 4.3: slower on the TUN path; faster on host port forwarding, but that is already fast enough |
| Smaller relay buffers | See 4.4: shrinking to 32 KiB already costs 8% throughput |
