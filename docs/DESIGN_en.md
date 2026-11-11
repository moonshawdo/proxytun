# proxytun design

[简体中文](DESIGN.md) · **English**

> This document records proxytun's design decisions and default assumptions; the implementation is based on it. To change behavior, change this document first and give the reason.

## 1. Goals

- Send only the TCP of **the given command and its entire child process tree** through a SOCKS5 / HTTP proxy, and **carry domain names to the proxy** (Clash and the like route on them).
- Works the same for statically linked programs and for programs that clear `LD_PRELOAD`.
- **No ptrace**, so strace / gdb / ltrace can be used at the same time (including `proxytun -- strace -f prog`, `proxytun -- gdb prog`, and `gdb -p` from outside).
- **Must support CentOS 7** (kernel 3.10, glibc 2.17).

Why not ptrace (graftcp, for one): a ptrace-based tool intercepts system calls, and a process can have only one tracer at a time, so it cannot coexist with strace/gdb.
Why not tun2proxy: its `--unshare` depends on the `unshare` command of a recent util-linux (CentOS 7's 2.23.2 lacks `--map-current-user`, `--keep-caps`, `--kill-child`)
and on unprivileged user namespaces (off by default on CentOS 7), and it has no sudo mode that drops privileges; all TCP goes through the proxy, with no direct connections and no handling of local loopback.

## 2. Overall approach

The program runs in an **anonymous network namespace** whose only exit is a TUN device held by proxytun; proxytun itself stays in the host namespace and opens the connections to the proxy.

```
proxytun (host namespace, ordinary user)
  ├─ holds: TUN fd, the listening socket inside the namespace, the host port forwarding listening sockets
  ├─ TCP on the TUN: address rewriting in user space -> handed to the listening socket in the namespace (kernel TCP stack) -> relay -> proxy / direct / drop
  ├─ UDP on the TUN: port 53 -> fake-ip DNS; everything else -> ICMP port unreachable
  └─ the program (inside the namespace, as the original user) and all its child processes
```

The TUN has no persist flag, so the kernel deletes it when the fd is closed; the namespace has no name and is destroyed when its last reference goes away. Nothing is left on the host: no interface, route or configuration.

## 3. Privilege model

| | Recent systems | CentOS 7 |
|---|---|---|
| Creating the namespaces + TUN | Unprivileged user namespace (`unshare(USER\|NET\|NS)`) | proxytun invokes `sudo` itself to start a minimal privileged helper |
| Program identity | uid/gid mapped to the user's own; capabilities inside the namespace are lost automatically at exec | Full privilege drop before exec (supplementary groups → gid → uid, real/effective/saved all dropped) |
| Afterwards | Same: the fds go to proxytun, and there is no root process anywhere in the tree | Same as left |

- A user namespace is used when possible; when it cannot be, sudo is used automatically, after a one-line message giving the reason; `--no-sudo` forbids invoking sudo (it fails with an error instead).
  Only problems with the user namespace itself (it cannot be created, or an LSM has taken away its capabilities, showing up as EPERM/EACCES) trigger the fallback; steps the host explicitly refuses
  (opening `/dev/net/tun` fails, the temporary directory for `resolv.conf` cannot be created) fail with an error: that is the administrator's setting, and root must not bypass it on the user's behalf.
- **The setup process is a re-exec'd proxytun**: proxytun makes itself non-dumpable at startup (to protect proxy credentials), and forked children inherit that,
  so their `/proc/self/uid_map` and similar files belong to root and cannot be written; making the child dumpable again would instead expose the memory copied from the parent (credentials included).
  So right after the fork the child calls `execv("/proc/self/exe", ["proxytun", "__proxytun_setup", ...])`: the new image holds no credentials and is dumpable again.
  It sets up the namespaces, hands the fds back, waits for the go-ahead, then execs the target program (same pid).
- **`sudo proxytun` is refused**: apart from the privileged helper, every proxytun entry point (including the internal `__proxytun_setup`), when euid is 0, refuses with exit status 2 if the real uid is not 0
  (setuid install) or the environment contains `SUDO_UID` / `SUDO_USER` / `SUDO_COMMAND` / `DOAS_USER` / `PKEXEC_UID`.
  Otherwise a sudoers rule that allows only proxytun would allow any root command: `sudo proxytun -- sh`, or
  `sudo proxytun __proxytun_setup 0 ... -- sh`, which passes fd 0 off as the control socket. There is no bypass switch; root mode is only for people who are root already (root login, `su -`).
  Ways of gaining root that set none of these variables (ksu, userhelper, `systemd-run --uid=0`) cannot be detected; the README states that proxytun may only be authorized through sudo.
- **Boundaries of the privileged helper**:
  - It only: creates the network + mount namespaces, creates the TUN, bind-mounts `resolv.conf`, creates the host port forwarding listening sockets, and forks the program; it exits as soon as the fds have been handed back, and the program is adopted by proxytun (a subreaper).
  - **A root process never receives the client's fds**: closing an fd supplied by the user can block forever (a socket with `SO_LINGER` set that cannot send, a file on the user's own FUSE mount,
    where not even SIGKILL helps), and the root helper and the sudo waiting for it would hang; the user cannot kill them, and they do not count toward the user's process count. So the helper first creates empty namespaces and forks the program;
    only after dropping to the user does the program read the request and the fds, and it then passes the raw request (bytes only) through a pipe to the helper, which validates it and configures. The helper itself never closes the control socket (messages carrying fds may be queued on it);
    it leaves that to the kernel at exit, where there is no more lingering. When the helper fails, it SIGKILLs the program but does not wait for it (closing the user's fds as it exits may block).
    It waits at most 10 + 5 seconds for the program to report back: by then the program is the user's process, and the user can stop it. Waiting for it to leave sudo's session (with `use_pty`) is also capped at 10 seconds.
    On proxytun's side, the wait for the namespaces to be ready is at most 60 seconds (the same in both modes); past that, it treats the side creating the namespaces as stuck and exits with an error instead of waiting forever.
  - It is started by sudo as the current executable's absolute path + a hidden subcommand; sudo closes fd≥3, and the two sides communicate over a unix socket in a private 0700 directory.
  - It only accepts real and effective uid both being 0 (what sudo does); when started setuid, the real uid is the caller and `SUDO_UID` is also set by the caller, so it refuses outright.
  - It connects to the socket with `SUDO_UID`/`SUDO_GID` as its effective uid/gid (`setresuid`/`setresgid` change only the effective ids, the saved uid stays 0 so it can switch back; supplementary groups cleared):
    root does not enter, on the caller's behalf, a directory the caller cannot enter; the peer sees the caller through `SO_PEERCRED`, not root, so the connection cannot be exploited as a root connection.
    proxytun accordingly requires the connecting side to have its own uid. When the ancestor check fails, the connection is simply closed, with no error message.
    Known limitation: since supplementary groups are cleared, connecting fails when `$TMPDIR` can only be entered through a supplementary group.
  - The peer (the socket's creator, `SO_PEERCRED`) must be an ancestor of the helper at most 4 levels up (sudo, the `use_pty` monitor process if there is one, proxytun),
    which also guarantees that it is still alive and its pid has not been reused, so what `/proc/<pid>` shows is that process; its uid must equal `SUDO_UID`. The program's uid/gid come from the socket's `SO_PEERCRED`, its supplementary groups from the peer's `/proc/<pid>/status`
    (whose Uid must match, otherwise the process is treated as gone), all supplied by the kernel; an identity self-reported in the message is not trusted.
  - Anyone can write their own client, so every item of the request is validated again: fake IP range /8–/22, the process group must equal the peer's process group, forwarded addresses must be loopback,
    ports not 0 and not 53, no duplicates, at most 250 of them.
  - The socket has 10-second send/receive timeouts, so a root process does not hang forever when the client stays silent; the program clears the timeout after reading the request, because it may wait for the go-ahead as long as it takes.
  - It reads no config, writes no logs, and opens no user-supplied path as root. The program drops privileges first (supplementary groups → gid → uid, then confirms that `setuid(0)` fails and CapPrm/CapEff are 0;
    failing to read `/proc/self/status`, e.g. because the caller set the fd limit to 0, is also treated as failure).
  - The session keyring survives fork, setuid and exec, and on RHEL `pam_keyinit` in `/etc/pam.d/sudo` may have created a root session keyring for the helper,
    linked to root's user keyring. After dropping privileges, the session keyring the program will get is checked: one owned by the caller (inherited when sudo has no pam_keyinit configured) is kept,
    as in userns mode; one owned by someone else (root) is replaced with a new keyring of the user's own; when the kernel has no keyring support (ENOSYS) it is let through; when keyctl is filtered
    (EPERM/EACCES, e.g. Docker's default seccomp profile) and the owner cannot be determined, it refuses to run and suggests allowing keyctl in the container's seccomp profile.
  - Finally `PR_SET_NO_NEW_PRIVS` is set: the network inside the namespace (DNS, routing) is fully controlled by the user's proxytun, so a setuid program (sudo, su,
    or PAM authenticating through LDAP/Kerberos) gaining root in there amounts to the user gaining root. After that, `chdir`, the PATH lookup and `exec` are done as the user.
  - When a root process writes `resolv.conf`, it is always under `/tmp` (`$TMPDIR` is ignored): in a directory the user controls, the directory made by mkdtemp could be replaced, before the write, by a link pointing to `/etc`;
    in the sticky `/tmp` nobody else can rename our directory. The file is created with `O_CREAT|O_EXCL|O_NOFOLLOW`, and its permissions are set through the fd.
  - Mount propagation is cut first, otherwise the bind-mounted `resolv.conf` would propagate back to the host. On kernels 4.11 and later it is set to slave: one-way, later mounts on the host
    (autofs, a plugged-in USB drive) can propagate in, and a propagated mount is placed under the existing mount, so it cannot cover our `resolv.conf`. On earlier kernels (CentOS 7's 3.10) it is set to private:
    there a propagated mount would stack on top of the existing one, and a later host mount on `/etc/resolv.conf` (a VPN script binding its own resolv.conf) would let the program bypass the fake DNS.
  - Installation requirement: what sudo runs as root is proxytun's own file, which must be in a location only root can write; a passwordless sudoers rule allows only
    `/usr/local/bin/proxytun __proxytun_root_setup *` (extra arguments are rejected by the helper).
  - When sudoers enables `use_pty`, sudo's monitor process runs the helper in a new session with a new pty as its controlling terminal; when the helper exits, the monitor process (the session leader) exits with it,
    and the kernel sends SIGHUP to that terminal's foreground process group. So when the helper finds it is not in the same session as the caller, it has the program `setsid()` out first thing after the fork and say so through a pipe, and only then reports back.
    The program is then not in proxytun's process group; Ctrl+C on the terminal reaches only proxytun, and proxytun forwards it (see section 5).
    The program has no controlling terminal, so Ctrl+Z and window size changes cannot reach it: a warn is logged when this is detected.
  - The program's process attributes match userns mode: the umask is passed along with the request; fds that are not close-on-exec (≥3, at most 249: 253 per SCM_RIGHTS message minus the fixed 4)
    are passed along with the request (their numbers must be below 2^20); after the go-ahead each is first copied to the lowest free number that is none of the target numbers, then `dup2`'d back to its original number, so even when the inherited fds sit right at the limit
    the caller's fd limit is not exceeded; a failed `dup2` of stdio is an error. Before dropping privileges, resource limits are set one by one to the caller's values (`prlimit` reads the caller's 16 limits):
    higher limits PAM gives root (CentOS 7's `20-nproc.conf` puts no limit on root's process count) are not carried in, and nproc/memlock limits the administrator set for the user still apply;
    lower limits sudo gives root (since sudo 1.9.13 the command's core limit is 0; a lower soft fd limit) are not carried in either. When root lacks `CAP_SYS_RESOURCE`
    (containers) and cannot restore a higher hard limit, the lower one is kept.
  - A sudoers `ROLE`/`TYPE` (or AppArmor profile) makes sudo run the helper in a different security context, which the program would carry: it compares
    `/proc/self/attr/current` with the caller's and refuses if they differ. With the default configuration sudo does not change the context.
  - sudoers `intercept` / `log_subcmds` make sudo trace (ptrace) the command or attach a seccomp filter to it, so every exec of the program would be seen by root
    and could be blocked: it refuses when the helper is traced (`TracerPid` non-zero) or its `Seccomp` / `Seccomp_filters` differ from the caller's. Filters a container puts on every process are on the caller too, so these are not affected.
- Ports below 1024: bind checks "whether `CAP_NET_BIND_SERVICE` is held in the user namespace that owns this network namespace",
  which the step that creates the namespace has anyway, so forwarding low ports needs no extra root; once created, the listening sockets are handed to an ordinary user process, and accept needs no privilege.
  The program itself listening on a low port inside the namespace still fails, the same as when it runs directly on the host.

## 4. Network details

### TCP interception and relay

- TUN + address rewriting in user space (the "system stack" approach of Clash/sing-box). When the program's SYN is read, its source/destination addresses and ports are rewritten to steer it to the listening socket in the namespace,
  and the kernel does the TCP; return packets are rewritten in reverse. After accept, the original target is looked up in the NAT table and handed to `proxytun_core::net::relay::route` (routing, SNI/Host sniffing, bidirectional copy).
  No dependence on netfilter (the 3.10 kernel has no nftables), and no user-space TCP stack.
- **No zero-copy (splice)**: proxytun's connections pass through the TUN first, and the TCP processing inside the namespace lands on the thread that writes the TUN, which is already the bottleneck; splice would only add to its load.
  Measured locally (WSL2, 8 cores, local SOCKS5 proxy and origin server, 2 GiB download):

  | Path | splice | Plain copy (64 KiB buffers) | Without proxytun |
  |---|---|---|---|
  | Connections captured through the TUN | ~800 MB/s | ~1070 MB/s | ~2100 MB/s |
  | Host port forwarding | ~2700 MB/s | ~1350 MB/s | ~4100 MB/s |

  On the main path plain copy is about a third faster; host port forwarding is half as fast, but 1.35 GB/s is enough for local services, and keeping splice just for it is not worth it.
  The main path tops out at about 1 GB/s (a single TUN read/write loop), far above the throughput of a real proxy, so there are no optimizations such as multi-queue TUN or checksum offload.
  The extra cost per connection is about 0.5 ms (compared with the client doing the SOCKS5 handshake itself; see [PERFORMANCE.md](PERFORMANCE_en.md)).
- Relay buffers are 64 KiB per direction (each connection takes 128 KiB as soon as it is established). Measured with a 3 GB download through the TUN: 64 KiB about 990 MB/s, 32 KiB about 915 (−8%),
  16 KiB about 750 (−24%), 8 KiB about 545 (−45%); by the criterion "throughput drops by no more than 5%" they are not reduced.
- When a relay ends with an error (dial failure, an RST from one end, a read/write error), both ends are closed with RST (host port forwarding likewise): with a FIN, a program whose download was cut short would read a clean EOF,
  and protocols that end on EOF (HTTP/1.0 without a length, nc) would take the truncated data as complete; a dial failure would look like "connected, then an empty reply"; an upload the program aborted would also look like a normal end on the target's side.
- Outbound connects (to a proxy, direct, host port forwarding) wait at most `connect_timeout_ms` (default 10 seconds, hot-reloadable); on timeout an RST is sent to the program as in the previous item.
  Every wait on an upstream proxy defaults to 10 seconds, and all are configurable: the connect `connect_timeout_ms`, each of the two handshake phases `handshake_timeout_ms`,
  health probes `[health] timeout_ms`. An upstream proxy's own timeouts may be long, and waiting too briefly would declare a slow but healthy proxy dead.
  Without a timeout, when the peer drops the SYN (a stuck service, a full accept queue, a firewall dropping packets) the kernel keeps retrying for about 2 minutes, holding a relay slot the whole time.
  It covers only the connect step: once connected, the relay copy has no timeout at all and never cuts a connection however long it is idle (ssh, websocket, long-lived database connections); dead links are found by the keepalive in the next item.
- Outbound connections enable TCP keepalive (probes start after 60 seconds idle, one every 15 seconds, failure after 4 unanswered): the program's own keepalives are answered by the listening side in the namespace
  and never reach the real path; without this, an idle long-lived connection through a remote proxy or direct would never notice that the path broke (NAT state cleared, peer lost power),
  and the relay slot and NAT table entry would stay occupied, and the fake IP pinned, forever. An idle dead link is detected in about 2 minutes, the relay ends with an error, and an RST is sent to the program as in the item above on relays that end with an error;
  a dead link with data that cannot be sent ends on the kernel's own retransmission timeout (about 15 minutes). `TCP_USER_TIMEOUT` is not set: it would also abort healthy transfers where the peer has merely paused reading (zero window).
  When the proxy is on this machine (e.g. `ssh -D`), only the leg up to the proxy can be checked.
- Rule matching lowercases only once per connection; suffix matching does not allocate.

### NAT table

- Source addresses are the 16 addresses `.2`–`.17` of the last /24 of `fake_ip_range`, 64512 ports each, about 1.03 million entries (a full table takes about 200–280 MB).
  Closed connections are kept for 75 seconds (LINGER, longer than the 60-second TIME_WAIT of the kernels at both ends), so the sustained rate of new connections is capped at about 13,800 per second.
  Ports never used are handed out in order by a counter (rotating across the addresses, so ordinary traffic already uses several addresses); only released ports go into a queue (the earliest released is reused first, the most recently released comes last),
  so the roughly 1.03 million ports are not all listed at startup.
- Entry lifecycle:
  - The program's SYN creates an entry and records the initial sequence number. A SYN on the same 4-tuple with a different initial sequence number is a new connection and gets another port; a retransmitted SYN (same sequence number) uses the original port.
    The old entry is still ended by its own relay, and its port is not reused before then; otherwise the old relay, when it ends, would close the new connection's entry.
  - Once the listening side answers with a SYN-ACK, the entry becomes "queued" (waiting for accept): when accept keeps failing for a long time because fds are exhausted, the program's end is already established, so the entry cannot be deleted.
    It stays queued for at most 30 seconds; on expiry an RST is sent to the program (sequence number = the listening side's SYN-ACK sequence number + 1; in the established state the kernel only accepts an RST whose sequence number exactly equals the expected one),
    and the program gets ECONNRESET; the entry is then kept for LINGER (the listening side may still hold that connection). If the program has already opened a new connection on the same 4-tuple, no RST is sent.
  - An RST from the listening side before accept, or from the program before accept (it closed the socket mid-handshake; the listening side's kernel just silently drops the half-open connection in that case), ends the entry.
  - A SYN entry the listening side has not answered within 60 seconds is deleted outright.
  - Once the relay has accepted, the entry never expires; when the relay ends, it is closed and kept for LINGER.
- Expiry uses three queues sorted by expiry time (unanswered, queued, closed), and the sweep only looks at expired entries; stale items in a queue (the entry has been replaced or its state has changed)
  are recognized by "state + time the state was entered" and skipped. The sweep runs once a second; each round handles at most 4096 expired items while holding the lock (about 1 ms), then releases the lock for 1 ms before continuing:
  the TUN thread needs this lock for every TCP packet, and tun0 has a queue of only 500 packets, so handling a large batch that expires at the same time in one go would stall the TUN thread for 100 ms or more and drop packets.
- When the table is full, an RST (acknowledging its SYN) is sent back to the program, which gets ECONNREFUSED at once instead of retrying for about 2 minutes per tcp_syn_retries; at most one error log line per 10 seconds
  (`dropped_table_full` still counts as usual). Other packets from the program that match no entry (the connection ended long ago, the entry is past LINGER) get an RST per RFC 793's Reset Generation,
  and the program gets ECONNRESET instead of retransmitting for about 15 minutes.
- Known limitation: when the table reaches about 460,000 and 920,000 entries (std `HashMap` doubles at a 7/8 load factor), the hash table grows on the TUN thread while holding the lock, stalling for tens of milliseconds, and the grown memory is not returned.
  This only happens under extreme load, once per doubling;
  preallocating for a full table would keep about 200 MB resident, which is not worth it.

### Limits and behavior on exhaustion

- Open files: after starting the program, proxytun raises its own soft limit to min(hard limit, `fs.nr_open`) (when the hard limit is above `nr_open`, every setrlimit fails,
  so the hard limit is lowered along with it); the program still gets the original values. A failure is logged at warn; the actual limit is logged at info at startup.
- Concurrently relayed connections (TUN-captured and host port forwarding combined) are capped at 8192: each holds two fixed 64 KiB buffers, about 1 GiB of buffers at full load.
  The actual cap depends on the open-files limit: two fds per connection, after first reserving enough for everything else (a fixed 64 + the number of host ports actually forwarded + 256 for DNS forwarding + 32 for name lookups,
  but at most half the limit is reserved); when it is below 8192, a warn is logged at startup. With CentOS 7's default hard limit of 4096 it is about 1870. Connections beyond the cap are closed with RST immediately
  (the program fails at once instead of waiting in the accept queue, or hitting EMFILE when dialing), counted in `relays_refused`, with at most one warn per 10 seconds.
  Their NAT table entries end when the TUN thread sees that RST; when the RST is dropped at tun0, the entry stays queued, and the program still gets an RST after 30 seconds.
- Local resource shortages (EMFILE/ENFILE/ENOBUFS/ENOMEM, EADDRNOTAVAIL from local ephemeral port exhaustion) do not count as proxy failures, neither for connections nor for health probes;
  otherwise running out of fds would mark healthy proxies DOWN. When a dial fails for lack of fds, memory and the like, at most one warn is logged per 10 seconds; when local ephemeral ports run out, every occurrence gets a warn
  and is retried with another member (ports run out separately per destination; another proxy may still have some). DNS forwarding failures from these causes are not blamed on the upstream either.
- At most 256 DNS forwards at a time (each holds a socket and a buffer, for up to 3 seconds); excess ones are dropped and the program's resolver retries; the receive buffer is not zeroed beforehand.
- At most 1024 DNS queries in progress at a time: the TUN thread counts before dispatching a task, and excess queries are dropped outright (`dropped_dns_busy`). Every query is copied and gets its own task;
  without a cap, queries arriving faster than they are handled (resolver retry storms, DNS tunnels) would pile up without bound. Only A queries build the escaped domain name.
- Name resolution for direct rules (blocking getaddrinfo) is capped at 32 at a time, fewer than the 64 blocking threads: lookups abandoned on timeout do not queue in the thread pool
  and hold up later lookups; beyond the cap the connection fails at once with the reason (at most one warn per 10 seconds).
- Processes/threads: the tokio blocking thread pool is capped at 64 (default 512). The blocking tasks are getaddrinfo for domain names under direct rules and asking the witness during signal forwarding (at most 1 second each); every thread counts against the user's process quota,
  shared with the program.
- listen backlog: on kernels before 5.4, `somaxconn` in a new network namespace is 128, which truncates 4096; root and sudo modes raise it to 4096 when creating the namespace,
  and userns mode has no permission to change it, so it stays as is.
- Fake IP mappings are capped at 2^20 (about 1.05 million) entries, about 280 MB (at worst about 2.3 GB with overlong domain names containing escaped characters), however large `fake_ip_range` is; beyond that, mappings are reclaimed under the reclaim rules;
  at most one error log line per 10 seconds when the pool is full.
- accept failures (fds exhausted), a full NAT table, a full fake IP pool: their logs are all rate-limited to at most one line per 10 seconds (`proxytun_core::throttle`).
  A full NAT table still counts in `dropped_table_full`; accept failures and a full fake IP pool have no counter of their own.
- The stats log takes the NAT table size first and then writes: taking the lock inside a `tracing` macro would hold it until the whole line is written.
- When the caller ignores SIGCHLD (which survives exec), proxytun resets its own SIGCHLD to the default after starting the program and before the go-ahead, otherwise the kernel reaps children automatically
  and the program's exit status is lost; the program has already been forked, so it keeps the caller's setting. `--doctor` resets it the same way before its trial run.

### DNS

- In a private mount namespace, `resolv.conf` is bind-mounted over with a file pointing to the fake DNS address; the host file is untouched. The original file's `search`/`domain`/`sortlist` lines
  and `options` lines are kept, but `ndots:N` is removed: the fake DNS returns an address for any name and never answers NXDOMAIN, so with ndots ≥ 2 (Kubernetes uses 5) the resolver tries
  "name + search domain" first and gets locked in; `github.com` turns into a request to the proxy for `github.com.default.svc.cluster.local`; with the default ndots 1 only names without a dot
  get the search domain first, which is exactly what search domains are for. Answering NXDOMAIN for names with a search domain appended would also hit real names that already end in a search domain, so that is not done.
- UDP and TCP to port 53 of any IP are always answered by the fake-ip DNS (catching programs that hardcode `8.8.8.8`).
  Every read and write over TCP has a 5-second deadline: a client that sends a length and then goes silent, sends no new query for 5 seconds, or does not read the answers is disconnected instead of holding a relay slot indefinitely.
- `nsswitch.conf` is not changed: resolution through the systemd-resolved / nscd unix socket gets real IPs, and sniffing is the fallback; the docs say so.
- Queries other than A, AAAA, HTTPS and SVCB are forwarded upstream: when `upstream_dns` is not set, the first nameserver in the host's `/etc/resolv.conf` is used (`127.0.0.1:53` if there is none, as in glibc),
  sent from the host, so local resolvers on the host such as `127.0.0.53` work too.
- **Fake IP reclaim**: once the addresses run out, the least recently used mapping that no connection is using is reclaimed, but not one answered or used less than 120 seconds ago (twice the answer TTL; some caches,
  past the TTL, still return the old answer first and refresh afterwards): the program may still have it cached, and reclaiming it for another domain would send traffic (including plaintext cookies) to the wrong place. When nothing can be reclaimed, the answer is SERVFAIL.
  Mappings in use by a connection are taken out of the reclaim queue, and reclaiming is O(log n).

### Other protocols and addresses

- **Non-DNS UDP (including QUIC)**: answered with ICMP port unreachable, so it fails fast and browsers fall back to TCP. UDP is not proxied.
- **ICMP**: dropped (ping does not work).
- **IPv6**: not supported. No IPv6 route is configured in the namespace (only `::1`), so connections to literal IPv6 addresses get "network unreachable" immediately; AAAA returns empty.
  HTTPS (65) and SVCB (64) also return empty: their answers carry real IP hints and ECH keys, which would let browsers bypass the fake IPs, and forwarding them upstream would leak the queries outside the proxy.
- **Address plan**: the last /24 of `fake_ip_range` is kept for the namespace's internal use (default `198.19.255.0/24`: `.1` the TUN itself, `.53` the fake DNS, `.2`–`.17` source addresses for rewriting),
  the rest serves as fake IPs, hence `fake_ip_range` must be at least /22. 198.18.0.0/15 is the range RFC 2544 reserves for testing and does not collide with real destinations.
- **MTU**: 65520. Packets only travel between the local kernel and proxytun; the larger the packets, the fewer packets user space has to handle.
- **localnet / the program's own proxy**: `Policy::is_passthrough` decides; matching targets are connected to directly by proxytun, bypassing rules and proxies (avoiding a proxy behind a proxy).
  `localnet` is empty by default: `127.0.0.0/8` in the namespace is the namespace's own loopback, which never reaches proxytun, so listing it does nothing.
  Proxies in the program's environment variables (`http_proxy`, `https_proxy`, `all_proxy`) are passed through as well; without a port, `http://` and scheme-less ones register both 80 and 1080
  (curl and git connect to 1080; pip, Go, wget, npm and apt connect to 80), socks registers 1080, `https://` registers 443.
  `direct_to_proxies` (on by default): the IP+port of each `[[proxies]]` entry is added to the same passthrough table, so when the program itself connects to these proxies (its own proxy settings, `curl -x`)
  it connects directly instead of taking a detour through the proxy. The difference from `localnet`: only that port passes through; other ports on the same host follow the rules as usual. Matching is done once per connection, after accept.

### The host's local services (loopback)

The namespace's `127.0.0.1` is isolated from the host's. At startup the host's TCP listeners (`/proc/net/tcp`, `tcp6`) are scanned **once** and forwarded into the namespace:

| Listener on the host | Opened in the namespace | Forwarded to on the host |
|---|---|---|
| `127.x.x.x:P` | The same address `127.x.x.x:P` | `127.x.x.x:P` |
| `0.0.0.0:P` | `127.0.0.1:P` | `127.0.0.1:P` |
| `[::1]:P` | `[::1]:P` | `[::1]:P` |
| `[::]:P` | `127.0.0.1:P` and `[::1]:P` | Same as left |

- For `[::]:P` both addresses are opened: a dual-stack listener also accepts IPv4 on the host; opening only `[::1]` would make `curl http://127.0.0.1:P` work on the host but not in the namespace.
- Only TCP is forwarded; port 53 is skipped (DNS must be answered by the fake DNS); listeners are not told apart by owner.
- At most 250 at a time (one SCM_RIGHTS message carries at most 253 fds, and the TUN and the capture listener come on top); those beyond are listed in a warn.
- The listening sockets are all created at once when the namespace is created; listeners added on the host later are not handled; restart the program when needed.
- `host_ports_forward = true` (default) / `--no-host-ports` switch the whole feature on/off; `host_ports_exclude = [...]` excludes individual ports (for when the program itself wants to listen on the same port number).
- At startup the forwarded ports are listed at info level.

## 5. Runtime behavior

- proxytun is a subreaper and exits only after the whole process tree has ended; the exit status is passed through. When the program is killed by a signal, proxytun shuts down core, restores the default disposition and sends itself the same signal
  (as `timeout`, sudo and strace do): bash's "wait and cooperative exit" only stops a loop when the child is WIFSIGNALED, and when systemd stops a service, `128+15` would be recorded as a failure.
  When proxytun itself exits because of a signal (Ctrl+C after the program has exited, a second SIGTERM, however long after the first), it likewise ends with that signal.
- Ctrl+C goes to the program; TERM/INT/QUIT sent only to proxytun are forwarded to the program, while those sent to the whole process group are not duplicated; SIGHUP hot-reloads; SIGUSR1 prints stats.
- **How "those sent to the whole process group are not duplicated" works**: proxytun does not use ptrace, so it cannot see which signals the program received, and `kill <pid>` and
  `kill -- -<pgid>`/`kill %1`/systemd's per-process sending all look like `SI_USER` to proxytun. For this, a **witness process** is started:
  - It is in the same process group as proxytun and blocks INT/QUIT/TERM (all other signals are ignored, so a terminal hangup or Ctrl+Z will not kill/stop it).
  - After receiving an `SI_USER` signal, proxytun waits 50 ms and asks the witness over a pipe which signals it has pending (`q` → 8-byte mask): if the witness got it too and the program is still in this process group
    → the program already has a copy, so it is not forwarded; otherwise it is forwarded. The witness's pending signals are cleared after each decision. Late old replies are drained from the pipe before asking; the question runs in the blocking thread pool
    and waits at most 1 second. `/proc/<witness>/status` is not read: under `hidepid` (`ProtectProc=invisible`) a non-dumpable witness cannot be seen.
  - The witness renames itself to `signal-witness` (both `comm` and the command line; the command line is overwritten in place), otherwise `pkill proxytun`, `killall` and `pidof` would select it as well,
    which would look like a group-wide signal and not be forwarded.
  - The witness double-forks (it is not a child of proxytun, so it does not affect "wait for the whole tree to exit") and exits as soon as the pipe breaks. When proxytun is process 1 of its pid namespace
    (a container without `--init`) or was made a subreaper beforehand, the orphaned witness is re-parented back to it, so once the program has been reaped the witness's pipe is closed, letting it exit and be reaped.
  - A program that receives signals with `sigwait`/`signalfd` does not get them twice either when its whole group is killed.
- When the program has left proxytun's process group itself (`setsid`, shell job control, or sudo mode under sudo `use_pty`), group-wide signals do not reach it, and they are forwarded as usual.
  `SI_KERNEL` signals from the terminal work the same way: not forwarded while the program is still in this process group, forwarded when it is not; when the program is in a group of its own (it is the group leader), they are forwarded to its whole process group,
  so the processes in its pipeline receive them too, the same as the terminal would have done. Group-wide signals sent by a process are forwarded to the program itself only: when systemd stops a service, it sends to each process in the cgroup one by one,
  so the processes in the pipeline already have one each.
- Known cases that cannot be told apart (documented in the README): when the program is not in this process group, per-process sending (systemd, `kill -1`, `pkill -u`) makes it receive two copies;
  with two SIGTERMs within 50 ms, the second makes proxytun exit immediately, and the program may have received none; two group-wide signals of the same kind within 50 ms cause one extra forward
  (the witness records only "whether", not how many times); signals received in the first few milliseconds of startup (before these three signals are blocked) end proxytun under the default disposition; group-wide signals (Ctrl+C on the terminal, or one sent by a process to the whole group after the witness has started) received after that but before the program is forked
  (reading the config, scanning host ports) are not forwarded: the program does not exist yet at that point, but is treated as having received them.
- Signals the caller ignored at startup (`nohup`, `cmd &`) stay ignored in the program: dispositions survive both execs, and proxytun installs its own handlers only after the fork.
  SIGPIPE is the exception: the Rust runtime sets it to ignored before `main`, so an ELF constructor (`.init_array`, which runs before the runtime) records the disposition at the start of the process image;
  in userns mode the setup process sets the caller's disposition back before the re-exec, so its own constructor can read it; in sudo mode it is passed to the helper with the request.
- If proxytun exits abnormally (`kill -9`, a crash): **the program is not killed**. The TUN disappears when its fd is closed, leaving the program with only loopback, i.e. cut off from the network; it does not bypass the proxy and connect directly. The logs and docs say so.
- What hot reload covers is in the "Takes effect after" column of the [CONFIG.md quick reference](CONFIG_en.md#1-quick-reference); host port forwarding, the address plan, `fake_ip_range` and `upstream_dns` need a restart.
- Credential protection: `PROXYTUN_PROXY` is removed from the program's environment (the original value zeroed in place), and proxytun is made non-dumpable; `--proxy` carrying a password triggers a warn.
  `--doctor` does the same.
- `--proxy` / `PROXYTUN_PROXY`: with an override, the config file is first parsed without validation and validated after the override is applied, so the config file may be missing, or may contain only rules and no proxies
  (credentials kept in the environment variable); the override replaces all proxies, rules that name other groups also use the override proxy, and a warn is logged once at startup. A SIGHUP reload is handled the same way.

## 6. Logging and monitoring

- Levels off/error/warn/info/debug/trace, `-q`, `-v`/`-vv`, `--log-level`, `--log-file` (append, 600, no color; `O_NOFOLLOW`,
  an existing file must be owned by the user, so that nobody else can pre-create a readable file in `/tmp`; opened non-blocking, so a FIFO pre-created by someone else cannot make it hang),
  environment variable `PROXYTUN_LOG`. A panic is additionally written to the log only when `--log-file` is used (otherwise it would appear twice on stderr).
- Logging to stderr never blocks and never fails: when the reader stalls (Ctrl+S, a pipe nobody reads), the threads that log (relay, DNS, signal handling) must not stall with it;
  when the reader closes, tracing by default reports the write failure with `eprintln!`, which itself panics when it fails. So `log_internal_errors` is turned off, and when stderr is a pipe or a terminal,
  a separate non-blocking open file description is opened (`/proc/self/fd/2`, leaving the one shared with the program unchanged); when that open is refused (someone else's terminal or pipe), each write is preceded by a poll,
  and the write happens only once writing is confirmed possible, at most 4 KiB at a time (`PIPE_BUF`); when it is a socket, `send(MSG_DONTWAIT)`; a regular file is written normally. Log lines that cannot be written are dropped.
- Each connection gets an increasing id, with span `conn{id=… target=…}`; at info level, one line with the routing result; at trace level a connection can be followed from the SYN arriving on the TUN all the way to the proxy handshake.
  **The pid of the process that opened the connection is not looked up** (it is not visible on the TUN, and searching `/proc` is expensive).
- **Connection summary at close** (info level): `closed ms dial_ms via up down`; a failure records the reason, a block records `blocked by a rule`.
  Byte counts are accumulated during forwarding by counters wrapped around the two sockets, so they are there even when an error occurs midway; they are also added to the global `relayed_up/down`, so a long-lived connection shows up in the stats before it ends.
- **DNS**: `-v` logs one line per query (fake IP / local empty answer / forwarded, with the upstream's latency); counters `dns_queries`, `dns_forwarded`, `dns_forward_failed`;
  the first time the upstream does not answer, a warn is logged once, after that at debug.
- **Proxy health**: only the proxy's own problems count against its health: cannot connect to the proxy, SOCKS5 greeting/authentication failure or timeout, protocol errors.
  - A proxy answers the connect request only once it has a result for the target (squid, ssh -D, dante), so a timeout after the request has been sent is the target's problem: not counted, and no retry with another proxy;
    otherwise connecting to a single black-hole address could mark a whole group of proxies DOWN, and the program would also wait for every member to time out once. The cost: an HTTP proxy that "accepts the TCP connection but never answers CONNECT"
    is not marked DOWN through connection failures (health probes of HTTP proxies only make a TCP connection).
  - A SOCKS5 proxy that accepts the connect request and then disconnects without replying (EOF/RST, which is exactly what `ssh -D` does when it cannot reach the target) is not counted against health, and the connection is retried with another member:
    another server may be able to reach it.
  - SOCKS5 0x03–0x06 (network/host unreachable, connection refused, TTL expired) and HTTP 502/504 are the target's problem: no member switch, and since the proxy answered, a success is recorded.
    SOCKS5 0x01 (general failure), 0x02 (not allowed by ruleset) and unknown codes, as well as HTTP 403, 500, 503 and the like, may come from the proxy's own upstream or access control:
    retry with another member; not counted as a failure, and since the proxy answered, a success is recorded.
    SOCKS5 0x07/0x08 (command or address type not supported) and HTTP 405/407 (CONNECT not supported, authentication failed) are this proxy's own problem: counted against health, retry with another member.
    When the proxy returned not a single byte (request timeout) or was never asked at all (a target no request can be built for: empty domain name, overlong domain name, failing before the proxy is even connected to), no success is recorded,
    otherwise the failure count would be reset and a node just marked DOWN would be brought back. The root domain `.` gets no fake IP.
  - The SOCKS5 greeting and request phases are timed separately, so a slow greeting does not get a request-phase timeout blamed on the target.
  - Local ephemeral port exhaustion is per destination address, and another proxy often still has ports, so on EADDRNOTAVAIL the connection is retried with another member (still not counted against health).
  - SOCKS5 health probes use the same greeting as real connections, authentication included; rejected authentication or no acceptable method counts as a failure, so such a node is not brought back by probes.
  - Known limitations: with an IPv6 proxy configured on a host with IPv6 disabled, the EADDRNOTAVAIL from connecting to it is also taken as port exhaustion, so the node never goes DOWN
    (every connection tries it once first, fails immediately, then switches member); `least-latency` favors HTTP in groups that mix SOCKS5 and HTTP (the SOCKS5 probe has one extra greeting round trip).
- **SIGUSR1**: cumulative counters (NAT table, connections, relayed bytes, DNS, packets and bytes received/sent on the TUN, drops broken down by reason), rates since the last print, and each proxy's state.
- **The TUN loop runs on a dedicated thread named `tun`** (blocking reads), so the bottleneck thread is obvious in `top -H`; compared with running inside the runtime, the throughput difference is within ±5% noise.

## 7. Command line and configuration

- Command line: `proxytun [options] program args...` (`--` optional), `-c` (default `proxytun.toml`), `--proxy`, `-q`, `-v`/`-vv`,
  `--log-level`, `--log-file`, `--doctor`; in addition `--no-sudo`, `--no-host-ports`. Environment variables `PROXYTUN_PROXY`, `PROXYTUN_LOG`.
  Arguments after the program name are passed to the program unchanged; arguments and environment variables are passed as bytes (UTF-8 not required).
- Config keys proxytun does not know (usually typos) get a warn at startup and are ignored rather than refused. The last /24 of `fake_ip_range`
  is kept for the namespace's own addresses, so the prefix is limited to /8–/22;
  the error says why. The example `proxytun.toml` contains only the required `[[proxies]]`; everything else is given in comments with its default value.
- `--doctor`: reports which mode will be used (userns / sudo / root). Rather than guessing from sysctls, it creates the namespaces once along the real run path and runs `true` as the program to completion;
  when userns is unavailable it gives the reason and lists the relevant sysctls (`max_user_namespaces`, `unprivileged_userns_clone`, AppArmor restrictions),
  and reports the sudo a run would use (the first `sudo` on PATH that is owned by root and has the setuid bit) without invoking it; it also checks `/dev/net/tun`, Yama (the scope of `gdb -p`), the host ports that will be forwarded, and every proxy (SOCKS5/HTTP probe).
  The exit status is 1 when there is any FAIL; when the config cannot be read, that is recorded as one FAIL and the remaining checks still run.

## 8. Code organization

- workspace: `crates/proxytun-core` (shared library) + `crates/proxytun` (the binary).
- core (`config`, `types`, `policy`, `balancer`, `health`, `proxy`, `sniff`, `net::{fakeip, dns, relay}`) only deals with a connection once it has been captured, whatever the capture method:
  the relay's entry point `relay::route()` gets just an accepted connection and its original target; DNS has only the answer/forward logic (`respond`) and `serve_tcp`, no listening server,
  and is handed the queries the capture side receives. core is split into small modules with narrow interfaces: `proxy::{socks5, http}` are the two handshakes,
  and `proxy` itself only handles dialing, switching members and attributing failures; `live` (`Live`, `build_live`) and `net::pump` (bidirectional copy and teardown, also used by host port forwarding) are separate from the relay,
  leaving the relay with only `route()`; `config::proxy_url` parses the `--proxy` URL. For how the modules on the binary side (`crates/proxytun`) divide the work, see
  [architecture/modules.md](architecture/modules_en.md).
- Proxy protocols and load balancing strategies are closed sets, so they use enums with exhaustive `match`, not traits: adding a protocol is one new file and one enum variant, plus the `match` arms the compiler points out.
- License GPL-2.0. Docs default to Chinese; the English versions are the `*_en.md` files alongside, kept in sync. Code comments in English. x86-64 only (gnu + musl static), no architecture-specific code.
- No heavy new dependencies: the TUN and address configuration use ioctl; the NAT table's capacity and timeouts take reasonable defaults, which are documented.
