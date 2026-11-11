# proxytun architecture · 3.0–3.2 Core flows

[简体中文](flow.md) · **English**

> [Index](../ARCHITECTURE_en.md) · [0 Primer](primer_en.md) · [1–2 Overview](overview_en.md) · **3.0–3.2 Core flows** · [3.3–3.6 Flow details](flow-details_en.md) · [4 Modules](modules_en.md) · [5 Run modes and the sudo helper](privilege_en.md) · [6 Processes, signals and lifecycle](lifecycle_en.md) · [7–8 Load balancing and operations](operations_en.md)

## 3. Core flows

### 3.0 Telling the addresses apart

Taking the default `fake_ip_range = "198.18.0.0/15"` as an example:

| | Example | What it is | Who sees it |
|---|---|---|---|
| **Fake IP** | `198.18.0.1` | The "domain answer" fake DNS gives the program, taken from `fake_ip_range` minus its last /24 | The program (it believes it is connecting to this address) |
| **TUN address** | `198.19.255.1` | The address of `tun0` in the namespace; also the source address of the program's connections and the capture listener's address | The program, the namespace kernel |
| **Fake DNS address** | `198.19.255.53` | `/etc/resolv.conf` in the namespace points to it; queries to port 53 of any address are also answered by fake DNS | The program's resolver |
| **NAT source addresses** | `198.19.255.2`–`.17` : `1024`–`65535` | The keys of the NAT table: each TCP connection of the program gets one "address:port" | The namespace kernel, proxytun |
| **Capture listener** | `198.19.255.1:<random port>` | proxytun's listening socket in the namespace; every rewritten connection is accepted by it | proxytun |

In one sentence: **the fake IP answers "which domain is this", the NAT source address answers "which connection is this", the capture listener answers "who handles the connection".**

```mermaid
flowchart LR
    subgraph P["What the program sees"]
        A["DNS answer: example.com = 198.18.0.1"]
        B["connect(198.18.0.1:443)<br/>source address 198.19.255.1:59754"]
    end
    subgraph T["tun thread rewrites the headers"]
        C["SYN 198.19.255.1:59754 -> 198.18.0.1:443<br/>rewritten to<br/>198.19.255.2:1024 -> 198.19.255.1:L<br/>recorded in the NAT table"]
    end
    subgraph R["Relay (proxytun, host side)"]
        D["accept: peer = 198.19.255.2:1024<br/>NAT table lookup = 198.18.0.1:443<br/>fake IP pool lookup = example.com"]
        E["SOCKS5 CONNECT example.com:443<br/>sent to the upstream proxy"]
    end
    A --> B --> C --> D --> E
```

Key points:

- **A fake IP never appears on the network.** Packets the program sends to a fake IP only reach the TUN device and, rewritten, go to the listening socket in the namespace; UDP sent to a fake IP gets ICMP port unreachable.
- **The NAT source addresses never leave the namespace either**; they are only one end of TCP connections in the namespace kernel. 16 addresses × 64512 ports, about 1.03 million entries (see 3.4).
- The peer address the program sees is the address it connected to (`curl -w '%{remote_ip}'` prints `198.18.0.1`), because the rewriting happens at the packet header level and the program's socket is unaware of it.

Log excerpt from a real run (`proxytun -vv --proxy socks5://... curl https://www.baidu.com`, timestamps and lines unrelated to this section omitted), matching the flow above:

```
INFO  proxytun::app: namespace up tun=198.19.255.1 dns=198.19.255.53
DEBUG proxytun_core::net::dns: dns: A -> fake ip domain=www.baidu.com ip=198.18.0.1
                    ^ the program's A query reached fake DNS and got a fake IP
TRACE proxytun::capture: syn src=198.19.255.1:34830 dst=198.18.0.1:443 nat=198.19.255.2:1024
                    ^ the program connects to the fake IP; the SYN is rewritten to NAT source address 198.19.255.2:1024
TRACE conn{id=1}: proxytun::accept: accepted nat=198.19.255.2:1024 dst=198.18.0.1:443
INFO  conn{id=1 target=Domain("www.baidu.com", 443)}: proxytun_core::net::relay: routing decision=Proxy { group: "default" }
                    ^ the relay looks up the target by peer address, maps it back to the domain, and after the rule decision hands it to the proxy. Every later line of this connection carries the same conn{…}
http=200 remote_ip=198.18.0.1
INFO  proxytun::signals: program exited exit=Code(0)
```

### 3.1 Startup flow (user namespace mode)

```mermaid
sequenceDiagram
    autonumber
    participant PT as proxytun
    participant W as Witness process
    participant S as Setup process (later the program)
    participant K as Kernel

    Note over PT: set non-dumpable, clear PROXYTUN_PROXY<br/>record the signals the caller ignores<br/>take over INT / QUIT / TERM with signalfd
    PT->>W: double-fork the witness process (same process group)<br/>not created when INT / QUIT / TERM are all ignored by the caller
    Note over PT: read config, build fake IP pool, rules and proxy groups<br/>become subreaper, scan host ports
    PT->>S: fork, immediately execv(/proc/self/exe, __proxytun_setup)
    S->>K: unshare(USER | NET | NS), write uid_map / gid_map
    S->>K: bind mount resolv.conf, lo up<br/>create tun0, addresses and MTU, default route<br/>create capture listener, bind host port listeners
    S-->>PT: SCM_RIGHTS hands back TUN fd, capture listener, host port listeners
    Note over S: wait for the go-ahead (read control socket)
    Note over PT: raise own open-file limit, compute relay limit<br/>start tokio: relay, host ports, sweep, health probes, signals<br/>start tun thread
    PT->>S: go-ahead (write 1 byte)
    S->>K: restore signal mask and dispositions, execvp(program), same pid
    Note over PT: main thread waitpid(-1) until the whole process tree has ended
```

- **Why the setup process re-execs.** proxytun makes itself non-dumpable right at startup (to protect proxy credentials), and a forked child inherits that,
  so its `/proc/self/uid_map` is owned by root and cannot be written; making the child dumpable again would instead expose the memory copied from the parent (credentials included).
  After the re-exec, the new image holds no credentials and is dumpable again.
- **Why wait for the go-ahead.** Before the program is exec'd, proxytun must already be reading TUN and able to accept; otherwise nobody handles the program's first packet.
- Without unprivileged user namespaces, steps 2–5 (creating the setup process, creating and configuring the namespaces, handing back the fds) are done instead by the privileged helper that sudo starts,
  proxytun still sends the go-ahead in step 6, and the one that receives it and execs in step 7 is the program side, which the helper forks and which has already dropped privileges; see [section 5](privilege_en.md) for the flow. When run as root, no user namespace is created.

### 3.2 The full sequence of one HTTPS request

```mermaid
sequenceDiagram
    autonumber
    participant App as Program
    participant KN as Namespace kernel
    participant TT as tun thread
    participant Dns as Fake DNS
    participant Pool as FakePool
    participant Nat as NAT table
    participant Rl as Relay
    participant Px as Upstream proxy

    Note over App,Dns: ① Resolve the domain
    App->>KN: A? example.com sent to 198.19.255.53:53
    KN->>TT: UDP packet
    TT->>Dns: dispatch to tokio (in-flight queries ≤ 1024)
    Dns->>Pool: alloc(example.com)
    Pool-->>Dns: 198.18.0.1
    Dns->>KN: tokio task writes straight back to TUN<br/>source address is the address the program queried
    KN-->>App: A 198.18.0.1 (TTL 60)

    Note over App,Nat: ② Set up the connection (the kernel does TCP)
    App->>KN: connect(198.18.0.1:443)
    KN->>TT: SYN 198.19.255.1:59754 -> 198.18.0.1:443
    TT->>Nat: outbound: new entry 198.19.255.2:1024
    TT->>KN: rewritten SYN 198.19.255.2:1024 -> 198.19.255.1:L
    KN->>TT: capture listener replies SYN-ACK to 198.19.255.2:1024
    TT->>Nat: inbound: look up 198.18.0.1:443 / 198.19.255.1:59754
    TT->>KN: rewritten back to 198.18.0.1:443 -> 198.19.255.1:59754
    KN-->>App: connect returns
    App->>KN: final ACK of the three-way handshake
    KN->>TT: ACK
    TT->>KN: rewritten the same way and handed to the capture listener, connection enters the accept queue

    Note over Rl,Px: ③ Relay
    Rl->>KN: accept, peer 198.19.255.2:1024
    Rl->>Nat: accept: target 198.18.0.1:443
    Rl->>Pool: acquire(198.18.0.1) = example.com, pinned while the connection lasts
    Rl->>Rl: rule decision = Proxy{default}, node selected
    Rl->>Px: SOCKS5 CONNECT ATYP=3 example.com:443
    Px-->>Rl: success
    Rl-->>App: bidirectional copy (64 KiB buffer per direction)
```

DNS details: A queries are answered locally with a fake IP; AAAA, HTTPS (65) and SVCB (64) get an empty answer; `localhost` gets `127.0.0.1`; other types (MX/TXT/PTR...)
are forwarded from the host to `upstream_dns`. Whatever address the program queried, the answer is sent back with that address as its source; only then does the resolver accept it (see 3.6).

When the connection ends, the relay closes both ends (with RST on error, see 3.5), and the NAT table entry goes to "Closed" and is kept for 75 seconds, so the final FIN/ACK of the kernels on both ends can still be rewritten (see 3.4).
