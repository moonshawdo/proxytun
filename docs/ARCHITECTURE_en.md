# proxytun architecture

[简体中文](ARCHITECTURE.md) · **English**

> For users and future developers. After reading it you should be able to answer: what a connection from the program passes through between leaving the program and reaching the proxy; what each module is responsible for;
> which designs were forced by kernel or security constraints and need care before they are changed.
>
> **Suggested reading order**: readers new to network namespaces and TUN start with [section 0](architecture/primer_en.md) and the glossary;
> readers who only want to know "how the data flows" read from [section 1](architecture/overview_en.md) through section 3; those who will change the code go on from [section 4](architecture/modules_en.md) through section 8;
> those doing deployment or security review read [section 5](architecture/privilege_en.md). The reasons for every design trade-off are collected in [DESIGN.md](DESIGN_en.md).

The body is split by section into the pages below; each page starts with the same navigation. So that all diagrams render, each page has at most three diagrams.

| Page | Sections | Contents |
|---|---|---|
| [Primer](architecture/primer_en.md) | 0 | Network namespaces, user namespaces, mount namespaces, TUN, user-space address rewriting, other kernel mechanisms used, glossary |
| [Overview](architecture/overview_en.md) | 1–2 | The problem being solved, overall architecture (processes, threads and shared state) |
| [Core flows](architecture/flow_en.md) | 3.0–3.2 | The kinds of addresses, the startup flow, the full sequence of one HTTPS request |
| [Flow details](architecture/flow-details_en.md) | 3.3–3.6 | Handling of each packet on the TUN, the NAT table and entry states, relay decisions and sniffing, host port forwarding, fake DNS |
| [Modules](architecture/modules_en.md) | 4 | The two crates, what each module is responsible for, shared state and threads |
| [Run modes and the sudo helper](architecture/privilege_en.md) | 5 | The three modes userns / sudo / root, the sudo helper's flow and security boundary, installation requirements |
| [Processes, signals and lifecycle](architecture/lifecycle_en.md) | 6 | The process tree and the witness process, signal forwarding, exit, ignored signals and SIGPIPE, writing logs |
| [Load balancing and operations](architecture/operations_en.md) | 7–8 | Node selection, handshake failure classes and failover, health checks, hot reload, stats, logs, the various limits and behavior when they are exhausted |

Other documents:

| Document | Contents |
|---|---|
| [CONFIG.md](CONFIG_en.md) | Every config option: meaning, default, how it takes effect, examples and common errors |
| [PERFORMANCE.md](PERFORMANCE_en.md) | Performance test method, results and analysis |
| [DESIGN.md](DESIGN_en.md) | Design decisions and their reasons |
| [CENTOS7.md](CENTOS7_en.md) | Steps for verifying sudo mode on a real CentOS 7 machine |
