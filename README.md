# proxytun

让**指定的程序及其全部子进程**走 SOCKS5 / HTTP 代理，并且**把域名一路带到代理**,Clash、sing-box 等就能按域名分流。
不使用 ptrace,所以 **strace、gdb、ltrace 照常可用**;普通用户即可运行，也支持 CentOS 7。

```bash
proxytun -c proxytun.toml curl https://example.com
proxytun --proxy socks5://172.25.32.1:7897 git clone https://github.com/user/repo
proxytun --proxy socks5://172.25.32.1:7897 strace -f -e trace=network ./my-static-binary
proxytun --proxy socks5://172.25.32.1:7897 gdb --args ./my-program
```

## 为什么需要它

| 现有方案 | 问题 |
|---|---|
| proxychains-ng(LD_PRELOAD) | 静态链接程序无效;程序启动子进程时清空 `LD_PRELOAD` 就逃出去了 |
| proxyhook / graftcp(ptrace) | 一个进程同一时刻只能有一个 tracer,不能与 strace / gdb / ltrace 同时使用 |
| tun2proxy `--unshare` | 依赖新版 util-linux 的 `unshare` 命令和非特权 user namespace,CentOS 7 上两者都没有;所有 TCP 都经代理，不处理本机回环服务 |
| 全局 TUN / 透明代理 | 需要 root,并且接管整台机器的流量 |

proxytun 把程序放进一个**私有网络命名空间**,命名空间唯一的出口是 proxytun 持有的 TUN 设备。命名空间是进程属性,fork/exec 时由内核继承，
与链接方式、环境变量、调试器都无关:

```
proxytun(主机网络，普通用户)
  ├─ TUN 上的 TCP  → 改写地址，交给命名空间内的监听 socket(内核 TCP 栈)→ 规则 → 代理 / 直连 / 丢弃
  ├─ TUN 上的 UDP  → 53 端口:fake-ip DNS;其余:ICMP 端口不可达(QUIC 回落 TCP)
  └─ 程序(私有网络 + 挂载命名空间，原用户身份)及其全部子进程
```

1. 程序问 DNS(命名空间里的 `/etc/resolv.conf` 指向假 DNS,发往任意 IP 53 端口的查询也一律拦下)→ 拿到假 IP(`198.18.0.0/15`),proxytun 记住 `假IP ↔ 域名`。
2. 程序连接假 IP → 包从 TUN 出来 → proxytun 反查回域名 → SOCKS5 `ATYP=3` 或 HTTP `CONNECT host:port` 交给代理。
3. 程序直连字面 IP 时按 `ip-cidr` 规则处理;80/443/8443 端口还会从首包的 TLS SNI / HTTP Host 恢复域名。

原理(含入门知识、流程图和各模块说明)见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),设计取舍见 [docs/DESIGN.md](docs/DESIGN.md)。

## 核心功能

- **保留域名**:代理收到的是域名而不是假 IP;程序直连字面 IP 时按 IP 规则处理，并尽量从首包恢复域名。
- **整棵进程树**:子进程、孙进程、`env -i` 清空环境后 exec 的程序、静态链接程序，全部在命名空间里。
- **调试工具可用**:`proxytun -- strace -f ...`、`proxytun -- gdb ...`、`proxytun -- ltrace ...`,也可以 `strace -f proxytun -- ...`,或从外部 `gdb -p`。
- **无需 root**:有非特权 user namespace 时直接用;没有时(CentOS 7)自动通过 `sudo` 启动一个短命的特权助手，程序仍以你自己的身份(uid、gid、附加组)运行，之后没有任何 root 进程。
- **DNS 全接管**:UDP 与 TCP、`/etc/resolv.conf` 与硬编码的 `8.8.8.8` 都由假 DNS 应答;AAAA、HTTPS、SVCB 本地答空，避免绕过假 IP;MX/TXT 等从主机转发给上游。
- **规则与负载均衡**(来自 proxyhook):`domain-suffix` / `domain-keyword` / `domain` / `ip-cidr` / `final`,动作 `proxy` / `direct` / `block`;
  6 种均衡策略，主动健康检查，故障转移，全部不可用时断开(**不会静默直连**)。目标被代理拒绝不算代理故障。
- **本机服务可达**:启动时把主机上监听回环地址的 TCP 端口转发进命名空间，程序照常连 `127.0.0.1:5432`。
- **行为与直接运行一致**:退出码(含被信号杀死)、Ctrl+C、`kill`、被忽略的信号都按程序自己的方式表现;程序自己配置的代理不会被二次代理。
- **不留痕迹**:TUN 不持久、命名空间匿名，退出(包括崩溃、`kill -9`)后内核自动回收;主机的网卡、路由、`resolv.conf` 都不动。proxytun 意外退出时程序断网，不会绕过代理直连。
- **运维**:`--doctor` 自检;`SIGHUP` 热加载;`SIGUSR1` 打印统计;日志分级与日志文件(同 proxyhook);`--proxy` / `PROXYTUN_PROXY` 覆盖代理地址。

## 开发栈

| 层 | 选型 |
|---|---|
| 语言 | Rust 2021(在 Rust 1.99 上开发和测试，更低版本未验证),Linux x86-64 |
| 流量捕获 | 网络 + 挂载命名空间(能用时加 user namespace)、TUN 设备、用户态地址改写，由内核 TCP 栈终止连接;用 ioctl 配网，不依赖 `ip` 命令和 netlink |
| 异步 | `tokio`(中继、DNS、健康探测、信号);TUN 收发在独立的 `tun` 线程上 |
| DNS 报文 | `hickory-proto` 0.24 |
| 系统调用 | `nix`、`libc` |
| 其他 | `ipnet`、`clap`、`serde` + `toml`(+ `serde_ignored` 报告拼错的键)、`tracing` + `tracing-subscriber`、`anyhow` |
| 无 user namespace 时 | sudo 启动的特权助手，经 unix socket 与 `SCM_RIGHTS` 交回 fd |
| 发布 | musl 静态二进制,CentOS 7 等旧系统可直接运行 |

## 编译依赖

- Rust stable(在 1.99 上开发和测试，推荐用 `rustup` 安装)。
- 构建本机版本只需要 `cargo` 和一个 C 链接器(`cc`)。
- 构建**静态版本**(给 CentOS 7 等旧系统用)还需要 musl target:`rustup target add x86_64-unknown-linux-musl`。
- 运行测试额外需要的工具见[测试](#测试)。

## 编译步骤

```bash
# 开发 / 本机使用
cargo build --release            # 产物: target/release/proxytun

# 静态版本，可在任意 glibc 版本的 x86-64 Linux 上运行(包括 CentOS 7)
./scripts/build-static.sh        # 产物: dist/proxytun-x86_64-linux-musl
```

> **不要把在新发行版上 `cargo build --release` 得到的二进制拷到 CentOS 7**:它链接了较新的 glibc 符号，在 glibc 2.17 上无法启动。
> 请用上面的静态构建。

## 使用说明

### 快速开始

```bash
# 1. 看当前机器是否满足要求、会用哪种模式(首次在新机器上务必先跑)
proxytun --doctor --proxy socks5://172.25.32.1:7897

# 2. 用配置文件
proxytun -c proxytun.toml curl -I https://example.com

# 3. 或者只指定代理地址(不需要配置文件)
proxytun --proxy socks5://172.25.32.1:7897 curl -I https://example.com
PROXYTUN_PROXY=http://user:pass@10.0.0.5:8080 proxytun git ls-remote https://github.com/user/repo

# 4. 看每条连接去了哪里、用了哪个出口
proxytun -v -c proxytun.toml curl https://example.com

# 5. 日志写到文件，终端只留程序自己的输出
proxytun --log-file ~/proxytun.log -c proxytun.toml curl https://example.com
```

proxytun 自己的选项写在程序名**之前**;从程序名起的所有参数原样交给程序，所以 `proxytun -c proxytun.toml curl -c cookies.txt https://x`
里第二个 `-c` 属于 curl。程序名前也可以加 `--`,效果相同。

proxytun 的退出码就是程序的退出码;程序被信号杀死时,proxytun 也以同一信号结束(与 `timeout`、sudo 相同:shell 循环里按 Ctrl+C 会停下，
systemd 停止服务时不算失败),不留 core。只要程序的进程树里还有进程在运行,proxytun 就继续运行。

### 命令行参数

| 参数 | 说明 |
|---|---|
| `-c, --config <FILE>` | 配置文件，默认 `proxytun.toml`。给了 `--proxy` 时可以不存在，也可以只写规则不写代理 |
| `--proxy <URL>` | 覆盖配置里的全部代理:`socks5://[user:pass@]IP:端口`(`socks5h://` 同)或 `http://[user:pass@]IP:端口`,主机必须是 IP(密码里的 `@ : /` 写成 `%40 %3A %2F`)。也可用环境变量 `PROXYTUN_PROXY`。指定了其他分组的规则也走它(启动和每次热加载时 warn)。**带密码时请用环境变量或配置文件**:命令行参数任何本机用户都能用 `ps` 看到,proxytun 会给出警告 |
| `--no-sudo` | user namespace 不可用时直接报错，不调用 sudo |
| `--no-host-ports` | 不把主机的回环监听端口转发进命名空间 |
| `--doctor` | 自检后退出;有 FAIL 时退出码为 1 |
| `-q, --quiet` | 只输出 error 级别的日志(等价 `--log-level error`) |
| `-v` / `-vv` | 输出 debug / trace 级别的日志 |
| `--log-level <LEVEL>` | `off`、`error`、`warn`、`info`(默认)、`debug`、`trace`;与 `-q`、`-v` 只能用一个 |
| `--log-file <PATH>` | 日志追加写入该文件(新建时权限 600),不再写 stderr;程序自己的输出不受影响。不跟随符号链接，已存在的文件必须是你自己的普通文件 |

### 配置文件

带注释的示例见 [proxytun.toml](proxytun.toml)(只有必填的 `[[proxies]]`,其余大多以注释给出默认值);**每一项的说明(默认值、取值范围、能否热加载、常见报错)
见 [docs/CONFIG.md](docs/CONFIG.md)**。格式与 proxyhook 相同,`proxyhook.toml` 可以直接用(`fake_ip_range` 比 /22 窄时要放宽)。要点:

```toml
# 顶层键必须写在任何 [表] 之前 (TOML 规则)
fake_ip_range = "198.18.0.0/15"  # 末尾 /24 留给命名空间自己, 所以至少 /22
# upstream_dns = "1.1.1.1:53"    # 非 A 查询的上游; 默认用主机 /etc/resolv.conf 的第一个 nameserver
localnet = ["192.168.0.0/16"]    # 这些字面 IP 从主机直连, 不看规则; 默认为空
direct_to_proxies = true         # 程序自己连下面的代理时直连, 不经代理绕一次
sniff = true                     # 字面 IP 连接从 TLS SNI / HTTP Host 恢复域名
sniff_ports = [80, 443, 8443]
host_ports_forward = true        # 主机的回环监听转发进命名空间
host_ports_exclude = []          # 程序要自己监听的端口
retries = 2                      # 代理握手失败时再换几个出口
connect_timeout_ms = 10000       # 连代理 / 直连 / 主机端口的建连超时; 连代理超时换下一个成员, 无可换时向程序发 RST
handshake_timeout_ms = 10000     # 与代理握手每一步的超时: SOCKS5 问候认证, 等代理回复请求 / CONNECT

[[proxies]]
name = "clash"
type = "socks5"                  # 或 "http"
addr = "172.25.32.1:7897"        # 必须是 IP; proxytun 从主机连它, 127.0.0.1 指主机

[[rules]]                        # 从上到下, 第一条命中的生效
match = "domain-suffix"
value = "cn"
action = "direct"

[[rules]]
match = "final"
action = "proxy"                 # 可写 group = "<组名>"
```

规则说明:

- 域名类规则(`domain*`)在程序**经假 DNS 解析了域名**(或嗅探恢复出域名)时生效;`ip-cidr` 在程序**直接连字面 IP** 时生效。
- 有 `ip-cidr` 规则覆盖的字面 IP 不做嗅探替换，以 IP 规则为准。
- 没有任何规则命中、也没有 `final` 时走 `default` 组(**不会**默认直连)。
- `direct` 对域名目标由 proxytun 用主机的系统解析器解析真实 IP 后连接(程序拿到的只是假 IP)。
- 配置文件里写了代理密码而文件对组或其他用户可读时，启动会提示 `chmod 600`;拼错的键名会警告并忽略。

常见用法(完整写法见 [CONFIG.md 第 9 节](docs/CONFIG.md#9-配置示例)):

| 场景 | 写法 |
|---|---|
| 只有一个代理 | 只写一个 `[[proxies]]`;或不要配置文件，直接 `--proxy` |
| 配置文件不含密码、可以放进版本库 | 配置文件只写规则，代理放在 `PROXYTUN_PROXY=http://user:pass@...` |
| 局域网、国内域名直连，其余走代理 | `localnet` 写局域网网段;`match = "domain-suffix"`、`value = "cn"`、`action = "direct"` 等规则,最后 `final` → `proxy` |
| 多个代理选最快的，个别网站固定出口 | `[[groups]]` 的 `strategy = "least-latency"`;另建 `strategy = "hash"` 的组，用规则的 `group` 指过去 |
| 阻断某些域名 | `action = "block"` |
| 程序要监听主机上已占用的端口 | `host_ports_exclude = [端口]` |

### 多代理与负载均衡

```toml
[[proxies]]
name = "hk"
type = "socks5"
addr = "10.0.0.1:1080"
weight = 3                       # 仅 weighted-round-robin 使用, 1~1000

[[proxies]]
name = "jp"
type = "http"
addr = "10.0.0.2:8080"
username = "u"
password = "p"

[[groups]]
name = "default"                 # 必须有 default; 没写 group 的规则用它
strategy = "least-latency"
members = ["hk", "jp"]

[[groups]]
name = "sticky"
strategy = "hash"                # 同一个域名总走同一个出口
members = ["hk", "jp"]
```

| 策略 | 行为 |
|---|---|
| `round-robin` | 依次轮流(默认) |
| `random` | 随机(种子取自 `/dev/urandom`,每次启动和热加载都不同) |
| `least-conn` | 当前活跃连接最少的;平局时轮转 |
| `least-latency` | 到代理的探测延迟(EWMA)最低的;还没有样本时先轮转 |
| `weighted-round-robin` | 按 `weight` 比例轮流 |
| `hash` | 按目标主机一致性哈希，出口下线时只迁移它负责的主机 |

健康检查:每 `health.interval_secs` 秒并发探测所有代理(TCP 连接,SOCKS5 再做一次含认证的问候),连续 `fail_threshold` 次失败标记 DOWN,
之后一次探测成功即恢复。代理应答失败时分三种：明确是目标的问题(SOCKS5 0x03~0x06、HTTP 502/504、等代理回复请求超时)直接断开，不算代理故障也不重试;
说不清或是代理自己的规则(SOCKS5 0x01/0x02、HTTP 403/500/503 等，以及 SOCKS5 代理收下请求后直接断开)换别的成员再试，但不算代理故障;
代理自己的问题(连不上或建连超时、SOCKS5 问候 / 认证超时或被拒、SOCKS5 0x07/0x08、HTTP 405/407、HTTP 代理回应前断开)算代理故障并换成员。细节见 [ARCHITECTURE 第 7 节](docs/architecture/operations.md)。

### 运行模式

| 情况 | 怎么建命名空间 | 程序的身份 |
|---|---|---|
| 有非特权 user namespace(大多数新发行版、WSL2) | 自己建，无需任何权限 | 你自己(uid/gid 映射为自身) |
| 没有(CentOS 7 默认、`max_user_namespaces=0`、AppArmor 限制) | 调 `sudo` 启动特权助手 | 你自己(含附加组),能力全部清空 |
| 以 root 登录后运行 proxytun | 直接建(不用 user namespace) | root(完整能力) |

sudo 模式下，特权助手只做建命名空间这一件事，建好后立即退出，之后没有 root 进程。它的安全边界(只为运行 sudo 的那个进程服务、
身份只取自内核、请求逐项重新校验、从不以 root 接收你传来的 fd、程序先完全降权并设置 `no_new_privs` 等)见
[ARCHITECTURE 第 5 节](docs/architecture/privilege.md)。sudoers 给命令设了 SELinux `ROLE`/`TYPE`、开了 `intercept` / `log_subcmds`,
或容器的 seccomp 配置禁止了 keyctl 时，助手拒绝运行。

proxytun 拒绝经 sudo、doas、pkexec 或 setuid 以 root 身份运行(只有特权助手例外):即使 sudoers 只放行了 proxytun,也拿不到一个 root 程序。
需要 root 模式，请以 root 登录(或 `su -`)后运行。**只用 sudo 授权 proxytun**,不要用 ksu、userhelper/consolehelper、`systemd-run --uid=0`
等方式让普通用户以 root 运行它：这些方式不留可识别的痕迹,proxytun 会当成真正的 root。`--no-sudo` 禁止回退到 sudo。

sudo 以 root 身份执行 proxytun 自己的可执行文件，所以要放在只有 root 能写的位置(普通用户能改它，就等于能以 root 执行任意代码)。想免密码时，只放行特权助手:

```bash
sudo install -o root -g root -m 0755 dist/proxytun-x86_64-linux-musl /usr/local/bin/proxytun
# visudo -f /etc/sudoers.d/proxytun
alice ALL=(root) NOPASSWD: /usr/local/bin/proxytun __proxytun_root_setup *
```

### 访问本机服务

命名空间里的 `127.0.0.1` 是隔离的。proxytun **启动时**扫描一次主机上正在监听的 TCP 端口，按同样的地址开进命名空间:

| 主机上 | 命名空间里 |
|---|---|
| `127.x.x.x:P` | 同一地址 |
| `0.0.0.0:P` | `127.0.0.1:P` |
| `[::1]:P` | `[::1]:P` |
| `[::]:P` | `127.0.0.1:P` 与 `[::1]:P` |

- 53 端口不转发(DNS 必须由假 DNS 应答)。
- 启动之后主机上新开的端口看不到，需要时重启程序。
- 程序要在同一端口上自己监听会失败(`EADDRINUSE`),用 `host_ports_exclude` 排除，或 `--no-host-ports`。

### 调试工具

```bash
proxytun -c proxytun.toml strace -f -e trace=network ./prog          # strace 在命名空间里
strace -f -o trace.txt proxytun -c proxytun.toml ./prog              # strace 在外面，连 proxytun 一起跟
proxytun -c proxytun.toml gdb --args ./prog                          # gdb 在命名空间里
gdb -p <程序的 pid>                                                   # 从外面附加
proxytun -c proxytun.toml ltrace -f ./prog
```

从外面 `gdb -p` / `strace -p` 的限制与不用 proxytun 时相同:Yama `ptrace_scope=1`(Ubuntu、WSL2 默认)时只能附加自己的后代进程,
`--doctor` 会报告当前设置。

### 运行时控制

| 操作 | 效果 |
|---|---|
| Ctrl+C(终端发给整个前台进程组) | 程序自己处理;proxytun 不重复转发，等程序退出后随之退出。程序自成一组时(sudo `use_pty`),proxytun 转给它的整个进程组，管道里的其他进程也收到 |
| `kill <proxytun pid>`、`pkill proxytun`、`killall proxytun`(只发给 proxytun) | 转发给程序，恰好一次(见证进程叫 `signal-witness`,不会被这些命令选中) |
| `kill %1`、`kill -- -<pgid>`、systemd 逐进程发送 | 程序已经收到，不重复转发(靠一个"见证进程"判断)。程序不在 proxytun 的进程组时(sudo `use_pty`),逐进程发送会让它收到两份 |
| 第二次 `SIGTERM`(不论间隔多久);或主程序已退出、只剩后台子进程时按 Ctrl+C | proxytun 立即以该信号结束 |
| `kill -HUP <pid>` | 重新加载规则、localnet、`direct_to_proxies`、代理和分组、`retries`、`connect_timeout_ms`、`handshake_timeout_ms`、嗅探与健康检查设置;配置有错则保留旧配置 |
| `kill -USR1 <pid>` | 打印统计：假 IP 数、地址改写表大小、连接数、流量、DNS 查询数、按原因分开的丢弃、各代理的健康与延迟 |
| proxytun 被 `kill -9` 或崩溃 | 程序**不会被杀**,继续运行但断网(TUN 已随 proxytun 消失),不会绕过代理直连 |

启动时被忽略的信号(`nohup`、脚本里的 `cmd &`、`trap '' PIPE`)在程序里保持忽略(sudo 模式下 SIGPIPE 一定如此，其他信号取决于 sudo 是否把原有处置留给命令)。`fake_ip_range`、`upstream_dns` 和主机端口转发需要重启才能改变。
信号处理的细节与边界情况见 [ARCHITECTURE 第 6 节](docs/architecture/lifecycle.md)。

### 日志

| 级别 | 选项 | 内容 |
|---|---|---|
| `off` | `--log-level off` | 不输出(启动失败的错误仍打印到终端) |
| `error` | `-q` | 需要处理的问题：配置重载失败、地址改写表满、假 IP 池满 |
| `warn` | `--log-level warn` | 降级但仍可用：改用 sudo 模式、代理 DOWN、拨号失败换节点、fd 不足、配置文件权限、`--proxy` 带密码、拼错的配置键 |
| `info` | 默认 | 启动与退出(版本、程序名、转发的主机端口、退出方式)、每条连接两行(选路结果、结束汇总)、代理恢复、重载成功、`SIGUSR1` 统计 |
| `debug` | `-v` | 每条 DNS 查询(`dns: A -> fake ip`、`dns: forwarding upstream`、上游耗时)、嗅探结果、不计健康的代理重试原因(目标被拒、代理断开) |
| `trace` | `-vv` | TUN 上的每个 SYN 与它改写用的地址，可以从 SYN 一直跟到连接结束 |

- 没给级别选项时读环境变量 `PROXYTUN_LOG`:可以是一个级别，也可以按模块写，如 `proxytun=info,proxytun::capture=trace,proxytun::accept=trace`(TUN 上的 SYN,以及接走它的是哪条连接)。命令行选项优先。
- **跟踪一条连接**:每条连接有一个递增编号，日志里写作 `conn{id=… target=…}`。默认级别下每条连接两行(下面省略了时间、级别和模块名):

  ```
  conn{id=1 target=Domain("example.com", 443)}: routing decision=Proxy { group: "default" }
  conn{id=1 target=Domain("example.com", 443)}: closed ms=812 dial_ms=35 via=clash up=812 down=153204
  ```

  `ms` 是连接存活时长,`dial_ms` 是出站建连用的时间(经代理时含连代理、握手直到代理回复已连上目标，以及换成员重试;直连时含解析域名),`via` 是用的代理节点(`direct` / `host` 表示直连 / 主机端口),
  `up`、`down` 是两个方向的字节数。失败时写成 `closed: <原因>`,被规则拦下写成 `closed: blocked by a rule`。日志不记录是哪个进程发起的连接。
- **写 stderr 从不阻塞也不报错**:读端停住(Ctrl+S、没人读的管道)时写不下的日志行直接丢弃，读端关掉(`2>&1 | head`、终端断开)时日志丢失，
  proxytun 和程序照常运行。要完整的日志请用 `--log-file`。
- **`--log-file` 与程序的输出**:只有 proxytun 自己的日志写进文件，程序的 stdin/stdout/stderr 原样继承，程序也不会继承这个日志文件。
  文件是追加写，新建时权限 600(`info` 级别会记下访问过的每个域名)。

### 程序自己配置了代理怎么办

程序环境变量里的 `http_proxy` / `https_proxy` / `all_proxy` 指向的代理会被直连，不会被二次代理:写的是 `IP:端口` 时连它直连，
写的是主机名时连"主机名:端口"按 `direct` 处理;不写端口时,`http://` 或不带 scheme 的 80 和 1080 都算(curl、git 用 1080,pip、Go、wget、npm、apt 用 80),`https://` 为 443,`socks5://` 等为 1080。
程序直接连 `[[proxies]]` 里的某个代理(`curl -x`)时同样直连(`direct_to_proxies`,默认开)。代理在主机回环上
(如 `http_proxy=http://127.0.0.1:7890`)时，只要启动时在监听，就经主机端口转发自然可用。proxytun 不改写、不删除这些环境变量。

### 在 CentOS 7 上使用

1. 用 `scripts/build-static.sh` 在新机器上构建静态二进制，拷到 CentOS 7,按[运行模式](#运行模式)一节的方法安装到 `/usr/local/bin`。
2. 先运行 `proxytun --doctor --proxy socks5://代理IP:端口`。CentOS 7 默认没有非特权 user namespace,应报告会使用 sudo 模式。
3. 实际代理一次，确认整条链路通:
   ```bash
   proxytun --proxy socks5://代理IP:端口 getent hosts example.com      # 应得到 198.18.x.x
   proxytun -v --proxy socks5://代理IP:端口 curl -sI https://example.com
   ```
   curl 正常返回，日志里有 `asking sudo` 和 `target=Domain("example.com", 443)`,就说明 sudo 模式工作、代理收到的是域名。

**验证情况**:sudo 模式在开发机上用"外层 user namespace + `max_user_namespaces=0` + setuid 的假 sudo"模拟 CentOS 7 并全部通过;
**CentOS 7 真机**(3.10 内核、真实 sudo 1.8.23、SELinux)尚未验证。逐步验证的方法见 [docs/CENTOS7.md](docs/CENTOS7.md),欢迎反馈结果。

## 测试

```bash
cargo test                                         # 单元测试 + 端到端测试
cargo test --target x86_64-unknown-linux-musl      # 同一套测试跑静态版本
cargo test --release --test bench -- --ignored --nocapture --test-threads=1   # 性能基准
```

- **单元测试**覆盖所有纯逻辑：配置校验与覆盖、规则引擎、假 IP 池(LRU、钉住、回收间隔)、负载均衡策略、健康检查、SOCKS5 / HTTP 握手字节与失败分类、
  DNS 应答与转发校验、嗅探、包解析与地址改写(含校验和)、地址改写表的状态机与分批清扫、sudo 助手的请求编码与校验、信号转发判断、中继上限的计算。
- **端到端测试**用真实的命名空间和 TUN 跑 `curl`、`python3`、`dig`、`strace`、`gdb`、`ltrace` 等，由内置的 mock SOCKS5 / HTTP 代理记录代理端实际收到的是域名还是 IP。
  覆盖:域名保留、字面 IP 与嗅探、各条 DNS 路径(含硬编码的 `8.8.8.8` 与 TCP DNS)、规则、localnet、主机端口转发、调试器、退出码与信号
  (伪终端上真实的 Ctrl+C、`kill`、`pkill`、整组信号、`sigwait` 程序、被忽略的信号)、作为 pid 1 或 subreaper 运行、stderr 停住或断开、
  fd 耗尽、挂载传播、热加载、`--doctor`,以及**模拟 CentOS 7 的 sudo 模式**(用户身份、资源限制、umask、继承的 fd、会话 keyring、
  拒绝被跟踪或被过滤的 sudo、恶意的助手客户端)。
- 端到端测试需要 `curl`、`python3`、`cc`、`strace`、`gdb`、`ltrace`、`dig`、`pkill`、`mount`、`unshare`(util-linux);sudo 模式的测试和一个 stderr 用例
  另需 `newuidmap`(uidmap 包)、`setpriv`、支持 `--map-auto` 的 `unshare`(util-linux ≥ 2.38)和 `/etc/subuid` 里的区间。宿主机建不了 proxytun 的命名空间时，所有端到端用例都 SKIP。
  缺少时对应用例打印 `SKIP`(用 `-- --nocapture` 才看得到)并按通过计;例外是那个 stderr 用例，`unshare` 不支持 `--map-auto` 时它会失败而不是 SKIP。
- 测试目录在 `$TMPDIR/proxytun-test-<pid>-*`,保留到下一次运行时尽量删除(只删本用户的、原进程已退出的),便于查看失败现场。

### 性能

基准在本机回环上，用同一个客户端对比"经 proxytun"与"不经 proxytun"(Intel i5-8265U,WSL2,内核 6.18):

| 测试 | proxytun | 不经 proxytun |
|---|---|---|
| 1 GiB 下载，经 TUN 捕获、经 SOCKS5 代理 | **约 1130 MB/s** | 约 2050 MB/s(curl 自己连代理) |
| 1 GiB 下载，主机端口转发 | **约 1190 MB/s** | 约 4060 MB/s(直连本机端口) |
| 短连接，每条 | **+0.53 ms** | |
| 假 DNS,顺序 A 查询 | **约 4500 次/秒** | |
| `proxytun -- true` 启动到退出 | **约 90 ms** | |

单连接吞吐的上限在 `tun` 线程(下载时约 95% CPU),约 1 GB/s,远高于真实代理与网络的速度。测试方法、更多数据与分析见 [docs/PERFORMANCE.md](docs/PERFORMANCE.md)。

## 不支持的功能

**平台与进程**
- 只在 **Linux x86-64** 上构建和测试(gnu 与 musl 静态)。
- 需要 TUN 设备(`/dev/net/tun`)。管理员限制了它(权限 0600、容器的设备 cgroup)时直接报错，不会改用 sudo 绕过;容器里要 `--device /dev/net/tun`。
- **setuid 程序**:`sudo`、`su`、`ping` 等在里面都不能提权。user namespace 模式下 root 拥有的文件显示为 `nobody`;sudo 模式下程序带着 `no_new_privs`。
- **sudo 的 `use_pty`**(Ubuntu 22.04+、Debian 12、sudo ≥ 1.9.14 默认开，CentOS 7 默认没开):sudo 模式下程序在自己的会话里运行，没有控制终端:
  Ctrl+C、Ctrl+\ 由 proxytun 转给它，但 Ctrl+Z 作业控制、窗口大小变化到不了它，要打开 `/dev/tty` 的程序(如密码提示)会失败。proxytun 会警告。
- **抽象 unix socket** 按网络命名空间隔离(X11 会回落到 `/tmp/.X11-unix` 路径，通常不受影响);文件路径型 unix socket 不受影响。
- 只认得 sudo 这一种提权方式来启动特权助手;容器的 seccomp 配置禁止了 keyctl 时,sudo 模式拒绝运行。

**网络**
- 只代理 **TCP**。DNS 以外的 UDP(含 QUIC)立即收到端口不可达;不支持 SOCKS5 `UDP ASSOCIATE`。
- **ICMP** 丢弃,ping 不通。
- **IPv6** 不支持：命名空间里没有 IPv6 路由,AAAA 查询返回空，字面 IPv6 连接立即"网络不可达"。
- **DoH / DoT** 不能拦截;经 systemd-resolved / nscd 的 unix socket 解析(`nsswitch.conf` 里的 `resolve`)也会拿到真 IP。这些只能靠首包嗅探恢复域名，
  而嗅探不适用于：真正使用 ECH 的连接、不在 `sniff_ports` 里的端口、服务器先发数据的协议。`/etc/hosts` 照常生效。
- **HTTPS / SVCB(类型 65 / 64)DNS 记录**一律本地答空，程序拿不到 ECH 密钥和 IP 提示。
- 程序看到的 `resolv.conf` 去掉了 `options ndots:N`(其余照留)。
- 代理协议只支持 SOCKS5(无认证 / 用户名密码，仅 `CONNECT`)和 HTTP `CONNECT`(Basic 认证)。不支持 SOCKS4、到代理的 TLS、代理链。
  代理地址必须是 IP。SOCKS5 域名最长 255 字节。
- 主机端口转发只转发 TCP,且只转发启动时已在监听的端口。

**功能**
- 热加载(`SIGHUP`)不改变 `fake_ip_range`、`upstream_dns` 和主机端口转发。
- fake-ip 映射不落盘，重启后失效。
- 地址改写表最多约 103 万条(含关闭后保留 75 秒的),即持续每秒约 1.37 万条新连接;同时中继的连接最多 8192 条(fd 上限低时更少)。
  超出时新连接立即收到 RST,不会卡住重试。
- 信号的几种边界情况(50 ms 内连发两次 SIGTERM 等)见 [ARCHITECTURE 第 6 节](docs/architecture/lifecycle.md)。
- **CentOS 7 真机**尚未验证，见上文。

## 项目结构

```
crates/proxytun-core/  代理侧: 配置、规则、负载均衡与健康检查、SOCKS5/HTTP 握手、假 IP 池与假 DNS、嗅探、中继
crates/proxytun/       捕获侧与程序: 命名空间与 TUN、地址改写、sudo 助手、见证进程、主机端口、自检、命令行
  tests/e2e.rs         端到端测试(真实命名空间、TUN、调试器, 模拟 CentOS 7 的 sudo 模式)
  tests/bench.rs       性能基准
scripts/               build-static.sh 静态构建
docs/                  ARCHITECTURE.md 技术架构索引(正文分篇在 architecture/), CONFIG.md 配置项说明,
                       PERFORMANCE.md 性能测试, DESIGN.md 设计决策, CENTOS7.md CentOS 7 验证步骤
proxytun.toml          带注释的示例配置
```

## 排错

| 现象 | 排查 |
|---|---|
| `user namespaces are not usable here` 后 `sudo failed` | 没有非特权 user namespace,sudo 也没成功：确认能 sudo,或按[运行模式](#运行模式)配置免密规则;`--doctor` 会说明原因 |
| `open /dev/net/tun: Permission denied` | 管理员限制了 TUN 设备(这时不会改用 sudo);容器里加 `--device /dev/net/tun` |
| `proxytun refuses to run as root through sudo` | 不要 `sudo proxytun`:以自己的身份运行,proxytun 需要时会自己调 sudo |
| sudo 模式报 `security context` / `traced` / `syscall filter` / `session keyring` | sudoers 设了 `ROLE`/`TYPE`、开了 `intercept` / `log_subcmds`,或容器禁止了 keyctl:去掉这些设置，或在容器的 seccomp 配置中放行 keyctl |
| `the helper socket ... is too long a path` | `$TMPDIR` 太长，换一个短的目录 |
| `no healthy proxy available` | 代理已被标记 DOWN:检查代理地址与连通性,`kill -USR1` 看各代理状态 |
| 某个连接失败 | info 级别的 `closed: <原因>`;`-v` 看代理重试经过 |
| 慢 | `closed` 行:`dial_ms` 大是连代理、代理连目标或直连慢(`-v` 看是否换过成员);`dial_ms` 小而 `ms` 大、字节数不多，是代理或目标传得慢 |
| 吞吐上不去 | `kill -USR1` 的速率行;`top -H -p <pid>` 里名为 `tun` 的线程接近 100% 时，是到了 proxytun 本身的上限(约 1 GB/s),否则瓶颈在代理 |
| 域名解析不了 / 很慢 | `-v` 的 `dns:` 行;统计里的 `dns_forward_failed`(上游第一次不应答时会 warn);检查 `upstream_dns` |
| 代理端看到的是 IP 而不是域名 | 程序没有经过假 DNS(DoH、硬编码 IP、经 nscd / systemd-resolved 解析):端口在 `sniff_ports` 里吗?地址是内网地址或有 `ip-cidr` 规则吗(这两种不嗅探)? |
| 程序连不上本机的 `127.0.0.1:P` | 服务是不是在 proxytun 启动之后才开的?端口是否在 `host_ports_exclude` 里、是否用了 `--no-host-ports`?启动日志列出了转发的端口 |
| 程序在命名空间里监听报 `EADDRINUSE` | 主机上同一端口有服务，被转发进来了:`host_ports_exclude` 排除它 |
| 连接卡住 | 统计里的丢弃计数:`dropped_no_flow`(找不到连接的 TCP 包)、`dropped_table_full`(地址改写表满)、`relays_refused`(同时中继的连接已达上限，启动时 warn 写明上限;CentOS 7 默认 fd 上限 4096 约 1870 条)、`dropped_dns_busy`(同时处理的 DNS 查询已达 1024 个)、`dropped_unparsed`(IPv6、分片)、`dropped_other_proto`(ICMP 等) |

## 许可证

GPL-2.0(代码来自 proxyhook)。
