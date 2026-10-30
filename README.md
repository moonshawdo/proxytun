# proxytun

让**指定的程序及其全部子进程**走 SOCKS5 / HTTP 代理,并且**把域名一路带到代理**,
Clash、sing-box 等就能按域名分流。不使用 ptrace,所以 **strace、gdb、ltrace 照常可用**。

```bash
proxytun -c proxytun.toml curl https://example.com
proxytun --proxy socks5://172.25.32.1:7897 git clone https://github.com/user/repo
proxytun --proxy socks5://172.25.32.1:7897 strace -f -e trace=network ./my-static-binary
proxytun --proxy socks5://172.25.32.1:7897 gdb --args ./my-program
```

## 为什么需要它

| 方案 | 问题 |
|---|---|
| proxychains-ng(LD_PRELOAD) | 静态链接程序无效;程序启动子进程时清空 `LD_PRELOAD` 就逃出去了 |
| proxyhook(ptrace) | 一个进程同一时刻只能有一个 tracer,不能与 strace / gdb / ltrace 同时使用 |
| tun2proxy `--unshare` | 依赖新版 util-linux 的 `unshare` 命令和非特权 user namespace,CentOS 7 上两者都没有;程序以 root 身份运行;不处理本机回环服务 |
| 全局 TUN / 透明代理 | 需要 root,并且接管整台机器的流量 |

proxytun 把程序放进一个**私有网络命名空间**,命名空间唯一的出口是 proxytun 持有的 TUN 设备。命名空间是进程属性,fork/exec 时由内核继承,
与链接方式、环境变量、调试器都无关。设计决策见 [docs/DESIGN.md](docs/DESIGN.md)。

## 工作原理

```
proxytun(主机网络,普通用户)
  ├─ TUN 上的 TCP  → 改写地址,交给命名空间内的监听 socket(内核 TCP 栈)→ 规则 → 代理 / 直连 / 丢弃
  ├─ TUN 上的 UDP  → 53 端口:fake-ip DNS;其余:ICMP 端口不可达(QUIC 回落 TCP)
  └─ 程序(私有网络 + 挂载命名空间,原用户身份)及其全部子进程
```

1. 程序问 DNS(`/etc/resolv.conf` 在命名空间里被换成假 DNS;发往任意 IP 53 端口的查询也一律拦下)→ 拿到假 IP(`198.18.0.0/15`),proxytun 记住 `假IP ↔ 域名`。
2. 程序连接假 IP → 包从 TUN 出来 → proxytun 反查回域名 → SOCKS5 `ATYP=3` 或 HTTP `CONNECT host:port` 交给代理。
3. 程序直连字面 IP 时按 `ip-cidr` 规则处理;80/443/8443 端口还会从首包的 TLS SNI / HTTP Host 恢复域名。

## 核心功能

- **保留域名**:代理收到的是域名而不是假 IP。
- **整棵进程树**:子进程、孙进程、`env -i` 清空环境后 exec 的程序、静态链接程序,全部在命名空间里。
- **调试工具可用**:`proxytun -- strace -f ...`、`proxytun -- gdb ...`、`proxytun -- ltrace ...`,也可以 `strace -f proxytun -- ...`,或从外部 `gdb -p`。
- **无需 root**:有非特权 user namespace 时直接用;没有时(CentOS 7)自动通过 `sudo` 启动一个短命的特权助手,程序仍以你自己的身份(uid、gid、附加组)运行,之后没有任何 root 进程。
- **规则与负载均衡**(来自 proxyhook):`domain-suffix` / `domain-keyword` / `domain` / `ip-cidr` / `final`,6 种均衡策略,健康检查,故障转移,全部不可用时断开(**不会静默直连**)。
- **本机服务可达**:启动时把主机上监听回环地址的 TCP 端口转发进命名空间,程序照常连 `127.0.0.1:5432`。
- **不留痕迹**:TUN 不持久、命名空间匿名,退出(包括崩溃、`kill -9`)后内核自动回收;主机的网卡、路由、`resolv.conf` 都不动。
- **零拷贝转发**:`splice(2)`。
- **运维**:`--doctor` 自检;`SIGHUP` 热加载;`SIGUSR1` 打印统计;日志分级与日志文件(同 proxyhook)。

## 运行模式

| 情况 | 怎么建命名空间 | 程序的身份 |
|---|---|---|
| 有非特权 user namespace(大多数新发行版、WSL2) | 自己建,无需任何权限 | 你自己(uid/gid 映射为自身) |
| 没有(CentOS 7 默认、`max_user_namespaces=0`、AppArmor 限制) | 调 `sudo` 启动特权助手 | 你自己(含附加组),能力全部清空 |
| 以 root 运行 proxytun | 直接建(不用 user namespace) | root(完整能力) |

sudo 模式的安全边界:特权助手只为 `SUDO_UID` 服务(核对 socket 对端),程序的 gid 和附加组取自你的进程在 `/proc` 里的记录,
不读配置、不以 root 打开你给的任何路径;它先降权再进入你的工作目录、按你的 `PATH` 找程序,把 fd 交回后立即退出。
`--no-sudo` 禁止回退到 sudo。

## 编译

```bash
cargo build --release            # target/release/proxytun
./scripts/build-static.sh        # dist/proxytun-x86_64-linux-musl:静态版本,可在 CentOS 7 等旧系统上运行
```

需要 Rust stable(在 1.99 上开发和测试);静态版本另需 `rustup target add x86_64-unknown-linux-musl`。
不要把在新发行版上 `cargo build` 出的动态版本拷到 CentOS 7:它链接了较新的 glibc 符号。

## 使用说明

### 快速开始

```bash
proxytun --doctor --proxy socks5://172.25.32.1:7897      # 新机器上先跑一次
proxytun -c proxytun.toml curl -I https://example.com
proxytun --proxy socks5://172.25.32.1:7897 curl -I https://example.com
PROXYTUN_PROXY=http://user:pass@10.0.0.5:8080 proxytun git ls-remote https://github.com/user/repo
proxytun -v --log-file proxytun.log -c proxytun.toml curl https://example.com
```

proxytun 自己的选项写在程序名**之前**,从程序名起的参数原样交给程序;程序名前的 `--` 可写可不写。
proxytun 的退出码就是程序的退出码(信号终止为 `128+信号`)。只要程序的进程树里还有进程在运行,proxytun 就继续运行。

### 命令行参数

| 参数 | 说明 |
|---|---|
| `-c, --config <FILE>` | 配置文件,默认 `proxytun.toml`。给了 `--proxy` 时可以不存在 |
| `--proxy <URL>` | 覆盖配置里的全部代理:`socks5://host:port` 或 `http://[user:pass@]host:port`。也可用环境变量 `PROXYTUN_PROXY`。带密码时请用环境变量或配置文件(命令行参数任何本机用户都能用 `ps` 看到) |
| `--no-sudo` | user namespace 不可用时直接报错,不调用 sudo |
| `--no-host-ports` | 不把主机的回环监听端口转发进命名空间 |
| `--doctor` | 自检后退出;有 FAIL 时退出码为 1 |
| `-q` / `-v` / `-vv` / `--log-level <LEVEL>` | 日志级别:error / debug / trace / 指定。只能用其中一个 |
| `--log-file <PATH>` | 日志追加写入该文件(新建时权限 600),不再写 stderr;程序自己的输出不受影响 |

### 配置文件

格式与 proxyhook 相同,`proxyhook.toml` 可以直接用(proxytun 用不到的键会给出警告并忽略,拼错的键也一样)。
完整的带注释示例见 [proxytun.toml](proxytun.toml),其余各键的含义与 proxyhook 仓库的 `docs/CONFIG.md` 一致。proxytun 特有或含义不同的键:

| 键 | 说明 |
|---|---|
| `fake_ip_range` | 末尾的 /24 留给命名空间内部(TUN `.1`、假 DNS `.53`),所以至少要 /22 |
| `localnet` | 命中的目标由 proxytun 从主机直连,不走规则与代理。命名空间里的 `127.0.0.0/8` 是命名空间自己的回环,到不了 proxytun |
| `host_ports_forward` | 是否把主机的回环监听转发进命名空间,默认 `true` |
| `host_ports_exclude` | 不转发的端口(程序要自己在这个端口上监听时用) |

### 访问本机服务

命名空间里的 `127.0.0.1` 是隔离的。proxytun **启动时**扫描一次主机上正在监听的 TCP 端口,按同样的地址开进命名空间:

| 主机上 | 命名空间里 |
|---|---|
| `127.x.x.x:P` | 同一地址 |
| `0.0.0.0:P` | `127.0.0.1:P` |
| `[::1]:P` | `[::1]:P` |
| `[::]:P` | `127.0.0.1:P` 与 `[::1]:P` |

- 53 端口不转发(DNS 必须由假 DNS 应答)。
- 启动之后主机上新开的端口看不到,需要时重启程序。
- 程序要在同一端口上自己监听会失败(`EADDRINUSE`),用 `host_ports_exclude` 排除,或 `--no-host-ports`。
- 程序环境里 `http_proxy=http://127.0.0.1:7890` 这类本机代理,只要启动时在监听,就自然可用。

### 调试工具

```bash
proxytun -c proxytun.toml strace -f -e trace=network ./prog          # strace 在命名空间里
strace -f -o trace.txt proxytun -c proxytun.toml ./prog              # strace 在外面,连 proxytun 一起跟
proxytun -c proxytun.toml gdb --args ./prog                          # gdb 在命名空间里
gdb -p <程序的 pid>                                                   # 从外面附加
proxytun -c proxytun.toml ltrace -f ./prog
```

从外面 `gdb -p` / `strace -p` 的限制与不用 proxytun 时相同:Yama `ptrace_scope=1`(Ubuntu、WSL2 默认)时只能附加自己的后代进程,
`--doctor` 会报告当前设置。

### 信号与生命周期

| 操作 | 效果 |
|---|---|
| Ctrl+C(终端发给整个前台进程组) | 程序自己处理;proxytun 不重复转发,等程序退出后随之退出 |
| `kill <proxytun pid>`(只发给 proxytun) | 转发给程序,恰好一次 |
| `kill %1`、`kill -- -<pgid>`、systemd 逐进程发送 | 程序已经收到,不重复转发(靠一个"见证进程"判断,见 DESIGN.md 5) |
| 连发两次 `SIGTERM` | proxytun 立即退出 |
| `kill -HUP <pid>` | 重新加载规则、localnet、代理和分组;配置有错则保留旧配置 |
| `kill -USR1 <pid>` | 打印统计:假 IP 数、地址改写表大小、连接数、DNS 查询数、被拒的 UDP 数、各代理的健康与延迟 |
| proxytun 被 `kill -9` 或崩溃 | 程序**不会被杀**,继续运行但断网(TUN 已随 proxytun 消失),不会绕过代理直连 |

启动时被忽略的信号(`nohup`、脚本里的 `cmd &`)在程序里保持忽略。

### 日志

级别与 proxyhook 相同:`off`、`error`(`-q`)、`warn`、`info`(默认)、`debug`(`-v`)、`trace`(`-vv`);
没有级别选项时读 `PROXYTUN_LOG`(可以按模块写,如 `proxytun=info,proxytun::capture=trace`)。

每条连接有一个递增编号,日志里写作 `conn{id=… target=…}`,info 级别一行选路结果。`-vv` 时 TUN 收到的每个 SYN 也会记下(带改写用的端口),
可以从 SYN 一直跟到代理握手。日志不记录是哪个进程发起的连接。

## 限制

- **IPv6**:不支持。命名空间里没有 IPv6 路由,AAAA 查询返回空,字面 IPv6 连接立即"网络不可达"。
- **UDP**:只处理 DNS;其余 UDP(含 QUIC)立即收到端口不可达。
- **ICMP**:丢弃,ping 不通。
- **绕过假 DNS 的解析**:经 systemd-resolved / nscd 的 unix socket 解析(`nsswitch.conf` 里的 `resolve`)会拿到真 IP,只能靠 SNI/Host 嗅探兜底;`/etc/hosts` 照常生效。
- **抽象 unix socket** 按网络命名空间隔离(X11 会回落到 `/tmp/.X11-unix` 路径,通常不受影响);文件路径型 unix socket 不受影响。
- **非 root 模式**(user namespace)下:root 拥有的文件显示为 `nobody`,`sudo`、`ping` 等 setuid 程序在里面不能用。sudo 模式下没有这个限制。
- **sudo 的 `use_pty`**:如果 sudoers 开了它,程序会落在 sudo 的伪终端会话里,终端的 Ctrl+C 到不了程序(proxytun 会警告)。CentOS 7 默认没开。
- **地址改写表**:同时存在的 TCP 连接(含关闭后保留 75 秒的)最多约 6.4 万条。
- **CentOS 7 真机**(3.10 内核、真实 sudo 1.8.23、SELinux)尚未验证,只在开发机上模拟过;验证步骤见 [docs/CENTOS7.md](docs/CENTOS7.md)。

## 开发

```bash
cargo test                                         # 单元 + 端到端(真实命名空间、TUN、调试器)
cargo test --target x86_64-unknown-linux-musl      # 静态版本
```

端到端测试需要 `curl`、`python3`、`cc`、`strace`、`gdb`、`ltrace`、`dig`;sudo 模式的测试另需 `newuidmap`(uidmap 包)、`setpriv`
和 `/etc/subuid` 里的区间,用"外层 user namespace + `max_user_namespaces=0` + setuid 的假 sudo"模拟 CentOS 7。缺少时对应用例输出 `SKIP`。

代码结构:`crates/proxytun-core`(从 proxyhook 复制的配置、规则、负载均衡、代理握手、fake-ip DNS、嗅探、中继)与
`crates/proxytun`(命名空间与 TUN、地址改写、sudo 助手、见证进程、主机端口、自检)。进度与交接见 [HANDOFF.md](HANDOFF.md)。

许可证:GPL-2.0(代码来自 proxyhook)。
