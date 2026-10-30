# proxytun 设计决策

> 本文记录 2026-10-30 ~ 10-31 架构澄清会话中定下的全部决策与默认假设,是实现的依据。
> 实现中如需偏离,先改这里并说明原因。

## 1. 目标

- 只让**指定命令及其整棵子进程树**的 TCP 走 SOCKS5 / HTTP 代理,并且**把域名带到代理**(Clash 等据此分流)。
- 对静态链接程序、清空 `LD_PRELOAD` 的程序同样有效。
- **不使用 ptrace**,因此 strace / gdb / ltrace 可以同时使用(包括 `proxytun -- strace -f prog`、`proxytun -- gdb prog`、从外部 `gdb -p`)。
- **必须支持 CentOS 7**(内核 3.10、glibc 2.17)。

为什么不是 proxyhook:proxyhook 用 ptrace 拦截系统调用,一个进程同一时刻只能有一个 tracer,所以不能与 strace/gdb 共存。
为什么不是 tun2proxy:`--unshare` 依赖新版 util-linux 的 `unshare` 命令(CentOS 7 的 2.23.2 缺 `--map-current-user`、`--keep-caps`、`--kill-child`),
且依赖非特权 user namespace(CentOS 7 默认关闭),没有 sudo 降权模式;所有 TCP 都经代理,没有直连与本机回环处理。

## 2. 总体方案

程序运行在一个**匿名网络命名空间**里,命名空间唯一的出口是 proxytun 持有的 TUN 设备;proxytun 本身留在主机命名空间,向代理发起连接。

```
proxytun(主机命名空间,普通用户)
  ├─ 持有:TUN fd、命名空间内的监听 socket、主机端口转发的监听 socket
  ├─ TUN 上的 TCP:用户态改写地址 -> 交给命名空间内监听 socket(内核 TCP 栈)-> 中继 -> 代理 / 直连 / 丢弃
  ├─ TUN 上的 UDP:53 端口 -> fake-ip DNS;其余 -> ICMP 端口不可达
  └─ 程序(命名空间内,原用户身份)及其全部子进程
```

TUN 不设持久标志,fd 关闭即由内核删除;命名空间没有名字,最后一个引用消失即销毁。主机上不留任何网卡、路由或配置。

## 3. 权限模型

| | 新系统 | CentOS 7 |
|---|---|---|
| 建命名空间 + TUN | 非特权 user namespace(`unshare(USER\|NET\|NS)`) | proxytun 自动调用 `sudo` 启动最小特权助手 |
| 程序身份 | uid/gid 映射为自身,exec 时自动失去命名空间内的能力 | exec 前完全降权(附加组 → gid → uid,real/effective/saved 全降) |
| 之后 | 相同:fd 交给 proxytun,整棵树里没有 root 进程 | 同左 |

- 能用 user namespace 就用;不能用时自动走 sudo,先打印一行说明原因;`--no-sudo` 禁止调用 sudo(直接报错)。
- **准备进程是重新 exec 的 proxytun**(M1 实现时确定):proxytun 启动即设为 non-dumpable(保护代理凭据),fork 出的子进程会继承,
  其 `/proc/self/uid_map` 等文件因此归 root、写不进去;而让子进程恢复 dumpable 又会暴露从父进程复制来的内存(含凭据)。
  所以子进程 fork 后立即 `execv("/proc/self/exe", ["proxytun", "__proxytun_setup", ...])`:新映像里没有凭据,也恢复为 dumpable。
  它完成命名空间准备、交回 fd、等待放行后 exec 目标程序(pid 不变)。sudo 模式的特权助手走同一条路径。
- 不推荐用户直接 `sudo proxytun`:CentOS 7 默认 sudoers 有 `always_set_home`、`env_reset`、`secure_path`,程序会拿到 `HOME=/root`、被替换的 `PATH`、丢失的 `http_proxy`。
- **特权助手的边界**:
  - 只做:建网络 + 挂载命名空间、建 TUN、bind-mount `resolv.conf`、建主机端口转发的监听 socket、fork 出程序;fd 交回后立即退出,程序由 proxytun(subreaper)收养。
  - 由 sudo 以当前可执行文件的绝对路径 + 隐藏子命令启动;sudo 会关闭 fd≥3,双方经 0700 私有目录里的 unix socket 通信。
  - 对端凭据的 uid 必须等于 `SUDO_UID`;程序的 uid/gid/附加组取自对端进程的 `/proc` 状态(内核提供),不信任消息里自报的身份。
  - 不读配置、不写日志、不以 root 打开用户给的任何路径;先降权,再以用户身份 `chdir`、查 PATH、`exec`。
  - root 模式下先把挂载传播设为 private,否则 bind-mount 的 `resolv.conf` 会传播回主机。
  - sudoers 开了 `use_pty` 时程序会落入 sudo 的伪终端会话,交互工具的终端控制会出问题:检测到时 warn。
- 1024 以下端口:绑定检查的是"拥有该网络命名空间的 user namespace 里是否有 `CAP_NET_BIND_SERVICE`",
  建命名空间的那一步本来就有,所以转发低端口不需要额外的 root;建好的监听 socket 交给普通用户进程后 accept 不需要权限。
  程序自己在命名空间里监听低端口仍会失败,与它在主机上直接运行时一致。

## 4. 网络细节

- **TCP 接管**:TUN + 用户态地址改写(Clash/sing-box 的 "system stack" 思路)。读到程序的 SYN 后改写源/目的地址与端口,导向命名空间内的监听 socket,
  由内核完成 TCP;回程包反向改写。accept 后按改写表查回原目标,交给 `proxytun_core::net::relay::route`(选路、splice 零拷贝、SNI/Host 嗅探)。
  不依赖 netfilter(3.10 内核没有 nftables),不引入用户态 TCP 栈。
- **DNS**:
  - 私有挂载命名空间里把 `resolv.conf` bind-mount 成指向假 DNS 地址的文件(保留原文件的 `search`/`domain`/`options` 行),主机文件不动;
  - 发往任意 IP 53 端口的 UDP 和 TCP 一律由 fake-ip DNS 应答(拦住硬编码 `8.8.8.8` 的程序);
  - 不改 `nsswitch.conf`:经 systemd-resolved / nscd 的 unix socket 解析会拿到真 IP,靠嗅探兜底,文档写明。
- **非 DNS 的 UDP(含 QUIC)**:回 ICMP 端口不可达,快速失败,浏览器回落 TCP。v1 不代理 UDP。
- **ICMP**:丢弃(ping 不通)。
- **IPv6**:v1 不支持。命名空间内不配 IPv6 路由(只有 `::1`),字面 IPv6 连接立即"网络不可达";AAAA 返回空(同 proxyhook)。
- **地址规划**:`fake_ip_range` 末尾的 /24 留给命名空间内部(默认 `198.19.255.0/24`:`.1` TUN 自身、`.53` 假 DNS、若干改写用源地址),
  其余作 fake IP,因此 `fake_ip_range` 至少 /22。198.18.0.0/15 是 RFC 2544 测试保留段,不会与真实目标冲突。
- **MTU**:65520。包只在本机内核与 proxytun 之间流转,包越大用户态处理的包数越少。
- **localnet / 程序环境里的代理**:沿用 proxyhook 的 `Policy::is_passthrough`,命中的目标由 proxytun 直连,不走规则与代理(避免代理套代理)。
- **主机本地服务(回环)**:命名空间的 `127.0.0.1` 与主机隔离。启动时扫描**一次**主机的 TCP 监听(`/proc/net/tcp`、`tcp6`),转发进命名空间:

  | 主机上的监听 | 命名空间里开 | 转发到主机 |
  |---|---|---|
  | `127.x.x.x:P` | 同一地址 `127.x.x.x:P` | `127.x.x.x:P` |
  | `0.0.0.0:P` | `127.0.0.1:P` | `127.0.0.1:P` |
  | `[::1]:P`、`[::]:P` | `[::1]:P` | `[::1]:P` |

  - 只转发 TCP;跳过 53 端口(DNS 必须由假 DNS 应答);不区分监听者属主。
  - 监听 socket 在建命名空间时一次性建好;之后主机上新增的监听不处理,需要时重启程序。
  - `host_ports_forward = true`(默认)/ `--no-host-ports` 整体开关;`host_ports_exclude = [...]` 排除个别端口(程序自己要监听同号端口时用)。
  - 启动时以 info 级别列出转发了哪些端口。
  - tun2proxy 不处理这种情况(程序连 `127.0.0.1` 只到命名空间自己的回环)。

## 5. 运行时行为

- 与 proxyhook 一致:proxytun 是 subreaper,等整棵进程树结束才退出;退出码透传(信号终止为 128+信号);
  Ctrl+C 交给程序;只发给 proxytun 的 TERM/INT/QUIT 转发给程序,发给整个进程组的不重复;SIGHUP 热加载;SIGUSR1 打印统计。
- **"发给整个进程组的不重复"怎么做到**(M2 实现时确定):proxyhook 靠 ptrace 看见程序收到信号;proxytun 没有 ptrace,
  而 `kill <pid>` 与 `kill -- -<pgid>`/`kill %1`/systemd 逐进程发送,在 proxytun 看来都是 `SI_USER`。为此启动一个**见证进程**:
  与 proxytun 同一进程组、屏蔽 INT/QUIT/TERM(其余信号一律忽略,终端挂断或 Ctrl+Z 不会杀死/停住它)。
  proxytun 收到 `SI_USER` 信号后等 50 ms,读 `/proc/<见证>/status` 的待处理信号:见证也收到且程序仍在本进程组 → 程序已有一份,不转发;
  否则转发。每次判断后清空见证的待处理信号。见证 double-fork(不是 proxytun 的子进程,不影响"等整棵树退出"),管道断开即退出。
  比 proxyhook 多覆盖一种情况:用 `sigwait`/`signalfd` 收信号的程序被整组 kill 时也不会收到两次。
  程序自己离开了 proxytun 的进程组(`setsid`、shell 作业控制)时,整组信号到不了它,照常转发。
- proxytun 异常退出(`kill -9`、崩溃):**不杀程序**。TUN 随 fd 关闭消失,程序只剩回环,等于断网,不会绕过代理直连;日志与文档写明。
- 热加载范围同 proxyhook;主机端口转发、地址规划、`fake_ip_range`、`upstream_dns` 需要重启。
- 凭据保护同 proxyhook:程序环境里去掉 `PROXYTUN_PROXY`(原值就地清零),proxytun 设为 non-dumpable;`--proxy` 带密码时 warn。

## 6. 日志与监控

- 沿用 proxyhook:级别 off/error/warn/info/debug/trace,`-q`、`-v`/`-vv`、`--log-level`、`--log-file`(追加、600、无颜色),环境变量 `PROXYTUN_LOG`。
- 每条连接一个递增编号,span 为 `conn{id=… target=…}`;info 级别一行选路结果;trace 级别可从 TUN 收到 SYN 一直跟到代理握手。
  **不查发起连接的进程 pid**(TUN 上看不到,查 `/proc` 代价高)。
- 代理健康检查、故障转移同 proxyhook。
- SIGUSR1 统计:proxyhook 已有内容 + 地址改写表大小、活跃连接、被拒 UDP 数、DNS 查询数、已转发的主机端口。

## 7. 命令行与配置

- 命令行与 proxyhook 一致:`proxytun [选项] 程序 参数...`(`--` 可选),`-c`(默认 `proxytun.toml`)、`--proxy`、`-q`、`-v`/`-vv`、
  `--log-level`、`--log-file`、`--doctor`;新增 `--no-sudo`、`--no-host-ports`。环境变量 `PROXYTUN_PROXY`、`PROXYTUN_LOG`。
- 配置文件格式与 `proxyhook.toml` 相同,可直接拿来用;proxytun 用不到的键(`verify_peer_uid`、`block_quic`、`dns_udp_unconnected`)
  和拼错的键,启动时 warn 并忽略。
- `--doctor`:报告将使用哪种模式(userns / sudo),在临时命名空间里实际试建 TUN、配地址、bind-mount;userns 不可用时说明原因
  (`max_user_namespaces=0`、AppArmor 限制、内核未开),检查 `sudo` 是否存在但不调用;沿用代理连通性检测。

## 8. 代码组织

- workspace 根在 `~/aicode/proxytun`:`crates/proxytun-core`(共享库)+ `crates/proxytun`(程序)。
- core 从 proxyhook `e0be192` 复制:`config`、`types`、`policy`、`balancer`、`health`、`proxy`、`sniff`、`net::{fakeip, splice, dns, relay}`;
  去掉了 ptrace、ticket、uid 校验(`peer`)、`doctor`、`app`。DNS 只保留应答/转发逻辑和 `serve_tcp`(无监听服务器),
  中继只保留与 ticket 解耦的 `route()` 与 `build_live()`。复制后按 proxytun 需要自由修改。
- proxyhook 仓库不改动;以后要么改为依赖 core,要么退役。
- 许可证 GPL-2.0(代码来自 proxyhook)。文档中文,代码注释英文。只做 x86-64(gnu + musl 静态),不写架构相关代码。
- 不引入重量级新依赖:TUN 与地址配置用 ioctl;改写表的容量与超时取合理默认值并写入文档。

## 9. 里程碑

| | 内容 | 验证 |
|---|---|---|
| M0 | workspace + core,复制过来的单测全部通过;本文档 | `cargo test`、clippy、fmt |
| M1 | 非 root 模式:命名空间 + TUN + TCP 地址改写 + DNS 两层 + UDP 拒绝;curl 经 SOCKS5 / HTTP 代理,代理收到域名 | 单测 + 端到端;对真实 Clash(`172.25.32.1:7897`)冒烟 |
| M2 | 生命周期与信号、静态链接程序、清空 `LD_PRELOAD` 的程序、命名空间里跑 strace/gdb/ltrace、外部 `gdb -p` | 端到端 |
| M3 | sudo 特权助手(用 uidmap 在 userns 里模拟 root 模式测试)、musl 静态构建、el7 验证清单 | 端到端 + 用户在 el7 真机验证 |
| M4 | 主机端口转发、`--doctor`、README / HANDOFF | 端到端 |

每个里程碑的测试全部通过后提交,再进入下一个;跳过的测试必须明确报告。
