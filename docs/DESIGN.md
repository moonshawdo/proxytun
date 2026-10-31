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
  只有 user namespace 本身的问题(建不了,或其中的能力被 LSM 收走,表现为 EPERM/EACCES)才回退;主机明确拒绝的步骤
  (打开 `/dev/net/tun` 失败、建不了放 `resolv.conf` 的临时目录)直接报错:那是管理员的设置,不能让 root 替用户绕过。
- **准备进程是重新 exec 的 proxytun**(M1 实现时确定):proxytun 启动即设为 non-dumpable(保护代理凭据),fork 出的子进程会继承,
  其 `/proc/self/uid_map` 等文件因此归 root、写不进去;而让子进程恢复 dumpable 又会暴露从父进程复制来的内存(含凭据)。
  所以子进程 fork 后立即 `execv("/proc/self/exe", ["proxytun", "__proxytun_setup", ...])`:新映像里没有凭据,也恢复为 dumpable。
  它完成命名空间准备、交回 fd、等待放行后 exec 目标程序(pid 不变)。sudo 模式的特权助手走同一条路径。
- **拒绝 `sudo proxytun`**(安全复查后由"不推荐"改为拒绝):除特权助手外,proxytun 的任何入口(含内部的 `__proxytun_setup`)
  在 euid 为 0 时,只要 real uid 不是 0(setuid 安装),或环境里有 `SUDO_UID` / `SUDO_USER` / `SUDO_COMMAND` / `DOAS_USER` / `PKEXEC_UID`,
  就以退出码 2 拒绝。否则只放行 proxytun 的 sudoers 规则就等于放行任意 root 命令:`sudo proxytun -- sh`,
  或把 fd 0 冒充控制 socket 的 `sudo proxytun __proxytun_setup 0 ... -- sh`。不提供绕过开关;root 模式只给本来就是 root 的人用(root 登录、`su -`)。
  不设这些变量的提权方式(ksu、userhelper、`systemd-run --uid=0`)识别不了;第二轮复查后用户决定不加 audit loginuid 判据
  (它会连 `su -` 一起拒绝,且仍拦不住 systemd 启动的服务),改为在 README 写明只能用 sudo 授权 proxytun。
- **特权助手的边界**:
  - 只做:建网络 + 挂载命名空间、建 TUN、bind-mount `resolv.conf`、建主机端口转发的监听 socket、fork 出程序;fd 交回后立即退出,程序由 proxytun(subreaper)收养。
  - **root 进程从不接收客户端的 fd**(第五轮复查):关闭一个用户给的 fd 可能永久阻塞(设了 `SO_LINGER` 且发不出去的 socket、
    用户自己 FUSE 挂载上的文件,后者连 SIGKILL 都无效),root 助手和等它的 sudo 就会挂着,用户杀不掉、也不计入他的进程数。
    所以助手先建好空的命名空间并 fork 出程序;程序降为用户之后才读请求和 fd,再把请求原文(只有字节)经管道交给助手校验、配置。
    客户端协议不变。助手自己从不关闭控制 socket(上面可能排着带 fd 的消息),留给内核在退出时关闭,那时不再 linger。
    助手失败时 SIGKILL 程序但不等它(它退出时关闭用户的 fd 可能阻塞)。等程序回报最多 10 + 5 秒:那时它已是用户的进程,用户可以把它停住。
  - 由 sudo 以当前可执行文件的绝对路径 + 隐藏子命令启动;sudo 会关闭 fd≥3,双方经 0700 私有目录里的 unix socket 通信。
  - 只接受 real 与 effective uid 都为 0(sudo 的做法);setuid 启动时 real uid 是调用者,`SUDO_UID` 也由调用者设置,直接拒绝。
  - 以 `SUDO_UID`/`SUDO_GID` 为有效 uid/gid(`setresuid`/`setresgid` 只改有效 id,saved uid 仍为 0 以便切回;清空附加组)连接 socket:
    调用者自己进不去的目录,root 也不替他进去;对端用 `SO_PEERCRED` 看到的是调用者而不是 root,无法被当成 root 的连接利用
    (第二轮复查由 fsuid 改为 euid)。proxytun 相应地要求连上来的是自己的 uid。祖先检查不通过时直接断开,不发错误消息。
    已知限制:清空了附加组,`$TMPDIR` 只能经附加组进入时连接会失败。
  - 对端(socket 创建者,`SO_PEERCRED`)必须是助手往上 4 层以内的祖先(sudo、可能存在的 `use_pty` 监控进程、proxytun),
    这同时保证它还活着、pid 没有被复用,`/proc/<pid>` 读到的就是它;其 uid 必须等于 `SUDO_UID`。程序的 uid/gid/附加组取自它的 `/proc` 状态,
    不信任消息里自报的身份。
  - 任何人都能写自己的客户端,所以请求逐项重新校验:假 IP 段 /8–/22,进程组必须等于对端的进程组,转发地址只能是回环、
    端口非 0 非 53、不重复、最多 250 个。
  - socket 收发超时 10 秒,客户端不说话时 root 进程不会一直挂着;程序读完请求后清除超时,因为它等放行要多久都行。
  - 不读配置、不写日志、不以 root 打开用户给的任何路径;程序先降权(附加组 → gid → uid,确认 `setuid(0)` 失败且 CapPrm/CapEff 为 0;
    读不到 `/proc/self/status`,例如调用者把 fd 上限设为 0,也按失败处理),换上一个自己的会话 keyring(RHEL 的 `/etc/pam.d/sudo` 里
    `pam_keyinit` 可能给助手建了 root 的会话 keyring 并链着 root 的 user keyring,会话 keyring 跨 fork、setuid、exec 保留;
    只有内核不支持 keyring 的 ENOSYS 放过,其余错误一律拒绝),再设置 `PR_SET_NO_NEW_PRIVS`:命名空间里的网络(DNS、路由)完全由用户的 proxytun 控制,setuid 程序(sudo、su,或经 LDAP/Kerberos 认证的 PAM)
    在里面拿到 root 就等于用户拿到 root。之后以用户身份 `chdir`、查 PATH、`exec`。
  - root 进程写 `resolv.conf` 一律放在 `/tmp` 下(不看 `$TMPDIR`):在用户能控制的目录里,mkdtemp 建的目录可能在写入前被换成指向 `/etc` 的链接;
    粘滞位的 `/tmp` 里别人改不了我们的目录名。文件用 `O_CREAT|O_EXCL|O_NOFOLLOW` 创建,权限经 fd 设置。
  - root 模式下先把挂载传播设为 private,否则 bind-mount 的 `resolv.conf` 会传播回主机。
  - 安装要求:sudo 以 root 执行的是 proxytun 自己的文件,必须放在只有 root 能写的位置;免密码的 sudoers 规则只放行
    `/usr/local/bin/proxytun __proxytun_root_setup *`(多余参数会被助手拒绝)。
  - sudoers 开了 `use_pty` 时,sudo 的监控进程在新会话里以新伪终端为控制终端运行助手;助手退出后监控进程(会话首进程)随之退出,
    内核向该终端的前台进程组发 SIGHUP。所以助手发现自己与调用者不在同一会话时,让程序 fork 后先 `setsid()` 离开,经管道告知后才回报。
    此时程序不在 proxytun 的进程组,终端的 Ctrl+C 只到 proxytun:`SI_KERNEL` 的信号也按"程序是否还在本进程组"决定是否转发(见第 5 节)。
    程序没有控制终端,Ctrl+Z 与窗口大小变化到不了它:检测到时 warn。
  - 程序的进程属性与 userns 模式一致:umask 随请求传过去;非 close-on-exec 的 fd(≥3,最多 249 个,SCM_RIGHTS 一次 253 个减去固定的 4 个)
    随请求传过去(编号须小于 2^20),放行后先各自复制到不属于任何目标编号的最低空闲编号,再 `dup2` 回原编号:
    继承的 fd 紧挨着上限时也不会超出调用者的 fd 上限;资源限制在降权前逐项设为调用者的值(`prlimit` 读调用者的 16 项)。
    第五轮复查前是"只降不升"(取两者较小值),但 sudo 也会给 root 更低的限制:sudo 1.9.13 起命令的 core 上限为 0,
    pam_limits 给 root 的 fd 软上限可能低于调用者,继承的 fd 编号超过它时 `dup2` 失败。现在与 userns 模式一样完全是调用者的值
    (CentOS 7 的 `20-nproc.conf` 给 root 不限进程数,管理员给用户设的 nproc/memlock 照样有效);root 没有 `CAP_SYS_RESOURCE`
    (容器)恢复不了更高的硬上限时,保留较低的那个。stdio 的 `dup2` 失败即报错。
  - sudoers 的 `ROLE`/`TYPE`(或 AppArmor profile)会让 sudo 在另一个安全上下文里运行助手,程序会带着它:比较
    `/proc/self/attr/current` 与调用者的,不同就拒绝。默认配置下 sudo 不改上下文。
  - sudoers 的 `intercept` / `log_subcmds` 让 sudo 跟踪(ptrace)命令或给它加 seccomp 过滤器,程序的每次 exec 都会被 root 看到、
    可被拦住:助手被跟踪(`TracerPid` 非 0)或 `Seccomp` / `Seccomp_filters` 与调用者不同就拒绝。容器给所有进程的过滤器调用者也有,不受影响。
- 1024 以下端口:绑定检查的是"拥有该网络命名空间的 user namespace 里是否有 `CAP_NET_BIND_SERVICE`",
  建命名空间的那一步本来就有,所以转发低端口不需要额外的 root;建好的监听 socket 交给普通用户进程后 accept 不需要权限。
  程序自己在命名空间里监听低端口仍会失败,与它在主机上直接运行时一致。

## 4. 网络细节

- **TCP 接管**:TUN + 用户态地址改写(Clash/sing-box 的 "system stack" 思路)。读到程序的 SYN 后改写源/目的地址与端口,导向命名空间内的监听 socket,
  由内核完成 TCP;回程包反向改写。accept 后按改写表查回原目标,交给 `proxytun_core::net::relay::route`(选路、SNI/Host 嗅探、双向拷贝)。
  不依赖 netfilter(3.10 内核没有 nftables),不引入用户态 TCP 栈。
- **不用零拷贝(splice)**(2026-10-31 实测后删除):proxyhook 的中继两端都是普通 socket,splice 有明显收益;
  proxytun 的连接先经过 TUN,命名空间里的 TCP 处理落在写 TUN 的线程上,它本来就是瓶颈,splice 只会加重它。
  本机(WSL2、8 核、本地 SOCKS5 代理与源站,2 GiB 下载)实测:

  | 路径 | splice | 普通拷贝(64 KiB 缓冲) | 不经 proxytun |
  |---|---|---|---|
  | 经 TUN 捕获的连接 | 约 800 MB/s | 约 1070 MB/s | 约 2100 MB/s |
  | 主机端口转发 | 约 2700 MB/s | 约 1350 MB/s | 约 4100 MB/s |

  主路径普通拷贝快 20–30%;主机端口转发慢一半,但 1.35 GB/s 对本地服务足够,为它单留 splice 不值得。
  主路径的上限约 1 GB/s(单个 TUN 收发循环),远高于真实代理的吞吐,不再做多队列 TUN、校验和卸载等优化。
  每条连接的额外开销约 0.2–0.3 ms(含假 DNS)。将来 proxyhook 改为依赖 core 时,splice 可以从 proxyhook 仓库(或本仓库 `59d8f75`)
  拷回 `net/splice.rs`,再给 `relay::pump` 加一个选择参数,proxyhook 传 splice、proxytun 传拷贝。
- **第二轮复查的性能项**(2026-10-31):
  - 中继缓冲仍为每方向 64 KiB(每条连接一建立就占 128 KiB)。实测经 TUN 下载 3 GB:64 KiB 约 990 MB/s,32 KiB 约 915(−8%),
    16 KiB 约 750(−24%),8 KiB 约 545(−45%);按"吞吐下降不超过 5%"的标准不缩小。改用 32 KiB 可让内存减半、仍远高于真实代理。
  - proxytun 启动程序后把自己的打开文件软上限提到硬上限(每条连接占 2 个 fd,常见软上限 1024);程序拿到的仍是原值。
    本机资源不足(EMFILE/ENFILE/ENOBUFS/ENOMEM,第三轮加上本机临时端口耗尽的 EADDRNOTAVAIL)不再算作代理故障,
    连接和健康探测都不计入,否则 fd 用尽会把健康的代理标成 DOWN。DNS 转发因此失败时也不怪上游(不报"检查 upstream_dns")。
  - DNS 转发同时最多 256 个(每个占一个 socket 和缓冲,最长 3 秒),超出的丢弃由程序的解析器重试;接收缓冲不再预先清零 64 KiB。
  - 地址改写表满时的 error 日志每 10 秒最多一条(`dropped_table_full` 照常计数),不再每个被丢的 SYN 都在 TUN 线程上写日志。
    第三轮复查后表满时还向程序回 RST(确认它的 SYN),程序立即得到 ECONNREFUSED,而不是按 tcp_syn_retries 重试约 2 分钟。
    第五轮复查起同一规则(RFC 793 的 Reset Generation)用于程序发来的所有找不到条目的非 RST 报文(连接早已结束、条目过了 LINGER):
    回 RST,程序得到 ECONNRESET,而不是重传约 15 分钟;原先静默丢弃。
  - 规则匹配每条连接只转一次小写,后缀匹配不分配内存。
  - 地址改写表的定时清扫原是全表遍历,实测 64512 条时 release 下最坏 0.68 ms、每 5 秒一次,当时低于 1 ms 的门槛未改。
    第三轮复查把表扩到 16 个源地址(约 100 万条)后全表遍历会到约 10 ms,改为按到期时间排序的队列(第四轮起三条:未应答的、
    排队的、已关闭的),清扫只看到期的条目;队列里过时的项(条目已被替换或状态已变)靠"状态 + 进入该状态的时间"识别后跳过。
  - 地址改写表的源地址(第三轮复查,用户选 A):末尾 /24 的 `.2`–`.17` 共 16 个,每个 64512 个端口,约 100 万条(最多约 100 MB);
    关闭的连接保留 75 秒,所以持续新建连接的上限约每秒 1.37 万条(原来单个地址约 860 条)。没用过的端口由计数器依次给出
    (各地址轮流,平常的连接就会用到多个地址),只有释放的端口进队列(先释放的先复用,刚释放的最后才轮到),不在启动时列出全部约 103 万个(第四轮复查)。
- **各类上限与耗尽时的行为**(第三轮复查,2026-10-31):
  - 打开文件数:软上限提到 min(硬上限, `fs.nr_open`)(硬上限高于 `nr_open` 时任何 setrlimit 都会失败,所以连硬上限一起降);
    失败时 warn,启动时 info 打出实际上限。
  - 进程/线程数:tokio 阻塞线程池上限 64(默认 512)。阻塞任务是 direct 规则对域名的 getaddrinfo,每个线程都占用户的进程数额度,
    与程序共用;panic 信息同时写进日志(`--log-file` 时 stderr 上看不到)。
  - listen backlog:5.4 以前的内核里新网络命名空间的 `somaxconn` 是 128,会把 4096 截断;root 与 sudo 模式在建命名空间时调到 4096,
    userns 模式无权修改,保持原样。
  - 假 IP 映射最多 100 万条(约 150 MB),再大的 `fake_ip_range` 也一样,超出后按原规则回收;池满时的 error 日志每 10 秒最多一条。
  - accept 失败(fd 用尽)、地址改写表满、假 IP 池满:日志都限速为每 10 秒最多一条(`proxytun_core::throttle`),计数照常。
  - 统计日志先取出地址改写表的大小再写:在 `tracing` 宏里取锁会持锁到整行写完,stderr 被暂停(Ctrl+S、分页器)时 TUN 线程会跟着卡住。
  - 第五轮复查:写 stderr 的日志本身也不再阻塞、不再失败。原先 tokio worker 和主线程同步写 stderr,读端停住时所有写日志的线程
    (中继、DNS、信号处理)一起卡住;读端关掉时 tracing 默认用 `eprintln!` 报告写失败,而它本身失败就 panic,于是每个新中继被重置、
    两次 SIGTERM 停不掉、退出码变成 101。现在关掉 `log_internal_errors`,stderr 是管道或终端时另开一个非阻塞的打开文件描述
    (`/proc/self/fd/2`,不改程序共用的那个),是 socket 时 `send(MSG_DONTWAIT)`,写不下的日志行丢弃;普通文件照常写。
  - 地址改写表:监听侧回了 SYN-ACK 的条目进入"排队"状态(accept 因 fd 用尽长时间失败时,程序那端已是 established,
    条目删掉后它永远收不到关闭);监听侧在 accept 前发 RST 则结束该条目。第四轮复查补正:排队最多 30 秒(用户定),到期向程序发 RST,
    序号取监听侧 SYN-ACK 的序号 + 1(established 状态下内核只接受序号正好等于期望值的 RST),程序得到 ECONNRESET;
    否则监听侧内核悄悄丢掉连接(accept 队列溢出后握手请求超时)时条目会永久泄漏。程序在 accept 前发 RST(握手中途关掉 socket)
    也结束条目:监听侧内核对这种 RST 只是静默丢弃半连接,不会有任何回应。同一 4 元组关闭后又重连时,旧条目留在原端口直到 LINGER
    期满,新连接另分一个端口(原先旧端口立即回到空闲队列,表接近满时会被马上复用,而监听侧可能还持有旧连接)。
    第五轮复查补正:旧连接还没结束(中继还在拨号,或还在等 accept)时,同一 4 元组上初始序号不同的 SYN 同样是新连接,另分端口;
    原先沿用旧条目,旧中继结束时把它关掉,75 秒后新连接的包被全部丢弃、两端永久挂起。条目记下程序 SYN 的初始序号,重传的 SYN
    (序号相同)仍用原端口;旧条目照旧由它自己的中继结束,端口在此之前不会被复用。排队到期的条目不再立即释放端口,
    同样保留 LINGER(监听侧可能还持有那条连接);到期时若程序已在同一 4 元组上开了新连接,就不再向它发 RST。
  - direct 规则的域名解析(阻塞的 getaddrinfo)同时最多 32 个,少于 64 个阻塞线程:超时放弃的解析不会在线程池队列里排队、
    挡住后面的解析;超出时该连接立即失败并说明原因(warn 每 10 秒最多一条)。
  - `--doctor` 试运行前同样把 SIGCHLD 恢复为默认(试运行的程序是 `true`,无需保留调用方的设置)。panic 只在用了 `--log-file`
    时额外写进日志(否则 stderr 上会出现两遍)。
  - 第四轮复查决定不改:地址改写表超过约 52 万条时哈希表在 TUN 线程上持锁扩容,停顿几十毫秒、扩出的内存不归还。只在极端负载下、
    每次翻倍发生一次;按满表预分配要常驻约 100 MB,不值得。
  - 同时中继的连接(TUN 捕获的与主机端口转发的合计)最多 8192 条:每条固定占两个 64 KiB 缓冲,fd 上限提高后不再先把它挡住,
    满载时缓冲约 1 GiB(用户决定,替代"只在统计里显示内存")。超出的连接立即用 RST 关闭(程序马上失败,而不是等一个没人服务的连接),
    计数 `relays_refused`,warn 每 10 秒最多一条。其地址改写条目由 TUN 线程看到这个 RST 时结束(第五轮复查:原先 accept 时就结束,
    RST 一旦在 tun0 被丢,程序就永远等下去;现在条目仍在排队,30 秒后程序照样收到 RST)。
  - 中继以错误结束(拨号失败、一端 RST、读写出错)时两端都用 RST 关闭(第五轮复查,主机端口转发同样):原先发正常 FIN,
    下载被截断的程序读到干净的 EOF,以 EOF 收尾的协议(HTTP/1.0 无长度、nc)会把截断的数据当成完整的;拨号失败表现为"连上后空回复";
    程序中止的上传在目标那边也像正常结束。
  - 出站连接开 TCP keepalive(空闲 60 秒后探测,每 15 秒一次)并设 `TCP_USER_TIMEOUT` 120 秒(第五轮复查):程序自己的 keepalive
    由命名空间里的监听侧应答,永远到不了真实路径;原先经远端代理或 direct 的空闲长连接在路径中断(NAT 清掉状态、对端掉电)后永远发现不了,
    程序挂起,中继槽位、地址改写条目、假 IP 钉住都被永久占用。约 2 分钟发现死链后中继出错结束,按上一条向程序发 RST。
    代理在本机(如 `ssh -D`)时只能发现到代理这一段。
  - 调用方忽略 SIGCHLD 时(跨 exec 保留),程序启动后、放行前把 proxytun 自己的 SIGCHLD 恢复为默认,否则内核自动回收子进程,
    程序的退出码丢失;程序已经 fork,保留调用方的设置。
- **DNS**:
  - 私有挂载命名空间里把 `resolv.conf` bind-mount 成指向假 DNS 地址的文件(保留原文件的 `search`/`domain`/`options` 行),主机文件不动;
  - 发往任意 IP 53 端口的 UDP 和 TCP 一律由 fake-ip DNS 应答(拦住硬编码 `8.8.8.8` 的程序);
  - 不改 `nsswitch.conf`:经 systemd-resolved / nscd 的 unix socket 解析会拿到真 IP,靠嗅探兜底,文档写明。
- **非 DNS 的 UDP(含 QUIC)**:回 ICMP 端口不可达,快速失败,浏览器回落 TCP。v1 不代理 UDP。
- **ICMP**:丢弃(ping 不通)。
- **IPv6**:v1 不支持。命名空间内不配 IPv6 路由(只有 `::1`),字面 IPv6 连接立即"网络不可达";AAAA 返回空(同 proxyhook)。
- **地址规划**:`fake_ip_range` 末尾的 /24 留给命名空间内部(默认 `198.19.255.0/24`:`.1` TUN 自身、`.53` 假 DNS、`.2`–`.17` 改写用源地址),
  其余作 fake IP,因此 `fake_ip_range` 至少 /22。198.18.0.0/15 是 RFC 2544 测试保留段,不会与真实目标冲突。
- **fake IP 回收**(第二轮复查):地址用完后回收最久未用、且没有连接在用的映射,但距上次应答或使用不足 120 秒(应答 TTL 的两倍,
  第五轮复查起留出余量:有的缓存过了 TTL 仍先返回旧答案再刷新)的不回收:
  程序可能还缓存着它,回收给别的域名会把流量(含明文 Cookie)送错地方。回收不了就答 SERVFAIL。有连接在用的映射移出回收队列,
  回收是 O(log n),不再逐个跳过。
- **MTU**:65520。包只在本机内核与 proxytun 之间流转,包越大用户态处理的包数越少。
- **localnet / 程序环境里的代理**:沿用 proxyhook 的 `Policy::is_passthrough`,命中的目标由 proxytun 直连,不走规则与代理(避免代理套代理)。
  `localnet` 默认为空(proxyhook 默认 `127.0.0.0/8`,在 proxytun 里不起作用:命名空间的回环到不了 proxytun)。
  `direct_to_proxies`(默认开,2026-10-31 加):`[[proxies]]` 的 IP+端口并入同一张放行表,程序自己连这些代理(它自己的代理设置、`curl -x`)
  时直连,不再经代理绕一次。与 `localnet` 的区别:只放行那个端口,同一主机的其他端口照常走规则。匹配在每条连接 accept 后做一次、
  逐个比较几个地址,不在每个包上做,没有性能影响。
- **非 A 记录的上游 DNS**:`upstream_dns` 不写时用主机 `/etc/resolv.conf` 的第一个 nameserver(没有则 `127.0.0.1:53`,同 glibc),
  从主机发出,所以主机上的 `127.0.0.53` 之类本地解析器也能用。proxyhook 默认 `1.1.1.1:53`,在内网或 CentOS 服务器上常被挡,
  MX/TXT/PTR 查询会卡满 3 秒超时。
- **主机本地服务(回环)**:命名空间的 `127.0.0.1` 与主机隔离。启动时扫描**一次**主机的 TCP 监听(`/proc/net/tcp`、`tcp6`),转发进命名空间:

  | 主机上的监听 | 命名空间里开 | 转发到主机 |
  |---|---|---|
  | `127.x.x.x:P` | 同一地址 `127.x.x.x:P` | `127.x.x.x:P` |
  | `0.0.0.0:P` | `127.0.0.1:P` | `127.0.0.1:P` |
  | `[::1]:P` | `[::1]:P` | `[::1]:P` |
  | `[::]:P` | `127.0.0.1:P` 与 `[::1]:P` | 同左 |

  - `[::]:P` 两个地址都开(M4 实现时确定,原表只有 `[::1]`):双栈监听在主机上也接受 IPv4,
    只开 `[::1]` 的话 `curl http://127.0.0.1:P` 在主机上能通、在命名空间里不通。
  - 只转发 TCP;跳过 53 端口(DNS 必须由假 DNS 应答);不区分监听者属主。
  - 一次最多 250 个(一条 SCM_RIGHTS 最多 253 个 fd,另有 TUN 与捕获监听),超出的在 warn 里列出。
  - 监听 socket 在建命名空间时一次性建好;之后主机上新增的监听不处理,需要时重启程序。
  - `host_ports_forward = true`(默认)/ `--no-host-ports` 整体开关;`host_ports_exclude = [...]` 排除个别端口(程序自己要监听同号端口时用)。
  - 启动时以 info 级别列出转发了哪些端口。
  - tun2proxy 不处理这种情况(程序连 `127.0.0.1` 只到命名空间自己的回环)。

## 5. 运行时行为

- 与 proxyhook 一致:proxytun 是 subreaper,等整棵进程树结束才退出;退出码透传。第五轮复查起(用户决定 A),程序被信号杀死时
  proxytun 不再以 `128+信号` 正常退出,而是关掉 core、恢复默认处置后对自己发同一信号(`timeout`、sudo、strace 的做法):
  bash 的"等待并协同退出"只在子进程 WIFSIGNALED 时停下循环,systemd 停止服务时 `128+15` 会被记为失败。proxytun 自己因信号退出
  (程序已退出后的 Ctrl+C、连发两次 SIGTERM)同样以该信号结束;
  Ctrl+C 交给程序;只发给 proxytun 的 TERM/INT/QUIT 转发给程序,发给整个进程组的不重复;SIGHUP 热加载;SIGUSR1 打印统计。
- **"发给整个进程组的不重复"怎么做到**(M2 实现时确定):proxyhook 靠 ptrace 看见程序收到信号;proxytun 没有 ptrace,
  而 `kill <pid>` 与 `kill -- -<pgid>`/`kill %1`/systemd 逐进程发送,在 proxytun 看来都是 `SI_USER`。为此启动一个**见证进程**:
  与 proxytun 同一进程组、屏蔽 INT/QUIT/TERM(其余信号一律忽略,终端挂断或 Ctrl+Z 不会杀死/停住它)。
  proxytun 收到 `SI_USER` 信号后等 50 ms,问见证有哪些待处理信号:见证也收到且程序仍在本进程组 → 程序已有一份,不转发;
  否则转发。每次判断后清空见证的待处理信号。见证 double-fork(不是 proxytun 的子进程,不影响"等整棵树退出"),管道断开即退出。
  第五轮复查补正:见证改名为 `signal-witness`(`comm` 与命令行都改,命令行就地覆写),否则 `pkill proxytun`、`killall`、`pidof`
  会同时选中它,看起来像整组信号而不转发,程序什么也收不到;待处理信号改经管道问见证(`q` → 8 字节掩码),不再读
  `/proc/<见证>/status`:`hidepid`(`ProtectProc=invisible`)下 non-dumpable 的见证看不到,整组信号会重复送达;
  proxytun 是 pid 命名空间的 1 号进程(容器没加 `--init`)或预先被设为 subreaper 时,孤儿见证会被过继回来,
  所以程序被回收后关闭见证的管道,让它退出、被回收,否则 proxytun 等它等到永远。
  比 proxyhook 多覆盖一种情况:用 `sigwait`/`signalfd` 收信号的程序被整组 kill 时也不会收到两次。
  程序自己离开了 proxytun 的进程组(`setsid`、shell 作业控制,或 sudo `use_pty` 下的 sudo 模式)时,整组信号到不了它,照常转发;
  终端发的 `SI_KERNEL` 信号同理:程序还在本进程组就不转发(它已有一份),不在就转发。第五轮复查起,程序自成一组(是组长)时
  整组信号转给它的整个进程组,而不只是它自己:sudo `use_pty` 下 Ctrl+C 原先只到 `sh -c 'a | b'` 的 sh,管道里的进程继续运行。
  已知的、分不出来的情况(写在 README):程序不在本进程组时,逐进程发送(systemd、`kill -1`、`pkill -u`)会让它收到两份;
  50 ms 内连发两次 SIGTERM 时第二次让 proxytun 立即退出,程序可能一份也没收到;50 ms 内两次同类整组信号会多转发一次
  (见证只记"有没有",不记次数);见证启动前的几毫秒里收到的整组信号不转发。
- SIGPIPE:Rust 运行时在 `main` 之前把它设为忽略,原先 exec 前一律恢复默认,调用方 `trap '' PIPE` 时程序里却不再忽略
  (与"启动时被忽略的信号保持忽略"不符)。第五轮复查起用 ELF 构造函数(`.init_array`,在运行时之前执行)记下进程映像启动时的处置:
  userns 模式下准备进程 re-exec 前先设回调用方的处置,它自己的构造函数就能读到;sudo 模式下随请求传给助手(请求格式第 3 版)。
- proxytun 异常退出(`kill -9`、崩溃):**不杀程序**。TUN 随 fd 关闭消失,程序只剩回环,等于断网,不会绕过代理直连;日志与文档写明。
- 热加载范围同 proxyhook;主机端口转发、地址规划、`fake_ip_range`、`upstream_dns` 需要重启。
- 凭据保护同 proxyhook:程序环境里去掉 `PROXYTUN_PROXY`(原值就地清零),proxytun 设为 non-dumpable;`--proxy` 带密码时 warn。

## 6. 日志与监控

- 沿用 proxyhook:级别 off/error/warn/info/debug/trace,`-q`、`-v`/`-vv`、`--log-level`、`--log-file`(追加、600、无颜色;`O_NOFOLLOW`,已存在的文件必须属于自己,防止别人在 `/tmp` 里预先建好可读的文件),环境变量 `PROXYTUN_LOG`。
- 每条连接一个递增编号,span 为 `conn{id=… target=…}`;info 级别一行选路结果;trace 级别可从 TUN 收到 SYN 一直跟到代理握手。
  **不查发起连接的进程 pid**(TUN 上看不到,查 `/proc` 代价高)。
- **连接结束汇总**(2026-10-31 加,info 级别):`closed ms dial_ms via up down`,失败写原因,被拦下写 `blocked by a rule`。
  字节数由包在两个 socket 外的计数器边转发边累加,中途出错也有;同时累加进全局的 `relayed_up/down`,长连接在结束前就能在统计里看到。
- **DNS**:`-v` 每条查询一行(fake IP / 本地空应答 / 转发及上游耗时);计数 `dns_queries`、`dns_forwarded`、`dns_forward_failed`,
  上游第一次不应答时 warn 一次,之后记 debug。
- 代理健康检查、故障转移同 proxyhook,只有代理自己的问题才计入健康(第三轮复查):连不上代理、SOCKS5 问候/认证失败或超时、
  协议错误。代理只在目标有了结果后才回连接请求(squid、ssh -D、dante),所以请求发出后的超时算目标的问题:不计入、不换代理重试,
  否则连一个黑洞地址就能把整组代理标成 DOWN,程序还要等每个成员各超时一次。代价是"连得上 TCP 却永不回应 CONNECT"的
  HTTP 代理不会因连接失败被标成 DOWN(健康探测对 HTTP 代理只做 TCP 连接)。第五轮复查补正:SOCKS5 代理收下连接请求后不回复、
  直接断开(EOF/RST)也算目标的问题,`ssh -D` 连不上目标时正是这样,原先连续 3 个连不上的目标就把它标成 DOWN、所有连接一起失败;
  SOCKS5 0x02(规则不允许)与 HTTP 403 改为换其他成员重试、不计入健康(那是这个代理自己的访问控制,别的成员未必一样;
  代价是所有代理都拒绝的目标会多试几次);SOCKS5 的健康探测走与真实连接相同的问候,含认证,认证被拒或不接受任何方法都算失败
  (原先只发不带认证的问候、只看版本号,认证失败被标 DOWN 的节点会被探测拉回,来回跳)。根域 `.` 不分配假 IP;构造不出请求的目标
  (空域名、超长域名)在连代理之前就失败,也不计入。第四轮复查补正:这两种"代理一个字节没回/根本没问"的情况也不记成功
  (原先会清零失败计数、把刚标 DOWN 的节点拉回来);SOCKS5 问候与请求两阶段各自计时(共用截止时间时,慢问候会把请求阶段的超时
  算到目标头上);本机临时端口耗尽按目的地址计算,换个代理往往还有,所以遇到 EADDRNOTAVAIL 换成员重试(仍不计入健康)。
- **SIGUSR1**:累计计数(改写表、连接、中继字节、DNS、TUN 收发的包数与字节数、按原因分开的丢包)、距上次打印的速率、每个代理的状态。
- **TUN 循环跑在名为 `tun` 的专用线程上**(阻塞读),`top -H` 里一眼能看到瓶颈线程。改动前后本机基准(交替各 5 次):
  经 TUN 约 1060 → 1030 MB/s,主机端口约 1220 → 1280 MB/s,2000 条短连接 1.64–1.78 → 1.75–1.82 s,都在 ±5% 的波动内,没有性能收益也没有损失,
  保留它是为了可观测性。

## 7. 命令行与配置

- 命令行与 proxyhook 一致:`proxytun [选项] 程序 参数...`(`--` 可选),`-c`(默认 `proxytun.toml`)、`--proxy`、`-q`、`-v`/`-vv`、
  `--log-level`、`--log-file`、`--doctor`;新增 `--no-sudo`、`--no-host-ports`。环境变量 `PROXYTUN_PROXY`、`PROXYTUN_LOG`。
- 配置文件格式与 `proxyhook.toml` 相同,可直接拿来用;proxytun 用不到的键(`verify_peer_uid`、`block_quic`、`dns_udp_unconnected`、`splice`)
  和拼错的键,启动时 warn 并忽略。不兼容的只有 `fake_ip_range`:最后一个 /24 留给命名空间自己的地址,前缀限 /8–/22(proxyhook 允许到 /30),报错时说明原因。示例 `proxytun.toml` 只有必填的 `[[proxies]]`,其余以注释给出默认值。
- `--doctor`:报告将使用哪种模式(userns / sudo / root)。不靠猜 sysctl,而是按真实运行的路径建一次命名空间、以 `true` 为程序跑完;
  userns 不可用时说明原因并列出相关 sysctl(`max_user_namespaces`、`unprivileged_userns_clone`、AppArmor 限制),
  检查 PATH 里有没有 `sudo` 但不调用;另查 `/dev/net/tun`、Yama(`gdb -p` 的范围)、将转发的主机端口、每个代理(SOCKS5/HTTP 探测)。
  有 FAIL 时退出码为 1;配置读不出时把它记为一项 FAIL,其余照查。

## 8. 代码组织

- workspace 根在 `~/aicode/proxytun`:`crates/proxytun-core`(共享库)+ `crates/proxytun`(程序)。
- core 从 proxyhook `e0be192` 复制:`config`、`types`、`policy`、`balancer`、`health`、`proxy`、`sniff`、`net::{fakeip, dns, relay}`(`splice` 已删,见第 4 节);
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
