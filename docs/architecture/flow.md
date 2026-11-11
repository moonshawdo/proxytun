# proxytun 技术架构 · 3.0–3.2 核心流程

**简体中文** · [English](flow_en.md)

> [索引](../ARCHITECTURE.md) · [0 入门](primer.md) · [1–2 总览](overview.md) · **3.0–3.2 核心流程** · [3.3–3.6 流程细节](flow-details.md) · [4 模块](modules.md) · [5 运行模式与 sudo 助手](privilege.md) · [6 进程、信号与生命周期](lifecycle.md) · [7–8 负载均衡与运维](operations.md)

## 3. 核心流程

### 3.0 先分清几种地址

以默认的 `fake_ip_range = "198.18.0.0/15"` 为例:

| | 例子 | 是什么 | 谁看得到 |
|---|---|---|---|
| **假 IP** | `198.18.0.1` | 假 DNS 给程序的"域名答案",取自 `fake_ip_range` 去掉最后一个 /24 | 程序(它以为自己连的是这个地址) |
| **TUN 地址** | `198.19.255.1` | 命名空间里 `tun0` 的地址，也是程序连接的源地址和捕获监听的地址 | 程序、命名空间内核 |
| **假 DNS 地址** | `198.19.255.53` | 命名空间里 `/etc/resolv.conf` 指向它;发往任何地址 53 端口的查询也都由假 DNS 应答 | 程序的解析器 |
| **改写用的源地址** | `198.19.255.2`–`.17` : `1024`–`65535` | 地址改写表的键：每条程序的 TCP 连接分到一个"地址:端口" | 命名空间内核、proxytun |
| **捕获监听** | `198.19.255.1:<随机端口>` | 命名空间里 proxytun 的监听 socket,所有被改写的连接由它 accept | proxytun |

一句话：**假 IP 回答"这个域名是什么",改写用的源地址回答"这是哪一条连接",捕获监听回答"连接交给谁处理"。**

```mermaid
flowchart LR
    subgraph P["程序眼里看到的"]
        A["DNS 答案: example.com = 198.18.0.1"]
        B["connect(198.18.0.1:443)<br/>源地址 198.19.255.1:59754"]
    end
    subgraph T["tun 线程改写包头"]
        C["SYN 198.19.255.1:59754 -> 198.18.0.1:443<br/>改写成<br/>198.19.255.2:1024 -> 198.19.255.1:L<br/>记入改写表"]
    end
    subgraph R["中继 (proxytun, 主机侧)"]
        D["accept: 对端 = 198.19.255.2:1024<br/>查改写表 = 198.18.0.1:443<br/>查假 IP 池 = example.com"]
        E["SOCKS5 CONNECT example.com:443<br/>发给上游代理"]
    end
    A --> B --> C --> D --> E
```

要点:

- **假 IP 从头到尾不会出现在网络上。** 程序发往假 IP 的包只到 TUN,被改写后交给命名空间里的监听 socket;发往假 IP 的 UDP 得到 ICMP 端口不可达。
- **改写用的源地址也不出命名空间**,它们只是命名空间内核里 TCP 连接的一端。16 个地址 × 64512 个端口，约 103 万条(见 3.4)。
- 程序看到的对端地址就是它连的地址(`curl -w '%{remote_ip}'` 打印 `198.18.0.1`),因为改写在包头层完成，程序的 socket 不知道这回事。

一次真实运行的日志节选(`proxytun -vv --proxy socks5://... curl https://www.baidu.com`,略去时间戳和与本节无关的行),对应上面的流程:

```
INFO  proxytun::app: namespace up tun=198.19.255.1 dns=198.19.255.53
DEBUG proxytun_core::net::dns: dns: A -> fake ip domain=www.baidu.com ip=198.18.0.1
                    ^ 程序的 A 查询到了假 DNS,分到假 IP
TRACE proxytun::capture: syn src=198.19.255.1:34830 dst=198.18.0.1:443 nat=198.19.255.2:1024
                    ^ 程序连假 IP,SYN 被改写到改写用的源地址 198.19.255.2:1024
TRACE conn{id=1}: proxytun::accept: accepted nat=198.19.255.2:1024 dst=198.18.0.1:443
INFO  conn{id=1 target=Domain("www.baidu.com", 443)}: proxytun_core::net::relay: routing decision=Proxy { group: "default" }
                    ^ 中继按对端地址查回目标，反查出域名，规则判定后交给代理。之后这条连接的每一行都带同一个 conn{…}
http=200 remote_ip=198.18.0.1
INFO  proxytun::signals: program exited exit=Code(0)
```

### 3.1 启动流程(user namespace 模式)

```mermaid
sequenceDiagram
    autonumber
    participant PT as proxytun
    participant W as 见证进程
    participant S as 准备进程 (之后是程序)
    participant K as 内核

    Note over PT: 设 non-dumpable, 清除 PROXYTUN_PROXY<br/>记下调用方忽略的信号<br/>用 signalfd 接管 INT / QUIT / TERM
    PT->>W: double-fork 见证进程 (同一进程组)<br/>INT / QUIT / TERM 都被调用方忽略时不建
    Note over PT: 读配置, 建假 IP 池、规则与代理组<br/>设为 subreaper, 扫描主机端口
    PT->>S: fork, 立即 execv(/proc/self/exe, __proxytun_setup)
    S->>K: unshare(USER | NET | NS), 写 uid_map / gid_map
    S->>K: bind mount resolv.conf, lo up<br/>建 tun0, 地址与 MTU, 默认路由<br/>建捕获监听, 绑定主机端口的监听
    S-->>PT: SCM_RIGHTS 交回 TUN fd、捕获监听、主机端口监听
    Note over S: 等放行 (读控制 socket)
    Note over PT: 提高自己的打开文件数上限, 算出中继上限<br/>启动 tokio: 中继、主机端口、清扫、健康探测、信号<br/>启动 tun 线程
    PT->>S: 放行 (写 1 字节)
    S->>K: 恢复信号屏蔽与处置, execvp(程序), pid 不变
    Note over PT: 主线程 waitpid(-1) 直到整棵进程树结束
```

- **准备进程为什么要重新 exec。** proxytun 一启动就设为 non-dumpable(保护代理凭据),fork 出的子进程继承这一点，
  它的 `/proc/self/uid_map` 因此归 root、写不进去;而让子进程恢复 dumpable 又会暴露从父进程复制来的内存(含凭据)。
  重新 exec 后的新映像里没有凭据，也恢复为 dumpable。
- **为什么要等放行。** 程序 exec 之前,proxytun 必须已经在读 TUN、能 accept,否则程序的第一个包会无人处理。
- 没有非特权 user namespace 时，第 2–5 步(建准备进程、建并配置命名空间、交回 fd)改由 sudo 启动的特权助手完成，
  第 6 步的放行仍由 proxytun 发出，接收它并在第 7 步 exec 的是助手 fork 出、已经降权的程序一侧，流程见[第 5 节](privilege.md)。以 root 运行时不建 user namespace。

### 3.2 一次 HTTPS 访问的完整时序

```mermaid
sequenceDiagram
    autonumber
    participant App as 程序
    participant KN as 命名空间内核
    participant TT as tun 线程
    participant Dns as 假 DNS
    participant Pool as FakePool
    participant Nat as 地址改写表
    participant Rl as 中继
    participant Px as 上游代理

    Note over App,Dns: ① 解析域名
    App->>KN: A? example.com 发往 198.19.255.53:53
    KN->>TT: UDP 包
    TT->>Dns: 派发到 tokio (在途查询 ≤ 1024)
    Dns->>Pool: alloc(example.com)
    Pool-->>Dns: 198.18.0.1
    Dns->>KN: tokio 任务直接写回 TUN<br/>源地址是程序问的地址
    KN-->>App: A 198.18.0.1 (TTL 60)

    Note over App,Nat: ② 建立连接 (内核完成 TCP)
    App->>KN: connect(198.18.0.1:443)
    KN->>TT: SYN 198.19.255.1:59754 -> 198.18.0.1:443
    TT->>Nat: outbound: 新条目 198.19.255.2:1024
    TT->>KN: 改写后的 SYN 198.19.255.2:1024 -> 198.19.255.1:L
    KN->>TT: 捕获监听回 SYN-ACK 发往 198.19.255.2:1024
    TT->>Nat: inbound: 查回 198.18.0.1:443 / 198.19.255.1:59754
    TT->>KN: 改写回 198.18.0.1:443 -> 198.19.255.1:59754
    KN-->>App: connect 返回
    App->>KN: 第三次握手的 ACK
    KN->>TT: ACK
    TT->>KN: 同样改写后交给捕获监听, 连接进入 accept 队列

    Note over Rl,Px: ③ 中继
    Rl->>KN: accept, 对端 198.19.255.2:1024
    Rl->>Nat: accept: 目标 198.18.0.1:443
    Rl->>Pool: acquire(198.18.0.1) = example.com, 连接期间钉住
    Rl->>Rl: 规则判定 = Proxy{default}, 选出节点
    Rl->>Px: SOCKS5 CONNECT ATYP=3 example.com:443
    Px-->>Rl: 成功
    Rl-->>App: 双向拷贝 (每方向 64 KiB 缓冲)
```

DNS 侧的细节:A 查询本地回答假 IP;AAAA、HTTPS(65)、SVCB(64)回答空;`localhost` 回答 `127.0.0.1`;其余类型(MX/TXT/PTR...)
从主机转发给 `upstream_dns`。程序问的是哪个地址，应答就以哪个地址为源地址发回，解析器才会接受(见 3.6)。

连接结束时，中继关闭两端(出错时用 RST,见 3.5),改写表条目进入"已关闭"并保留 75 秒，让两端内核最后的 FIN/ACK 还能被改写(见 3.4)。
