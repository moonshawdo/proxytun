# proxytun 配置说明

本文逐项说明配置文件里的每个键：作用、类型、默认值、取值范围、能否热加载，以及与其他项的关系。
带注释的示例见 [proxytun.toml](../proxytun.toml);命令行参数和日志选项见 [README](../README.md#命令行参数);
各项背后的机制见 [ARCHITECTURE.md](ARCHITECTURE.md)。

- [1. 速查表](#1-速查表)
- [2. 文件、校验与加载](#2-文件校验与加载)
- [3. 顶层键](#3-顶层键)
- [4. `[health]` 健康检查](#4-health-健康检查)
- [5. `[[proxies]]` 上游代理](#5-proxies-上游代理)
- [6. `[[groups]]` 代理组与负载均衡](#6-groups-代理组与负载均衡)
- [7. `[[rules]]` 分流规则](#7-rules-分流规则)
- [8. 命令行与环境变量的覆盖](#8-命令行与环境变量的覆盖)
- [9. 配置示例](#9-配置示例)
- [10. 常见报错](#10-常见报错)

## 1. 速查表

"热加载"指改完配置后 `kill -HUP <proxytun pid>` 即生效;"重启"指必须重新运行 proxytun。

| 键 | 类型 | 默认值 | 取值范围 | 生效方式 |
|---|---|---|---|---|
| `fake_ip_range` | 字符串,IPv4 CIDR | `"198.18.0.0/15"` | 前缀 /8 ~ /22 | 重启 |
| `upstream_dns` | 字符串,`IP:端口` | 主机 `/etc/resolv.conf` 里第一个是 IP 的 nameserver,端口 53 | 必须是 IP,不能是主机名 | 重启 |
| `localnet` | CIDR 字符串数组 | `[]` | IPv4 或 IPv6 CIDR | 热加载 |
| `direct_to_proxies` | 布尔 | `true` | | 热加载 |
| `sniff` | 布尔 | `true` | | 热加载 |
| `sniff_ports` | 端口数组 | `[80, 443, 8443]` | 0 ~ 65535 | 热加载 |
| `sniff_skip_domains` | 字符串数组 | `["cloudflare-ech.com"]` | 域名后缀 | 热加载 |
| `sniff_override_destination` | 布尔 | `true` | | 热加载 |
| `sniff_timeout_ms` | 整数(毫秒) | `300` | 1 ~ 10000 | 热加载 |
| `host_ports_forward` | 布尔 | `true` | | 重启 |
| `host_ports_exclude` | 端口数组 | `[]` | 0 ~ 65535 | 重启 |
| `retries` | 整数 | `2` | ≥ 0 | 热加载 |
| `[health] interval_secs` | 整数(秒) | `10` | 1 ~ 3600 | 热加载 |
| `[health] fail_threshold` | 整数 | `3` | 1 ~ 100 | 热加载 |
| `[health] timeout_ms` | 整数(毫秒) | `3000` | 100 ~ 60000 | 热加载 |
| `[[proxies]]` `name` | 字符串 | 无(必填) | 唯一 | 热加载 |
| `[[proxies]]` `type` | `"socks5"` / `"http"` | 无(必填) | | 热加载 |
| `[[proxies]]` `addr` | 字符串,`IP:端口` | 无(必填) | 必须是 IP | 热加载 |
| `[[proxies]]` `username` / `password` | 字符串 | 无 | 各 ≤ 255 字节 | 热加载 |
| `[[proxies]]` `weight` | 整数 | `1` | 1 ~ 1000 | 热加载 |
| `[[groups]]` `name` | 字符串 | 无(必填) | 唯一;必须有 `default` | 热加载 |
| `[[groups]]` `strategy` | 枚举 | `"round-robin"` | 见第 6 节 | 热加载 |
| `[[groups]]` `members` | 字符串数组 | 无(必填) | 非空，均为已定义的代理名 | 热加载 |
| `[[rules]]` `match` | 枚举 | 无(必填) | 见第 7 节 | 热加载 |
| `[[rules]]` `value` | 字符串 | `""` | `final` 以外必填 | 热加载 |
| `[[rules]]` `action` | `"proxy"` / `"direct"` / `"block"` | 无(必填) | | 热加载 |
| `[[rules]]` `group` | 字符串 | `"default"` | 只能配合 `action = "proxy"` | 热加载 |

## 2. 文件、校验与加载

**位置。** 默认读当前目录下的 `proxytun.toml`,用 `-c <文件>` 指定其他路径。给了 `--proxy` 或 `PROXYTUN_PROXY` 时，配置文件可以不存在
(其余各项全部取默认值),也可以只写规则、不写代理(见第 8 节);没给代理又找不到配置文件则报错退出。

**与 proxyhook 兼容。** 格式与 `proxyhook.toml` 相同，可以直接拿来用。proxytun 用不到的 proxyhook 键(`verify_peer_uid`、`block_quic`、
`dns_udp_unconnected`、`splice`)启动时 warn 并忽略。唯一不兼容的是 `fake_ip_range` 的前缀范围(见 3.1)。

**TOML 顺序。** 顶层键(第 3 节的所有键)必须写在第一个 `[表]` / `[[表]]` 之前。写在某个表后面的键会被当成该表的字段。

**未知的键会警告并忽略。** 拼错的键名(如 `sniff_port`、`proxies.0.usrname`)启动时记一条 warn
(`config key has no effect in proxytun (a typo, or a proxyhook-only setting); ignored`),该项保持默认值。

**整体校验。** 启动和热加载时对整个文件做一次校验，任何一项不合法都会报错(见第 10 节),不会只生效一部分。
启动时报错则 proxytun 退出，目标程序不会运行;热加载时报错则保留旧配置继续运行，日志里有 `reload failed`。

**文件权限。** 文件里写了代理密码、而文件对组或其他用户有任何权限位(`mode & 077` 不为 0)时，启动会警告并提示 `chmod 600`。注意：被代理的程序与 proxytun 是同一用户，
它总能读到这个文件;不想让它看到密码时，改用环境变量 `PROXYTUN_PROXY`(第 8 节)。

**热加载(`kill -HUP <proxytun pid>`)。**

| 热加载生效 | 需要重启 |
|---|---|
| `[[rules]]`、`localnet`、`direct_to_proxies`、`[[proxies]]` / `[proxy]`、`[[groups]]`、`retries`、`sniff*` 全部、`[health]` 全部 | `fake_ip_range`、`upstream_dns`、`host_ports_forward`、`host_ports_exclude` |

- 已经建立的连接不受影响，之后的新连接使用新配置。
- 重载后各代理的健康状态和统计从头开始(全部视为健康),健康检查按新的 `[health]` 立即重新开始。
- 启动时给的 `--proxy` / `PROXYTUN_PROXY` 在重载后依然覆盖配置里的代理。
- 主机端口转发的监听 socket 在建命名空间时一次性建好，重载不改变。

## 3. 顶层键

### 3.1 fake-ip 与 DNS

#### `fake_ip_range`

程序解析域名时,proxytun 的假 DNS 从这个网段里给它分配一个"假 IP"。程序随后连这个假 IP,proxytun 据此反查出原来的域名，把**域名**交给代理。
这就是域名能一直保留到代理的原因(见 [核心流程](architecture/flow.md))。

- 类型:IPv4 CIDR 字符串;默认 `"198.18.0.0/15"`;前缀长度 /8 ~ /22;修改需重启。
- **最后一个 /24 留给命名空间自己**:默认 `198.19.255.0/24` 里,`.1` 是 TUN 设备,`.53` 是假 DNS,`.2`–`.17` 是地址改写用的源地址。
  所以前缀至少 /22(proxyhook 允许到 /30,比 /22 更窄的段要放宽，报错里会说明)。
- 其余地址分给域名。映射最多 100 万条，再大的网段也一样;DNS 应答的 TTL 为 60 秒。地址用完后，回收最久未使用、
  且当前没有连接在用、距上次应答或使用超过 120 秒的映射;回收不了时新的查询得到 `SERVFAIL`,不会覆盖正在使用的映射。映射只在内存里，重启后失效。
- **选段要求：不能与程序真正要访问的地址重叠。** 默认的 198.18.0.0/15 是 RFC 2544 规定的基准测试保留段，公网上不会出现，通常不需要改。
- 只有 IPv4。程序的 AAAA 查询得到空应答，会退回到 IPv4。

#### `upstream_dns`

proxytun 自己不伪造的那些 DNS 查询，从主机原样转发到这里。

- 类型:`"IP:端口"` 字符串;默认是主机 `/etc/resolv.conf` 里第一个能解析为 IP 的 nameserver(跳过带 `%网卡` 的 IPv6 链路本地地址),端口 53;没有时 `127.0.0.1:53`,同 glibc;必须是 IP 地址;修改需重启。
- 从主机发出，所以主机上的 `127.0.0.53`(systemd-resolved)之类本地解析器也能用。
- 各类查询的处理:

  | 查询 | 处理 |
  |---|---|
  | `A` | 分配假 IP 应答(`localhost` 及 `*.localhost` 答 `127.0.0.1`;根域 `.` 答空) |
  | `AAAA`、`HTTPS`(65)、`SVCB`(64) | 本地答空(NOERROR,无记录),让程序走 IPv4 假 IP |
  | 其他(`MX`、`TXT`、`PTR`、`SRV` …)及非 `IN` 类 | 转发到 `upstream_dns`:UDP 查询走 UDP,TCP 查询走 TCP,3 秒超时 |

- **转发是直连，不经过代理**,是明文 DNS。所在网络不能直连外部 DNS 时，改成内网 DNS,例如 `"192.168.1.1:53"`。
- 与 `direct` 规则无关:`direct` 的域名由 proxytun 用主机的系统解析器(`getaddrinfo`)解析，不经过这里。
- 程序发往**任意** IP 53 端口的查询(UDP 与 TCP)都由假 DNS 应答，包括硬编码 `8.8.8.8` 的程序;命名空间里的 `/etc/resolv.conf`
  也被换成只指向假 DNS(保留主机的 `search` / `domain` / `options`,去掉 `ndots`)。

### 3.2 直连范围

#### `localnet`

目标地址落在这些网段内的连接由 proxytun 从主机直接连接，不嗅探、不看 `[[rules]]`、不经代理。作用和 proxychains 的 `localnet` 相同。

- 类型:CIDR 字符串数组,IPv4 / IPv6 均可;默认 `[]`;可热加载。
- 只对**字面 IP** 的目标生效(程序没有经假 DNS 解析，直接连 IP)。经假 DNS 解析的域名按规则处理。
- 默认为空的原因：命名空间里的 `127.0.0.0/8` 是命名空间自己的回环，程序连 `127.0.0.1` 根本到不了 proxytun(主机的本地服务见 3.4)。
- 想让局域网不走代理，把它加进来，例如 `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]`。
- 与 `ip-cidr` + `direct` 规则的区别：两者都由 proxytun 从主机直连;`localnet` 先于嗅探和规则判定，命中后不再看别的。

#### `direct_to_proxies`

程序自己连 `[[proxies]]` 里的某个代理时(它自己的代理设置、`curl -x`),按 IP + 端口直连，不再经代理绕一次。

- 类型：布尔;默认 `true`;可热加载。
- 只放行那个端口：同一主机的其他端口照常走规则。这是与 `localnet` 的区别。
- 用 `--proxy` / `PROXYTUN_PROXY` 时，覆盖后的代理同样适用。

**程序环境变量里的代理。** 不管 `direct_to_proxies` 如何，程序环境变量 `http_proxy` / `https_proxy` / `all_proxy`(大小写均可)
指向的代理也直连，避免"代理套代理":

- 写的是 `IP:端口` 时，连这个地址直连;写的是主机名时，连这个"主机名:端口"按 `direct` 处理。
- 没写端口时:`http://` 和不带 scheme 的同时登记 80 和 1080(curl、git 连 1080,pip、Go、wget、npm、apt 连 80),
  `socks5://` 等为 1080,`https://` 为 443。
- proxytun 不改写、不删除这些环境变量。

### 3.3 嗅探(从首包恢复域名)

程序没有经过 proxytun 的假 DNS、直接连了一个字面 IP 时(Chrome 的安全 DNS / DoH、硬编码 IP、`/etc/hosts`、经 nscd /
systemd-resolved 的 unix socket 解析),proxytun 先看一眼程序发出的第一段数据，从 TLS ClientHello 的 SNI 或 HTTP 的 `Host` 头里恢复域名。
只偷看，不消耗数据，程序和服务器之间的字节流不变。

以下情况**不嗅探**:目标本来就是域名;端口不在 `sniff_ports` 里;目标是私网、回环、链路本地、CGNAT(100.64.0.0/10)或 IPv6 ULA 地址
(这类地址是有意连的);目标地址被某条 `ip-cidr` 规则覆盖(以你写的 IP 规则为准);目标在 `localnet` 里或是程序自己的代理。

#### `sniff`

- 类型：布尔;默认 `true`;可热加载。总开关,`false` 时下面几项都不起作用。

#### `sniff_ports`

- 类型：端口号数组;默认 `[80, 443, 8443]`;可热加载。
- 只在这些目标端口上等待首包，其他端口没有任何延迟。
- 不要放"服务器先说话"的协议端口(SMTP 25、SSH 22、FTP 21 等):客户端在收到服务器问候前不会发数据，每个连接都会白等 `sniff_timeout_ms`。

#### `sniff_skip_domains`

- 类型：字符串数组;默认 `["cloudflare-ech.com"]`;可热加载。
- 嗅探到的名字等于其中某项或是它的子域名时，不采用这个名字，保留原 IP。比较不区分大小写，开头的 `.` 会被忽略。
- 用途：真正启用 ECH(加密 ClientHello)的连接，明文 SNI 里只有服务商的"公共名",不是真实目的地。

#### `sniff_override_destination`

- 类型：布尔;默认 `true`;可热加载。
- `true`:嗅探出的域名既用于匹配规则，也作为目的地发给代理，代理可以按域名分流、自己解析。
- `false`:域名只用于匹配规则，发给代理的仍是原 IP。

#### `sniff_timeout_ms`

- 类型：整数，毫秒;默认 `300`;范围 1 ~ 10000;可热加载。
- 等待首包的最长时间，超时就保留原 IP。只影响 `sniff_ports` 上连字面 IP 的连接的建连时间。

### 3.4 主机的本地服务

命名空间里的 `127.0.0.1` 是命名空间自己的回环，与主机隔离。proxytun 启动时扫描一次主机上监听回环或通配地址(`0.0.0.0`、`[::]`)的 TCP 端口，开进命名空间的回环地址，
程序连这些地址时转发到主机(映射表见 [README](../README.md#访问本机服务))。

#### `host_ports_forward`

- 类型：布尔;默认 `true`;修改需重启。命令行 `--no-host-ports` 等价于 `false`。
- 一次最多 250 个地址(`[::]:P` 对应两个),超出的在 warn 里列出;53 端口不转发(DNS 必须由假 DNS 应答);不区分监听者属主。
- 启动之后主机上新开的端口看不到，需要时重启。

#### `host_ports_exclude`

- 类型：端口号数组;默认 `[]`;修改需重启。
- 不转发的端口。程序自己要在命名空间里监听同号端口时用，否则它会得到 `EADDRINUSE`。

### 3.5 重试

#### `retries`

- 类型：非负整数;默认 `2`;可热加载。
- 与代理握手失败时，最多再换几个组内成员重试。总尝试次数 = `retries` + 1,且不超过组内健康成员的数量。`0` 表示不换。
- 只在握手阶段重试：这时程序的数据一个字节都还没发出，重试是安全的。
- 会换成员重试：连不上代理、连接超时(5 秒)、问候超时、代理回复"一般性失败"或访问控制拒绝(SOCKS5 0x01、0x02,HTTP 403、500、503 等)、
  SOCKS5 代理收下请求后直接断开(`ssh -D` 连不上目标时就是这样)、本机临时端口耗尽。
- 不重试：代理明确回复目标拒绝、不可达(SOCKS5 0x03 ~ 0x06,HTTP 502、504),或代理等目标超时(换一个代理也会是同样的结果)。
  本机 fd / 内存不足，或目标域名为空、超过 255 字节(SOCKS5 编码不了)时也直接失败。
- 所有尝试都失败时向程序发 RST 关闭连接，**不会回落到直连**。

## 4. `[health]` 健康检查

proxytun 定期主动探测每个代理，并结合真实连接的结果，判断代理是否可用。

```toml
[health]
interval_secs = 10
fail_threshold = 3
timeout_ms = 3000
```

| 键 | 默认 | 范围 | 说明 |
|---|---|---|---|
| `interval_secs` | `10` | 1 ~ 3600 | 两轮探测之间的间隔。启动时立即探测一轮，每轮并发探测所有代理 |
| `fail_threshold` | `3` | 1 ~ 100 | 连续失败多少次标为 DOWN。主动探测失败和真实连接里代理自己的失败都计数;目标的问题、本机资源不足不计 |
| `timeout_ms` | `3000` | 100 ~ 60000 | 单次探测的超时。设得太小会把正常代理都标成 DOWN |

- 探测内容：与代理建立 TCP 连接;SOCKS5 代理再做一次与真实连接相同的问候(含用户名密码认证),被拒或不接受任何方法都算失败;
  HTTP 代理只建 TCP 连接。测的是到代理这一跳，不包括代理到目标。
- 探测往返时间做指数加权平均(新样本占 0.3),供 `least-latency` 策略使用。
- 被标为 DOWN 的代理不再被选中，只有探测成功才恢复为健康。
- 组内成员全部 DOWN 时，走这个组的连接直接失败(`no healthy proxy available`),不会直连。
- 本机资源不足(打开文件数、内存、临时端口用尽)时探测跳过，不计为失败。
- 日志：健康探测把代理标为 DOWN 时记 warn(`proxy marked DOWN`),由真实连接的失败标为 DOWN 时只有那次的 `dial failed` warn;恢复记 info,单次探测失败记 debug。`kill -USR1 <proxytun pid>` 打印各代理的状态和计数。

## 5. `[[proxies]]` 上游代理

每个 `[[proxies]]` 表定义一个上游代理。至少要有一个(或者用 `--proxy` / `PROXYTUN_PROXY` 给出)。

```toml
[[proxies]]
name = "hk"
type = "socks5"
addr = "10.0.0.1:1080"
username = "user"     # 可选
password = "pass"     # 可选
weight = 3            # 可选，只有 weighted-round-robin 使用
```

| 键 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 唯一名称,`[[groups]]` 的 `members` 引用它 |
| `type` | 是 | `"socks5"`:按 SOCKS5 的域名方式(ATYP=3)把域名发给代理，支持无认证和用户名密码认证。`"http"`:发送 `CONNECT 域名:端口`,有用户名时带 `Proxy-Authorization: Basic` |
| `addr` | 是 | 代理的 `IP:端口`,IPv6 写成 `"[::1]:1080"`。**必须是 IP 地址**,proxytun 不解析代理的主机名。proxytun 从主机连它，所以 `127.0.0.1` 指主机自己 |
| `username` / `password` | 否 | 各不超过 255 字节(SOCKS5 协议的限制) |
| `weight` | 否 | 1 ~ 1000,默认 1。只有 `weighted-round-robin` 策略使用 |

- 不支持：到代理的 TLS(HTTPS 代理)、SOCKS4、经过多个代理的链式转发。
- 日志和报错里的密码一律显示为 `***`。
- **旧写法 `[proxy]`**:单个代理,`name` 可以省略(默认 `"default"`),等价于一个 `[[proxies]]`;没写 `[[groups]]` 时再加上只包含它的 `default` 组。
  同时写了 `[[proxies]]` 时,`[proxy]` 会被忽略。

## 6. `[[groups]]` 代理组与负载均衡

一个组把若干代理放在一起，按策略为每条连接选一个出口。规则通过组名把流量交给某个组。

```toml
[[groups]]
name = "default"
strategy = "least-latency"
members = ["hk", "jp"]
```

| 键 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 唯一名称。**必须有一个叫 `default` 的组**:没写 `group` 的 `proxy` 规则，以及没有命中任何规则的连接，都用它 |
| `strategy` | 否 | 默认 `"round-robin"`,取值见下表 |
| `members` | 是 | 非空，每项都必须是已定义的代理 `name`。同一个代理可以出现在多个组里 |

一个 `[[groups]]` 都不写时，自动生成 `default` 组，包含全部代理，策略为 `round-robin`。

每次选择只在"健康、且这条连接还没试过"的成员里进行:

| `strategy` | 行为 | 适用场景 |
|---|---|---|
| `round-robin` | 依次轮流 | 默认;各代理能力相近 |
| `random` | 随机：每次启动和热加载时从 `/dev/urandom` 取种子 | 频繁短时运行(每次只有几条连接):`round-robin` 每次启动都从第一个成员开始,`random` 能把负载分散开 |
| `least-conn` | 当前经它转发的活跃连接最少的;数量相同时轮流 | 长连接多、连接时长差异大 |
| `least-latency` | 健康检查测得的延迟(加权平均)最低的;还没有测量结果时轮流 | 代理位置不同，想选最快的。SOCKS5 与 HTTP 混在一组时偏向 HTTP(SOCKS5 的探测多一个问候往返) |
| `weighted-round-robin` | 按 `weight` 的比例轮流 | 代理带宽不同 |
| `hash` | 按目标主机(域名或 IP,不含端口)做一致性哈希，同一主机总走同一个代理;某个代理下线时，只有原来由它负责的主机会改走别的代理 | 需要固定出口 IP 的网站(登录态、风控) |

## 7. `[[rules]]` 分流规则

规则决定每条 TCP 连接是走代理、直连还是被阻断。**从上到下，第一条命中的规则生效。**

```toml
[[rules]]
match  = "domain-suffix"
value  = "openai.com"
action = "proxy"
group  = "sticky"     # 可选，默认 "default"
```

| 键 | 必填 | 说明 |
|---|---|---|
| `match` | 是 | 匹配方式，见下表 |
| `value` | `final` 以外必填 | 要匹配的值;`final` 不需要 |
| `action` | 是 | `"proxy"`、`"direct"` 或 `"block"` |
| `group` | 否 | 只能和 `action = "proxy"` 一起用，必须是已定义的组;不写则用 `default` 组 |

### 7.1 匹配方式

| `match` | 匹配对象 | 命中条件 | 例子(`value`) |
|---|---|---|---|
| `domain-suffix` | 域名 | 等于 `value`,或以 `.value` 结尾 | `example.com` 命中 `example.com`、`a.b.example.com`,不命中 `badexample.com` |
| `domain-keyword` | 域名 | 包含 `value` 这个子串 | `google` 命中 `www.google.com`、`googleapis.com` |
| `domain` | 域名 | 与 `value` 完全相同 | `api.example.com` 只命中它自己 |
| `ip-cidr` | 字面 IP | 落在网段内 | `192.168.0.0/16`、`2001:db8::/32`;单个地址写 `/32` 或 `/128` |
| `final` | 任何连接 | 总是命中 | 通常放在最后，作为兜底 |

- 域名比较不区分大小写。`domain-suffix` 的 `value` 写成 `*.example.com` 或 `.example.com` 也可以，会被规范成 `example.com`。
  国际化域名用 punycode 形式(`xn--…`)书写。
- `ip-cidr` 的 `value` 必须带前缀长度，只写 `1.2.3.4` 会报错。IPv4 映射的 IPv6 地址(`::ffff:1.2.3.4`)按 IPv4 匹配。

### 7.2 动作

| `action` | 行为 |
|---|---|
| `proxy` | 交给 `group` 指定的组(默认 `default`),按第 6 节选出口;失败时按 `retries` 重试，最终失败则向程序发 RST |
| `direct` | proxytun 从主机直接连目标，不经代理。目标是域名时用主机的系统解析器解析出真实 IP(程序手里只有假 IP);同时最多 32 个解析，超出时该连接立即失败 |
| `block` | 连接被立即关闭 |

### 7.3 一条连接如何被判定

1. **捕获阶段**(TUN 线程):
   - UDP 53 端口：交给假 DNS,不看规则。
   - 其他 UDP:回 ICMP 端口不可达，程序立即失败(QUIC 回落 TCP)。
   - TCP:改写地址，交给命名空间里的监听 socket,由中继接手。
2. **中继阶段**:
   - 目标端口 53:按 TCP DNS 交给假 DNS。
   - 目标是假 IP:反查回域名，以域名为目标。
   - 目标是字面 IP 且在 `localnet` 里、或是程序自己的代理(环境变量里的 `IP:端口`、`direct_to_proxies` 的 `[[proxies]]`):从主机直连，
     不嗅探、不看规则。
   - 目标是字面 IP、端口在 `sniff_ports` 里:按 3.3 嗅探域名。
   - 目标是程序代理环境变量里的"主机名:端口":直连。
   - 否则按顺序匹配 `[[rules]]`,第一条命中的生效。
   - **没有任何规则命中时，交给 `default` 组走代理，不会直连。**

匹配用到哪类规则，取决于目标是什么:

- **目标是域名**(程序经假 DNS 解析，或嗅探恢复出了域名):只看 `domain-*` 规则和 `final`。proxytun 不会为了匹配 `ip-cidr` 去解析域名。
- **目标是字面 IP**(程序没经过假 DNS,也没嗅探出域名):只看 `ip-cidr` 规则和 `final`。

## 8. 命令行与环境变量的覆盖

| 方式 | 效果 |
|---|---|
| `--proxy <URL>` | 用这一个代理替换配置里的全部 `[[proxies]]` / `[proxy]` 和 `[[groups]]`:它成为名为 `default` 的代理，放在 `default` 组里。其余配置(规则、`localnet`、嗅探等)不变 |
| `PROXYTUN_PROXY=<URL>` | 同 `--proxy`;两者都给时 `--proxy` 优先。读取后立即在内存里清零并从环境中删除，程序继承不到。带密码时用它，不要用 `--proxy`(命令行参数任何本机用户都能从 `ps` 看到) |

- URL 格式:`socks5://[用户名:密码@]IP:端口`(`socks5h://` 等同)或 `http://[用户名:密码@]IP:端口`。主机部分同样必须是 IP。
  用户名或密码里的 `@`、`:`、`/` 写成 `%40`、`%3A`、`%2F`。
- 有覆盖时，配置文件先解析、覆盖之后再校验，所以配置文件可以不存在，也可以只写规则不写代理。
- 覆盖替换全部代理，原先指定了其他分组(`group = "hk"`)的规则也改走这个代理，启动和每次热加载时各 warn 一次。
- 日志级别和日志文件只能在命令行设置(`-q`、`-v`、`--log-level`、`--log-file`、`PROXYTUN_LOG`),不在配置文件里，见 README"日志"一节。
  `--no-sudo` 同样只有命令行选项;`--no-host-ports` 在配置文件里对应 `host_ports_forward = false`。

## 9. 配置示例

### 9.1 最小配置

```toml
[[proxies]]
name = "clash"
type = "socks5"
addr = "127.0.0.1:7890"
```

所有 TCP 连接都经这个代理，域名原样交给它;主机的本地服务照常可达。`127.0.0.1` 指主机(proxytun 从主机连代理)。

### 9.2 只写规则，代理来自环境变量

```toml
# rules.toml:不含任何代理或密码，可以放进版本库
[[rules]]
match = "domain-suffix"
value = "corp.example"
action = "direct"
```

```bash
PROXYTUN_PROXY=http://user:pass@10.0.0.5:8080 proxytun -c rules.toml git fetch
```

`corp.example` 下的域名从主机直连，其余走 `PROXYTUN_PROXY`。

### 9.3 局域网和国内直连，其余走代理

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

### 9.4 多个代理：默认选最快的，个别网站固定出口，广告域名阻断

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

最后没有写 `final`:未命中的连接走 `default` 组。文件里有密码，记得 `chmod 600`。

### 9.5 程序要在命名空间里监听主机上已占用的端口

```toml
host_ports_exclude = [8080]

[[proxies]]
name = "clash"
type = "socks5"
addr = "127.0.0.1:7890"
```

主机上 8080 端口有服务在监听时，默认会被转发进命名空间;程序自己要监听 8080 时把它排除。

### 9.6 从 proxyhook 迁移

`proxyhook.toml` 一般可以直接用。需要注意的只有:

- `fake_ip_range` 比 /22 窄时要放宽(proxytun 要占用最后一个 /24)。
- `localnet` 里的 `127.0.0.0/8` 在 proxytun 里不起作用(主机回环服务由主机端口转发处理),可以删掉。
- `verify_peer_uid`、`block_quic`、`dns_udp_unconnected`、`splice` 会被警告并忽略。
- `upstream_dns` 不写时默认用主机的 nameserver,而不是 `1.1.1.1:53`。

## 10. 常见报错

启动或热加载时的配置错误，报错信息及原因:

| 报错信息 | 原因 |
|---|---|
| `parsing config toml` | TOML 语法错误、缺少必填字段(`missing field`)、类型或整数范围不对(如 `retries = -1`)、枚举值写错(如 `strategy = "rr"` 会提示 `unknown variant`) |
| `reading config proxytun.toml` | 配置文件不存在，也没有 `--proxy` / `PROXYTUN_PROXY` |
| `no upstream proxy configured (add [[proxies]] or [proxy])` | 一个代理都没有定义，也没有 `--proxy` / `PROXYTUN_PROXY` |
| `every [[proxies]] entry needs a name` | `[[proxies]]` 缺 `name` |
| `duplicate proxy name '…'` / `duplicate group name '…'` | 名称重复 |
| `proxy '…': bad addr "…" (want ip:port)` | `addr` 不是 `IP:端口`,例如写了主机名 |
| `proxy '…': weight must be between 1 and 1000` | `weight` 超出范围 |
| `proxy '…': username/password longer than 255 bytes` | 用户名或密码过长 |
| `group '…' has no members` / `group '…': unknown proxy '…'` | 组成员为空，或引用了不存在的代理 |
| ``no group named 'default' (rules without `group` use it)`` | 写了 `[[groups]]` 但没有 `default` 组 |
| `health.interval_secs must be between 1 and 3600` 等 | `[health]` 的值超出范围 |
| `sniff_timeout_ms must be between 1 and 10000` | 同上 |
| `bad fake_ip_range …` / `fake_ip_range prefix must be between /8 and /22 …` | 不是 IPv4 CIDR,或前缀长度超出范围(proxyhook 配置里比 /22 更窄的段要放宽) |
| `bad upstream_dns …` | 不是 `IP:端口` |
| `bad localnet entry …` | 不是合法的 CIDR |
| `rule #N: bad ip-cidr …` | `ip-cidr` 的值不是 CIDR(比如漏了 `/32`) |
| ``rule #N: `value` is required for …``(… 是规则类型的内部名，如 `DomainSuffix`) | 非 `final` 规则缺 `value` |
| ``rule #N: `group` only applies to action = "proxy"`` | `direct` / `block` 规则写了 `group` |
| `rule #N: unknown group '…'` | 引用了不存在的组 |
| `unsupported proxy scheme …` | `--proxy` / `PROXYTUN_PROXY` 的 scheme 不是 `socks5`、`socks5h`、`http` |
| `proxy url "…" needs a scheme (socks5:// or http://)` | `--proxy` / `PROXYTUN_PROXY` 没写 `socks5://` 或 `http://` |
| `bad percent-escape in proxy url credentials` | 代理 URL 里用户名或密码的 `%XX` 转义写错 |
| `seeding the random strategy from /dev/urandom` | 有 `random` 策略的组，但读不到 `/dev/urandom`(没有 `/dev`、fd 用尽):拒绝启动或这次重载，不退回固定种子 |
