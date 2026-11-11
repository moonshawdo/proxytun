# 在 CentOS 7 真机上验证 proxytun

**简体中文** · [English](CENTOS7_en.md)

开发机上已经用"外层 user namespace + `max_user_namespaces=0` + setuid 的假 sudo"模拟了 CentOS 7 的 sudo 模式,
端到端测试全部通过(gnu 与 musl 静态版本都跑过)。模拟覆盖不到、只能在真机上确认的是:

| 项目 | 为什么模拟不了 |
|---|---|
| 3.10 内核上 root 建网络命名空间、TUN、ioctl 配地址与路由、`/proc` 字段 | 容器和模拟都共用宿主机的 6.18 内核 |
| 真 sudo 1.8.23 的行为(进程组、`closefrom`、`requiretty`、密码提示) | 模拟用的是自己写的假 sudo |
| SELinux enforcing 下 bind-mount `resolv.conf`、TUN 设备访问 | 开发机没有 SELinux |

请按下面的顺序执行,把每一步的输出发回来。`HOST:PORT` 换成你的代理。

## 0. 准备

```bash
# 开发机上构建静态版本,拷到 el7
./scripts/build-static.sh
scp dist/proxytun-x86_64-linux-musl el7:/tmp/proxytun
# el7 上:sudo 会以 root 执行这个文件,所以装到只有 root 能写的位置(不要从家目录运行)
sudo install -o root -g root -m 0755 /tmp/proxytun /usr/local/bin/proxytun && rm /tmp/proxytun
```

## 1. 环境信息

```bash
uname -r; cat /etc/centos-release
cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "no max_user_namespaces (kernel before 7.4)"
sudo -V | head -1
sudo grep -E '^\s*Defaults.*(use_pty|requiretty)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
getenforce 2>/dev/null
```

## 2. 自检

```bash
proxytun --doctor --proxy socks5://HOST:PORT
```

预期:报告将使用 **sudo** 模式,并说明 user namespace 为什么不可用;代理连通性 OK。

## 3. 基本代理

```bash
proxytun --proxy socks5://HOST:PORT -- curl -sI https://example.com
```

预期:
- 先有一行 `WARN ... user namespaces are not usable here: ...; asking sudo to create the namespace (--no-sudo refuses)`,然后 sudo 要密码;
- curl 返回 `HTTP/... 200`;
- 日志里有 `conn{id=1 target=Domain("example.com", 443)}`:代理收到的是域名。

## 4. 程序的身份与看到的网络

```bash
proxytun --proxy socks5://HOST:PORT -- sh -c 'id; grep -E "^Cap(Prm|Eff)" /proc/self/status; cat /etc/resolv.conf; getent hosts example.com; ip -br addr; ip route'
ulimit -u; umask; proxytun --proxy socks5://HOST:PORT -- sh -c 'ulimit -u; umask'
proxytun --proxy socks5://HOST:PORT -- cat /proc/sys/net/core/somaxconn
```

预期:
- 最后一行是 `4096`(3.10 内核上新网络命名空间默认 128,会让成批的连接等 SYN 重传;这一项开发机测不了);
- 倒数第 2–3 行(程序里的值)与再往前两行(你自己 shell 的值)相同:程序拿到的是你的进程数上限和 umask,不是 sudo 给 root 的(CentOS 7 的 `20-nproc.conf` 对 root 不限);
- `id` 是你自己的 uid、gid 和附加组(不是 root);
- `CapPrm` / `CapEff` 全为 0;
- `nameserver 198.19.255.53`;`example.com` 解析为 `198.18.x.x`;
- 只有 `lo` 和 `tun0`(`198.19.255.1/24`),默认路由走 `tun0`。

## 4a. 不能借 proxytun 提权

```bash
sudo /usr/local/bin/proxytun --proxy socks5://HOST:PORT -- id; echo "exit=$?"   # 绝对路径:secure_path 里没有 /usr/local/bin
proxytun --proxy socks5://HOST:PORT -- sudo -n true; echo "exit=$?"
proxytun --proxy socks5://HOST:PORT -- grep NoNewPrivs /proc/self/status
```

预期:
- 第一条输出 `proxytun refuses to run as root through sudo ...`,`exit=2`,`id` 没有运行;
- 第二条里 sudo 报 `The "no new privileges" flag is set ...` 一类的错误,退出码非 0(程序里的 setuid 程序不能提权);
- 第三条输出 `NoNewPrivs:	1`。

## 5. 运行期间没有 root 进程

一个终端:

```bash
proxytun --proxy socks5://HOST:PORT -- sleep 60
```

另一个终端:

```bash
pstree -pu $(pgrep -f 'proxytun --proxy' | head -1)
ps -o user,pid,ppid,pgid,sid,cmd --ppid $(pgrep -f 'proxytun --proxy' | head -1)
```

预期:进程树里只有你的用户(sudo 和特权助手已经退出);`sleep` 的父进程是 proxytun,进程组(PGID)与 proxytun 相同。

## 6. 调试工具

```bash
proxytun --proxy socks5://HOST:PORT -- strace -f -e trace=connect curl -s -o /dev/null https://example.com
proxytun --proxy socks5://HOST:PORT -- gdb -batch -nx -ex 'break connect' -ex run -ex 'bt 1' -ex delete -ex continue \
    --args curl -s -o /dev/null -w '%{http_code}\n' https://example.com
```

预期:strace 打出 `connect(... 198.18.x.x ...)` 且 curl 成功;gdb 停在 `connect`,继续后打印 `200`。

## 7. 信号

```bash
proxytun --proxy socks5://HOST:PORT -- sleep 100      # 按 Ctrl+C
echo "exit=$?"                                           # 预期 130,立即退出
proxytun --proxy socks5://HOST:PORT -- sleep 100 &
sleep 3; kill %1; wait; echo "exit=$?"                   # 预期 143(sleep 被 SIGTERM 终止)
```

## 8. 退出后没有残留

```bash
ip -br link | grep -c tun0         # 预期 0:主机上没有 TUN
grep nameserver /etc/resolv.conf   # 预期与运行前相同
ls -ld /tmp/proxytun-* 2>/dev/null # 预期没有输出
```

## 出问题时请附上

- 加 `-vv --log-file ~/proxytun.log` 重跑那一步,发回日志;
- SELinux 为 Enforcing 时:`sudo ausearch -m avc -ts recent`;
- 启用了 devtoolset(`scl enable devtoolset-N`)时,PATH 上排在前面的 `sudo` 是它的包装脚本;proxytun 跳过它，直接用
  setuid 的 `/usr/bin/sudo`,`--doctor` 的 `sudo mode` 一行会显示实际用的路径;
- sudo 模式的启动过程不能用 `strace -f` 跟踪：以你的身份跟踪时 sudo 拿不到 root(报 `effective uid is not 0`);
  以 root 跟踪时特权助手发现自己被跟踪会拒绝运行(这是有意的)。请用 `-vv` 日志;要看程序的系统调用，用第 6 节的
  `proxytun -- strace -f ...`,或在启动后 `strace -p <proxytun 的 pid>`;
- 如果报 `sudo: sorry, you must have a tty to run sudo`:说明 sudoers 有 `requiretty`,请从交互终端运行(不要经 cron 或无 tty 的 ssh)。
