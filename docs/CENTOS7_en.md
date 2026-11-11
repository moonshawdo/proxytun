# Verifying proxytun on a real CentOS 7 machine

[简体中文](CENTOS7.md) · **English**

On the development machine, CentOS 7's sudo mode has already been simulated with "an outer user namespace + `max_user_namespaces=0` + a setuid fake sudo",
and the end-to-end tests all pass (both the gnu and the musl static builds were run). What the simulation cannot cover and only a real machine can confirm:

| Item | Why it cannot be simulated |
|---|---|
| On the 3.10 kernel: root creating a network namespace and TUN, configuring addresses and routes via ioctl, `/proc` fields | Containers and the simulation all share the host's 6.18 kernel |
| Behavior of the real sudo 1.8.23 (process groups, `closefrom`, `requiretty`, password prompt) | The simulation uses a fake sudo written for it |
| Under SELinux enforcing: bind-mounting `resolv.conf`, TUN device access | The development machine has no SELinux |

Run the steps below in order and send back the output of each step. Replace `HOST:PORT` with your proxy.

## 0. Preparation

```bash
# On the development machine: build the static binary and copy it to el7
./scripts/build-static.sh
scp dist/proxytun-x86_64-linux-musl el7:/tmp/proxytun
# On el7: sudo runs this file as root, so install it where only root can write (do not run it from your home directory)
sudo install -o root -g root -m 0755 /tmp/proxytun /usr/local/bin/proxytun && rm /tmp/proxytun
```

## 1. Environment

```bash
uname -r; cat /etc/centos-release
cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "no max_user_namespaces (kernel before 7.4)"
sudo -V | head -1
sudo grep -E '^\s*Defaults.*(use_pty|requiretty)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null
getenforce 2>/dev/null
```

## 2. Self-check

```bash
proxytun --doctor --proxy socks5://HOST:PORT
```

Expected: it reports that **sudo** mode will be used and explains why user namespaces are unusable; proxy connectivity OK.

## 3. Basic proxying

```bash
proxytun --proxy socks5://HOST:PORT -- curl -sI https://example.com
```

Expected:
- First a line `WARN ... user namespaces are not usable here: ...; asking sudo to create the namespace (--no-sudo refuses)`, then sudo asks for a password;
- curl returns `HTTP/... 200`;
- the log has `conn{id=1 target=Domain("example.com", 443)}`: the proxy receives the domain name.

## 4. The program's identity and the network it sees

```bash
proxytun --proxy socks5://HOST:PORT -- sh -c 'id; grep -E "^Cap(Prm|Eff)" /proc/self/status; cat /etc/resolv.conf; getent hosts example.com; ip -br addr; ip route'
ulimit -u; umask; proxytun --proxy socks5://HOST:PORT -- sh -c 'ulimit -u; umask'
proxytun --proxy socks5://HOST:PORT -- cat /proc/sys/net/core/somaxconn
```

Expected:
- The last line is `4096` (on the 3.10 kernel a new network namespace defaults to 128, which makes bursts of connections wait for SYN retransmits; the development machine cannot test this);
- The 2nd–3rd lines from the end (the program's values) are the same as the two lines before them (your own shell's values): the program gets your process limit and umask, not the ones sudo gives root (CentOS 7's `20-nproc.conf` sets no limit for root);
- `id` shows your own uid, gid and supplementary groups (not root);
- `CapPrm` / `CapEff` are all 0;
- `nameserver 198.19.255.53`; `example.com` resolves to `198.18.x.x`;
- Only `lo` and `tun0` (`198.19.255.1/24`), with the default route via `tun0`.

## 4a. proxytun cannot be used to gain privileges

```bash
sudo /usr/local/bin/proxytun --proxy socks5://HOST:PORT -- id; echo "exit=$?"   # absolute path: /usr/local/bin is not in secure_path
proxytun --proxy socks5://HOST:PORT -- sudo -n true; echo "exit=$?"
proxytun --proxy socks5://HOST:PORT -- grep NoNewPrivs /proc/self/status
```

Expected:
- The first prints `proxytun refuses to run as root through sudo ...`, `exit=2`, and `id` does not run;
- In the second, sudo reports an error like `The "no new privileges" flag is set ...` and the exit status is non-zero (setuid programs inside the program cannot gain privileges);
- The third prints `NoNewPrivs:	1`.

## 5. No root processes while running

In one terminal:

```bash
proxytun --proxy socks5://HOST:PORT -- sleep 60
```

In another terminal:

```bash
pstree -pu $(pgrep -f 'proxytun --proxy' | head -1)
ps -o user,pid,ppid,pgid,sid,cmd --ppid $(pgrep -f 'proxytun --proxy' | head -1)
```

Expected: the process tree has only your user (sudo and the privileged helper have exited); the parent of `sleep` is proxytun, and its process group (PGID) is the same as proxytun's.

## 6. Debugging tools

```bash
proxytun --proxy socks5://HOST:PORT -- strace -f -e trace=connect curl -s -o /dev/null https://example.com
proxytun --proxy socks5://HOST:PORT -- gdb -batch -nx -ex 'break connect' -ex run -ex 'bt 1' -ex delete -ex continue \
    --args curl -s -o /dev/null -w '%{http_code}\n' https://example.com
```

Expected: strace prints `connect(... 198.18.x.x ...)` and curl succeeds; gdb stops at `connect` and prints `200` after continuing.

## 7. Signals

```bash
proxytun --proxy socks5://HOST:PORT -- sleep 100      # press Ctrl+C
echo "exit=$?"                                           # expect 130, exits immediately
proxytun --proxy socks5://HOST:PORT -- sleep 100 &
sleep 3; kill %1; wait; echo "exit=$?"                   # expect 143 (sleep killed by SIGTERM)
```

## 8. Nothing left behind after exit

```bash
ip -br link | grep -c tun0         # expect 0: no TUN on the host
grep nameserver /etc/resolv.conf   # expect the same as before the run
ls -ld /tmp/proxytun-* 2>/dev/null # expect no output
```

## If something goes wrong, please include

- Rerun that step with `-vv --log-file ~/proxytun.log` and send back the log;
- If SELinux is Enforcing: `sudo ausearch -m avc -ts recent`;
- With devtoolset enabled (`scl enable devtoolset-N`), the `sudo` that comes first on PATH is its wrapper script; proxytun skips it and runs the
  setuid `/usr/bin/sudo` directly, and the `sudo mode` line of `--doctor` shows the path actually used;
- Sudo-mode startup cannot be traced with `strace -f`: traced as you, sudo cannot get root (it reports `effective uid is not 0`);
  traced as root, the privileged helper notices it is being traced and refuses to run (this is intentional). Use the `-vv` log instead; to see the program's system calls, use
  `proxytun -- strace -f ...` from section 6, or `strace -p <pid of proxytun>` after startup;
- If you get `sudo: sorry, you must have a tty to run sudo`: sudoers has `requiretty`; run from an interactive terminal (not from cron or ssh without a tty).
