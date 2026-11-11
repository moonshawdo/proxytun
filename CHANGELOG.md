# Changelog

Changes in each proxytun release, newest first. Each version has a `## vX.Y.Z`
section, with `### 🐞 Fixes`, `### ✨ New features` and `### 🚀 Improvements` as
needed; changes for the next release go under its version heading as they are
made. The release workflow publishes the section of the version being released
as its GitHub release notes, followed by the downloads, so every release needs
one here.

## v0.1.0

First release.

### ✨ New features

- Runs a program and its whole process tree (children, `env -i` execs, statically
  linked programs) through a SOCKS5 or HTTP CONNECT proxy, inside a private network
  namespace whose only exit is a TUN device held by proxytun.
- Domain names reach the proxy: a fake-ip DNS takes over every query, and for literal
  IPs the domain is recovered from the TLS SNI or HTTP Host of the first packet.
- No ptrace: strace, gdb and ltrace work alongside, inside or from outside.
- No root needed: unprivileged user namespaces when available, otherwise (CentOS 7)
  a short-lived privileged helper started through `sudo`; the program always runs
  as you, and no root process remains.
- Rules (`domain-suffix`, `domain-keyword`, `domain`, `ip-cidr`, `final`; actions
  `proxy`, `direct`, `block`), proxy groups with 6 balancing strategies, active
  health checks and failover; never a silent direct connection.
- Loopback services listening on the host at startup are reachable from the program.
- Exit status, Ctrl+C, `kill` and ignored signals behave as if the program ran directly.
- `--doctor` self-check, `SIGHUP` hot reload, `SIGUSR1` stats, log levels and a log
  file, `--proxy` / `PROXYTUN_PROXY` override.
- A static musl build for x86-64 Linux that runs on any glibc, CentOS 7 included.
- Documentation in Chinese (default) and English.

### ⚠️ Known limitations

- Only TCP is proxied; no IPv6; x86-64 Linux only.
- Not yet verified on a real CentOS 7 machine (sudo mode is tested in a simulation);
  see `docs/CENTOS7_en.md`.
