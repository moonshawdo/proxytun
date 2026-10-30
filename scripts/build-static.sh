#!/usr/bin/env bash
# Build a fully static proxytun that runs on any x86-64 Linux regardless of its
# glibc (CentOS 7 ships glibc 2.17; a binary built on a modern distro links
# GLIBC_2.34 symbols and will not start there).
#
# Needs: rustup with the musl target (`rustup target add x86_64-unknown-linux-musl`).
# Output: dist/proxytun-x86_64-linux-musl
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "missing target; run: rustup target add $TARGET" >&2
    exit 1
fi

cargo build --release --target "$TARGET" -p proxytun
mkdir -p dist
cp "target/$TARGET/release/proxytun" dist/proxytun-x86_64-linux-musl
strip dist/proxytun-x86_64-linux-musl 2>/dev/null || true
ls -l dist/proxytun-x86_64-linux-musl
echo "On the target host run:  ./proxytun-x86_64-linux-musl --doctor"
