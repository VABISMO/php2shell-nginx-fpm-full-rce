#!/usr/bin/env bash
# build_php.sh — build a vulnerable/fixed PHP with FPM into a user prefix.
#
# Usage: lab/fpm/build_php.sh <version> [tarball]
#   e.g. lab/fpm/build_php.sh 8.4.26 /tmp/opencode/php-8.4.26.tar.gz
#
# The result is lab/fpm/runtime/php-<version>/{sbin/php-fpm,bin/php,...}.
# No root required.  Extensions kept minimal: session + standard (zif_system).
set -euo pipefail

VER="${1:?usage: build_php.sh <version> [tarball]}"
TARBALL="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$HERE/runtime"
SRC="$RUNTIME/src"
PREFIX="$RUNTIME/php-$VER"
JOBS="${JOBS:-$(nproc)}"

mkdir -p "$SRC"

if [ ! -d "$SRC/php-$VER" ]; then
    if [ -z "$TARBALL" ]; then
        TARBALL="$SRC/php-$VER.tar.gz"
        if [ ! -f "$TARBALL" ]; then
            echo "[*] downloading php-$VER"
            curl -fsSL -o "$TARBALL" "https://www.php.net/distributions/php-$VER.tar.gz" ||
                curl -fsSL -o "$TARBALL" "https://museum.php.net/php8/php-$VER.tar.gz"
        fi
    fi
    echo "[*] extracting $TARBALL"
    tar xzf "$TARBALL" -C "$SRC"
fi

cd "$SRC/php-$VER"
if [ ! -f Makefile ] || [ ! -f config.status ]; then
    echo "[*] configuring php-$VER (fpm, session, minimal)"
    ./configure \
        --prefix="$PREFIX" \
        --disable-all \
        --enable-cli \
        --enable-fpm \
        --enable-session \
        --without-pear \
        --disable-cgi \
        --disable-phpdbg \
        CFLAGS="-O2 -g"
fi
echo "[*] building php-$VER (-j$JOBS)"
make -j"$JOBS" >/dev/null
make install >/dev/null
echo "[+] php-$VER ready: $PREFIX/sbin/php-fpm"
"$PREFIX/sbin/php-fpm" -v | head -1
