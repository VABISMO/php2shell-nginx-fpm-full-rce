#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_fpm_labs.py — local nginx + PHP-FPM laboratory (no root, no docker).

Two user-prefix builds share one nginx:
    8.4.26  chain http :8110 -> fpm :9001   builder http :8111 -> fpm :9002
    8.4.27  chain http :8120 -> fpm :9011   builder http :8121 -> fpm :9012

Pools (php-fpm.conf.in):
    chain   memory_limit=8M,  cleanup=On,  save_path=<runtime>/session
    builder memory_limit=64M, cleanup=Off  (builds large session files)

Commands:
    python3 tools/php2shell_fpm_labs.py up [--only 8.4.26]
    python3 tools/php2shell_fpm_labs.py status
    python3 tools/php2shell_fpm_labs.py smoke
    python3 tools/php2shell_fpm_labs.py test
    python3 tools/php2shell_fpm_labs.py down
"""

from __future__ import annotations

import argparse
import os
import pwd
import signal
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, "lab", "fpm")
RUNTIME = os.path.join(LAB, "runtime")
WEBROOT = os.path.join(LAB, "webroot")
OUTDIR = os.path.join(WEBROOT, "out")
NGINX_PREFIX = os.path.join(RUNTIME, "nginx")
NGINX_BIN = os.path.join(NGINX_PREFIX, "sbin", "nginx")
NGINX_CONF_DIR = os.path.join(NGINX_PREFIX, "conf")
NGINX_CONF = os.path.join(RUNTIME, "nginx.conf")
PHP_INI = os.path.join(LAB, "php.ini")
FPM_CONF_TMPL = os.path.join(LAB, "php-fpm.conf.in")
NGINX_CONF_TMPL = os.path.join(LAB, "nginx.conf.in")

USER_NAME = pwd.getpwuid(os.getuid()).pw_name
GROUP_NAME = subprocess.run(
    ["id", "-gn"], capture_output=True, text=True
).stdout.strip() or USER_NAME

# version -> (chain_http, builder_http, chain_fpm, builder_fpm)
BUILDS: dict[str, tuple[int, int, int, int]] = {
    "8.4.26": (8110, 8111, 9001, 9002),
    "8.4.27": (8120, 8121, 9011, 9012),
}


def fpm_prefix(version: str) -> str:
    return os.path.join(RUNTIME, f"php-{version}")


def fpm_bin(version: str) -> str:
    return os.path.join(fpm_prefix(version), "sbin", "php-fpm")


def render(template: str, mapping: dict[str, str]) -> str:
    text = open(template, encoding="utf-8").read()
    for key, value in mapping.items():
        text = text.replace(f"@{key}@", value)
    return text


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def read_pid(path: str) -> int | None:
    try:
        pid = int(open(path, encoding="utf-8").read().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
        return pid
    except OSError:
        return None


def worker_pids(version: str, pool: str) -> list[int]:
    marker = f"php-fpm: pool {pool}".encode()
    needle = f"php-{version}".encode()
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                data = handle.read()
            if marker in data and needle in data + os.readlink(f"/proc/{name}/exe").encode():
                pids.append(int(name))
        except OSError:
            continue
    return pids


def ensure_dirs(version: str) -> None:
    prefix = fpm_prefix(version)
    for sub in ("logs", "session", "tmp"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    os.makedirs(OUTDIR, exist_ok=True)
    try:
        os.chmod(os.path.join(prefix, "session"), 0o700)
    except OSError:
        pass


def write_fpm_conf(version: str) -> str:
    chain_http, builder_http, chain_fpm, builder_fpm = BUILDS[version]
    prefix = fpm_prefix(version)
    rendered = render(FPM_CONF_TMPL, {
        "RUNTIME": prefix,
        "CHAIN_PORT": str(chain_fpm),
        "BUILDER_PORT": str(builder_fpm),
        "USER": USER_NAME,
        "GROUP": GROUP_NAME,
        "WEBROOT": WEBROOT,
        "SAVEDIR": os.path.join(prefix, "session"),
        "VER": version,
    })
    path = os.path.join(prefix, "php-fpm.conf")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    return path


def write_nginx_conf(versions: list[str]) -> None:
    servers = []
    for version in versions:
        chain_http, builder_http, chain_fpm, builder_fpm = BUILDS[version]
        prefix = fpm_prefix(version)
        for label, http_port, fpm_port in (
            ("chain", chain_http, chain_fpm),
            ("builder", builder_http, builder_fpm),
        ):
            servers.append(f"""
server {{
    listen 127.0.0.1:{http_port};
    server_name _;
    root {WEBROOT};
    access_log {prefix}/logs/{label}-access.log;

    location /out/ {{
        root {WEBROOT};
        default_type text/plain;
        add_header X-Lab-Static "1";
    }}

    location / {{
        include {NGINX_CONF_DIR}/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass 127.0.0.1:{fpm_port};
    }}
}}""")
    rendered = render(NGINX_CONF_TMPL, {
        "RUNTIME": RUNTIME,
        "NGINX_CONF": NGINX_CONF_DIR,
        "SERVERS": "\n".join(servers),
    })
    with open(NGINX_CONF, "w", encoding="utf-8") as handle:
        handle.write(rendered)


def wait_http(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def up(only: set[str] | None) -> None:
    versions = [v for v in BUILDS if only is None or v in only]
    for version in versions:
        if not os.path.isfile(fpm_bin(version)):
            print(f"[!] {version}: missing {fpm_bin(version)}; run lab/fpm/build_php.sh {version}")
            return
        if not os.path.isfile(NGINX_BIN):
            print(f"[!] missing {NGINX_BIN}; run lab/fpm/build_nginx.sh")
            return
    for version in BUILDS:
        ensure_dirs(version)
    for version in versions:
        write_fpm_conf(version)
    os.makedirs(os.path.join(RUNTIME, "logs"), exist_ok=True)
    # full conf (all versions) so nginx stays the single front
    write_nginx_conf(list(BUILDS))

    busy = []
    for version in versions:
        for port in BUILDS[version]:
            if not port_free(port):
                busy.append(port)
    if busy:
        print(f"[!] ports busy: {busy} (run 'down' first?)")
        return

    for version in versions:
        conf = os.path.join(fpm_prefix(version), "php-fpm.conf")
        print(f"[*] {version}: php-fpm -t", flush=True)
        result = subprocess.run(
            [fpm_bin(version), "-t", "-y", conf, "-c", PHP_INI, "-p", fpm_prefix(version)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stdout, result.stderr)
            print(f"[!] {version}: fpm config test failed")
            return

    print("[*] nginx -t", flush=True)
    result = subprocess.run(
        [NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF, "-t"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stdout, result.stderr)
        print("[!] nginx config test failed")
        return

    for version in versions:
        conf = os.path.join(fpm_prefix(version), "php-fpm.conf")
        print(f"[*] {version}: starting php-fpm", flush=True)
        result = subprocess.run(
            [fpm_bin(version), "-y", conf, "-c", PHP_INI, "-p", fpm_prefix(version), "-D"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(result.stderr)
            print(f"[!] {version}: php-fpm failed to start")
            return
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        chain_http, builder_http, _c, _b = BUILDS[version]
        ok_chain = wait_http(f"http://127.0.0.1:{chain_http}/index.php")
        ok_builder = wait_http(f"http://127.0.0.1:{builder_http}/index.php")
        workers = worker_pids(version, "chain") + worker_pids(version, "builder")
        print(f"    master={master} workers={workers} "
              f"chain={'ok' if ok_chain else 'FAIL'} builder={'ok' if ok_builder else 'FAIL'}")

    print("[*] starting nginx", flush=True)
    result = subprocess.run(
        [NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stderr)
        print("[!] nginx failed to start")
        return
    nginx_pid = read_pid(os.path.join(NGINX_PREFIX, "logs", "nginx.pid"))
    print(f"    nginx pid={nginx_pid}")
    for version in versions:
        chain_http, builder_http, _c, _b = BUILDS[version]
        ok = wait_http(f"http://127.0.0.1:{chain_http}/index.php")
        print(f"    {version} front chain:{chain_http}={'ok' if ok else 'FAIL'} "
              f"builder:{builder_http}")
    print("[+] lab up")


def down() -> None:
    nginx_pid = read_pid(os.path.join(NGINX_PREFIX, "logs", "nginx.pid"))
    if nginx_pid:
        subprocess.run([NGINX_BIN, "-p", NGINX_PREFIX, "-c", NGINX_CONF, "-s", "quit"],
                       capture_output=True)
        for _ in range(20):
            if read_pid(os.path.join(NGINX_PREFIX, "logs", "nginx.pid")) is None:
                break
            time.sleep(0.2)
        else:
            os.kill(nginx_pid, signal.SIGKILL)
    for version in BUILDS:
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        if master:
            os.kill(master, signal.SIGTERM)
            for _ in range(30):
                if read_pid(pidfile) is None:
                    break
                time.sleep(0.2)
            else:
                os.kill(master, signal.SIGKILL)
        for pid in worker_pids(version, "chain") + worker_pids(version, "builder"):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    print("[+] lab down")


def status() -> None:
    nginx_pid = read_pid(os.path.join(NGINX_PREFIX, "logs", "nginx.pid"))
    print(f"nginx  pid={nginx_pid}")
    for version, (chain_http, builder_http, _c, _b) in BUILDS.items():
        pidfile = os.path.join(fpm_prefix(version), "logs", "fpm.pid")
        master = read_pid(pidfile)
        chain = worker_pids(version, "chain")
        builder = worker_pids(version, "builder")
        print(f"{version} fpm master={master} chain_worker={chain} builder_worker={builder} "
              f"http chain=:{chain_http} builder=:{builder_http}")


def smoke() -> None:
    ok = True
    for version, (chain_http, builder_http, _c, _b) in BUILDS.items():
        for label, port in (("chain", chain_http), ("builder", builder_http)):
            url = f"http://127.0.0.1:{port}/index.php"
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read().decode()
                good = body.strip() == "OK"
            except Exception as exc:
                good = False
                body = str(exc)
            print(f"{version} {label:8} {'ok' if good else 'FAIL'} {body.strip()[:60]}")
            ok = ok and good
            url = f"http://127.0.0.1:{port}/app.php"
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    body = resp.read().decode()
                good = "SESSION_END" in body
            except Exception as exc:
                good = False
                body = str(exc)
            print(f"{version} {label:8} app.php {'ok' if good else 'FAIL'} {body.strip()[:60]}")
            ok = ok and good
    return 0 if ok else 1


def test() -> None:
    results = []
    for version in BUILDS:
        chain_http, _b, _c, _f = BUILDS[version]
        proof = os.path.join(OUTDIR, "p1")
        try:
            os.unlink(proof)
        except OSError:
            pass
        cmd = [
            sys.executable, os.path.join(HERE, "php2shell_fpm.py"),
            "chain",
            "--base", f"http://127.0.0.1:{chain_http}",
            "--builder", f"http://127.0.0.1:{BUILDS[version][1]}",
            "--version", version,
            "--command", "id>out/p1",
            "--proof-file", proof,
        ]
        print(f"\n=== {version} chain ===", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        print((result.stdout + result.stderr).strip(), flush=True)
        if result.returncode == 0 and os.path.isfile(proof):
            results.append((version, "RCE", open(proof, encoding="utf-8").read().strip()))
        else:
            results.append((version, "no RCE (exit %d)" % result.returncode, ""))
    print("\n=== summary ===")
    for version, text, proof in results:
        print(f"  {version:8} {text:24} {proof}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Local nginx+FPM PHP2Shell laboratory.")
    parser.add_argument("command", choices=("up", "down", "status", "smoke", "test"))
    parser.add_argument("--only", default=None, help="comma-separated versions")
    args = parser.parse_args()
    only = set(args.only.split(",")) if args.only else None
    if args.command == "up":
        up(only)
        return 0
    if args.command == "down":
        down()
        return 0
    if args.command == "status":
        status()
        return 0
    if args.command == "smoke":
        return smoke()
    test()
    return 0


if __name__ == "__main__":
    sys.exit(main())
