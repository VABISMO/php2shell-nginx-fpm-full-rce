#!/usr/bin/env python3
"""readme_table.py — regenerate the profile table in README.md.

The table between ``<!-- profile-table:start -->`` and
``<!-- profile-table:end -->`` is generated from ``profiles/*-fpm.json`` so it
can never drift from the shipped profiles (tests/test_fpm.py checks exactly
that).  Run it after adding or calibrating a profile:

    python3 tools/readme_table.py            # rewrite the table
    python3 tools/readme_table.py --check    # exit 1 if it is outdated
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
PROFILES = os.path.join(ROOT, "profiles")
START = "<!-- profile-table:start -->"
END = "<!-- profile-table:end -->"

# rows that differ between builds; everything else identical goes in the note
VARIABLE_ROWS = (
    ("zif_system", lambda p: f"`{p['libphp']['zif_system']}`"),
    ("zval_ptr_dtor", lambda p: f"`{p['libphp']['zval_ptr_dtor']}`"),
    ("basic_globals", lambda p: f"`{p['fpm']['basic_globals']}`"),
    ("BG data / level offset",
     lambda p: f"`{p['fpm']['bg_unserialize_data_off']}` / "
               f"`{p['fpm']['bg_unserialize_level_off']}`"),
    ("`reclaim_size`", lambda p: f"`{p['fpm']['reclaim_size']}`"),
    ("`no_oracle` candidate",
     lambda p: "`{d_off}`+`{k}`".format(
         **p["fpm"]["no_oracle"]["candidates"][0])),
    ("chunk base offset", lambda p: f"`{p['fpm']['leak']['chunk_base_off']}`"),
    ("PIE base offset", lambda p: f"`{p['fpm']['leak']['pie_base_off']}`"),
)

# fields that must hold for every shipped profile (rendered as prose)
IDENTICAL_ROWS = (
    ("struct_size", lambda p: f"`{p['fpm']['struct_size']}`"),
    ("reclaim_pads", lambda p: f"`{p['fpm']['reclaim_pads']}`"),
    ("leak arm", lambda p: f"`{p['fpm']['leak']['arm_path']}`"),
    ("leak pads", lambda p: f"`{p['fpm']['leak']['pads']}`"),
    ("forged header", lambda p: f"`{p['fpm']['leak']['header_content_off']}`"),
    ("read length", lambda p: f"`{p['fpm']['leak']['read_len']}`"),
    ("chunk pointer offset", lambda p: f"`{p['fpm']['leak']['chunk_ptr_off']}`"),
    ("PIE pointer offset", lambda p: f"`{p['fpm']['leak']['pie_ptr_off']}`"),
)


def load_profiles(committed: bool = False) -> list[tuple[str, dict]]:
    """Every shipped profile; ``committed`` limits the table to the profiles
    that are in git, which is what a fresh CI checkout will see."""
    names = sorted(name for name in os.listdir(PROFILES)
                   if name.endswith("-fpm.json"))
    if committed:
        tracked = subprocess.run(["git", "ls-files", "profiles"],
                                 capture_output=True, text=True,
                                 cwd=ROOT).stdout.split()
        tracked = {os.path.basename(item) for item in tracked}
        names = [name for name in names if name in tracked]
    profiles = []
    for name in names:
        with open(os.path.join(PROFILES, name), encoding="utf-8") as handle:
            profiles.append((name.split("-")[0], json.load(handle)))
    return profiles


def render(profiles: list[tuple[str, dict]]) -> str:
    versions = [version for version, _profile in profiles]
    out = [
        "Every shipped profile is `verified: true` / `rce: true` and was "
        "produced by the automatic `calibrate` run against a live build:",
        "",
        "| Field | " + " | ".join(versions) + " |",
        "| --- | " + " | ".join("---" for _ in versions) + " |",
    ]
    for label, value in VARIABLE_ROWS:
        out.append(f"| {label} | "
                   + " | ".join(value(profile) for _version, profile in profiles)
                   + " |")
    out.append("")

    identical = []
    for label, value in IDENTICAL_ROWS:
        values = {value(profile) for _version, profile in profiles}
        if len(values) == 1:
            identical.append(f"{label} {values.pop()}")
    if identical:
        out.append("Identical on every build: " + ", ".join(identical) + ".")
        out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the table is outdated")
    parser.add_argument("--committed", action="store_true",
                        help="table only for the profiles already in git")
    args = parser.parse_args()

    with open(README, encoding="utf-8") as handle:
        text = handle.read()
    if START not in text or END not in text:
        print(f"[!] {README} has no profile-table anchors", file=sys.stderr)
        return 1

    head = text[:text.index(START) + len(START)]
    tail = text[text.index(END):]
    block = "\n" + render(load_profiles(args.committed)) + "\n"
    updated = head + block + tail

    if args.check:
        if updated != text:
            print("[!] README profile table is outdated: "
                  "run python3 tools/readme_table.py", file=sys.stderr)
            return 1
        print("[+] README profile table is up to date")
        return 0

    if updated == text:
        print("[+] README profile table already up to date")
        return 0
    with open(README, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print("[+] README profile table regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
