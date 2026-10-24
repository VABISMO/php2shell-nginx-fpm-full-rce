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
import contextlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
PROFILES = os.path.join(ROOT, "profiles")
START = "<!-- profile-table:start -->"
END = "<!-- profile-table:end -->"
COVERAGE_START = "<!-- coverage:start -->"
COVERAGE_END = "<!-- coverage:end -->"
VERIFICATION = os.path.join(PROFILES, "verification.json")

# one row per profile: the fields that differ between builds; everything
# else identical across the shipped profiles is rendered as prose below
ROW_FIELDS = (
    ("zif_system", lambda p: f"`{p['libphp']['zif_system']}`"),
    ("zval_ptr_dtor", lambda p: f"`{p['libphp']['zval_ptr_dtor']}`"),
    ("basic_globals", lambda p: f"`{p['fpm']['basic_globals']}`"),
    ("BG offs", lambda p: f"{p['fpm']['bg_unserialize_data_off']}/"
                          f"{p['fpm']['bg_unserialize_level_off']}"),
    ("reclaim", lambda p: f"{p['fpm']['reclaim_pads']} x "
                          f"{p['fpm']['reclaim_size']}"),
    ("no_oracle", lambda p: "{d_off}+{k}".format(
        **p["fpm"]["no_oracle"]["candidates"][0])),
    ("chunk base", lambda p: f"`{p['fpm']['leak']['chunk_base_off']}`"),
    ("PIE base", lambda p: f"`{p['fpm']['leak']['pie_base_off']}`"),
)

# fields that must hold for every shipped profile (rendered as prose)
IDENTICAL_ROWS = (
    ("struct_size", lambda p: f"`{p['fpm']['struct_size']}`"),
    ("leak arm", lambda p: f"`{p['fpm']['leak']['arm_path']}`"),
    ("leak pads", lambda p: f"`{p['fpm']['leak']['pads']}`"),
    ("forged header", lambda p: f"`{p['fpm']['leak']['header_content_off']}`"),
    ("read length", lambda p: f"`{p['fpm']['leak']['read_len']}`"),
    ("chunk pointer offset", lambda p: f"`{p['fpm']['leak']['chunk_ptr_off']}`"),
    ("PIE pointer offset", lambda p: f"`{p['fpm']['leak']['pie_ptr_off']}`"),
)


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (99,)


def compress(versions: list[str]) -> str:
    """8.4.0, 8.4.1, 8.4.2 -> `8.4.0`-`8.4.2` when the run is contiguous."""
    by_branch: dict[str, list[int]] = {}
    for version in versions:
        parts = version.split(".")
        if len(parts) == 3 and parts[0].isdigit():
            by_branch.setdefault(f"{parts[0]}.{parts[1]}", []).append(int(parts[2]))
        else:
            by_branch.setdefault(version, []).append(0)
    out = []
    for branch, patches in sorted(by_branch.items()):
        patches.sort()
        start = previous = patches[0]
        for patch in patches[1:] + [None]:
            if patch is not None and patch == previous + 1:
                previous = patch
                continue
            if branch.count(".") and patches[0] == previous:
                out.append(f"`{branch}.{start}`" if start == previous
                           else f"`{branch}.{start}`-`{branch}.{previous}`")
            else:
                out.append(f"`{branch}.{start}`" if start == previous
                           else f"`{branch}.{start}`-`{branch}.{previous}`")
            if patch is not None:
                start = previous = patch
    return ", ".join(out)


def render_coverage(profiles: list[tuple[str, dict]],
                    verification: dict[str, dict]) -> str:
    """The coverage table: RCE from the shipped profiles, plant from the
    verdicts the matrix runner persisted, patched from the registry."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import php2shell_fpm_versions as registry

    rce = [version for version, profile in profiles if profile.get("rce")]
    plant = [version for version, record in sorted(
        verification.items(), key=lambda item: _version_key(item[0]))
        if record.get("result") == "SESSION PLANT"
        and not any(v == version for v in rce)]
    # every branch this registry tracks knows the release that fixed it
    patched = sorted((branch["fixed_in"] for branch in registry.BRANCHES.values()
                      if branch["fixed_in"]), key=_version_key)

    rows = [
        ("RCE over HTTP only", compress(rce) or "-"),
        ("Session-file plant (pre-auth write)", compress(plant) or "-"),
        ("Patched upstream (cannot RCE)", ", ".join(f"`{v}`" for v in patched)),
        ("Out of scope",
         "`5.0`-`5.3` (no `session.upload_progress`), `8.5.x` (not calibrated)"),
    ]
    out = ["Coverage generated from `profiles/*-fpm.json`, "
           "`profiles/verification.json` and the version registry:", "",
           "| Status | Versions |", "| --- | --- |"]
    for label, value in rows:
        out.append(f"| {label} | {value} |")
    out.append("")
    return "\n".join(out)


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
    # 8.4.2 before 8.4.10, not the lexicographic order of strings
    profiles.sort(key=lambda item: tuple(int(part) for part in item[0].split(".")))
    return profiles


def render(profiles: list[tuple[str, dict]]) -> str:
    headers = [label for label, _value in ROW_FIELDS]
    out = [
        "Every shipped profile is `verified: true` / `rce: true`, produced by "
        "the automatic `calibrate` run against a live build:",
        "",
        "| Version | " + " | ".join(headers) + " |",
        "| --- | " + " | ".join("---" for _ in headers) + " |",
    ]
    for version, profile in profiles:
        out.append(f"| {version} | "
                   + " | ".join(value(profile) for _label, value in ROW_FIELDS)
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
    updated = head + "\n" + render(load_profiles(args.committed)) + "\n" + tail

    # the coverage block follows the same rules: generated from the shipped
    # profiles plus the verdicts the matrix runner persisted
    if COVERAGE_START in updated and COVERAGE_END in updated:
        verification: dict[str, dict] = {}
        if os.path.isfile(VERIFICATION):
            with open(VERIFICATION, encoding="utf-8") as handle, \
                    contextlib.suppress(ValueError):
                verification = json.load(handle)
        head = updated[:updated.index(COVERAGE_START) + len(COVERAGE_START)]
        tail = updated[updated.index(COVERAGE_END):]
        updated = head + "\n" + render_coverage(
            load_profiles(args.committed), verification) + "\n" + tail

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
