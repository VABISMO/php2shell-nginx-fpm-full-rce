# Security policy

## Supported versions

This repository is a proof of concept for **CVE-2026-109619** (and the
upload-progress half of the advisory, sometimes tracked together with
**CVE-2026-109618**). The version support of the *tooling* mirrors what is
verified in [README.md](README.md):

| Branch | Status in this repository |
| --- | --- |
| 8.0, 8.1, 8.2, 8.3, 8.4 (unpatched releases) | RCE chain, verified profiles (8.5.x: builds only, no profile yet) |
| 5.4 – 5.6, 7.x | session-file plant, verified in the lab |
| 8.2.35, 8.3.36, 8.4.27, 8.5.12 | patched upstream, cannot be exploited |
| 5.0 – 5.3 | no `session.upload_progress`, no attack surface |

## Reporting a vulnerability

In **this repository** (a defect in the exploit client, the laboratory, or the
documentation): open a GitHub issue with the label `security`. Do not include
payloads aimed at third-party systems.

In **PHP itself**: follow the PHP security team's process at
<https://www.php.net/security.php>. Do not disclose PHP core issues publicly
before a fix is available.

## Disclosure timeline of the underlying advisory

| Date | Event |
| --- | --- |
| 2026-10-20 | PHP security team announces the advisory |
| 2026-10-21 14:00 UTC | fixes released: 8.2.35, 8.3.36, 8.4.27, 8.5.12 |

End-of-life branches (5.x, 7.x, 8.0, 8.1) never received a fix; upgrading is
the only remediation. Restarting PHP-FPM workers wipes the stale in-memory
state the chain relies on.

## Authorized use only

See [LICENSE](LICENSE) and the *Legal and responsible use* section of
[README.md](README.md): run this tooling only against systems you own or have
explicit written permission to test.
