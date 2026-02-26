# Security Policy

## What constitutes a security vulnerability

A security vulnerability is any bug that threatens the safety of ModelAudit users or their scanning environments. Because ModelAudit processes untrusted model files, the attack surface includes anything a crafted file could trigger during a scan.

**Vulnerability categories:**

| Category                      | Examples                                                                                                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Code execution in the scanner | A crafted model file causes ModelAudit itself to execute arbitrary code during scanning                                                                                        |
| Detection bypass              | Security-relevant malicious behavior goes undetected within a format or attack class that ModelAudit claims to cover, even if unrelated detectors still produce other findings |
| Denial of service             | A crafted file causes an out-of-memory condition, infinite loop, or crash in ModelAudit                                                                                        |
| Information disclosure        | Scan results or error output leak host filesystem paths, environment variables, or API keys                                                                                    |
| Supply chain compromise       | Malicious code introduced through the PyPI package, Docker images, or GitHub Actions workflows                                                                                 |

**Not considered a vulnerability:**

- Malicious content that ModelAudit **correctly detects** — that is working as designed.
- False positives and **non-security** false negatives (e.g., a new obfuscation technique not yet covered, or a heuristic that needs tuning) — these are detection quality issues. Report them via [GitHub Issues](https://github.com/promptfoo/modelaudit/issues) using the bug report template, or see [CONTRIBUTING.md](CONTRIBUTING.md) for guidance. **However**, if a false negative causes security-relevant malicious behavior to go undetected within a format or attack class that ModelAudit claims to cover — even if unrelated detectors still produce other findings — that is a detection bypass and should be reported privately as a vulnerability. See [How to report](#how-to-report-a-vulnerability).
- Bugs in third-party dependencies that are not reachable through ModelAudit's own code paths — report those to the respective upstream maintainers.
- Issues that require the attacker to already have equivalent privilege on the scanning host **and** do not enable privilege escalation, lateral movement, persistence, or additional data access. (Bugs exploitable in shared CI runners or multi-tenant environments where the attacker starts with limited access are in scope.)

> If you are unsure whether your finding is a security issue, **report it as one**. We would rather triage a non-issue than miss a real vulnerability.

## How to report a vulnerability

**Do not open a public GitHub issue.** Public disclosure of unpatched vulnerabilities puts all ModelAudit users at risk. If this happens, maintainers may close the issue, redact sensitive details when possible, and redirect you to private reporting channels.

### Primary: GitHub Private Vulnerability Reporting

Use GitHub's built-in private vulnerability reporting to submit your report directly in the repository. This is the preferred method — it creates a private advisory draft, supports threaded discussion, and integrates with CVE assignment.

Report here: **[Report a vulnerability](https://github.com/promptfoo/modelaudit/security/advisories/new)**

### Fallback: Email

If you do not have a GitHub account, send your report to **security@promptfoo.dev** with the subject line `[ModelAudit Security] <brief description>`.

## What to include in your report

A good report helps us confirm and fix the issue quickly. Include as much of the following as possible:

- **Description** of the vulnerability and its security impact.
- **Step-by-step reproduction instructions.**
- **Triggering model file**, if the issue is caused by scanning a specific file. For GitHub private advisory reports, attach the file directly — the advisory is only visible to maintainers and the reporter. For email reports, send report metadata first (impact, repro steps, versions) and **do not send exploit artifacts or sensitive files** until we establish a secure transfer channel in our acknowledgment response.
- **ModelAudit version** (`modelaudit --version`).
- **Python version** (`python --version`).
- **Operating system and architecture** (e.g., Ubuntu 22.04 x86_64, macOS 15 arm64).
- **Installation method** (pip, uv, Docker, source).
- **Verbose scan output** (`modelaudit scan <file> --verbose`), with sensitive data redacted (paths, usernames, hostnames, tokens, credentials, keys).
- **Fuzzer details**, if the issue was found through fuzzing — include the fuzzer name, configuration, and corpus entry.

If you cannot share the triggering file, describe how to generate a file that reproduces the issue.

## Response timeline

| Milestone                   | Target                            |
| --------------------------- | --------------------------------- |
| Acknowledgment              | Within 48 hours of receipt        |
| Initial severity assessment | Within 5 business days            |
| Fix developed and tested    | See fix windows below             |
| Coordinated disclosure      | Simultaneously with patch release |

### Fix windows by severity

We assess severity using [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document). Fix windows are targets, not guarantees — we will communicate proactively if a fix requires more time.

| CVSS score | Severity | Target fix window  |
| ---------- | -------- | ------------------ |
| 9.0–10.0   | Critical | 30 days            |
| 7.0–8.9    | High     | 30–60 days         |
| 4.0–6.9    | Medium   | Next release cycle |
| 0.1–3.9    | Low      | Best effort        |

**ModelAudit-specific severity factors:**

- A crafted model file that causes arbitrary code execution in the scanner is treated as **Critical**.
- A bypass that causes security-relevant malicious behavior to go undetected within a format or attack class that ModelAudit claims to cover is treated as at least **High**.
- Exposure of host secrets or credentials during scanning is treated as at least **High**.
- A vulnerability reachable only through an optional dependency not installed by default may be reduced by one tier.

## Embargo and non-disclosure

We ask reporters to keep vulnerability details confidential until a patch is released. The embargo window depends on severity:

| Severity         | Embargo window                                                    |
| ---------------- | ----------------------------------------------------------------- |
| Critical or High | 90 days from acknowledgment                                       |
| Medium           | Until the next scheduled release (typically shorter than 90 days) |
| Low              | No formal embargo                                                 |

If a fix requires longer than the default window, we will negotiate an extension with you before the deadline. If we fail to ship a fix within the agreed window, you are free to disclose.

## When we issue CVEs

We request CVE IDs through [GitHub's CVE Numbering Authority (CNA)](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-github-security-advisories-for-repositories) program. Not every security fix warrants a CVE.

**CVE issued:**

- Remote code execution in ModelAudit when scanning untrusted input.
- Detection bypass with broad or material security impact — security-relevant malicious behavior goes undetected within a format or attack class that ModelAudit covers (see [claimed coverage](#claimed-coverage)).
- Supply chain compromise of the PyPI package, Docker images, or release pipeline.
- Information disclosure of sensitive host data during a scan.

**Typically no CVE (fixed in a normal release):**

- Denial of service that only affects local interactive CLI usage, cannot be triggered remotely, and does not suppress or bypass scanning enforcement in automated pipelines.
- Crashes with no security impact beyond terminating a single interactive scan.
- Detection quality improvements (heuristic tuning, new signatures, coverage gaps for novel techniques).
- Issues requiring the attacker to already control the scanning host's configuration with equivalent privilege (see exclusion above).

**CVE-eligible (assess on impact):**

- Denial of service that can suppress, abort, or bypass scanning in automated CI/CD pipelines or gating systems — effectively disabling security enforcement.
- Denial of service when ModelAudit is used as a library in a network-facing service.
- Detection bypass affecting a single format with limited real-world adoption, where the practical security impact is narrow. (Bypasses with broader impact fall under "CVE issued" above.)

When in doubt, we err toward issuing a CVE.

## Scope

**In scope:**

- The `modelaudit` Python package published on [PyPI](https://pypi.org/project/modelaudit/).
- The official Docker images.
- The GitHub Actions CI/CD workflows in the [modelaudit repository](https://github.com/promptfoo/modelaudit).

**Out of scope:**

- Third-party dependencies — report those to the respective upstream maintainers. (If you believe a third-party vulnerability is reachable through ModelAudit's code paths, that is in scope.)
- The promptfoo.dev documentation website.
- Model files scanned by ModelAudit — report malicious models to the model publisher or hosting platform.

## Supported versions

We support the latest release only. We do not backport security fixes to older release lines.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Older releases | No        |

We recommend always upgrading to the latest version. See the [CHANGELOG](CHANGELOG.md) for release history.

## Coordinated disclosure

After a fix is released, we will:

1. **Publish a GitHub Security Advisory** with CVE ID, affected and patched versions, CVSS score, and a description of the vulnerability and its impact.
2. **Credit the reporter** in the advisory and CHANGELOG, unless you prefer anonymity.
3. **Include the fix** in the `### Security` section of the [CHANGELOG](CHANGELOG.md).

## Safe harbor

We consider security research conducted in accordance with this policy to be authorized and will not initiate legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, destruction of data, and disruption of service.
- Only interact with accounts they own or with explicit permission of the account holder.
- Report vulnerabilities through the channels described in this policy.
- Allow us a reasonable period to address the issue before public disclosure.

If legal action is initiated by a third party against you for activities conducted in compliance with this policy, we will make it known that your actions were authorized.

## Claimed coverage

References to what ModelAudit "claims to cover" throughout this policy mean the formats, attack classes, and detection capabilities described in:

- [Security model and limitations](docs/user/security-model.md) — what ModelAudit is designed to catch and what it does not guarantee.
- [Compatibility matrix](docs/user/compatibility-matrix.md) — supported file formats and the detectors applied to each.

If a format or attack class is listed in these documents, bypasses against it are treated as security-relevant under this policy. If documentation is stale or ambiguous relative to implemented scanner behavior, we triage in favor of security handling.

## Related documentation

- [Security model and limitations](docs/user/security-model.md) — what ModelAudit catches and what it does not guarantee.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to report false positives, false negatives, and general bugs.
- [CHANGELOG.md](CHANGELOG.md) — release history including security fixes.
