# Security Advisory Template

Use this template when publishing a [GitHub Security Advisory](https://github.com/promptfoo/modelaudit/security/advisories/new) for ModelAudit.

---

## Advisory Title

`[CVE-YYYY-NNNNN] Brief description of the vulnerability`

## Affected Versions

- **Affected:** `>= X.Y.Z, < A.B.C`
- **Fixed in:** `A.B.C`

## Severity

Use the CVSS 3.1 calculator to determine the score and vector string.

- **Severity:** Critical / High / Medium / Low
- **CVSS Score:** X.X
- **CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## Summary

One-paragraph description of the vulnerability, what it allows an attacker to do,
and which component is affected.

## Details

Technical explanation of the root cause. Include:

- Which scanner/module is affected
- The attack vector (e.g., crafted model file, malicious archive)
- Why the vulnerability exists (logic error, missing check, parser bug)

## Impact

What can an attacker achieve by exploiting this vulnerability?

- Can they execute arbitrary code?
- Can they bypass a detection?
- Can they cause denial of service?
- What user action is required (e.g., scanning a malicious file)?

## Proof of Concept

```python
# Minimal reproduction steps (sanitize any weaponizable details)
```

## Remediation

- **Upgrade:** `pip install --upgrade modelaudit>=A.B.C`
- **Workaround:** (if any interim mitigation exists before upgrading)

## Timeline

| Date       | Event                      |
| ---------- | -------------------------- |
| YYYY-MM-DD | Vulnerability reported     |
| YYYY-MM-DD | Report acknowledged        |
| YYYY-MM-DD | Fix developed and verified |
| YYYY-MM-DD | Fixed version released     |
| YYYY-MM-DD | Advisory published         |

## Credit

Reported by [Name / Handle] (unless they prefer anonymity).

---

## Publishing Checklist

Before publishing the advisory:

- [ ] Fix merged and released to PyPI
- [ ] CHANGELOG updated with security note
- [ ] CVE ID requested (via GitHub advisory or MITRE)
- [ ] Advisory draft reviewed by at least one other maintainer
- [ ] Reporter notified of planned disclosure date
- [ ] Advisory published on GitHub
- [ ] Email sent to security@promptfoo.dev distribution list (if applicable)
