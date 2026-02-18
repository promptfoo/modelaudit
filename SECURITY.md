# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ModelAudit, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

- **Email:** security@promptfoo.dev
- **Subject line:** `[ModelAudit Security] <brief description>`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (if known)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix or mitigation:** Depends on severity, typically within 30 days for critical issues

### Scope

This policy covers:

- The `modelaudit` Python package (published on PyPI)
- The official Docker images
- The GitHub Actions CI/CD workflows in this repository

This policy does **not** cover:

- Third-party dependencies (report those to the respective maintainers)
- The promptfoo.dev documentation website
- Models scanned by ModelAudit (report those to the model publisher)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest  | Yes       |
| < 0.2.x | No        |

We recommend always using the latest version of ModelAudit.

## Disclosure Policy

We follow coordinated disclosure. After a fix is released, we will:

1. Publish a security advisory on GitHub
2. Credit the reporter (unless they prefer anonymity)
3. Include details in the CHANGELOG
