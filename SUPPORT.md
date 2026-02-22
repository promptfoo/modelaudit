# Support Policy

This document defines what versions and environments are currently supported for ModelAudit.

## Supported Versions

| Component        | Supported              |
| ---------------- | ---------------------- |
| ModelAudit       | Latest release         |
| Python           | 3.10, 3.11, 3.12, 3.13 |
| Operating system | Linux, macOS, Windows  |

Older ModelAudit releases may continue to function, but only the latest release receives routine fixes.

## Dependency Model

ModelAudit supports a core scanner set with optional extras for framework-specific scanners.

- Core install (`pip install modelaudit`) is supported.
- Optional extras are supported on a best-effort basis based on upstream ecosystem compatibility.
- CI validates the project's supported Python versions and main dependency sets.

## Maintenance Window

- Security and reliability fixes are prioritized for the latest release line.
- We may ask reporters to reproduce issues on the latest release before triage.

## Getting Help

- Usage and troubleshooting: open a GitHub issue.
- Feature requests: open a GitHub issue with the feature template.
- Security vulnerabilities: do not file public issues. Follow `SECURITY.md`.
