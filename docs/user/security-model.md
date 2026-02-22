# Security Model and Limitations

ModelAudit is a static security scanner for model artifacts. It analyzes files and metadata without loading models into serving runtimes or executing embedded model code.

## What ModelAudit is designed to catch

- Unsafe deserialization patterns in high-risk formats (for example pickle- and PyTorch-based artifacts)
- Suspicious code and command execution indicators in model payloads and metadata
- Archive abuse patterns (path traversal, symlink abuse, decompression abuse)
- Known malicious patterns and CVE-related indicators covered by existing scanner rules

## What ModelAudit does not guarantee

- It does not prove a model is safe. A clean scan means "no known indicators were found," not "risk is zero."
- It does not execute model behavior, so runtime-only backdoors and environment-triggered logic may not be visible.
- It does not replace environment hardening (sandboxing, network controls, least privilege, egress controls).
- Coverage depends on file format support and installed optional dependencies.

## Operational assumptions

- Artifacts may be untrusted, so scans should run in isolated CI runners or dedicated analysis environments.
- Security decisions should combine scan output with provenance checks (source trust, signatures, checksums, release process).
- High-risk findings should block promotion until reviewed and resolved.

## Interpreting scan results

- `CRITICAL`: High-confidence risk indicator. Block release/use by default.
- `WARNING`: Potential risk. Require manual review.
- `INFO`: Context signal. Useful for triage and audit trails.

Exit codes:

- `0`: No issues found
- `1`: Issues found
- `2`: Scan error

## Recommended usage pattern

1. Scan artifacts before loading or serving them.
2. Treat `CRITICAL` findings as release blockers.
3. Keep scanner dependencies current (`modelaudit[all]` for broadest coverage).
4. Pair scanning with provenance and runtime controls.

## Reporting gaps or misses

If you find a false negative or a false positive, report it with a reproducible sample as described in `CONTRIBUTING.md`.
For sensitive bypass details, use the private reporting flow in `SECURITY.md`.
