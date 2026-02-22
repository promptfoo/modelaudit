# Dependency Addition Policy

This document governs how new dependencies are added to ModelAudit.

## License Allowlist

| Status                       | Licenses                                                           |
| ---------------------------- | ------------------------------------------------------------------ |
| Approved                     | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, PSF-2.0, MPL-2.0 |
| Requires maintainer approval | LGPL (any version), other weak copyleft                            |
| Blocked                      | GPL, AGPL, proprietary, unlicensed                                 |

### Approved Exceptions

| Package  | License        | Rationale                                                              |
| -------- | -------------- | ---------------------------------------------------------------------- |
| py7zr    | LGPL-2.1+      | Optional `sevenzip` extra; dynamically linked; user-initiated install  |
| nvidia-* | NVIDIA EULA    | Transitive deps of PyTorch CUDA; redistributable under NVIDIA's EULA   |

Exceptions are enforced in CI via `APPROVED_LGPL_PACKAGES` and `NVIDIA_PREFIXES` in
`.github/workflows/test.yml`. Any new LGPL or proprietary dependency requires a PR
adding it to the exception list with maintainer approval and a corresponding entry in
`THIRD_PARTY_NOTICES.md`.

When in doubt, check with `pip-licenses` or inspect the package metadata on PyPI before merging.

## Core vs. Optional

- **Core deps** (`[project.dependencies]`): Must be justified by a fundamental security or
  correctness need. Every user pays the install cost. Raise the bar here.
- **Optional extras** (`[project.optional-dependencies]`): Preferred for framework-specific
  scanners (pytorch, tensorflow, onnx, h5, safetensors, etc.). Scanners must degrade gracefully
  when the extra is absent—raise a clear `ImportError` message, do not crash the base tool.
- **Never add** a new core dependency to support a single file format or ML framework.

## Security Review Checklist

Before approving any new dependency:

- [ ] Check [OSV](https://osv.dev) and [PyPI advisories](https://pypi.org/security) for known CVEs.
- [ ] Confirm the project is actively maintained (commits within the last 12 months, responsive
      to security reports).
- [ ] Assess supply chain risk: small, well-scoped packages are preferred over large ones with
      many transitive deps.
- [ ] Review the package's own dependencies; a lightweight package that pulls in something heavy
      or risky is still risky.
- [ ] For security-critical code paths, prefer vendoring a minimal implementation over adding a
      large external package.

## Version Constraints

- Pin a minimum version: `>=X.Y.Z` based on the first release with the API you need.
- Add an upper bound only when a breaking change is known or anticipated (e.g., `<3.0`).
- Use environment markers for Python-version-specific or platform-specific requirements.
- NumPy dual-version rule: if your code touches NumPy, verify it works with both 1.x (Python
  3.10) and 2.x (Python 3.11+). See `AGENTS.md` for the full version strategy.

```toml
# Example: platform-agnostic extra with minimum pin
"onnx>=1.14.0",

# Example: environment marker for Python-version split
"numpy>=1.19.0,<2.0; python_version == '3.10'",
"numpy>=2.4,<2.5; python_version >= '3.11'",
```

## PR Requirements

Every PR that adds or changes a dependency must include in the description:

1. **Why** — what capability it enables and why no existing dep satisfies the need.
2. **License** — confirmed license identifier (SPDX).
3. **Alternatives considered** — at least one alternative evaluated and why it was rejected.
4. **Size impact** — approximate install size increase for the affected extra or core install.
5. **Security review** — confirmation that the checklist above was completed.

At least one maintainer must approve before merging. For core dependency changes, two approvals
are required.

## Removing Dependencies

Prefer removing unused or redundant dependencies over keeping them. Open a PR with a note on
what broke the dependency's usefulness and verify CI passes across the full Python matrix
(3.10–3.13) before merging.
