# New Scanner Quickstart (Security-First)

Use this checklist to add a new scanner safely and consistently.

## 1. Define scope before coding

- Identify exact file formats/extensions.
- Document the concrete security risks you are detecting (CVE, known exploit class, or clearly documented abuse pattern).
- Decide whether dependencies are optional and how scanner behavior degrades when missing.

References: `docs/agents/architecture.md` and
`docs/maintainers/scanner-cve-gap-analysis.md`

## 2. Implement scanner class

Create `modelaudit/scanners/<format>_scanner.py` with:

- `name`, `description`, and `supported_extensions`
- `can_handle()` that is strict and deterministic
- `scan()` that uses `result.add_check(...)` with clear severity and rationale
- Path/size validation via base helpers before heavy parsing

For large scanners, move reusable parser/state helpers into
`modelaudit/scanners/<format>_support/` and keep `<format>_scanner.py` as the
public class entrypoint plus orchestration layer.

Skeleton:

```python
from __future__ import annotations

from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult


class ExampleScanner(BaseScanner):
    name = "example"
    description = "Scans Example model artifacts for security issues"
    supported_extensions: ClassVar[list[str]] = [".example"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        # extension + minimal signature checks
        ...

    def scan(self, path: str) -> ScanResult:
        result = self._create_scan_result_after_preflight(path)
        if not result.success:
            return result

        # Add checks here
        result.finish(success=not result.has_errors)
        return result
```

## 3. Register the scanner

Update `modelaudit/scanner_registry_metadata.py`:

- Add one scanner descriptor entry with module/class metadata
- Set priority, direct extensions, and any descriptor-owned `header_formats` / `content_routed_extensions` carefully
- Declare dependency names for load-time diagnostics
- Document intentional descriptor/class extension differences with `scanner_only_extensions` instead of leaving silent drift
- If the extension is authoritative enough for extension-only format validation, add it to the descriptor-owned `EXTENSION_FORMAT_MAP`; leave generic text/config extensions out
- Do not add a second class map in `__getattr__`; lazy exports are resolved from descriptor metadata

## 4. Dependency handling rules

- Optional deps must fail gracefully with actionable messages.
- Never crash import-time for missing optional packages.
- If adding a new dependency, update `pyproject.toml` extras and justify it in PR notes.

## 5. Required tests

Add focused tests under `tests/`:

- Safe/benign sample: scanner passes expected checks
- Malicious sample: scanner emits expected findings and severities
- Corrupt input: parser errors are handled cleanly
- Missing dependency path (if optional)
- Regression tests for edge cases and previously reported bypasses
- Registry/routing regressions: add `scan_file()` and `ScannerRegistry.get_scanner_for_path()` positives/negatives for extension collisions, header aliases, and content-routed archive names

## 6. Validation before PR

```bash
uv run ruff format modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
uv run ruff check --fix modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
uv run mypy modelaudit/ packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests tests/
PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest -n auto -m "not slow and not integration" --maxfail=1
```

If the change touches `packages/modelaudit-picklescan`, also run:

```bash
cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check
cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml
cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml
PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests -q
```

## 7. PR checklist

- Scanner implementation + tests are included
- Registry wiring and dependency metadata are correct
- User-facing docs updated if behavior is visible to end users
- No security checks were downgraded without explicit rationale

## Adding CVE Detections to Existing Scanners

Adding a CVE detection differs from adding a whole new scanner — you wire into existing scanners and shared detector infrastructure. Here is the typical multi-file workflow:

### Files touched for each new CVE detection

1. **`modelaudit/detectors/suspicious_symbols.py`** — Add regex pattern list, register it in `CVE_COMBINED_PATTERNS`, and update `validate_patterns()`.
2. **`modelaudit/detectors/cve_patterns.py`** — Add `_check_cve_XXXX_multiline()` detection function + `_create_cve_XXXX_attribution()` helper, then wire into `analyze_cve_patterns()`.
3. **`modelaudit/scanners/<format>_scanner.py`** — Add version check method (if version-gated) and wire into the scanner's vulnerability checks.
4. **`modelaudit/config/explanations.py`** — Add explanation function with type-specific messages.
5. **`tests/detectors/test_cve_detection.py`** — Positive detection + false positive prevention + bypass prevention tests.
6. **`tests/scanners/test_<format>_scanner.py`** — Version check tests (vulnerable + fixed).
7. **`tests/conftest.py`** — Add test filenames to `allowed_test_files`.

### Key pitfalls (see AGENTS.md § "CVE Detection Checklist" for full details)

- Use `_is_primarily_documentation()` for doc guards, not substring checks like `"#" in content`.
- `STACK_GLOBAL` opcodes have `arg=None` — reconstruct by walking backwards to preceding `SHORT_BINUNICODE`/`BINUNICODE` ops.
- Always assert specific check names/messages in tests, not just `result is not None`.
- Handle PEP 440 prerelease tags in version comparisons (`2.10.0a0` is still vulnerable).
- Use `except Exception` (not `except ImportError`) for framework version-check imports.
