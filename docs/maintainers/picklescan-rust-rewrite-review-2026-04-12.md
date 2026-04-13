# PR #990 Comprehensive Review — `feat: replace picklescan with Rust-native engine`

**Branch:** `mdangelo/codex/rust-picklescan-rewrite`
**Latest audited:** `060f73b3` (hardening commit: `fix: harden rust picklescan parity and performance`, +1,984/−514 across 32 files)
**Scope:** Rust rewrite of pickle scanner, Python engine removed.

This review combines five specialized agents (Rust core, Python integration, test coverage, CI/packaging, simplification), a Momus critical re-review, and hands-on QA on 31 synthetic fixtures + 21 committed exploits. All validation gates pass locally on the hardened branch (`pytest` 264 picklescan tests, `cargo test` 15, `ruff`, `mypy`, `clippy`).

On the repo's own 21 exploit fixtures and 2 safe samples the scanner is **0 FN / 0 FP** across every revision.

## Revision history

> **Rev 1** (`02712463`): initial 5-agent review + QA. Flagged ~150 items across P0/P1/P2.
>
> **Rev 2** (`c215cf70`): Momus critical pass. Withdrew T-P0-17 (CVE-2025-32434 lives in `pytorch_zip_scanner.py`, not pickle scanner). Downgraded R-P0-1 (`NEXT_BUFFER`) to R-P1-BUF pending PoC. Narrowed wording on R-P0-3, R-P0-7, P-P0-10, P-P0-13. Added P-P1-42a (systematic S201+S104 double-emission) and P-P1-42b (`S211` unregistered).
>
> **Rev 3 (current)**: Re-audit after author's hardening commit `060f73b3`. **~35 of ~50 prior findings are now FIXED or mitigated.** QA re-run confirms: `importlib # harmless` FP gone, `__version__` wrapper FP gone, `__main__.Evil` REDUCE now CRITICAL, 16 MB benign scan dropped from **6.28 s → 0.65 s**, non-seekable stream raw-detector bypass closed, `S211` registered, `copyreg.EXT → REDUCE` now escalates to CRITICAL, multi-stream follow-on detection covered, `.bin` PE/ELF/Mach-O tail scan restored, multi-platform wheel matrix (linux+macOS-arm64+windows) with abi3, Docker uses rustup. Remaining residuals are listed per-section below and a new P1 surfaced around the multi-rule-alias triple-emission pattern for `builtins.eval/exec/compile/__import__`.

**Rev 3 hands-on QA (re-run after hardening):**

| Case | Before hardening | After hardening |
| --- | --- | --- |
| 16 MB benign literal scan | 6.28 s | **0.65 s** |
| 16 MB malicious-middle scan | 6.22 s | **0.68 s** |
| `"importlib # harmless"` FP | flagged WARNING | **clean** |
| `"['__version__', '__author__']"` FP | flagged WARNING | **clean** |
| `"  __version__  "` FP | flagged WARNING | **clean** |
| `__main__.Evil` REDUCE | WARNING only | **CRITICAL** |
| Non-seekable stream scan | silently skipped raw detectors | **full detection** |
| Copyreg EXT → REDUCE | WARNING | **CRITICAL S213** |
| 21 committed exploit fixtures | 21/21 CRITICAL | **21/21 CRITICAL** |
| 2 safe samples | 2/2 clean | **2/2 clean** |
| `S211` stderr noise | warning per process | **gone** (S211 registered) |
| Mid-string proto-0 encoded nested | not probed | **detected (S601)** |
| `{"outer": b"JUNK" + nested}` small-blob | not probed | **detected (S213)** |

---

## TL;DR — Merge-blocker status (rev 3)

| # | Where | Issue | Status |
|---|------|-------|--------|
| 1 | `pickle_scanner.py` `_pickle_opcode_summary` | `extract_metadata()` byte-substring false positive | **FIXED** — now walks opcodes via `pickletools.genops`, tracks all 8 dangerous opcodes + `opcode_counts`/`total_opcodes`/`pickle_protocol`/`dangerous_globals` |
| 2 | `pickle_scanner.py:1029-1107` | CVE-2026-24747 fallback heuristic false positives | **FIXED** — now gated on `has_setitem_opcode` from opcode walk, plus `_rebuild_tensor_indicators_are_documentation_literals` guard against doc-string embedding |
| 3 | `pickle_scanner.py:745-775` + `_BINARY_TAIL_SIGNATURES` | `.bin` tail scan removed | **FIXED** — `_scan_binary_tail_if_needed` restored with MZ/ELF/Mach-O 32&64-bit/shell/PowerShell signatures, guarded by `_looks_like_portable_executable` for MZ to suppress FP; rule codes S501–S506; 3 new regression tests |
| 4 | `pickle_scanner.py:22, 706-743` | 100 MB raw-window, no interrupts, silent non-seekable skip | **FIXED** — default lowered to 8 MB, `skip_expensive_detectors` on parse errors, secrets/JIT/network gated by `_contains_any_seed`/`_has_alnum_secret_shape`/`_has_domain_or_ip_shape`; non-seekable stream path now buffers full payload to `BytesIO` before detector run |
| 5 | `pickle_scanner.py:902-936` | Systematic S201+S104 double emission for raw eval/exec/__import__ | **UNCHANGED — now INTENTIONAL**. `_scan_raw_text_indicators` still emits two rows (S201 primary + S104 alias); see **new P1-TRIPLE** below for the adapter-layer triple emission it combines with |
| 6 | `rust/src/nested.rs:326-356` `starts_encoded_pickle_at` | Mid-string proto-0 encoded probes missing | **FIXED** — prefix table now covers base64 starters `KA`/`Y2`/`Y3`/`Yw`/`ZA`/`bA`/`aQ`/`SQ`/`Uw`/`Vg` plus hex `28`/`63`/`64`/`6c`/`6C`/`69` and escaped `\x28`/`\x63`; regression test `test_scan_bytes_detects_protocol0_encoded_nested_pickle_mid_literal` added |
| 7 | `rust/src/strings.rs:230-325` `has_suspicious_ascii_seed` | Fast-reject seed table missing terms | **FIXED** — seed table now includes `commands`/`compile`/`ctypes`/`codecs`/`getattr`/`runpy`/`pickle`/`popen`/`marshal`/`dill`/`webbrowser` + whitespace-aware `os.`/`os `/`os\t`/`os\n`/`os\r`. `OS .system(...)` now detected via `_contains_module_attr`. `os[.]system` still bypasses but this is not valid Python attribute syntax. |
| 8 | `picklescan_adapter.py:507-575` `_legacy_rule_code_for_finding` | Legacy S104/S105/S106 rule-code regression for builtins.eval/exec/compile/__import__ | **FIXED** — primary mapping restored (eval/exec→S104, compile→S105, `__import__`→S106); adapter test at `test_picklescan_adapter.py:315` updated. **New P1-TRIPLE surfaced** — adapter now emits 3 criticals (S104 primary + S201 + S115 supporting) per REDUCE, see below. |
| 9 | `picklescan_adapter.py` `_should_suppress_parse_failure_escalation` | Broadened parse-failure suppression | **PARTIAL** — still broader than pre-Rust. `UnicodeDecodeError` no longer requires benign-refs guard; `.joblib` zero-padding branch covers more extensions. Not rolled back in `060f73b3`. Needs a conscious decision + CHANGELOG. See P1-PARSE below. |
| 10 | `rule_mapper.py:115` + `rule_catalog.py:165-171` | `S211` unregistered | **FIXED** — `S211` "Pickle extension opcode" now registered in `rule_catalog.py` with severity HIGH and patterns; stderr noise gone. |
| 11 | `test.yml:870` `picklescan-package` matrix | `test_api.py` ran only on Python 3.12 | **FIXED** — job now runs on `["3.10", "3.11", "3.12", "3.13"]`. |
| 12 | `release-please.yml:404-423` wheel matrix | No multi-platform wheels, Docker MSRV mismatch | **FIXED** — matrix now includes `ubuntu-latest` (linux + sdist), `macos-14` (arm64), `windows-latest`. Dockerfile installs Rust via `rustup toolchain install stable` then removes `/root/.cargo` and `/root/.rustup` after build. **RESIDUAL**: no `macos-13` (x86_64) or `linux-aarch64` wheels; see T-P1-WHEEL below. |
| 13 | `Cargo.toml:19` + `pyproject.toml:41` | No abi3 bindings | **FIXED** — `abi3 = ["pyo3/abi3-py310"]` feature added and referenced from `[tool.maturin] features`. Single wheel per OS now covers Python 3.10+. `pyo3` spec at `0.27.2` matches `Cargo.lock:71`. |
| 14 | Comment-token bypass regression tests | Entirely deleted | **PARTIAL** — `test_scan_bytes_ignores_comment_only_importlib_literal`, `test_raw_cve_setitem_detection_is_not_suppressed_by_comment_token`, `test_raw_cve_comment_only_text_does_not_trigger_setitem`, `test_scan_stream_does_not_flag_primarily_documentation_raw_text` added. Still missing explicit pip.main comment-token bypass, `__main__.Evil` comment-token bypass, torch.load comment-token bypass. See T-P2-COMMENT below. |
| 15 | Benchmark claim in PR body | 16 MB benign = 6.28 s, contradicts 40-80× speedup | **FIXED** — re-measured at 0.65 s (≈10× faster than rev 1) via (a) 8 MB raw-window default, (b) seed-gated secrets/JIT/network detectors, (c) abi3 compile path. Standalone `scan_bytes` is ~10 ms, root scanner is ~650 ms; no true "skip when malicious" hot-path but `skip_expensive_detectors=result.has_errors` avoids work on parse-failed inputs. |

---

## Rev 3 residuals and new findings after hardening

### Remaining P1 / P2 items on the hardened branch

**P1-TRIPLE.** `builtins.eval/exec/compile/__import__` REDUCE findings now emit **three** CRITICAL rows per event (`picklescan_adapter.py:616-650` + `_legacy_rule_code_for_finding`). Verified locally on `pickle.dumps(Evil())` where `Evil.__reduce__ = (eval, ("1+1",))`:
```
[S104] CRITICAL  Found REDUCE opcode invoking dangerous global: builtins.eval  pos 39
[S201] CRITICAL  Found REDUCE opcode invoking dangerous global: builtins.eval  pos 39
[S115] CRITICAL  Found REDUCE opcode invoking dangerous global: builtins.eval  pos 39  (legacy_rule_alias=True)
```
The adapter intentionally emits S104 (primary) + S201 (REDUCE opcode supporting) + S115 (legacy alias). This is by-design backwards compatibility for three different rule-code dashboards, but it 3× inflates total issue counts for this class of finding. Consumers counting unique `(location, rule_code)` pairs are correct; consumers counting `len(result.issues)` are inflated. **Recommendation**: either consolidate into a single `add_check` with `rule_codes=[...]` and expose `issue.rule_code_aliases` downstream, or mark the S115 alias as `informational_alias: true` in `details` so counters can filter it out. Add a CHANGELOG note.

**P1-PARSE.** `_should_suppress_parse_failure_escalation` broadening not rolled back. `picklescan_adapter.py:391-439` still has:
- `UnicodeDecodeError + trusted_boundary` suppressed regardless of extension or import-ref danger.
- `.joblib/.pkl/.pickle/.dill` zero-padding-tail `ValueError "opcode b'\x00' unknown"` suppressed with no benign-imports check.
The fail-closed posture on analysis-incomplete scans is therefore weaker than pre-Rust. Not a bug given the Rust engine's own `has_security_findings` guard, but needs an explicit CHANGELOG callout ("parse-failure escalation is now stricter-on-security-findings but more permissive on clean analysis-incomplete inputs") so downstream consumers don't silently lose aborted-scan errors.

**P1-EMPTY.** Empty file still maps to CRITICAL severity. `state.rs:420 record_empty_input_error` sets `category = "empty_input"` which the adapter (`picklescan_adapter.py:303`) treats as non-parse-error → CRITICAL. My QA: `scan("/tmp/empty.pkl")` → `[CRITICAL] Input is empty and does not contain a pickle stream`. Empty `.pkl` placeholders in data dirs will light up as malware. **Recommendation**: map `empty_input` to `IssueSeverity.INFO` or `IssueSeverity.WARNING`, or emit as a notice instead of an error.

**P1-BINTAIL-SCOPE.** `_scan_binary_tail_if_needed` (`pickle_scanner.py:746`) gates on `Path(source).suffix.lower() != ".bin"`. Only `.bin` extensions get the PE/ELF/Mach-O tail scan. Old scanner covered `.bin`, `.pt`, `.pkl`, `.pth`, `.ckpt`. Non-ZIP `.pt`/`.pth`/`.ckpt` files that fall through PyTorchZipScanner into PickleScanner will miss the binary tail scan. **Recommendation**: broaden the gate to `_PYTORCH_CONTAINER_EXTENSIONS` (already defined at line 25) and add regression tests for a `.pt` with trailing PE/ELF.

**P1-SEED-SHAPE.** `_has_alnum_secret_shape` and `_has_domain_or_ip_shape` (`pickle_scanner.py:262-287`) are very loose — any `_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES` prefix with at least one digit and one letter returns True, and `_has_domain_or_ip_shape` returns True as soon as it finds one digit and one `.`. Real ML pickles almost always satisfy both, so the seed gating only skips detectors for degenerate inputs (huge all-`A` or pure-binary-float blobs). Not a correctness bug, but the perf win is narrower than it appears. Consider tightening to at least N digits, N letters, and structural hints (e.g., `/`, `://`, `=`) before running the expensive detectors.

**P1-DUNDER-WALKER.** `contains_only_common_dunder_metadata_literals` (`strings.rs:345-372`) correctly allowlists `__version__`, `__metadata__`, `__schema__`, `__name__`, `__author__`, `__license__` in all wrapping contexts (list, whitespace, newline, adjacent, comma-separated — all verified via QA). However, `__a__` and `__x_y__` still trip `magic method` as WARNING because they look like legitimate Python dunders. These are rare in practice but will FP on any benign pickle carrying a user-defined dunder metadata key outside the allowlist. **Recommendation**: either expand the allowlist to cover common user dunders (`__dict__`, `__slots__`, `__module__`, `__qualname__`, `__doc__`, `__all__`, `__annotations__`) or gate `magic method` warning on combining with another suspicious seed.

**P1-NESTED-DEPTH.** `DEFAULT_MAX_NESTED_DEPTH = 1` is still hardcoded. My 2-layer nested base64 test: outer layer detected as S601 CRITICAL but inner REDUCE is not surfaced. Attacker can pile N layers to hide deep analysis after the first encoding. **Recommendation**: either raise to 2–3 or add an explicit fail-closed notice when the cap is hit and a plausible encoded-pickle prefix is still present deeper.

**T-P1-WHEEL.** Multi-platform wheel matrix is improved but incomplete. `release-please.yml:411-423` covers `ubuntu-latest`, `macos-14` (Apple Silicon), `windows-latest`, but NOT `macos-13` (Intel Mac) or `linux-aarch64`. With abi3 this is less severe (a single wheel covers Python 3.10+), but Intel Mac users and Linux ARM users will still fall through to sdist and need local Rust. Add the two missing targets, or explicitly document the gap in the README.

**T-P2-COMMENT.** Comment-token bypass coverage is partial. New tests added for `importlib`, `_rebuild_tensor` SETITEM, and the primarily-documentation guard. **Still missing**: dedicated bypass tests for pip.main, `__main__.*`, torch.load, `builtins.eval`/`exec`, and dill.loads with embedded comment tokens (the ones deleted with `test_pickle_scanner.py:5776,5926,6776,6813,7695,7753`). AGENTS.md §CVE Detection Checklist mandates these.

**T-P2-EXPANSION.** Expansion heuristics (memo-growth, dup-heavy, follow-on stream) are still untested at the Python level. `follow_on_stream_detected` notice has some coverage via `test_scan_bytes_detects_follow_on_malicious_pickle_streams` parametrize, but `test_pickle_expansion_heuristics_*` suite of 6 tests remains deleted with no replacement. Billion-laughs DoS via memo-inflation is still uncovered end-to-end.

**T-P2-STRUCTURAL.** Structural tamper / duplicate-PROTO / misplaced-PROTO tests still not restored. 8 test functions from `test_pickle_scanner.py:4818-4933` deleted with no replacement. Rust state machine may or may not detect these; no regression gate catches a future regression either way.

**P2-STALE-PYCACHE.** `packages/modelaudit-picklescan/src/modelaudit_picklescan/__pycache__/_parity_corpus.cpython-311.pyc` lingers after the source file moved to `tests/parity_corpus.py`. Harmless but worth cleaning in a follow-up commit (or add to `.gitignore`).

**P2-NEW-HELPER-DUP.** `_has_alnum_secret_shape` and `_has_domain_or_ip_shape` in `pickle_scanner.py:262-287` are near-duplicate loops over the same byte range with almost-identical scanner state. Refactor to a shared `_has_text_shape(data, require_dot=False)` helper.

---

## Rev 3 — New issues introduced by the hardening commit `060f73b3`

An oracle second-pass audit of the hardening commit surfaced ~30 new issues, several of which are **regressions** introduced by the fixes themselves. Items prefixed `N-` are new findings not present in Rev 1 or Rev 2.

### P0 — New regressions introduced by the hardening

**N-P0-1.** **`scan_stream` raises uncaught `ValueError` on non-seekable streams > 8 MB.** `pickle_scanner.py:656-681` `_read_stream_payload_for_root` reads in 1 MB chunks and hits `if bytes_read > limit: raise ValueError(...)`. `limit` defaults to `_root_raw_scan_limit() = 8 MB` when `max_file_read_size` is unset, but `_check_scan_stream_size_limit` at line 1202 only rejects files above `max_file_read_size`. A non-seekable caller (archive member extraction, HTTP body) passing a 10 MB pickle with default config raises `ValueError: File read exceeds limit: 9437184 bytes (max: 8388608)` **mid-scan**, which propagates out of `scan_stream` instead of producing a `ScanResult`. **Reproduced locally** with `NonSeekable(pickle.dumps({'pad': b'A'*10_000_000, 'evil': Evil()}))`. Either wrap the read in `try/except ValueError` and emit a `truncated` notice + finish with `success=False`, or raise `_root_raw_scan_limit()` to match the default `max_file_read_size`.

**N-P0-2.** **Non-seekable large streams produce a spurious `short_read` CRITICAL.** Same refactor. `pickle_scanner.py:1214-1215` buffers `payload` from the non-seekable stream but then calls `self._scan_standalone_stream(io.BytesIO(payload), standalone_size, ...)` passing the **caller-reported** `standalone_size`, not `len(payload)`. When the stream was truncated by the 8 MB cap (caller says 20 MB, buffer is 8 MB), `state.rs:record_short_read` fires with `category="short_read"` and `picklescan_adapter.py:297` maps non-parse errors to `IssueSeverity.CRITICAL`. Legitimate truncated-scan flows emit CRITICAL without any real security finding, and flip `operational_error=True`. Fix: pass `size=len(payload)` (or `None`) for the buffered branch.

**N-P0-3.** **`_is_primarily_documentation` gates the ENTIRE raw-text pass on a global doc-line ratio.** `pickle_scanner.py:240-245, 838-840`. The whole raw window (up to 8 MB) is split by `splitlines()` and a `doc_lines / total_lines > 0.5` check decides whether to skip every indicator. An attacker can suppress all of `_scan_raw_text_indicators` — eval/exec/os.system/importlib/copyreg — by padding a dict value with enough `#`-prefixed lines:
```python
pickle.dumps({"a": "# line\n" * 32 + "trailing", "evil": EvilReduce()})
```
Rust still catches `cos\nsystem\n` via opcode dispatch, so the verdict stays critical, but the belt-and-suspenders raw layer is globally defeated. AGENTS.md §CVE Detection Checklist explicitly mandates that doc-gating scope must be "the specific literal, not the whole buffer". The guard should move inside each `if token in lower:` branch with a literal-context bounded window.

**N-P0-4.** **`_rebuild_tensor_indicators_are_documentation_literals` can be weaponized to suppress CVE-2026-24747 attribution.** `pickle_scanner.py:460-481`. The walker only inspects STRING/UNICODE literal opcodes (line 465-472) and returns `True` if every `_rebuild_tensor`-containing literal is doc-like. An attacker can craft a pickle with:
1. A benign literal like `"# _rebuild_tensor\n# documentation"` (passes doc-literal check).
2. A real `GLOBAL` opcode `torch\n_rebuild_tensor_v2\n` (skipped by the walker because GLOBAL isn't STRING/UNICODE).

`_analyze_cve_patterns` at line 1077 drops the CVE attribution. The DANGEROUS_CALL finding itself is still emitted by Rust, so `verdict=malicious`, but `cve_id`, `cvss`, `cwe`, `cve_count`, and `primary_cve` metadata all vanish — a SARIF/dashboard regression for CVE-2026-24747 attribution specifically. Fix: include `GLOBAL`/`STACK_GLOBAL` arg walks in the literal walker, or key doc-literal suppression on the specific literal that was the SETITEM operand.

**N-P0-5.** **`Duration::from_secs_f64(options.timeout_s)` can panic on user-controlled large timeouts.** `packages/modelaudit-picklescan/rust/src/state.rs:178`. `option_f64` accepts any positive finite `f64`, so a caller passing `timeout_s = 1e18` hits `Duration::from_secs_f64(1e18)` which panics because the value overflows `u64::MAX` seconds. The PyO3 extension has no `catch_unwind` so this crashes the whole Python process. Clamp `timeout_s` to a safe ceiling (e.g. `86400.0` or `Duration::MAX.as_secs_f64() - 1.0`) in `ScanOptions::from_py` before constructing the `Duration`.

**N-P0-6.** **Hot-path skip still not implemented on clean Rust verdicts.** `pickle_scanner.py:1253, 1218`. The prior review flagged `_run_root_raw_detectors` as unconditional. This commit lowered the window to 8 MB and added seed gating, but `skip_expensive_detectors` is keyed only on `result.has_errors`, not on "Rust already emitted no findings AND status is complete". A clean benign pickle still runs secrets/JIT/network regex over the full 8 MB window (or its seed-gated subset) even though Rust just completed in 10 ms. Local measurement: 16 MB benign scan is 0.65 s, standalone `scan_bytes` is 10 ms — 65× gap. Add `if not result.has_security_findings and not result.has_errors: return` before the expensive-detector block, or lower the expensive-detector cap further.

### P1 — Correctness / parity gaps in new helpers

**N-P1-7.** **`_pickle_opcode_summary` clears the string stack on every non-memo opcode.** `pickle_scanner.py:404-457`. Line 444-445: `if name not in {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}: stack.clear()`. Much more aggressive than the old engine. Any pickle interleaving a string arg with even one structural opcode (MARK, EMPTY_DICT, TUPLE1) before a STACK_GLOBAL consumer has its string operands wiped. Downstream: `dangerous_globals` (line 1082) is systematically under-reported for non-trivial pickles that use memoized module/name resolution (common in protocol 4/5). Rust catches the global via opcode dispatch so the direct CRITICAL stays, but the CVE-2026-24747 S209 attribution at lines 1087-1107 is skipped. Fix: walk opcodes the same way Rust does (small memo-aware stack).

**N-P1-8.** **`_contains_call_token` misses `\x00`, line-continuation, and semicolon separators.** `pickle_scanner.py:248-249`. Pattern `(?<![A-Za-z0-9_])eval(?:\s|#[^\n]*\n)*\(` doesn't match:
- `eval\x00(` — `\s` excludes `\x00`. A BINBYTES payload with null separator bypasses.
- `eval\\\n(` — Python line-continuation not handled.
- `eval;(` — semicolon.
- `eval/*c*/(` — C-style comment.
Widen to `[\s\x00-\x1f;]` or use a bounded non-word-char scan.

**N-P1-9.** **`_contains_module_attr` doesn't match pickle GLOBAL-opcode representation `module\nname`.** `pickle_scanner.py:252-254`. Pattern `os\s*\.\s*system` requires a literal `.`. The canonical pickle GLOBAL `cos\nsystem\n` has NO period, so this function never matches it. The file relies on three hardcoded `(b"cos\nsystem\n", ...)` / `cposix\nsystem\n` / `cnt\nsystem\n` byte-string checks at lines 876-882. That's OK for `system`, but the raw layer still misses `cos\npopen\n`, `cos\nspawn\n`, `cposix\npopen\n`, etc. Rust opcode dispatch catches these, but raw-layer coverage regressed vs. prior review. Add pickle-GLOBAL variants for popen/spawn or use `_contains_module_attr` with an alternate `module[.\n ]*name` pattern.

**N-P1-10.** **`_scan_binary_tail_if_needed` is bounded to the 8 MB raw window, not the whole file.** `pickle_scanner.py:745-775, 751`. `data` comes from `_read_root_raw_scan_window` which caps at 8 MB. If `first_pickle_end_pos > 8 MB`, the tail slice is empty and the scan does nothing. Old `_scan_remaining_bin_tail_if_needed` streamed past the pickle to EOF. Fix: for `.bin` files specifically, do a follow-up `open(path, "rb").seek(first_pickle_end_pos); read(1 MB)` after the Rust scan.

**N-P1-11.** **`_scan_binary_tail_if_needed` gated only on `.bin` suffix.** `pickle_scanner.py:746`. Gates on `Path(source).suffix.lower() != ".bin"` → early return. `.pt`/`.pth`/`.ckpt`/`.pkl` files that fall through PyTorchZipScanner into PickleScanner (non-ZIP raw pickles with trailing executables) miss the binary tail scan. Gate on `_PYTORCH_CONTAINER_EXTENSIONS` (already defined at line 25) for parity with `can_handle()`.

**N-P1-12.** **`_scan_binary_tail_if_needed` skips when `first_pickle_end_pos <= 0`.** `pickle_scanner.py:749`. For pickles that hit a parse error before `STOP`, Rust never sets `first_pickle_end_pos`, so `metadata.get("first_pickle_end_pos")` is None → isinstance check fails → early return. A **truncated/malformed pickle with a PE appended gets neither a pickle finding nor a binary-tail finding**. Use `len(truncated_pickle)` as the tail start when the Rust report is inconclusive.

**N-P1-13.** **File integrity check dropped for `scan_stream` with files > 8 MB.** `pickle_scanner.py:1210-1212`. Integrity hash runs only when `len(raw_data) == standalone_size`. For any file > 8 MB via `scan_stream` (archive extraction, remote fetch), `raw_data` is capped → inequality → no SHA-256 hash → no `File Integrity Check` record. `scan()` avoids this via `add_file_integrity_check(path, result)` which reads the whole file. Fix: hash the full payload in both branches, or hash incrementally before the Rust scan.

**N-P1-14.** **`_has_domain_or_ip_shape` returns False for alpha-only domains.** `pickle_scanner.py:275-287`. Loop tracks `has_digit`/`has_alpha` and returns True only if both fire. Fall-through is `return has_digit`. For `"example.com/api"` (no digits, has `.`, alpha-only) → returns `False` → network detector skipped. Seed table covers `http`/`://`/`webhook`/etc., so real URLs still trigger, but bare domains slip through. Change to `return has_digit or has_alpha`.

**N-P1-15.** **Shape checks capped at 1 MB (`_ROOT_EXPENSIVE_RAW_SCAN_LIMIT_BYTES`).** `pickle_scanner.py:265, 280`. Both helpers iterate `data[:1 MB]`. A secret or domain between 1 MB and 8 MB in the raw window is never sniffed, even though the window holds it. Either iterate the whole window or document the 1 MB cap in the emitted metadata.

**N-P1-16.** **Non-seekable branch passes caller-reported size to Rust scanner.** `pickle_scanner.py:1215`. Same root cause as N-P0-2. The `io.BytesIO(payload)` wrapper is called with `standalone_size` instead of `len(payload)`, so Rust sees `bytes_total > payload.len()` and fires `record_short_read`.

**N-P1-17.** **`_contains_any_seed` lowercases the entire buffer per call.** `pickle_scanner.py:257-259`. Runs three times per scan (secrets / network / JIT). 8 MB × 3 = 24 MB of copy work per clean scan. Cache the lowercased view once or compare bytes directly without lowercasing.

**N-P1-18.** **`_legacy_rule_code_for_finding` DANGEROUS_CALL mapping for builtins returns `S104` as primary, not `S201`.** `picklescan_adapter.py:525-549`. The builtins short-circuit at lines 528-534 runs before the fallback `return "S201" if finding.rule_code == "DANGEROUS_CALL" else None` at line 549. Net effect: `DANGEROUS_CALL builtins.eval` has primary `rule_code = S104`, not the historic `S201`. `_add_legacy_supporting_finding_checks` restores S201 as a *supporting* check, so dashboards filtering by S201 still see hits, but downstream contracts expecting `DANGEROUS_CALL → S201` on the primary Issue are broken. Pin via test if intentional.

**N-P1-19.** **Triple CRITICAL emission per `builtins.eval/exec/compile/__import__` REDUCE.** Same as P1-TRIPLE above, with line references: `picklescan_adapter.py:630-650`. S104 (primary) + S201 (supporting) + S115 (alias), all with identical message/location/severity. Consumers counting `len(result.issues)` see 3× inflation.

**N-P1-20.** **`record_buffer_opcode` emits an info notice per buffer op, not per pickle.** `packages/modelaudit-picklescan/rust/src/state.rs:721-738`. A protocol-5 pickle with many `READONLY_BUFFER`/`NEXT_BUFFER` ops emits N info notices. Dedup key is `(code, location, message)` but each uses a distinct `pos {position}` so no collapse. A crafted pickle with 10k buffer ops produces 10k notice entries. Collapse into a counter notice or dedupe on `code` alone.

**N-P1-21.** **`READONLY_BUFFER` asymmetric stack handling.** `rust/src/state.rs:502-507`. `if self.stack.is_empty() { self.stack.push(StackValue::Other); }` — a malformed `READONLY_BUFFER` on an empty stack pushes `Other`, but the real Python unpickler raises `IndexError`. Shapes differ in STACK_GLOBAL operand previews on malformed pickles. Not a security issue but a parity drift.

### P2 — Hygiene / noise gaps

- **N-P2-22.** Encoded-text S604+S104 twin emission still present in `_scan_encoded_text_indicators` (`pickle_scanner.py:998-1026`). Adds `legacy_rule_alias=True` detail but does not collapse the duplicates.
- **N-P2-23.** `_SECRET_SCAN_SEEDS` contains bare `b"key"` (line ~74). Matches any pickle with the substring `"key"` — PyTorch storage keys, HF metadata, dict keys. Defeats the seed gate. Replace with `b"api_key"`, `b"secret_key"`, `b"private_key"`.
- **N-P2-24.** `_SECRET_SCAN_SEEDS` has `b"-----begin "` (with trailing space). Redundant lowercase handling since the buffer is already lowercased; minor noise.
- **N-P2-25.** `_JIT_SCAN_SEEDS` contains `b"def "` and `b"class "`. Any pickle with docstrings in a model config triggers JIT detection. Tighten to `b"def main"`, `b"class Meta"`, or structural tokens.
- **N-P2-26.** `_contains_non_comment_token` still used in three call sites (`pickle_scanner.py:224-237, 852, 857, 867`) despite `_is_primarily_documentation` being added. AGENTS.md CVE Detection Checklist mandates the swap.
- **N-P2-27.** Rust `has_suspicious_ascii_seed` (`strings.rs:230-324`) still missing `joblib`, `cloudpickle`, `copyreg` seeds. A literal `"joblib.load(...)"` fails the fast-reject and `suspicious_string_matches` never runs. Rust opcode path catches REDUCE-on-joblib but string-literal matching regresses.
- **N-P2-28.** `starts_encoded_pickle_at` has `suffix.starts_with(b"800")` which prefixes `"8002"`..`"8005"` (valid protos) — verify tests exercise each proto.
- **N-P2-29.** Escape-hex branch (`\\x80`, `\\x28`, `\\x63`) misses `\\x49` (proto-0 `I` INT), `\\x64` (proto-0 `d` DICT), `\\x6c` (proto-0 `l` LIST), `\\x53` (proto-0 `S` STRING). Complete the table.
- **N-P2-30.** `encoded_nested_literal_probe_windows` linear cost — scans every byte for a prefix match, bounds only on `windows.len() >= MAX_NESTED_PAYLOAD_PROBES (64)`. For 8 MB of benign base64 chars, the loop runs through every byte even though no window ever accumulates. Early-out on total bytes scanned.
- **N-P2-31.** `DANGEROUS_GLOBALS` in `rust/src/policy.rs:140-211` is a `&[(&str, &str)]` slice with `.contains(&(module, name))` → O(n) per REDUCE lookup, n = 70+. Convert to `phf::Map` or sorted binary search for ~10× speedup on the hot path.
- **N-P2-32.** Stale `__pycache__/_parity_corpus.cpython-311.pyc` in `packages/modelaudit-picklescan/src/modelaudit_picklescan/__pycache__/` after the source moved to `tests/parity_corpus.py`. Clean in a follow-up.
- **N-P2-33.** `_read_stream_payload_for_root` (`pickle_scanner.py:656-681`) and `_read_root_raw_scan_window_from_stream` (`pickle_scanner.py:636-697`) duplicate the same "read into a bounded buffer" logic with slightly different error semantics. Unify.

### Proposed remediation order (rev 3)

1. **N-P0-1, N-P0-2** — `scan_stream` `ValueError` on large non-seekable inputs. One-file Python change; 15 minutes.
2. **N-P0-5** — clamp `timeout_s` in `ScanOptions::from_py` before `Duration::from_secs_f64`. Two-line Rust change.
3. **N-P0-3, N-P0-4** — scope `_is_primarily_documentation` per-literal; fold GLOBAL/STACK_GLOBAL walker into `_rebuild_tensor_indicators_are_documentation_literals`. Both are suppression-layer correctness bugs.
4. **N-P0-6** — hot-path skip on clean Rust verdicts.
5. **N-P1-7** — fix `_pickle_opcode_summary` memo-aware stack tracking.
6. **N-P1-10, N-P1-11, N-P1-12** — binary tail scan scope (tail past raw window, `.pt/.pth/.ckpt`, truncated pickle tail).
7. **N-P1-13** — stream integrity hash for > 8 MB.
8. **N-P1-19 + N-P2-22** — collapse triple/twin emissions into multi-rule-code single checks.
9. **N-P2-23, N-P2-25** — tighten noisy seeds.
10. **N-P2-27, N-P2-31** — sync Rust seed table and convert `DANGEROUS_GLOBALS` to phf/binary search.

---

## QA results (hands-on, 31 fixtures + 21 committed exploits)

### Confirmed true positives
- All 21 `tests/assets/**/*.pkl` exploit fixtures → CRITICAL.
- All 18 synthetic malicious pickles (eval/exec/os.system/subprocess/proto0/2/4/5 variants, PyTorch-ZIP embedded, comment-token bypass, large-middle, truncated) → CRITICAL.
- Nested base64 (1 layer) → CRITICAL with inner REDUCE surfaced.
- `mal_torch_like.pt` → detected via PyTorch-ZIP routing.

### False negatives (severity downgrades)
1. ~~`__main__.<symbol>` REDUCE chain only WARNING, never CRITICAL.~~ **FIXED** in `060f73b3` — `state.rs:648-677` emits a dedicated CRITICAL finding for `__main__` REDUCE with dedicated message and `why` text.
2. **2-level nested base64** still surfaces outer S601 CRITICAL but not the inner REDUCE (DEFAULT_MAX_NESTED_DEPTH = 1). Unchanged — see P1-NESTED-DEPTH above.
3. ~~Non-seekable stream silently skips raw-window detectors.~~ **FIXED** in `060f73b3` — `pickle_scanner.py:1213-1217` buffers non-seekable payloads to `BytesIO` before running detectors. Confirmed via direct `NonSeekable` test → 1 CRITICAL `posix.system` finding. But see **NEW N-P0-1 / N-P0-2** below for a new regression introduced by the same refactor.

### False positives
1. ~~`importlib # harmless` literal warning.~~ **FIXED** — added tests `test_scan_bytes_ignores_comment_only_importlib_literal` and the `_is_primarily_documentation` guard applied at `pickle_scanner.py:839`. QA confirms `pickle.dumps("importlib # harmless")` is now CLEAN. But see **NEW N-P0-3** for an exploitable side-effect of the fix.
2. ~~`__version__`-wrapped values flagged as "magic method".~~ **FIXED** — new `contains_only_common_dunder_metadata_literals` walker at `strings.rs:345-372` allowlists multi-token dunders, trimmed whitespace, list-wrapped. QA confirms `'__version__'`, `"['__version__', '__author__']"`, `'__version__,__metadata__'`, `'  __version__  '` all CLEAN. Residual: user-defined dunders outside the 6-entry allowlist (e.g. `__dict__`, `__slots__`, `__module__`) still warn — see P1-DUNDER-WALKER.
3. **Empty file → CRITICAL severity** — UNCHANGED. `state.rs:414-430 record_empty_input_error` still sets `category="empty_input"` → CRITICAL. See P1-EMPTY above.
4. ~~Duplicate CRITICAL emissions.~~ **BY DESIGN NOW** — the adapter intentionally emits S104 (primary) + S201 (supporting) + S115 (alias) for `builtins.eval/exec/compile/__import__` REDUCE. See P1-TRIPLE (N-P1-19) for the ongoing count-inflation concern. Other duplicate sources (S604+S104, raw S201+S104) still present — see N-P2-22.
5. ~~`rule_mapper returned unknown rule code: S211` stderr noise.~~ **FIXED** — `S211 "Pickle extension opcode"` now registered in `rule_catalog.py:165-171`. Confirmed via direct scan of `mal_copyreg_ext.pkl`: no stderr noise.
6. **`os.path` ref flagged CRITICAL** — only reproduced on hand-crafted `getattr(os.path, 'exists')` bypass attempt (not a real benign corpus hit). Unchanged; low severity since legitimate pickles rarely reference `os.path` as a GLOBAL.

### Perf regression vs PR claim
- PR body claims 40–80× speedup to 105–197 ms for 8 MB files after hot-path optimization.
- Local benchmark (same Python 3.11, built Rust extension, `/tmp/pr990_qa/benign_large_literal.pkl` = 16 MB): **6.28 s** in `PickleScanner().scan()`, **10 ms** in `modelaudit_picklescan.scan_bytes()`.
- `cProfile` attribution: 4.00 s `detectors/secrets.py::scan_text`, 1.96 s `detectors/network_comm.py::scan`, 0.19 s `_analyze_cve_patterns`. Only ~10 ms goes to Rust.
- Root cause: there is **no hot-path skip**. `scan()` (line 778-779) always reads up to 100 MB into `raw_data` and calls `_run_root_raw_detectors(...)` unconditionally, regardless of whether Rust already emitted a critical. The PR description's claim "skips duplicated Python compatibility work where Rust has already provided the primary signal" is not implemented in the code.
- `_run_root_raw_detectors` re-runs secrets, network, CVE, embedded-secrets, JIT-script, and encoded-text detectors on the 100 MB window, dominated by regex-heavy Python passes.

### Resource behavior
- **Deep recursion stress** (100k MARK + LIST opcodes): 0.12 s, clean. No panic. Good.
- **Massive memo stress** (500k `SHORT_BINUNICODE + MEMOIZE`): 1.65 s, `success=False`, info notice `Opcode analysis stopped after reaching max_opcodes=1000000`. Good.
- **max_opcodes tail evasion**: crafted 1.2M noise opcodes followed by `os.system` REDUCE — still flagged CRITICAL via the raw detector path (`Raw pickle content references dangerous helper: os.system`). Good — the raw layer is a belt-and-suspenders for budget exhaustion.

---

## P0 — Security / correctness regressions

### Rust engine

**R-P0-1.** ~~`NEXT_BUFFER`/`READONLY_BUFFER` treated as no-ops.~~ **Downgraded to R-P1-BUF after review** (see R-P1-BUF below). Latent parser drift; no concrete PoC demonstrating CRITICAL→CLEAN verdict flip.

**R-P0-2.** `INT`/`LONG`/`LONG1`/`LONG4` push `StackValue::Other` because `stack_value_from_integer_arg` rejects `ArgValue::Text`/`Bytes` (`state.rs:1724` + `opcode.rs:114-163`). Parity gap with old Python engine; breaks `pytorch_storage_key` detection for protocol-2 LONG1 storage sizes and any future integer-aware detection.

**R-P0-3.** `encoded_nested_literal_probe_windows` *mid-string* probe only matches `gA`/`800`/`\x80` prefixes (`nested.rs:306`). The full-value path at `nested.rs:293` via `base64_prefix_has_pickle_prefix`/`hex_prefix_has_pickle_prefix` + `has_pickle_prefix` at `nested.rs:271` already accepts proto-0 byte starts (`(` `c` `d` `l` `i` `I` `S` `V`), so encoded proto-0 pickles **at the start** of a literal are probed. The gap is specifically mid-string insertions of proto-0 candidates. Add base64 prefixes `KA`/`Y2`/`Y28`/`Yw...` and hex `28`/`63`/`64` to the mid-string window.

**R-P0-4.** `suspicious_string_matches` fast-rejects when neither `has_suspicious_ascii_seed` nor `has_base64_dangerous_seed` fires (`strings.rs:12,223`). Seed table missing `runpy`, `popen`, `spawn`, `compile`, `pickle`, `marshal`, `ctypes`, `codecs`, `dill`, `webbrowser`. `OS .system(...)` (trailing space) and `O\x00S.system` bypass entirely. Old Python ran every regex regardless.

**R-P0-5.** `__version__` allowlist is exact-match only (`strings.rs:27`). `"['__version__']"`, `"  __version__"`, `"__version__\n"` trip "magic method" warning. HF configs and pydantic models routinely serialize `__version__` inside lists/dicts.

**R-P0-6.** `EXT1/EXT2/EXT4` → REDUCE combination emits only WARNING severity and marks the global `malformed: true` so REDUCE short-circuits (`state.rs:595`). `_copyreg_extension_reduce_references` in Python backstop catches this only on root ModelAudit path, not standalone. Should raise to CRITICAL when the extension is followed by REDUCE on the stack.

**R-P0-7.** `scan_raw_nested_pickle_bytes` size-guard asymmetry (`state.rs:882`). The probe path at line 884-900 runs `nested_pickle_probe_offsets(value)` only when `value.len() > max_nested_pickle_bytes` (e.g. >2 MB default); the small-blob branch at line 902+ validates only at offset 0 via `looks_like_pickle_payload`. A junk-prefixed nested pickle under the size threshold (e.g. 1 MB with leading `b"\x00\x00JUNK" + malicious_pickle`) gets no probe walk. Run a bounded `nested_pickle_probe_offsets` pass on the small-blob branch too (cap at 64 probes).

**R-P0-8.** `POP`/`SETITEM`/`APPEND` unconditionally pop `Mark` values (`state.rs:542`). A malformed `MARK; APPEND` pops the mark and silently desyncs the stack for subsequent `POP_MARK`/`TUPLE`/`LIST`. Check popped value and push back if `Mark`.

### Python integration

**P-P0-9.** `extract_metadata()` uses naive byte-substring checks (`pickle_scanner.py:731-740`):
```python
if b"R" in payload: dangerous_opcodes.append("REDUCE")
if b"b" in payload: dangerous_opcodes.append("BUILD")
```
Any pickle containing the ASCII `R` or `b` reports "has REDUCE/BUILD" — effectively all pickles. Old code walked opcodes via `pickletools.genops` tracking 8 dangerous opcodes (REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX, STACK_GLOBAL, GLOBAL, BUILD) and exposed `opcode_counts`, `total_opcodes`, `pickle_protocol`.

**P-P0-10.** CVE-2026-24747 fallback heuristic false positive (`pickle_scanner.py:638-656`). The first heuristic at line 640 requires `b"_rebuild_tensor" in data and b"s" in data`; `b"s"` is always true so this attributes the CVE to every PyTorch checkpoint containing `_rebuild_tensor`. The companion branch at line 658 is **narrower** than the review initially suggested: it combines `(b"os" | b"posix" | b"nt") and b"system"` with `_contains_pickle_opcode(data, "SETITEM")`, so an actual SETITEM opcode walk gates the final attribution. Fix the first heuristic by replacing `b"s" in data` with a precise opcode-based check or remove the fallback entirely.

**P-P0-11.** `.bin` tail scanning **entirely removed.** Old `_scan_binary_content`/`_scan_remaining_bin_tail_if_needed` scanned bytes past `first_pickle_end_pos` for PE/ELF/Mach-O/shell/PowerShell signatures and `eval`/`exec`/`os.system`/`subprocess`/`__import__` binary substrings with rule codes S101, S103, S104, S501, S502, S503, S504, S506. New wrapper has none of this. Largest single detection-surface reduction in the PR.

**P-P0-12.** Root raw-window reads up to 100 MB synchronously without interrupt/timeout (`pickle_scanner.py:21,353-359`). Old code bounded to 8 KB in 1 KB chunks with `check_interrupted()`/`_check_timeout()` per chunk. Transient RSS ~200 MB per large pickle, unkillable from Ctrl-C during raw detector passes.

**P-P0-13.** `builtins.eval/exec/compile/__import__` rule-code regression for DANGEROUS_CALL/DANGEROUS_GLOBAL findings (`picklescan_adapter.py:525-543`). The builtins short-circuit at lines 528-529 returns `S115` before the opcode/import mapping at lines 531-542. Test at `test_picklescan_adapter.py:315` pins the new behavior. Note this is a **partial** regression: the SUSPICIOUS_STRING path at `picklescan_adapter.py:547-556` still maps eval/exec/compile/__import__ to S104/S105/S106 correctly, so a scan that also trips the suspicious-string detector will still surface the legacy codes via a parallel route. Dashboards filtering by S104/S105/S106 will see a reduced hit rate but not a total loss. `_add_legacy_supporting_finding_checks` does not add the legacy codes as supporting checks on DANGEROUS_CALL findings.

**P-P0-14.** `_should_suppress_parse_failure_escalation` dropped guards (`picklescan_adapter.py:391-439`):
- No longer early-returns when `has_trusted_pickle_boundary is False`.
- `UnicodeDecodeError` suppression used to require extension in `{.bin, .pkl, .pickle}` AND `_has_only_non_dangerous_import_references()`. Now any `UnicodeDecodeError` with trusted boundary is suppressed regardless of extension/refs.
- `.joblib "opcode b'\x00' unknown"` suppression used to require trusted boundary AND benign imports. Now broadens to `{.pkl, .pickle, .joblib, .dill}` and drops the benign-imports check.
Net effect: weaker fail-closed posture on analysis-incomplete scans.

**P-P0-15.** `numpy_scanner.py` trailing-bytes branch semantics changed (`numpy_scanner.py:45-55,394-396`). Inline `_finish_with_inconclusive_contract` now just `result.finish(success=default_success)` with `default_success=False` at line 395. Old helper flipped to `success=True` when embedded-pickle security findings existed. Net effect: a malicious object-dtype NumPy array with trailing bytes now flips completed-with-findings scans into `success=False` → exit-code regression.

**P-P0-16.** CVE attribution hardcoded to S310 (`pickle_scanner.py:673,696`). S310 is the network/C&C rule. Old mapped CVE patterns to S101/S103/S104/S105/S106/S115 per `attr.patterns_matched`. Also missing `cve_risk_score` metadata because `enhance_scan_result_with_cve` is no longer called.

### Tests / CI / packaging

**T-P0-17.** ~~**CVE-2025-32434 metadata regression.**~~ **Withdrawn after verification.** CVE-2025-32434 is implemented in `modelaudit/scanners/pytorch_zip_scanner.py:159-1799` with full `cvss`/`CWE-502`/`weights_only=True`/`PyTorch 2.6.0` metadata, and regression coverage still lives in `tests/scanners/test_pytorch_zip_scanner.py`. It was never handled by the pickle scanner. The initial finding conflated pickle-opcode REDUCE detection with PyTorch-archive CVE attribution. Follow-up only: add a smoke test that `PyTorchZipScanner` still attributes CVE-2025-32434 end-to-end against a fixture vulnerable `.pt` archive.

**T-P0-18.** **Comment-token bypass coverage entirely deleted.** Old suite had ≥6 regression tests (`test_pickle_scanner.py:5776,5926,6776,6813,7695,7753`). New test files contain zero `comment_token`, `_primarily_documentation`, or `# comment.*bypass` references. AGENTS.md §CVE Detection Checklist explicitly mandates these.

**T-P0-19.** **Expansion heuristics coverage removed.** Old tests `test_pickle_expansion_heuristics_detect_iterative_memo_growth`, `_detect_diluted_memo_growth`, `_detect_dup_heavy_payload`, `_detect_follow_on_stream`. No replacement. Billion-laughs-style DoS via memo growth is now uncovered.

**T-P0-20.** **Post-budget deep scan coverage shrunk** from 40+ tests (`test_post_budget_*`) to 2. Missing: memo-read STACK_GLOBAL recovery, reference count caps, logging caps, deadline interaction, benign classification caching.

**T-P0-21.** **Structural-tamper / duplicate-PROTO / misplaced-PROTO end-to-end tests gone.** Eight test functions deleted (`test_pickle_scanner.py:4818-4933`). Zero replacements.

**T-P0-22.** **Binary tail PE/ELF/Mach-O coverage gone.** Test methods `test_scan_bin_file_with_suspicious_binary_content`, `test_pe_file_detection_requires_dos_stub`, `test_pe_file_detection_with_dos_stub`, `test_scan_bin_file_with_executable_signatures` all deleted with no replacement. Aligns with P-P0-11 scanner regression above.

**T-P0-23.** **CI lane gap: `test_api.py` runs only on Python 3.12.** `tests/conftest.py:88` allowlist does not include the packages/modelaudit-picklescan/tests/ files, and the `picklescan-package` job in `test.yml:856-896` pins `uv python pin 3.12`. The primary malware coverage file (1,393 lines) does not run on the Python 3.10/3.11/3.13 matrix. Either run the `picklescan-package` job under the full matrix or include the package test dir in root `testpaths`.

**T-P0-24.** **No multi-platform wheel matrix** (`release-please.yml:404`). Single `ubuntu-latest` job produces one `linux-x86_64-cp312` wheel. No manylinux, aarch64, macOS (x86_64 or arm64), or Windows builds. `pyproject.toml` pins `modelaudit-picklescan>=0.1.0,<0.2.0` without a sdist-only fallback for the root package, so `pip install modelaudit` on any non-linux-x86_64 host will either:
- fall through to the sdist, requiring local Rust toolchain, or
- fail to resolve a compatible wheel entirely.

**T-P0-25.** **No abi3 bindings** (`Cargo.toml:21` — `pyo3 = "0.27.1"` with no `abi3-py310` feature; `[tool.maturin]` in `pyproject.toml` has no `bindings = "abi3"`). Each wheel is tied to a specific CPython minor version. Combined with T-P0-24, the only published artifact works on linux-x86_64 + cp312.

**T-P0-26.** **Docker build will fail at Debian `cargo`** (`Dockerfile:14`, `Dockerfile.full:21`). `apt-get install cargo` on `python:3.13-slim` (Debian bookworm) yields Rust 1.63, below the `rust-version = "1.74"` MSRV in `Cargo.toml:5`. Maturin will refuse to compile. Must install Rust via `rustup` and purge after the pip install, or use a multi-stage build.

---

## P1 — Significant gaps

### Rust engine

**R-P1-BUF (formerly R-P0-1).** `NEXT_BUFFER`/`READONLY_BUFFER` treated as no-ops (`state.rs:509`). Real pickle semantics: `NEXT_BUFFER` pops the next buffer from the loader's `buffers` iterable and pushes it; `READONLY_BUFFER` wraps the top of stack. A protocol-5 pickle using out-of-band buffers can desynchronize the scanner's stack vs the real unpickler (e.g. `SHORT_BINUNICODE "safe"; NEXT_BUFFER; SHORT_BINUNICODE "anything"; STACK_GLOBAL`). **Needs a concrete PoC demonstrating CRITICAL→CLEAN verdict flip to promote back to P0.** Until then, fix: push `StackValue::Other` on buffer ops and emit an informational notice when a buffer op appears near STACK_GLOBAL/REDUCE.

**R-P1-27.** `record_global_ref` dedupe key ignores `reference.malformed` (`state.rs:1138`). Memoized `__unknown__/memo_N` malformed refs can suppress legitimate refs at the same position. Trivial fix: add `reference.malformed` to the key tuple.

**R-P1-28.** `GET/BINGET/LONG_BINGET` on missing memo slot pushes a synthetic `GlobalRef{malformed:true}` (`state.rs:567`). Out-of-order GET in valid memoized pickles gets flagged `MALFORMED_STACK_GLOBAL` critical. Push `StackValue::Other` like old Python engine.

**R-P1-29.** `scan_post_budget_tail` position reporting is off by `(read_offset - stream_offset)` bytes (1–9, opcode length) when hit is past `tail_prefix` (`state.rs:1419`). Minor but surfaces wrong offsets in audit reports.

**R-P1-30.** `check_limits` calls `Instant::now()` on every opcode (`state.rs:366`). Budget of 1M opcodes × ~20–200 ns = 20–200 ms of pure timestamp overhead on Windows/slow clocks. Check every 4096 opcodes.

**R-P1-31.** `location_position` parses `"(pos N)"` with `rfind` (`state.rs:1827`). Brittle coalesce key; coalesces the wrong position when source contains `(pos ...)` text. Store position as structured field on `Finding`.

**R-P1-32.** `scan_post_budget_tail` needle table missing `os\npopen`, `os\nspawn*`, `commands\ngetoutput`, `importlib\nimport_module`, `marshal\nloads`, `ctypes\nCDLL`, `runpy\nrun_module` (`state.rs:1440`). Python backstop covers these but standalone package misses them after opcode budget overrun.

**R-P1-33.** `STACK_GLOBAL` operand resolution rejects `StackValue::Bytes` → `MALFORMED_STACK_GLOBAL` critical (`state.rs:1591`). Real Python `TypeError`s but the Rust scanner fails-closed here, which is arguably safer but may produce FP on legal BINBYTES module-name edge cases.

**R-P1-34.** `coalesce_redundant_global_findings` rebuilds `seen_finding_keys` but not `seen_notice_keys` (`state.rs:1501`). Latent bug if future code re-adds notices post-coalesce.

**R-P1-35.** `has_pickle_prefix` allows any byte after `0x80` (`nested.rs:264`). Wastes probe budget on `0x80 0x00` (bogus proto). Compare with `_looks_like_pickle` in Python which requires `data[1] in {2,3,4,5}`.

**R-P1-36.** `looks_like_pickle_payload` validator rejects `MARK; POP` (`nested.rs:151`). Legal in Python pickle VM but treated as invalid. Accept MARK-on-POP as equivalent to POP_MARK.

**R-P1-37.** `scan_raw_nested_pickle_bytes` doesn't emit truncation notice when the probe branch succeeds on truncated candidate (`state.rs:884`). Users can't distinguish "analyzed fully" from "truncated at 2 MB".

**R-P1-38.** `DEFAULT_MAX_NESTED_DEPTH = 1` (hardcoded). Matches old Python, but undocumented and exploitable by piling N layers of nesting. Document and consider raising to 2–3 with explicit cap.

**R-P1-39.** Only 12 Rust unit tests for ~4,000 lines (`state.rs:1912` → 2 tests, `opcode.rs:734` → 0, `policy.rs:180` → 0, `report.rs:203` → 0, `pybridge.rs:33` → 0). Core dispatch logic untested at the Rust layer; tests exist only via Python round-trip. Target ≥40 cargo tests covering opcode stack effects, REDUCE/NEWOBJ/OBJ/INST dispatch, timeout/budget caps, policy table matching, and report serialization.

### Python integration

**P-P1-40.** `_scan_raw_text_indicators` bypasses (`pickle_scanner.py:451-522`):
- `webbrowser.open` check has redundant `or (b"webbrowser" in lower and b"open" in lower)` — degenerates to "webbrowser is present".
- Comment-safe allowlist matches only exact literal `b"webbrowser# safe comment"`; `webbrowser #safe` (added space) bypasses.
- `eval(`/`exec(` with only `(` or ` (` — doesn't catch `eval\t(`, `eval\n(`, `eval # comment\n(`.
- `_contains_non_comment_token` uses a plain `find` loop with `#` look-ahead. AGENTS.md §CVE checklist forbids this in favor of `_is_primarily_documentation`.

**P-P1-41.** `_scan_encoded_text_indicators` minimum token length 16 chars (`pickle_scanner.py:24`) misses `base64(b"eval(x)")` = 12 chars. Lower to 12 with extra dedupe.

**P-P1-42.** Encoded-pattern double emission S604 + S104 (`pickle_scanner.py:594-622`). Identical `details`/`message`/`location`/`severity`, only differing `rule_code`. Dedupe or pick one canonical.

**P-P1-42a.** **Systematic raw-text double emission for `eval`/`exec`/`__import__`** (`pickle_scanner.py:500-521` and `:523-536`). `_scan_raw_text_indicators` first emits `S201` for every `eval`/`exec` hit via the indicator loop, then immediately emits a second `add_check` with `rule_code="S104"` carrying identical details at lines 513-521. The `__import__` path is identical — S201 from the indicator loop at 472-473 and a separate S104 at 523-536. Every raw-content eval/exec/`__import__` hit produces two CRITICAL rows. This is a deterministic, per-file source of duplicate criticals that is larger than any of the individually enumerated duplicates in the QA section (which listed four specific fixtures). Consolidate into a single `add_check` with `rule_codes=[primary, alias]` or drop the alias emission.

**P-P1-42b.** **`S211` rule code emitted but not registered** (`modelaudit/scanners/rule_mapper.py:115` + `modelaudit/rule_catalog.py`). `get_pickle_opcode_rule_code` returns `_rule("S211")` for `EXT1`/`EXT2`/`EXT4` opcodes, but `RuleRegistry.get_rule("S211")` returns `None`. Each scan of a pickle containing any extension-registry opcode triggers `rule_mapper.py:18 logger.warning("rule_mapper returned unknown rule code: %s", code)`, which prints once per process to stderr (guarded by `_warned_unknown_codes`). This is both log noise and a rule-catalog drift bug. Either register `S211` in the catalog or change `get_pickle_opcode_rule_code` to return `None` for extension opcodes.

**P-P1-43.** `scan_stream` skips `add_file_integrity_check` (`pickle_scanner.py:743-754`). Archive-member scans lose file hashes → compliance metadata regression.

**P-P1-44.** `_analyze_cve_patterns` runs `pickletools.genops` twice per scan over up to 100 MB (`pickle_scanner.py:658,202-207`). Surface `has_setitem_opcode` / `copyreg_extension_refs` from Rust metadata instead.

**P-P1-45.** Parse-error severity upgraded from INFO to WARNING (`picklescan_adapter.py:303`). Changes downstream CheckStatus counts, exit-code behavior; either intentional (needs CHANGELOG callout) or revert.

**P-P1-46.** `DEFAULT_MAX_UNBOUNDED_STREAM_READ_BYTES = 8 MB` silently errors on legitimate 20 MB pickles scanned via `scan_stream(stream, size=None)`. Becomes `io_error` via the outer `except Exception`. No dedicated `unbounded_stream_truncated` notice. Either raise the cap or emit a structured notice.

**P-P1-47.** `scan()` and `scan_stream()` have asymmetric ordering of raw detectors vs Rust merge (`pickle_scanner.py:777-801` vs `743-754`). Same malicious pickle produces different issue counts via path vs stream. Pick one ordering and apply consistently.

**P-P1-48.** `_add_root_legacy_metadata_detectors` can double-emit S207 on top of Rust's S203 for same `__main__` reference (`pickle_scanner.py:412-449` + `state.rs:1200`). Rust emits S203 ("OBJ opcode" code, but message is about `__main__`), Python legacy adds S207 ("BUILD"). Two or three rule codes per symbol. Pick canonical.

**P-P1-49.** `rust/src/policy.rs:60-125` missing modules that `modelaudit/detectors/suspicious_symbols.py:SUSPICIOUS_GLOBALS` flags: `xmlrpc.*`, `poplib`, `imaplib`, `nntplib`, `ntpath`, `posixpath`, `dill.load_module*`, `dill.load_session`, broader `joblib.*` wildcard, `copyreg.add_extension/remove_extension`, `_operator.*` wildcard, `torch._dynamo.guards.GuardBuilder.get`, `torch.fx.experimental.symbolic_shapes.ShapeEnv.evaluate_guards_expression`, `torch.utils.collect_env.run`, `torch.utils._config_module.ConfigModule.load_config`, `torch.utils.bottleneck.__main__.run_cprofile/run_autograd_prof`, `torch.utils.data.datapipes.utils.decoder.basichandlers`, `numpy.f2py.crackfortran.getlincoef`. Sync Rust policy table with SUSPICIOUS_GLOBALS, ideally from a shared data file.

**P-P1-50.** `_discover_pytorch_zip_pickle_entries` only gates pytorch-archive recognition on `data.pkl` existence (`api.py:243-257`). Archives with malicious `custom.pkl` but no `data.pkl` fall into raw-byte scan where the ZIP bytes get parsed as a pickle (`api.py:96-103`), producing a `PK\x03\x04` parse error — the malicious member is never scanned.

### Tests / CI / packaging

**T-P1-51.** `test_rust_engine_scans_parity_payloads` (`test_rust_engine.py:106-111`) only asserts `status in {COMPLETE, INCONCLUSIVE, ERROR}` — always true. Every parity payload including `malicious_reduce`, `stack_global`, `suspicious_string` could silently return `CLEAN` and the test passes. Add per-payload expected verdict table.

**T-P1-52.** `test_generated_payloads_scan_without_runtime_errors` (`test_rust_engine.py:114-124`) and `test_prefix_truncations_scan_without_runtime_errors` (`:148-160`) are pure crash-regression fuzz tests. Any malicious payload returning `CLEAN` passes.

**T-P1-53.** `test_picklescan_multi_stream_padded_payload` (`test_picklescan_benchmarks.py:170-183`) asserts `verdict == UNKNOWN` and `not report.findings` for `safe + 4096 null + malicious`. That contradicts old `test_multi_stream_large_padding_resync` which expected malicious-tail detection. **Either this pins a genuine regression (old engine caught, new engine doesn't) or the assertion is wrong** — needs investigation and a comment.

**T-P1-54.** Rust source-table tests (`test_rust_engine.py:79-103`) regex-extract `BUILTIN_DANGEROUS_NAMES` / `DANGEROUS_WILDCARD_MODULES` / `DANGEROUS_GLOBALS` from `.rs` source text. Textual, not functional — a table rename breaks the test without any real regression.

**T-P1-55.** `test_scan_bytes_detects_reduce_invoking_os_system` (`test_api.py:28,94-107`) accepts `{"nt.system", "os.system", "posix.system"}` via set-containment. On Linux CI only `posix.system` is valid; accepting `nt.system` allows the test to pass if the engine misreports. OS-conditional the assertion.

**T-P1-56.** `test_scan_bytes_does_not_treat_system_name_as_setitem_cve` (`test_pickle_scanner.py:168-173`) asserts only `all(rule_code != "S310")`. Negative-only — silent regression where the scanner stops flagging `os.system` entirely still passes.

**T-P1-57.** `test_scan_bytes_does_not_scan_raw_binbytes_payloads_as_text_strings` (`test_api.py:972-979`) pins `b"A"*256 + b"subprocess.run exec("` as CLEAN — codifies that BINBYTES payloads are not scanned. This is a design decision, but an attacker can store payloads in BINBYTES to bypass string detection. Needs explicit comment referencing decision + CHANGELOG callout.

**T-P1-58.** `release-please-config.json` does not track `packages/modelaudit-picklescan` as a separate component. Release-please will never bump its version. The dependency pin `modelaudit-picklescan>=0.1.0,<0.2.0` will keep resolving the stale `0.1.0` forever.

**T-P1-59.** Smoke test in `release-please.yml:261-265` uses `--find-links /tmp/modelaudit-picklescan-dist` with a platform-specific, non-abi3 wheel. Passes vacuously when the runner Python happens to match; gives no signal for other platforms.

**T-P1-60.** `Cargo.toml:21` pins `pyo3 = "0.27.1"` but `Cargo.lock:71` resolved `pyo3 = 0.27.2`. With `cargo check --locked` on MSRV, both must match; either the spec or the lockfile should be updated.

**T-P1-61.** `build-picklescan-package` and `picklescan-package` jobs pin Python 3.12 only. No CI for the Rust extension against Python 3.10, 3.11, or 3.13 in any workflow.

**T-P1-62.** Dockerfile layering is single-stage. `apt-get purge --auto-remove` does not reliably clean `~/.cargo/registry` or `target/`. Use a multi-stage build with a dedicated `builder` stage that produces the wheel.

**T-P1-63.** Missing module coverage in `test_scan_bytes_flags_expanded_high_risk_callables` (`test_api.py:771-787`): no tests for `smtplib`, `httplib`, `sqlite3`, `marshal`, `cloudpickle`, `pkgutil.resolve_name`. Old suite had dedicated regressions for each.

**T-P1-64.** No end-to-end tests for NEWOBJ_EX with real payloads driving the Rust engine. Old `test_newobj_ex_dangerous_class` deleted; only adapter-mapping parametrize references NEWOBJ_EX indirectly.

**T-P1-65.** Only one smoke test for EXT1/EXT2/EXT4 extension registry. Old had 6 tests covering ext-reduce, ext-unresolved, ext-resolved-to-safe, ext-functools-partial, multistream-promotion.

**T-P1-66.** Multi-stream regression suite shrunk from 7+ tests (benign-then-malicious, separator resync, large-padding resync, malformed-first-stream detects-second, httplib-in-second-stream, picklescan-gap-in-second, import-shaped padding, mark padding) to one test concatenating clean + malicious.

**T-P1-67.** Dill regression shrunk from 6 tests to 4. Missing: `dill.load` (not `loads`) single variant and benign-dill-string negative case.

---

## P2 — Hygiene, docs, simplification

### Rust maintainability

- **S-R2-1.** Dead `"SET"` arm (not a real pickle opcode) in `state.rs:535` and `nested.rs:165`. Remove.
- **S-R2-2.** `finalize_common_metadata` is empty (`state.rs:464`). Delete or repurpose.
- **S-R2-3.** `consume_top_operands(2)` called with the same constant from 3 `match` arms (`state.rs:699-722`). Small table would read better.
- **S-R2-4.** `stack_value_text` and `stack_value_string` near-duplicates (`state.rs:1662-1695`). Have `_string` call `_text(...).map(Cow::into_owned)` + a `Bytes` arm.
- **S-R2-5.** `add_nested_payload_finding` + `add_encoded_nested_payload_finding` near-duplicate Finding construction (`state.rs:922-959,1047-1091`). Consolidate into one helper with an `encoding`/`rule_code_override` parameter.
- **S-R2-6.** `record_global_ref` builds two overlapping detail vecs (`state.rs:1145-1184`). Share a base `vec![]`.
- **S-R2-7.** `option_usize` doesn't validate bounds while `option_f64` does (`state.rs:118-137`). Inconsistent.
- **S-R2-8.** `suspicious_string_matches` has a 70-line `if value.contains(...)` chain (`strings.rs:11-101`). Table-driven with ~10 lines + special cases.
- **S-R2-9.** `contains_getattr_target` and `contains_nested_getattr` near-duplicate parser (`strings.rs:357-426`).
- **S-R2-10.** `warning_globals` returns `Some(&[])` to mean "any name" (`policy.rs:30-38`). Obscure API — prefer explicit `enum Match { AnyName, OneOf(&[&str]) }`.
- **S-R2-11.** `bytes_scanned = max(parsed.next, parsed.pos.saturating_add(1))` is redundant (`state.rs:298`); `parsed.next > parsed.pos` always.

### Python maintainability

- **S-P2-12.** `can_handle()` unreachable branch `if suffix in _KNOWN_PICKLE_EXTENSIONS and not os.path.isfile(path)` (`pickle_scanner.py:252-254`).
- **S-P2-13.** `can_handle()` three nested `try/except` blocks re-doing extension/sniff checks (`pickle_scanner.py:256-282`). Collapse into one helper.
- **S-P2-14.** `_check_scan_stream_size_limit` always installs a `_path_validation_result` sentinel that `scan_stream` never reads (`pickle_scanner.py:327-338`).
- **S-P2-15.** `_scan_raw_text_indicators` ~50 lines of `if b"X" in lower: indicators.append(("X", b"X", {...}))` (`pickle_scanner.py:451-498`). Table-driven.
- **S-P2-16.** `_read_root_raw_scan_window_from_stream` defensive `isinstance(data, bytes | bytearray | memoryview)` check (`pickle_scanner.py:378`) — `read()` always returns `bytes`.
- **S-P2-17.** `_analyze_cve_patterns` attributes CVE-2026-24747 twice via overlapping code paths (`pickle_scanner.py:638-674`).
- **S-P2-18.** `extract_metadata()` three overlapping read-limit validations (`pickle_scanner.py:706-722`).
- **S-P2-19.** `ALWAYS_DANGEROUS_FUNCTIONS`/`ALWAYS_DANGEROUS_MODULES` Python frozensets duplicate `BUILTIN_DANGEROUS_NAMES`/`DANGEROUS_WILDCARD_MODULES` in Rust `policy.rs`. High drift risk.
- **S-P2-20.** `_LEGACY_NOTICE_RULE_CODES` keys identical to `_INCONCLUSIVE_NOTICE_CODES` (`picklescan_adapter.py:18-42`). Derive one from the other.
- **S-P2-21.** `_parse_min_int` over-defensive for `bool`/`float`/`str` cases that don't happen in practice (`picklescan_adapter.py:76-88`).
- **S-P2-22.** `_legacy_check_name_for_finding` arms for `DANGEROUS_CALL` and `DANGEROUS_GLOBAL` produce the same string (`picklescan_adapter.py:572-578`).
- **S-P2-23.** `_apply_member_context_to_record` final two branches are identical (`picklescan_adapter.py:489-492`).
- **S-P2-24.** `_optional_int` in api.py accepts `str`/`bytes`/`bytearray` but Rust always returns `int` (`api.py:517-524`).
- **S-P2-25.** `scan_stream` uses `"size" in locals()` trick for `BadZipFile` branch (`api.py:120`). Reorder.
- **S-P2-26.** `_combine_pytorch_zip_reports` takes full `list[ZipInfo]` but only uses `len()` (`api.py:295,326`).
- **S-P2-27.** `_parity_corpus.py` lives under `src/modelaudit_picklescan/` and ships in the published wheel. Move to tests-only.

### Docs / CHANGELOG / CI hygiene

- **S-D2-28.** `CHANGELOG.md:8` has no `[Unreleased]` entry for the Rust engine introduction. User-visible architecture change + Python fallback removal deserves explicit callout.
- **S-D2-29.** `CONTRIBUTING.md:24,28` lists `pip install -e .[all]` without noting that a Rust toolchain is required. `CONTRIBUTING.md:105` mentions it but not in the main Prerequisites section.
- **S-D2-30.** `packages/modelaudit-picklescan/pyproject.toml` has no `[project.urls]` block — PyPI page will have no repo/issues/changelog links.
- **S-D2-31.** `docs/maintainers/picklescan-rust-rewrite-plan.md:108-123` describes parity gates as future work even though the rewrite is complete. Misleading.
- **S-D2-32.** `docs/maintainers/picklescan-rust-large-corpus-qa-notes-2026-04-11.md` (+744) and `picklescan-rust-large-corpus-qa-plan.md` (+772) are ephemeral session notes with `/tmp` paths and branch state. Move to `archive/` or link as one-time QA artifacts.
- **S-D2-33.** `uv-lock-check` job (`test.yml:310`) only validates root lock, not the standalone package's `packages/modelaudit-picklescan/uv.lock`.
- **S-D2-34.** Nightly/perf workflows don't run `cargo test` standalone; Rust-only regressions won't page on nightly.
- **S-D2-35.** `release-please.yml:71-86` runs `uv lock` in the standalone package without installing Rust — fragile.
- **S-D2-36.** `.gitignore` coverage of `packages/modelaudit-picklescan/src/modelaudit_picklescan/_rust.*` and `packages/modelaudit-picklescan/target/` should be verified to prevent accidental commits.
- **S-D2-37.** `test_large_pickle_corpus_qa.py` missing `from __future__ import annotations` — inconsistent with sibling files.
- **S-D2-38.** `test_dill_joblib_enhanced.py` and `test_pickle_context_filtering.py` are not in `allowed_test_files` → only run on Python 3.11.
- **S-D2-39.** `test_rust_report_conversion_rejects_non_bool_coverage_flags` lives in `test_rust_engine.py` but doesn't need the Rust extension — gets skipped when extension unavailable.
- **S-D2-40.** `test_scan_file_detects_malicious_pytorch_zip_data_pickle` uses `model.bin` suffix (`test_api.py:330`) instead of canonical `.pt`/`.pth` — implicitly tests `.bin` routing simultaneously.

---

## Proposed remediation order

1. **Block on P-P0-9/10/11/12** (extract_metadata, CVE-2026-24747, .bin tail scan, 100 MB raw read) — largest real detection-surface losses.
2. **Block on R-P0-1/3/4** (NEXT_BUFFER desync, proto-0 encoded probes, fast-reject seed table) — concrete Rust bypasses.
3. **Block on T-P0-24/25/26** (multi-platform wheels, abi3, Docker MSRV) — `pip install modelaudit` will fail for most users post-release.
4. **Block on T-P0-23** (CI lane gap) — `test_api.py` needs to run on 3.10–3.13.
5. **Block on T-P0-17/18** (CVE-2025-32434 metadata regression + comment-token bypass coverage) — AGENTS.md §CVE Detection Checklist compliance.
6. **Follow-up P1 batch**: fix rule-code regressions (P-P0-13, P-P1-48), `_scan_raw_text_indicators` bypasses (P-P1-40), numpy trailing-bytes semantics (P-P0-15), Rust policy sync (P-P1-49), `__main__` severity escalation (QA finding 1).
7. **Non-blocking perf pass**: land a real hot-path skip in `scan()`/`scan_stream()` — after a Rust CRITICAL, shrink or skip the raw detector window. The current PR body's 40–80× speedup claim is not reproducible.
8. **Non-blocking cleanup**: 30 simplification items across Python and Rust; pick the highest-ROI ones (items 4/5/6/15/27 shave the most lines).

---

## Remediation tracker

This section is the active implementation log for follow-up commits after revision 3. Each review item below should be fixed in its own commit with targeted QA recorded here. Historical findings that the table above already marks FIXED are not reopened unless a later item depends on them.

### Active todo

- [x] N-P0-1 — Fix uncaught `ValueError` for non-seekable streams above the raw-read cap.
- [x] N-P0-2 / N-P1-16 — Pass buffered payload size to Rust for non-seekable streams to avoid spurious `short_read`.
- [x] N-P0-3 — Scope documentation/comment gating to the relevant literal or evidence window, not the entire raw detector pass.
- [x] N-P0-4 — Prevent documentation-like `_rebuild_tensor` literals from suppressing real CVE-2026-24747 GLOBAL evidence.
- [x] N-P0-5 — Clamp user-controlled Rust timeout values before `Duration::from_secs_f64`.
- [x] N-P0-6 — Add a clean-Rust hot path that skips expensive raw detectors when full Rust analysis completed cleanly.
- [x] P1-TRIPLE / N-P1-19 — Reduce or explicitly downgrade triple CRITICAL emissions for builtins eval/exec/compile/import aliases.
- [x] P1-PARSE — Decide and document parse-failure suppression semantics, or tighten them.
- [x] P1-EMPTY — Map empty pickle input to a non-CRITICAL operational outcome.
- [x] P1-BINTAIL-SCOPE / N-P1-11 — Broaden binary-tail scan beyond `.bin`.
- [x] P1-SEED-SHAPE / N-P1-14 / N-P1-15 / N-P1-17 / N-P2-23 / N-P2-25 — Tighten and de-duplicate expensive raw-detector seed/shape helpers.
- [x] P1-DUNDER-WALKER — Reduce benign user-dunder false positives.
- [x] P1-NESTED-DEPTH — Raise nested depth or fail closed when nested analysis depth is exhausted.
- [x] T-P1-WHEEL — Add missing macOS x86_64 and Linux aarch64 wheel coverage or document the gap.
- [x] T-P2-COMMENT — Restore missing comment-token bypass regression coverage.
- [x] T-P2-EXPANSION — Restore expansion/memo-growth regression coverage.
- [x] T-P2-STRUCTURAL — Restore structural tamper / duplicate-PROTO regression coverage.
- [x] P2-STALE-PYCACHE — Remove stale `_parity_corpus` pycache artifact or ignore it explicitly.
- [x] P2-NEW-HELPER-DUP — Refactor duplicated text-shape helper loops.
- [x] N-P1-7 — Make `_pickle_opcode_summary` memo-aware instead of clearing the string stack too aggressively.
- [x] N-P1-8 — Widen `_contains_call_token` separator handling.
- [x] N-P1-9 — Add raw-layer pickle GLOBAL newline-form module attribute coverage.
- [x] N-P1-10 / N-P1-12 — Scan binary tails past the 8 MB raw window and after malformed/truncated pickle prefixes.
- [x] N-P1-13 — Preserve stream integrity hashes for streams larger than the raw scan window.
- [x] N-P1-18 — Pin or adjust primary DANGEROUS_CALL rule-code mapping for builtins.
- [x] N-P1-20 — Collapse protocol-5 buffer opcode notices into bounded/count-based notices.
- [x] N-P1-21 — Review `READONLY_BUFFER` empty-stack parity behavior.
- [x] N-P2-22 — Collapse encoded-text S604/S104 twin emissions.
- [x] N-P2-24 — Clean redundant lowercase seed spelling.
- [x] N-P2-26 — Replace remaining `_contains_non_comment_token` guards with scoped documentation analysis.
- [x] N-P2-27 — Add Rust string seeds for joblib/cloudpickle/copyreg.
- [x] N-P2-28 — Add tests for encoded protocol 2-5 prefixes.
- [x] N-P2-29 — Complete escaped-hex protocol-0 prefix table.
- [x] N-P2-30 — Bound `encoded_nested_literal_probe_windows` linear scan cost.
- [x] N-P2-31 — Optimize Rust dangerous-global policy lookup.
- [x] N-P2-32 — Clean stale moved parity-corpus pycache.
- [x] N-P2-33 — Refactor duplicate stream-read helpers.
- [x] N-P0-34 — Bound recursive follow-on pickle probing for pickle-like binary tails.
- [x] R-P0-2 — Preserve integer stack values for `INT`/`LONG` variants.
- [x] R-P1-BUF / R-P1-20 / R-P1-21 — Protocol-5 buffer stack and notice parity follow-up.
- [x] R-P1-27 — Include malformed state in global-reference dedupe.
- [x] R-P1-28 — Push `Other` for missing memo GET/BINGET/LONG_BINGET.
- [x] R-P1-29 — Correct post-budget tail position reporting.
- [x] R-P1-30 — Confirm timeout checks are amortized.
- [x] R-P1-31 — Replace location-string parsing with structured positions where possible.
- [x] R-P1-32 — Expand post-budget dangerous needle table.
- [x] R-P1-33 — Decide/fuzz STACK_GLOBAL byte operand behavior.
- [x] R-P1-34 — Rebuild notice dedupe state if notices are ever coalesced.
- [x] R-P1-38 — Document or raise `DEFAULT_MAX_NESTED_DEPTH`.
- [x] R-P1-39 — Add more Rust unit coverage for dispatch, policy, report, and bridge behavior.
- [ ] R-P2-40 — Decide whether to support embedded-Python cargo tests for `pybridge`; bridge coverage currently runs through Python package tests.
- [x] T-P1-51 / T-P1-52 — Strengthen parity/fuzz tests with expected verdicts.
- [x] T-P1-53 / T-P1-66 — Restore multi-stream regression coverage.
- [x] T-P1-54 — Replace Rust policy source-text tests with functional tests.
- [x] T-P1-55 / T-P1-56 — Strengthen weak negative/overbroad assertions.
- [ ] T-P1-57 — Document BINBYTES text-scan design decision.
- [ ] T-P1-63 — Expand high-risk callable module coverage.
- [ ] T-P1-64 — Add real NEWOBJ_EX end-to-end test coverage.
- [ ] T-P1-65 — Expand EXT1/EXT2/EXT4 extension-registry tests.
- [ ] T-P1-67 — Restore dill load and benign dill-string tests.
- [ ] S-R2-5 / S-R2-6 / S-R2-8 / S-R2-9 / S-R2-10 — Rust readability refactors.
- [ ] S-P2-15 / S-P2-17 / S-P2-18 / S-P2-19 — Python readability/drift refactors.
- [ ] S-D2-29 / S-D2-30 / S-D2-33 / S-D2-34 / S-D2-35 / S-D2-37 / S-D2-38 / S-D2-39 / S-D2-40 — Documentation and CI hygiene follow-ups.

### Completed item QA log

- N-P0-1 — Same-item commit adds a bounded `_RootStreamPayloadRead` result for non-seekable root stream buffering, records truncation metadata, and emits an `S902` warning instead of raising when the stream exceeds the root raw-scan cap. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 30 tests.
  - Manual default-cap repro with a >8 MiB non-seekable pickle stream — no uncaught exception; returned `success=False`, `pickle_stream_truncated_for_root_scan=True`, and `pickle_stream_bytes_buffered=8388608`. The remaining `short_read` CRITICAL is tracked separately by N-P0-2 / N-P1-16.
- N-P0-2 / N-P1-16 — Same-item commit scans truncated non-seekable buffers using the buffered byte count, preserves the original declared size in metadata, and marks the wrapper result inconclusive with `non_seekable_stream_truncated`. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 30 tests.
  - Manual default-cap repro with a >8 MiB non-seekable pickle stream — returned `success=False`, `scan_outcome=inconclusive`, reasons `['pickle_analysis_incomplete', 'non_seekable_stream_truncated']`, no `operational_error_reason`, and zero `short_read` issues.
- R-P1-27 — Same-item commit adds `reference.malformed` to the Rust global-reference dedupe key and records malformed references in the dedupe set without surfacing them as import references. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 26 tests.
- R-P1-28 — Same-item commit verifies the Rust scanner pushes opaque operands for missing `GET`, `BINGET`, and `LONG_BINGET` memo reads instead of synthesizing malformed globals. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 27 tests.
- R-P1-29 — Same-item commit adds a structured `position` detail to post-budget tail findings and pins the precise offset for a pattern found after the tail prefix. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml post_budget_tail_reports_expanded_needles_at_precise_positions` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 27 tests.
- R-P1-30 — Same-item commit verifies `check_limits` skips the clock read between `TIME_CHECK_INTERVAL_OPCODES` boundaries and still times out on the interval boundary. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml timeout_checks_are_amortized_by_opcode_interval` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 28 tests.
- R-P1-31 — Same-item commit removes the brittle `(pos N)` location-string fallback from redundant global coalescing and verifies coalescing only happens when structured `position` details are present. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml global_finding_coalesce_uses_structured_positions_only` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 29 tests.
- R-P1-32 — Same-item commit lifts post-budget dangerous global byte patterns into a named Rust constant and verifies every table entry produces a `POST_BUDGET_GLOBAL` finding after opcode-budget exhaustion. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml post_budget_tail_detects_every_dangerous_pattern` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 30 tests.
- R-P1-33 — Same-item commit keeps the fail-closed decision for `STACK_GLOBAL` byte operands: CPython rejects bytes module/name operands, so Rust reports `MALFORMED_STACK_GLOBAL` instead of reinterpreting bytes as text globals. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml stack_global_rejects_byte_operands_fail_closed` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 31 tests.
- R-P1-34 — Same-item commit adds a notice dedupe-key helper and rebuilds `seen_notice_keys` during finalization so any future notice rewrite/coalescing keeps the dedupe state synchronized. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml notice_dedupe_state_can_be_rebuilt_after_notice_rewrites` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 32 tests.
- R-P1-38 — Same-item commit documents the default `max_nested_depth=2` in the standalone package README and notes the depth/byte budget tradeoff. Targeted QA:
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k default_depth_surfaces_two_layer` — passed, 1 test.
- R-P1-39 — Same-item commit raises Rust unit coverage from 32 to 41 tests, adding direct coverage for opcode parsing/truncation, report detail helpers, `INST`/`OBJ`/`NEWOBJ_EX` dispatch, and bridge behavior through the Python package API. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 41 tests.
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_detects_reduce_invoking_os_system -q` — passed, 1 test.
  - Note: an attempted direct embedded-Python `cargo test` for `pybridge::scan_bytes` failed because the cargo test binary could not initialize Python stdlib encodings in this workspace. Bridge coverage remains in the Python package tests; the embedded-test decision is tracked as R-P2-40.
- T-P1-51 / T-P1-52 — Same-item commit expands `test_rust_engine.py` so deterministic parity payloads, generated malicious/suspicious corpus entries, and full-length malicious prefix-fuzz payloads assert expected verdicts and non-empty findings instead of only asserting "no rust_engine_error". Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run pytest packages/modelaudit-picklescan/tests/test_rust_engine.py -q` — passed, 7 tests.
- T-P1-53 / T-P1-66 — Same-item commit expands standalone multi-stream coverage for 4 KiB null padding, text padding, mark-like padding, malformed-first-stream recovery, high-risk `httplib.HTTPConnection` in a second stream, and benign follow-on streams that must stay finding-free. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "follow_on"` — passed, 8 tests.
  - `uv run pytest tests/benchmarks/test_picklescan_benchmarks.py::test_picklescan_multi_stream_padded_payload -q` — skipped because `pytest_benchmark` is not installed in this environment.
- T-P1-54 — Same-item commit replaces Rust policy source-text regex checks with functional scans for required builtin, wildcard-module, and explicitly listed dangerous globals. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run pytest packages/modelaudit-picklescan/tests/test_rust_engine.py -q` — passed, 20 tests.
- T-P1-55 / T-P1-56 — Same-item commit tightens system-global assertions to exact expected import references: platform-specific `os.system` reduce payloads must report the platform-specific callable, and a literal `cos\nsystem` global-only stream must still report `os.system` while avoiding CVE-2026-24747 SETITEM attribution. Targeted QA:
  - `uv run ruff format tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff format --check tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_scan_malicious_pickle_reports_rust_finding tests/scanners/test_pickle_scanner.py::test_scan_stream_does_not_treat_system_name_as_setitem_cve packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_detects_reduce_invoking_os_system -q` — passed, 3 tests.
- N-P0-3 — Same-item commit removes the global raw-window documentation short-circuit, records documentation-like pickle literal spans, and filters only matches that fall inside documentation spans or comment-like lines. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 31 tests, including the doc-only negative and a doc-padded raw `cposix.system` positive.
- N-P0-4 — Same-item commit teaches `_rebuild_tensor_indicators_are_documentation_literals` to treat real `GLOBAL` and direct `STACK_GLOBAL` rebuild references as non-documentation evidence before applying doc-literal suppression. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 32 tests, including a doc-literal plus real `torch._rebuild_tensor_v2` GLOBAL regression that preserves `primary_cve=CVE-2026-24747`.
- N-P0-5 — Same-item commit clamps `timeout_s` to 24 hours in Python options and Rust `ScanOptions::from_py`, with a defensive Rust `timeout_duration` helper before `Duration::from_secs_f64`. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `uv run ruff format packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/tests/test_options.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/tests/test_options.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/src packages/modelaudit-picklescan/tests/test_options.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_options.py packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 159 tests, including `ScanOptions(timeout_s=1.0e18)` and native `scan_bytes` no-engine-error coverage.
- N-P0-6 — Same-item commit adds `_rust_scan_completed_cleanly` and skips expensive secrets/JIT/network raw detectors only when Rust completed cleanly and the expensive-detector seed set is absent from the bounded raw window. Initial QA showed that skipping on clean Rust alone would regress seeded secret/network findings; the implementation was narrowed before commit. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 32 tests, including low-information clean-pickle skip coverage and seeded secret/network preservation coverage.
- P1-TRIPLE / N-P1-19 — Same-item commit stops emitting the generic `S115` alias as a third failed issue for builtins `eval`/`exec`/`compile`/`__import__` REDUCE findings. The primary legacy rule and `S201` opcode support remain failed checks, while `S115` is preserved in `legacy_rule_aliases` metadata. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q` — passed, 59 tests, including exact `["S104", "S201"]` issue emission and `legacy_rule_aliases=["S115"]` coverage.
- P1-PARSE — Same-item commit documents the intended parse-incomplete tail policy in `CHANGELOG.md` and pins the security boundary with tests: trusted-tail suppression requires a trusted pickle boundary and no dangerous import references; dangerous refs still fail closed with `S901`. Targeted QA:
  - `uv run ruff format tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q` — passed, 61 tests, including UnicodeDecodeError and zero-padding tails with dangerous import references.
- P1-EMPTY — Same-item commit maps standalone `empty_input` errors to `IssueSeverity.INFO` in the ModelAudit adapter while preserving `success=False` and `operational_error_reason=empty_input`. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q` — passed, 62 tests, including empty-input severity and non-critical `has_errors=False` coverage.
- P1-BINTAIL-SCOPE / N-P1-11 — Same-item commit broadens binary-tail signature scanning from `.bin` only to the pickle/PyTorch raw-container extension set. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 33 tests, including a raw `.pt` pickle with trailing ELF bytes.
- P1-SEED-SHAPE / N-P1-14 / N-P1-15 / N-P1-17 / N-P2-23 / N-P2-25 — Same-item commit caches the expensive raw lowercase buffer once, replaces the bare `key` seed with specific key names, narrows generic JIT `def`/`class` seeds, and uses a domain-like dot shape so alpha-only bare domains still trigger network analysis without treating pickle `STOP` as a domain. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 35 tests, including seeded secret/network preservation, bare alpha-only domain detection, and a plain `key` substring skip regression.
- P1-DUNDER-WALKER — Same-item commit narrows Rust `magic method` string findings to dangerous dunder hooks/introspection names and expands the metadata allowlist for common benign dunders. User-defined metadata dunders like `__a__` and `__x_y__` now scan clean, while `__reduce__`/`__getnewargs_ex__` still warn. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 142 tests, including common/user-defined dunder clean regressions.
- P1-NESTED-DEPTH — Same-item commit raises the standalone default nested-pickle depth from 1 to 2 in both Python and Rust options, so two-layer encoded nested payloads are analyzed by default. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 143 tests, including default two-layer base64 nested malicious-payload coverage.
- T-P1-WHEEL — Same-item commit documents the remaining macOS x86_64 and Linux aarch64 wheel gap in the standalone package README, including the sdist/local-Rust fallback. Targeted QA:
  - `git diff --check` — passed.
- T-P2-COMMENT — Same-item commit restores comment-token bypass regressions for `pip.main`, `__main__.*`, `torch.load`, `builtins.eval`, `builtins.exec`, and `dill.loads`, plus a `__main__` `STACK_GLOBAL` warning case. Targeted QA:
  - `uv run ruff format tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff format --check tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 42 tests.
- T-P2-EXPANSION — Initial QA showed the old memo-growth, diluted memo-growth, and DUP-heavy expansion payloads scanned clean under Rust. Same-item commit adds bounded native Rust expansion heuristics, restores the legacy Python check names/rule mapping, preserves the old `post_budget_expansion_scan_limit_bytes` config alias, and restores the six Python-level expansion regressions plus standalone package coverage. Targeted QA:
  - Manual repro for iterative memo growth, diluted memo growth, DUP-heavy, benign shared references, and post-budget expansion tail — confirmed the first three initially scanned clean before the fix.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed after replacing an MSRV-incompatible `Option::inspect`.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 258 tests.
- N-P0-34 — While starting T-P2-STRUCTURAL QA, a valid pickle followed by `XYZNmore-binary-data` repetitions caused unbounded recursive follow-on probing because each synthetic follow-on scan could recursively probe later pickle-like text bytes at the same depth. Same-item commit increments follow-on scan depth, respects `max_nested_depth`, and adds standalone plus root scanner regressions for pickle-like binary tails. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_bounds_follow_on_probe_recursion_for_pickle_like_binary_tail tests/scanners/test_pickle_scanner.py::test_scan_bounds_follow_on_probe_recursion_for_pickle_like_binary_tail -q` — passed, 2 tests.
- T-P2-STRUCTURAL — Same-item commit restores native structural tamper detection for duplicate and misplaced `PROTO` opcodes, maps it back to the legacy `Pickle Structural Tamper Check` / `S902` contract at info severity in ModelAudit, and restores the deleted same-stream, mixed-version, misplaced, second-stream, malicious-plus-tamper, safe-ML, and binary-tail regressions. QA also found that broad follow-on candidates could misclassify ZIP local-header bytes before a real embedded pickle; the implementation now validates follow-on candidates as plausible pickle payloads before recursive scanning. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 16 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py tests/scanners/test_pickle_scanner.py -q` — passed, 206 tests.
- P2-STALE-PYCACHE / N-P2-32 — The stale moved `_parity_corpus.cpython-311.pyc` artifact was local ignored state rather than a tracked file; it was removed from `packages/modelaudit-picklescan/src/modelaudit_picklescan/__pycache__`, and `.gitignore` already ignores `__pycache__/`. Targeted QA:
  - `git ls-files 'packages/modelaudit-picklescan/src/modelaudit_picklescan/__pycache__/*'` — passed, no tracked pycache entries.
  - `find packages/modelaudit-picklescan/src/modelaudit_picklescan -maxdepth 2 -type f -path '*/__pycache__/*' -name '_parity_corpus*.pyc' -print` — passed, no stale parity-corpus pycache remains.
- P2-NEW-HELPER-DUP — Same-item commit replaces the duplicate digit/alpha scan loops in `_has_alnum_secret_shape` and `_has_domain_or_ip_shape` with shared `_has_text_shape(...)`, while preserving the domain-like-dot gate and allowing configured expensive raw windows larger than the default cap to be inspected. Targeted QA:
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 56 tests.
- N-P1-7 — Same-item commit makes `_pickle_opcode_summary` retain a small memo-aware stack for string operands instead of clearing it on structural opcodes. This restores CVE-2026-24747 S209 attribution for protocol 4/5 `STACK_GLOBAL` payloads that memoize module/name strings around ordinary container structure. Targeted QA:
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 57 tests, including a memoized `os.system` `STACK_GLOBAL` regression that emits `S209`.
- N-P1-8 — Same-item commit replaces the raw `eval`/`exec` call-token regex with a bounded byte scanner that accepts control/null separators, Python line continuations, semicolons, hash comments, and short C-style comments before `(` while still respecting documentation spans and identifier boundaries. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 61 tests, including `eval` separated by `\x00`, `\\\n`, `;`, and `/* comment */`.
- N-P1-9 — Same-item commit replaces the three hardcoded protocol-0 `GLOBAL` `system` byte checks with a shared raw protocol-0 GLOBAL reference table covering `system`, `popen`, `os.spawn*`, `commands.*`, and `subprocess.*` newline-form references. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 66 tests, including raw-window assertions for `cos\npopen\n`, `cos\nspawnv\n`, `cposix\npopen\n`, `csubprocess\nPopen\n`, and `ccommands\ngetoutput\n`.
- N-P1-10 / N-P1-12 — Same-item commit decouples file-backed binary-tail scanning from the bounded raw detector window. `scan(path)` now seeks from Rust's first pickle end position, or from a parse-progress fallback with signature-length backtracking when no `STOP` was found, and scans a bounded 1 MiB tail window from the actual file. Stream scans retain the raw-window-only behavior because no full file handle is available. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 68 tests, including an executable tail beyond a 64-byte raw window and an executable tail after a malformed pickle prefix with no `first_pickle_end_pos`.
- N-P1-13 — Same-item commit adds a seekable-stream integrity hashing path that reads the full declared stream in chunks, records the complete SHA-256 hash, and restores the original stream position independent of the bounded raw detector window. Non-seekable streams remain bounded and continue to hash only the buffered payload. Targeted QA:
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 69 tests, including a seekable stream whose full payload is larger than a 64-byte root raw scan window.
- N-P1-18 — Same-item commit pins the intentional adapter contract for builtin `DANGEROUS_CALL` findings: builtin-specific legacy rules remain primary (`eval`/`exec`→`S104`, `compile`→`S105`, `__import__`→`S106`) and `S201` remains a supporting REDUCE opcode issue with `S115` recorded as a metadata alias. Targeted QA:
  - `uv run ruff format tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q` — passed, 66 tests, including all four builtin primary-rule mappings.
- N-P1-20 — Same-item commit changes Rust protocol-5 `NEXT_BUFFER` / `READONLY_BUFFER` notices from one notice per opcode position to one count-based `buffer_opcode` notice per scan, preserving total, `NEXT_BUFFER`, and `READONLY_BUFFER` counts in details. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed after applying `cargo fmt`.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 17 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 151 tests, including Python API coverage for five buffer opcodes collapsing into one notice.
- N-P1-21 — Same-item commit stops treating `READONLY_BUFFER` on an empty stack as if it had pushed an opaque operand. Empty-stack `READONLY_BUFFER` is now counted in the coalesced buffer notice and subsequent malformed `STACK_GLOBAL` previews show both operands as missing. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 18 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_preserves_readonly_buffer_empty_stack_parity packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_collapses_protocol5_buffer_opcode_notices packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 152 tests.
- N-P2-22 — Same-item commit collapses encoded-text twin emissions from separate `S604` and legacy `S104` failed issues into a single `S604` failed issue with `legacy_rule_aliases=["S104"]` metadata. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 69 tests, including an encoded `os.system` payload with exactly one encoded-code issue and no legacy duplicate issue.
- N-P2-24 — Same-item commit replaces the broad lowercased `-----begin ` expensive-detector seed with specific lowercased private-key PEM header seeds, keeping private-key coverage while avoiding a generic certificate/PEM trigger. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 70 tests, including an RSA private-key PEM fixture that still emits `S703`.
- N-P2-26 — Same-item commit removes `_contains_non_comment_token` and routes the remaining importlib/webbrowser raw-text guards through `_contains_non_documentation_token`, so raw matching consistently uses literal-aware documentation spans. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 70 tests.
  - `rg -n "_contains_non_comment_token" modelaudit/scanners/pickle_scanner.py` — passed, no remaining references.
- N-P2-27 — Same-item commit adds Rust fast-reject seeds and suspicious-string patterns for `joblib.load`, `joblib._pickle_load`, `cloudpickle.load(s)`, and `copyreg.add/remove_extension`, so string-literal scanning no longer skips these loader/extension hints. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 19 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_flags_expanded_suspicious_string_patterns packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 155 tests.
- N-P2-28 — Same-item commit adds explicit Rust prefix/window coverage for base64 and hex encoded binary pickle protocol 2, 3, 4, and 5 prefixes, plus Python API coverage for malicious encoded nested pickles across protocols 2-5. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 20 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_detects_binary_protocol_encoded_nested_pickle_mid_literal packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 159 tests.
- N-P2-29 — Same-item commit expands the escaped-hex mid-literal prefix table for protocol-0 pickle starters (`I`, `S`, `V`, `d`, `l`, `i`) in addition to the existing protocol/bare global/list starters. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 21 tests.
- N-P2-30 — Same-item commit bounds the byte-by-byte middle scan in `encoded_nested_literal_probe_windows` to 1 MiB while retaining the existing prefix and suffix probes. This prevents huge benign encoded-looking literals from forcing an unbounded linear scan. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 22 tests, including an in-bound candidate positive and out-of-bound middle candidate negative for the new cap.
- N-P2-31 — Same-item commit replaces the linear `DANGEROUS_GLOBALS.contains(...)` lookup with a binary search over the sorted static table and adds tests that guard the sort invariant plus representative positive/negative lookups. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 24 tests.
- N-P2-33 — Same-item commit extracts the shared bounded chunked stream reader used by seekable raw-window reads and non-seekable root buffering, removing duplicated timeout/interruption/chunk logic while preserving existing stream semantics. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 70 tests.
- R-P0-2 — Same-item commit pins the Rust integer stack-value behavior for protocol-0 text `INT`/`LONG` operands and little-endian `LONG1`/`LONG4` byte operands. The implementation already preserved these paths; this adds direct regression coverage so future parser refactors cannot degrade them back to opaque `Other` values. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 25 tests.
- R-P1-BUF / R-P1-20 / R-P1-21 — Closed by the dedicated protocol-5 buffer commits above:
  - `fix: collapse protocol5 buffer notices` coalesces repeated buffer notices and records total/`NEXT_BUFFER`/`READONLY_BUFFER` counts.
  - `fix: preserve readonly buffer stack parity` keeps normal `NEXT_BUFFER` stack behavior while preventing empty-stack `READONLY_BUFFER` from fabricating an operand.
  - Targeted QA is recorded under N-P1-20 and N-P1-21, including Rust unit tests, native rebuilds, and Python API regressions.

### Newly discovered gaps while remediating

- N-P0-34 — Follow-on stream probing could recurse through pickle-like binary tails; fixed and tracked in the remediation checklist above.
- R-P2-40 — Direct PyO3 `pybridge` cargo tests currently require an embedded-Python initialization strategy; a naive `Python::initialize()` unit test failed with `ModuleNotFoundError: No module named 'encodings'` from the cargo test binary. Keep bridge behavior covered through Python package tests unless/until the Rust test harness sets a reliable Python home/path.

---

## What's working well

- Core opcode parser bounds safety: zero hot-path `unwrap`/`panic`/`expect`.
- All 21 committed exploit fixtures + 2 safe samples → correct verdict.
- Deep-recursion stress, massive-memo stress, post-budget tail evasion all handled gracefully.
- `size=-1` stream bug fix is real and verified (`api.py:535-538`, `pickle_scanner.py:749`).
- `MODELAUDIT_PICKLESCAN_ENGINE` env var + `use_standalone_pickle_primary` flag removal is clean (zero lingering refs).
- Rust `cargo test`, `cargo clippy`, `cargo fmt`, ruff, mypy, pytest all green locally.
- Legacy rule-code alias mapping is mostly correct modulo the three regressions above.
