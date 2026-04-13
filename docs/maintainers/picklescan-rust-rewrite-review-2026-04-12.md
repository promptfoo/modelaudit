# PR #990 Comprehensive Review — `feat: replace picklescan with Rust-native engine`

**Branch:** `mdangelo/codex/rust-picklescan-rewrite` (head `80d72db6`)
**Scope:** +11,792 / −21,408 across 60 files. Rust rewrite of pickle scanner, Python engine removed.

This review combines five specialized agents (Rust core, Python integration, test coverage, CI/packaging, simplification) with hands-on QA on 31 synthetic fixtures and 21 committed exploits. All validation gates passed locally (`pytest` 235 picklescan tests, `cargo test` 12, `ruff`, `mypy`, `clippy`), but behavior testing surfaced real issues.

On the repo's own 21 exploit fixtures and 2 safe samples the scanner is **0 FN / 0 FP**. Issues below are edge-case gaps, severity mismatches, perf claims, and lost coverage.

---

## TL;DR — Must-fix before merge

| # | Where | Issue |
|---|------|-------|
| 1 | `modelaudit/scanners/pickle_scanner.py:731-740` | `extract_metadata()` reports "has REDUCE/BUILD" for any pickle containing byte `R` or `b` — false positive on ~every pickle |
| 2 | `modelaudit/scanners/pickle_scanner.py:638-674` | CVE-2026-24747 heuristic `b"s" in data` is always-true; CVE-2025-32434 metadata (`cvss`, `cwe`, `remediation`) deleted |
| 3 | `modelaudit/scanners/pickle_scanner.py` (absent) | `.bin` tail scan for PE/ELF/Mach-O and binary code signatures **entirely removed** — largest lost detection surface |
| 4 | `modelaudit/scanners/pickle_scanner.py:21,353-378` | Raw-window default is 100 MB, no interrupt/timeout, silently returns `b""` on non-seekable streams |
| 5 | `packages/modelaudit-picklescan/rust/src/state.rs:509` | `NEXT_BUFFER`/`READONLY_BUFFER` treated as no-ops → stack desync vs real unpickler; crafted pickles can flip verdict |
| 6 | `packages/modelaudit-picklescan/rust/src/nested.rs:306` | Encoded-nested probe only sees `gA`/`800`/`\x80` — protocol-0 pickles embedded mid-string are never probed |
| 7 | `packages/modelaudit-picklescan/rust/src/strings.rs:223-282` | Fast-reject seed table missing `runpy`, `popen`, `spawn`, `compile`, `pickle`, `marshal`, `ctypes`, `codecs`, `dill`, `webbrowser`; `OS .system(...)` (space) bypasses |
| 8 | `picklescan_adapter.py:525-543` vs `rule_mapper.py` | `builtins.eval/exec/compile/__import__` now maps to generic `S115` instead of `S104/S105/S106` |
| 9 | `picklescan_adapter.py:391-439` | `_should_suppress_parse_failure_escalation` is broader than old; dropped `has_trusted_pickle_boundary` early-return and benign-imports guard |
| 10 | `tests/conftest.py` + `test.yml:876` | `test_api.py` (primary malware coverage file) only runs on Python 3.12 — not 3.10/3.11/3.13 |
| 11 | `release-please.yml:404` | No multi-platform wheel matrix; mac/arm/win users get sdist → need Rust toolchain → Dockerfile's Debian `cargo 1.63` < MSRV `1.74` (so Docker build also fails) |
| 12 | `Cargo.toml:21` + `pyproject.toml` | No `abi3` bindings → wheel is Python-version-locked; a single linux-x86_64 cp312 wheel is the only published artifact |
| 13 | `tests/scanners/test_pickle_scanner.py` et al | Comment-token bypass regression tests entirely deleted — violates the CVE Detection Checklist in AGENTS.md |
| 14 | CVE-2025-32434 test coverage | No replacement assertion for `cvss/cwe/description/remediation` metadata; may be a silent scanner regression, not just test gap |
| 15 | Benchmark claim in PR body | Not reproducible: 16 MB benign file takes **6.28 s** locally because `_run_root_raw_detectors` is unconditional (no hot-path skip); standalone `scan_bytes` is 10 ms |

---

## QA results (hands-on, 31 fixtures + 21 committed exploits)

### Confirmed true positives
- All 21 `tests/assets/**/*.pkl` exploit fixtures → CRITICAL.
- All 18 synthetic malicious pickles (eval/exec/os.system/subprocess/proto0/2/4/5 variants, PyTorch-ZIP embedded, comment-token bypass, large-middle, truncated) → CRITICAL.
- Nested base64 (1 layer) → CRITICAL with inner REDUCE surfaced.
- `mal_torch_like.pt` → detected via PyTorch-ZIP routing.

### False negatives (severity downgrades)
1. **`__main__.<symbol>` REDUCE chain only WARNING, never CRITICAL.** Tested three shapes (`c__main__\nDanger\n)R.`, `c__main__\nBackdoor\n)R.`, protocol-4 STACK_GLOBAL `__main__.evilfunc`). Rust emits S203 (warning) + legacy-metadata S207 (warning). A `__main__` REDUCE is always dangerous; should be CRITICAL. Current coverage relies on an incidental S310 C&C pattern hit for the message text `backdoor`.
2. **2-level nested base64** → outer layer detected as `S601 Encoded pickle payload detected` CRITICAL, but inner REDUCE is not surfaced. `DEFAULT_MAX_NESTED_DEPTH = 1`; documented in Rust review P1 but worth calling out.
3. **Non-seekable stream silently skips raw-window detectors** (`pickle_scanner.py:371-372`). Any archive member (`zipfile` streams are non-seekable) → `S104/S201/S604` raw rules do nothing. The Rust scan still runs, but the entire secrets/network/CVE layer is skipped with no notice.

### False positives
1. **`importlib # harmless` literal warning** — PR claims to have fixed "comment-only `importlib# ...` text" false positives, but a pickle containing the string `"importlib # harmless"` still emits `S101 Suspicious string literal contains code execution pattern: importlib`. The `contains("importlib")` check in `strings.rs` has no context awareness.
2. **`__version__`-wrapped values flagged as "magic method"** — `strings.rs:27` fires on any literal containing `__` that doesn't exactly match the six allowlisted dunders (`__version__`, `__metadata__`, etc.). Any list/JSON wrapping like `"['__version__']"` or trailing whitespace bypasses the allowlist. HuggingFace model configs will hit this.
3. **Empty file → CRITICAL severity.** `state.rs:420 record_empty_input_error` sets an error with category `empty_input` which the adapter maps to CRITICAL (not `parse_error`). Empty `.pkl` placeholders in data dirs will light up as malware.
4. **Duplicate CRITICAL emissions.** Observed on `mal_large_middle.pkl` (S115 + S201 for same REDUCE at pos 8000078), `mal_nested_b64.pkl` (S604 + S104), `tests/assets/pickles/multiple_stream_attack.pkl` (S115 + S201), and `nt_alias_attack.pkl`/`posix_alias_attack.pkl` (both 2-crit). Same message, same position, two rule codes — one is for the canonical rule, one for the "opcode" rule, both get emitted. Downstream dashboards/counts are inflated.
5. **`rule_mapper returned unknown rule code: S211` stderr noise.** `rule_mapper.get_pickle_opcode_rule_code` returns `S211` for `EXT1/EXT2/EXT4` but `S211` is not registered in `RuleRegistry`. Every scan of a pickle with an extension opcode emits this warning to stderr.
6. **`os.path` ref flagged as CRITICAL S206+S101.** Two criticals for the same reference. Legal pickles don't usually ref `os.path` directly but any ML library that does gets flagged twice.

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

**R-P0-1.** `NEXT_BUFFER`/`READONLY_BUFFER` treated as no-ops (`state.rs:509`). Crafted pickle with `SHORT_BINUNICODE "safe"; NEXT_BUFFER; SHORT_BINUNICODE "anything"; STACK_GLOBAL` can mislead operand resolution. Fix: push an opaque `Other` and flag a suspicious notice when a buffer op appears near STACK_GLOBAL/REDUCE.

**R-P0-2.** `INT`/`LONG`/`LONG1`/`LONG4` push `StackValue::Other` because `stack_value_from_integer_arg` rejects `ArgValue::Text`/`Bytes` (`state.rs:1724` + `opcode.rs:114-163`). Parity gap with old Python engine; breaks `pytorch_storage_key` detection for protocol-2 LONG1 storage sizes and any future integer-aware detection.

**R-P0-3.** `encoded_nested_literal_probe_windows` only matches `gA`/`800`/`\x80` prefixes (`nested.rs:306`). Protocol-0 pickles (starting with `(`, `c`, `d`, `l`, `i`, `I`, `S`, `V`) embedded mid-string are invisible. Add base64 prefixes `KA`/`Y2`/`Y28`/`Yw...` and hex `28`/`63`/`64`.

**R-P0-4.** `suspicious_string_matches` fast-rejects when neither `has_suspicious_ascii_seed` nor `has_base64_dangerous_seed` fires (`strings.rs:12,223`). Seed table missing `runpy`, `popen`, `spawn`, `compile`, `pickle`, `marshal`, `ctypes`, `codecs`, `dill`, `webbrowser`. `OS .system(...)` (trailing space) and `O\x00S.system` bypass entirely. Old Python ran every regex regardless.

**R-P0-5.** `__version__` allowlist is exact-match only (`strings.rs:27`). `"['__version__']"`, `"  __version__"`, `"__version__\n"` trip "magic method" warning. HF configs and pydantic models routinely serialize `__version__` inside lists/dicts.

**R-P0-6.** `EXT1/EXT2/EXT4` → REDUCE combination emits only WARNING severity and marks the global `malformed: true` so REDUCE short-circuits (`state.rs:595`). `_copyreg_extension_reduce_references` in Python backstop catches this only on root ModelAudit path, not standalone. Should raise to CRITICAL when the extension is followed by REDUCE on the stack.

**R-P0-7.** `scan_raw_nested_pickle_bytes` only runs `nested_pickle_probe_offsets` when `value.len() > max_nested_pickle_bytes` (`state.rs:882`). Junk-prefixed nested pickles under the 2 MB default (e.g. `b"\x00\x00JUNK" + malicious_pickle`) are not probed. Run bounded probes for the small-blob case too.

**R-P0-8.** `POP`/`SETITEM`/`APPEND` unconditionally pop `Mark` values (`state.rs:542`). A malformed `MARK; APPEND` pops the mark and silently desyncs the stack for subsequent `POP_MARK`/`TUPLE`/`LIST`. Check popped value and push back if `Mark`.

### Python integration

**P-P0-9.** `extract_metadata()` uses naive byte-substring checks (`pickle_scanner.py:731-740`):
```python
if b"R" in payload: dangerous_opcodes.append("REDUCE")
if b"b" in payload: dangerous_opcodes.append("BUILD")
```
Any pickle containing the ASCII `R` or `b` reports "has REDUCE/BUILD" — effectively all pickles. Old code walked opcodes via `pickletools.genops` tracking 8 dangerous opcodes (REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX, STACK_GLOBAL, GLOBAL, BUILD) and exposed `opcode_counts`, `total_opcodes`, `pickle_protocol`.

**P-P0-10.** CVE-2026-24747 fallback heuristic: `b"_rebuild_tensor" in data and b"s" in data` (`pickle_scanner.py:638-656`). `b"s"` is always true → CVE attributed to every PyTorch checkpoint. Companion heuristic `(b"os" or b"posix" or b"nt") and b"system"` has the same issue.

**P-P0-11.** `.bin` tail scanning **entirely removed.** Old `_scan_binary_content`/`_scan_remaining_bin_tail_if_needed` scanned bytes past `first_pickle_end_pos` for PE/ELF/Mach-O/shell/PowerShell signatures and `eval`/`exec`/`os.system`/`subprocess`/`__import__` binary substrings with rule codes S101, S103, S104, S501, S502, S503, S504, S506. New wrapper has none of this. Largest single detection-surface reduction in the PR.

**P-P0-12.** Root raw-window reads up to 100 MB synchronously without interrupt/timeout (`pickle_scanner.py:21,353-359`). Old code bounded to 8 KB in 1 KB chunks with `check_interrupted()`/`_check_timeout()` per chunk. Transient RSS ~200 MB per large pickle, unkillable from Ctrl-C during raw detector passes.

**P-P0-13.** `builtins.eval/exec/compile/__import__` rule-code regression (`picklescan_adapter.py:525-543`). Legacy rule codes S104 (eval/exec), S105 (compile), S106 (__import__) now collapse to generic S115 because the builtins branch is checked before opcode/import mapping. Test at `test_picklescan_adapter.py:315` acknowledges and pins the new behavior. `_add_legacy_supporting_finding_checks` does not add S104/S105/S106 as supporting checks. Dashboards filtering by rule code will see this regression.

**P-P0-14.** `_should_suppress_parse_failure_escalation` dropped guards (`picklescan_adapter.py:391-439`):
- No longer early-returns when `has_trusted_pickle_boundary is False`.
- `UnicodeDecodeError` suppression used to require extension in `{.bin, .pkl, .pickle}` AND `_has_only_non_dangerous_import_references()`. Now any `UnicodeDecodeError` with trusted boundary is suppressed regardless of extension/refs.
- `.joblib "opcode b'\x00' unknown"` suppression used to require trusted boundary AND benign imports. Now broadens to `{.pkl, .pickle, .joblib, .dill}` and drops the benign-imports check.
Net effect: weaker fail-closed posture on analysis-incomplete scans.

**P-P0-15.** `numpy_scanner.py` trailing-bytes branch semantics changed (`numpy_scanner.py:45-55,394-396`). Inline `_finish_with_inconclusive_contract` now just `result.finish(success=default_success)` with `default_success=False` at line 395. Old helper flipped to `success=True` when embedded-pickle security findings existed. Net effect: a malicious object-dtype NumPy array with trailing bytes now flips completed-with-findings scans into `success=False` → exit-code regression.

**P-P0-16.** CVE attribution hardcoded to S310 (`pickle_scanner.py:673,696`). S310 is the network/C&C rule. Old mapped CVE patterns to S101/S103/S104/S105/S106/S115 per `attr.patterns_matched`. Also missing `cve_risk_score` metadata because `enhance_scan_result_with_cve` is no longer called.

### Tests / CI / packaging

**T-P0-17.** **CVE-2025-32434 metadata regression.** Old asserted `cvss == 9.8`, `cwe == "CWE-502"`, description mentions `weights_only=True`, remediation mentions `PyTorch 2.6.0` on REDUCE warnings in `.pt` files. Zero hits across new test files for these strings. The Rust engine does not emit these CVE detail fields at all, so this is likely a silent scanner regression, not just a test gap.

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

## What's working well

- Core opcode parser bounds safety: zero hot-path `unwrap`/`panic`/`expect`.
- All 21 committed exploit fixtures + 2 safe samples → correct verdict.
- Deep-recursion stress, massive-memo stress, post-budget tail evasion all handled gracefully.
- `size=-1` stream bug fix is real and verified (`api.py:535-538`, `pickle_scanner.py:749`).
- `MODELAUDIT_PICKLESCAN_ENGINE` env var + `use_standalone_pickle_primary` flag removal is clean (zero lingering refs).
- Rust `cargo test`, `cargo clippy`, `cargo fmt`, ruff, mypy, pytest all green locally.
- Legacy rule-code alias mapping is mostly correct modulo the three regressions above.
