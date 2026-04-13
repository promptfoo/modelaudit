# PR #990 Comprehensive Review — `feat: replace picklescan with Rust-native engine`

**Branch:** `mdangelo/codex/rust-picklescan-rewrite`
**Latest audited:** `22b2d0df` (rev 5: `fix: close picklescan follow-up review items`, +542/−89 across 14 files)
**Scope:** Rust rewrite of pickle scanner, Python engine removed.

This review combines five specialized agents (Rust core, Python integration, test coverage, CI/packaging, simplification), three Momus/Oracle critical re-reviews, and hands-on QA on 31 synthetic fixtures + 21 committed exploits. **At rev 5, validation gates are partially regressed**: `cargo test` **46 passed**, `ruff`/`mypy`/`clippy` clean — but **`pytest packages/modelaudit-picklescan/tests/test_api.py` has 10 FAILING tests** and the broader suite has **4 additional regressions** in numpy/joblib scanners. All 14 are real implementation gaps that landed with `22b2d0df` itself (test files added without the corresponding Rust/Python wiring, or behavior changes that broke consumer tests).

On the repo's own 21 exploit fixtures and 2 safe samples the scanner is **0 FN / 0 FP** across every revision.

> **Rev 5 release-readiness verdict: NOT READY.** 14 test failures + 1 confirmed exploitable PERSID nested-pickle bypass + 2 P0 release-mechanics issues (no manylinux wheels, release-please can't bump the standalone package). Detailed list below.

## Revision history

> **Rev 5 (current)**: Re-audit at `22b2d0df` after `fix: close picklescan follow-up review items`. **Closed** P2-DIRECTORY-ERROR-SEVERITY (now INFO), P2-PROTO6-FORWARD-COMPAT (proto 6 magic recognized), P2-OVERSIZED-FRAME-NOT-FLAGGED (record_oversized_frame_notice added but the Rust→Python notice path is broken — see N5-FRAME-NOTICE), P2-WHEEL-MATRIX-INCOMPLETE (macos-15-intel + ubuntu-24.04-arm jobs added). **Surfaced** 14 test failures, 1 exploitable PERSID nested bypass, 2 P0 release-mechanics blockers, 21 P1 Rust correctness gaps, 6 P1 Python integration gaps, and ~30 P2 hygiene items. Details in **Rev 5 — new findings** section below.
>
> **Rev 4** (`1f087343`): Re-audit after 80 hardening commits + follow-up. Closed nearly all rev 3 N-P0/N-P1/N-P2 items. Confirmed P1-NESTED-DIVERGENCE / P2-CONFIRMED-SEEDS / P2-WHEEL-MATRIX / P2-DIRECTORY-SEVERITY / P2-PROTO6 / P2-OVERSIZED-FRAME as remaining residuals.
>
> **Rev 3** (`c6e5d677`): Re-audit after hardening commit `060f73b3`. ~35 of ~50 prior findings fixed. Added 30 new oracle findings (N-P0-1..6, N-P1-7..21, N-P2-22..33).
>
> **Rev 2** (`c215cf70`): Momus critical pass. Withdrew T-P0-17 (CVE-2025-32434 lives in `pytorch_zip_scanner.py`, not pickle scanner). Downgraded R-P0-1 (`NEXT_BUFFER`) to R-P1-BUF pending PoC. Narrowed wording on R-P0-3, R-P0-7, P-P0-10, P-P0-13. Added P-P1-42a (systematic S201+S104 double-emission) and P-P1-42b (`S211` unregistered).
>
> **Rev 1** (`02712463`): initial 5-agent review + QA. Flagged ~150 items across P0/P1/P2.
>
> **Rev 2** (`c215cf70`): Momus critical pass. Withdrew T-P0-17 (CVE-2025-32434 lives in `pytorch_zip_scanner.py`, not pickle scanner). Downgraded R-P0-1 (`NEXT_BUFFER`) to R-P1-BUF pending PoC. Narrowed wording on R-P0-3, R-P0-7, P-P0-10, P-P0-13. Added P-P1-42a (systematic S201+S104 double-emission) and P-P1-42b (`S211` unregistered).
>
> **Rev 3** (`c6e5d677`): Re-audit after hardening commit `060f73b3`. ~35 of ~50 prior findings fixed. Added 30 new oracle findings (N-P0-1..6, N-P1-7..21, N-P2-22..33).
>
> **Rev 4 (current)**: Re-audit after 80 additional commits (rev-3 follow-up tracker in `aba2c4d7 docs: add picklescan review remediation tracker`). **Nearly every N-P0 / N-P1 / N-P2 finding from rev 3 is now fixed.** 106 new pytest cases added, 27 new cargo tests. Remaining residuals are intentional severity-divergence between standalone and adapter paths (nested-benign downgrade), plus a handful of seed-check tightenings. One new surface surfaced around standalone-vs-adapter verdict divergence for `S213` benign-nested findings, but this is a documented design choice.

**Rev 4 hands-on QA (re-run after 80 follow-up commits):**

| Case | Rev 1 | Rev 3 | Rev 4 |
| --- | --- | --- | --- |
| pytest count | 235 | 264 | **370** |
| cargo test count | 12 | 15 | **42** |
| 16 MB benign literal scan | 6.28 s | 0.65 s | **0.53 s** |
| 16 MB malicious-middle scan | 6.22 s | 0.68 s | **0.58 s** |
| Standalone 16 MB scan_bytes | 10 ms | 10 ms | **10 ms** |
| Empty file severity | CRITICAL | CRITICAL | **INFO** |
| `builtins.eval` REDUCE: total issues | 2 (S115+S201) | 3 (S104+S201+S115) | **2 (S104+S201)** with S115 alias in details metadata |
| `N-P0-1`: scan_stream non-seekable > 8 MB | would silently bypass | **uncaught ValueError** | **success=False + S902 "Non-seekable exceeded bounded read"** |
| `N-P0-2`: non-seekable truncated → `short_read` CRITICAL | — | **spurious CRITICAL** | **no spurious critical** (passes `len(payload)` to Rust) |
| `N-P0-3`: global `#` suppression attack | — | **bypassed raw layer** | **per-literal span gating** → Rust still catches |
| `N-P0-4`: CVE-2026-24747 GLOBAL+doc suppression | — | **attribution lost** | **S209 still fires via opcode summary** |
| `N-P0-5`: `Duration::from_secs_f64(1e18)` panic | — | **panic crashes process** | **clamped; returns status=complete** |
| `N-P0-6`: hot-path skip on clean Rust | — | — | **`_should_skip_expensive_raw_detectors`** + `_rust_scan_completed_cleanly` + shape checks |
| `N-P1-7`: opcode summary memo tracking | — | **lost on structural opcodes** | **memo-aware walker** |
| `N-P1-8`: call-token separator bypass (`\x00(`, `\\\n(`) | — | missed | **all caught** |
| `N-P1-10/11/12`: binary tail scan scope | **`.bin` only, 8 MB cap, no truncated tail** | — | **`_PYTORCH_CONTAINER_EXTENSIONS`, file-seek past cap, bytes_scanned fallback** |
| `N-P1-13`: stream integrity hash for > 8 MB | — | **dropped** | **`_add_seekable_stream_integrity_check` + `_add_stream_integrity_check`** |
| `N-P1-14`: `_has_domain_or_ip_shape` alpha-only | — | returned False | **`_has_domain_like_dot` enforces alnum.alnum** |
| `N-P1-17`: `_contains_any_seed` per-call lowercase | — | 3× copy | **`_contains_any_seed_lowered` with cached view** |
| `N-P1-19`: triple critical emission | — | S104+S201+S115 | **S104+S201** (S115 in details.legacy_rule_aliases) |
| `N-P1-20`: buffer-op notice spam | — | N per pickle | **single counter notice via `emit_buffer_opcode_notice`** |
| `N-P2-22`: encoded-text S604+S104 twin | — | present | collapsed via `_legacy_rule_aliases` metadata |
| `N-P2-23`: bare `b"key"` seed | — | in list | **replaced with `api_key`, `secret_key`, `private_key`** |
| `N-P2-25`: `b"def "`, `b"class "` JIT seeds | — | too broad | **tightened to `def main`, `class meta`** |
| `N-P2-26`: `_contains_non_comment_token` remnants | — | 3 callers | **replaced with `_contains_non_documentation_token` + spans** |
| `N-P2-27`: Rust seed table gaps | — | joblib/cloudpickle/copyreg missing | **all added** |
| `N-P2-29`: escape-hex prefix completeness | — | 3 prefixes | **10 prefixes (`\x80/\x28/\x63/\x64/\x6c/\x6C/\x69/\x49/\x53/\x56`)** |
| `N-P2-31`: `DANGEROUS_GLOBALS` O(n) lookup | — | linear | **sorted + binary search, sort-order test** |
| `T-P0-19` expansion heuristics tests | deleted | deleted | **restored** (memo_growth, dup_heavy, diluted, benign baseline) |
| `T-P0-21` structural tamper tests | deleted | deleted | **restored** (duplicate PROTO, misplaced PROTO, binary-tail negative) |
| `T-P0-18` comment-token bypass: pip.main/__main__.Evil/torch.load/eval/exec/dill.loads | deleted | partial | **all six covered via parametrize** |
| T-P0-22 binary tail PE/ELF/Mach-O tests | deleted | 3 tests | **3 tests + `.pt/.pth/.ckpt` coverage** |
| Expansion + structural tamper Rust findings | absent | absent | **`PICKLE_EXPANSION` (line 1710) + `STRUCTURAL_TAMPER` (lines 1576/1613)** |
| 21 repo exploit fixtures | 21/21 | 21/21 | **24/24** (3 new malicious samples now detected) |
| 6 repo safe fixtures | 6/6 | 6/6 | **6/6** |
| `simple_nested.pkl` (benign dict inside outer) | — | — | **standalone=MALICIOUS CRITICAL S213, adapter=INFO S213** (benign-nested downgrade, see **P1-NESTED-DIVERGENCE** below) |

**Rev 3 hands-on QA (rev-3 snapshot):**

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

## Rev 5 — new findings (REV 5 IS NOT MERGE-READY)

After re-pulling at `22b2d0df` and re-running validation gates, **`pytest packages/modelaudit-picklescan/tests/test_api.py` produces 10 failures** and the broader pickle suite produces 4 additional regressions. These landed *with* the `fix: close picklescan follow-up review items` commit — the author added the test files and the documentation but several Rust/Python wirings are incomplete or out of sync.

### **N5-CRITICAL-RCE-BYPASS** — post-budget tail produces UNKNOWN for non-needle dangerous globals (validated end-to-end)

This is the most important finding in any revision of this review. **A 9 MB pickle that calls `subprocess.run(['echo', 'PWNED'])` produces `verdict=unknown, status=inconclusive, findings=0, criticals=0, warnings=0` from both the standalone `modelaudit_picklescan.scan_bytes()` and the full `modelaudit.scanners.pickle_scanner.PickleScanner().scan()` paths.** I executed the payload with `pickle.loads()` and confirmed it actually runs the subprocess and prints `PWNED` to stdout. Scanner reports only an INFO `opcode_budget` notice. CI policies that fail only on CRITICAL or WARNING let this through.

**Reproduction (validated by running `pickle.loads(mal)` in a sandbox):**
```python
import pickle, subprocess
class Evil:
    def __reduce__(self):
        return (subprocess.run, (['echo', 'PWNED'],))
header = b'\x80\x04'
filler = b'\x880' * 4_500_000          # 9 MB of NEWTRUE/POP — exhausts 1 M opcode budget
evil_bytes = pickle.dumps(Evil(), protocol=4)
mal = header + filler + evil_bytes[2:]  # skip duplicate proto

# Validation:
from modelaudit_picklescan import scan_bytes
r = scan_bytes(mal)
assert r.verdict.value == 'unknown'    # NOT MALICIOUS
assert len(r.findings) == 0            # ZERO findings

result = pickle.loads(mal)
# → CompletedProcess(args=['echo', 'PWNED'], returncode=0)
# → 'PWNED' printed to stdout
```

**Root cause:** `scan_post_budget_tail` (`packages/modelaudit-picklescan/rust/src/state.rs:1968`) reads up to 100 MB of tail bytes after the opcode budget is exhausted, but only matches the **24 hardcoded needles** in `POST_BUDGET_DANGEROUS_GLOBAL_PATTERNS` at `state.rs:57-83`. Confirmed missing from the needle table by hand-testing each:

| Tail global | Detected? |
|---|---|
| `csubprocess\nrun` | ❌ verdict=unknown |
| `csubprocess\ncheck_call` | ❌ verdict=unknown |
| `cimportlib\nreload` | ❌ verdict=unknown |
| `c__main__\n<symbol>` | ❌ verdict=unknown |
| `cos\npopen` | ⚠️ verdict=suspicious (warning, not critical) |
| `cctypes\nCDLL` | ⚠️ verdict=suspicious (warning, not critical) |

The Python belt-and-suspenders raw detector `_scan_raw_text_indicators` (`pickle_scanner.py:1341`) only runs on `data` capped at `_ROOT_RAW_SCAN_LIMIT_BYTES = 8 MB` (`pickle_scanner.py:24,1769`), so the tail at offset 9 000 003 is past that window — never seen. The full ModelAudit `PickleScanner().scan()` path on this payload returns:
```
success=False
total issues: 1
crits: 0  warns: 0
sev=info rule=S902 msg=Opcode analysis stopped after reaching max_opcodes=1000000
```

**Severity escalation gap (F2 from security agent):** Even when the needle table DOES match (e.g., `cos\nsystem\n...R.` past budget), the finding is hardcoded `severity: "warning"` at `state.rs:1997-2020` — never CRITICAL, even when followed immediately by a REDUCE-class byte. CI policies of "fail only on CRITICAL" let `os.system('id')` past budget through.

**Timeout exhaustion bypass (F3):** `LimitError::Timeout` at `state.rs:480-501` only emits a timeout notice and does NOT call `scan_post_budget_tail`. An attacker can craft any pickle that takes longer than `options.timeout_s` to parse (deep MARK nesting, large LONG4 buffers) and the post-budget tail scan is **completely skipped**. Default timeout is 3600 s but ModelAudit CI/CD configs often set lower.

**Required fix (one commit, three changes in `state.rs`):**
1. Generate `POST_BUDGET_DANGEROUS_GLOBAL_PATTERNS` from `policy.rs:DANGEROUS_WILDCARD_MODULES` + `DANGEROUS_GLOBALS` instead of hardcoding 24 needles.
2. Promote `POST_BUDGET_GLOBAL` to `severity: "critical"` when the matched needle is followed by a REDUCE-class byte (`R`/`o`/`b`/`\x81`/`\x92`) within ~64 bytes.
3. Call `scan_post_budget_tail` from the timeout branch too.

**This is a P0 RCE-bypass merge blocker. The PR cannot be merged until N5-CRITICAL-RCE-BYPASS is resolved.**

### Test failures landed at `22b2d0df` (CI would block the merge today)

**N5-FAIL-1.** `test_scan_bytes_records_oversized_frame_notice` (`packages/modelaudit-picklescan/tests/test_api.py:1897`). The Rust `record_oversized_frame_notice` exists at `state.rs:1674-1716` and a cargo-test `oversized_frame_lengths_emit_structural_notice` at `state.rs:3370` confirms it works inside Rust. But via the PyO3 boundary, `scan_bytes(b"\x80\x04\x95\xfe\xff\xff\xff\xff\xff\xff\xff}.")` returns `len(notices) == 0` and the test errors with `StopIteration`. Either the FRAME branch in `record_structural_opcode` (`state.rs:1596-1599`) is being skipped for some reason in the production build but not in the cargo test, or `add_notice` is deduping it against an unrelated key. Reproduction is one-line; my hands-on QA confirmed `notices == 0` for `frame_len=16`, `frame_len=255`, and `frame_len=u64::MAX-1`. **Real implementation gap, not just a test bug.**

**N5-FAIL-2..8.** Seven `test_scan_bytes_records_data_only_*_nested_pickle_*_as_notices` tests in `test_api.py:1426-1707`. They expect benign nested pickles (no execution opcode in the inner) to surface as **NOTICES** (`code="nested_payload_detected"`, `verdict=clean`, `findings=()`). Reality: the standalone `scan_bytes` still returns `verdict=malicious` with an `S213` finding for `pickle.dumps({'outer': pickle.dumps({'inner': 'data'})})`. The Rust code at `state.rs:1406-1419` does have the right "if not analysis_incomplete and not nested_has_execution_opcode → notice" branch, but in practice `nested_has_execution_opcode` is being computed as `True` (or the path isn't reached). The author wrote tests for a behavior that the underlying state machine doesn't deliver yet. **8 failures from the same root cause.**

**N5-FAIL-9.** `test_scan_bytes_applies_nested_byte_budget_after_unescaping_hex_literals` expects `verdict=clean` for a hex-encoded benign nested pickle that exceeds the budget; reality returns `malicious`. Same root cause as N5-FAIL-2..8.

**N5-FAIL-10.** `test_scan_bytes_still_checks_bounded_encoded_nested_windows_for_truncated_literals` expects `verdict=unknown` for a truncated literal containing a partial encoded pickle; reality returns `malicious`. Same root cause.

**N5-FAIL-11.** `tests/scanners/test_numpy_scanner.py::test_object_dtype_numpy_recurses_into_pickle_exec` asserts `any(issue.rule_code == "S115" for issue in result.issues)`. Reality emits `S104` + `S201` only — the S115 alias was moved to `details.legacy_rule_aliases` per N-P1-19 / `24e97188 fix: collapse builtin pickle alias issue noise`. The author landed the collapse but did not update the consuming numpy test. **Test out of sync with the code change in the same review cycle.**

**N5-FAIL-12.** `tests/scanners/test_joblib_scanner.py::test_joblib_scanner_preserves_legacy_pickle_rule_codes_on_embedded_pickle` asserts `any(issue.rule_code == "S310" for issue in supply_chain_result.issues)`. Reality emits `S201` (the new mapping). The legacy `S310` (network/C&C) mapping was dropped. Test was not updated. **Same shape as N5-FAIL-11.**

**N5-FAIL-13/14.** Two more `tests/scanners/test_*.py` failures in the broader suite (xdist stopped at 4 failures, didn't enumerate). Need a follow-up `--maxfail=20` run to enumerate.

### Confirmed exploitable detection bypass

**N5-EXPLOIT-PERSID-NESTED.** `looks_like_pickle_payload` in `nested.rs:101-126` validates a candidate via `validate_pickle_stack_effect` for every opcode. Lines 213 and 267 of `nested.rs` handle `BINPERSID` and have a catch-all `_ => { *stack_depth += 1; true }`, so PERSID *parses*. But **`pickle_payload_extent` at line 122 returns `Some(index)` only if `stack_depth > 0` at STOP**. For a pickle ending `GLOBAL os.system → PERSID → STOP`:
- After `GLOBAL`, stack_depth = 1 (catch-all `_ => +1`)
- After `PERSID`, stack_depth = 2 (catch-all `_ => +1`) — but PERSID's *real* semantics in CPython is "pop the stream-id arg, push the resolved persistent_id object", which is *net zero* on the stack, not net +1.
- The mismatch means `pickle_payload_extent` walks past STOP with the wrong stack height and returns `Some(extent)` only by coincidence.

What I actually verified empirically with a 24-byte payload:
```python
inner = b'\x80\x04cos\nsystem\nP\nfake_id\n.'
outer = pickle.dumps({'inner': inner})
scan_bytes(outer)  # → verdict=clean, findings=0, notices=0
scan_bytes(inner)  # → verdict=malicious, findings=2 (DANGEROUS_GLOBAL + PERSISTENT_ID)
```

`scan_bytes(inner)` finds the dangerous global directly, but **`scan_bytes(outer)` returns clean — neither a nested-payload finding nor a nested-payload notice**. The outer scanner doesn't recognize the SHORT_BINBYTES blob as a nested pickle because the validator/extent function rejects PERSID-containing pickles, so the inner is never recursed into. Comparison vs other opcodes I tested:

| Inner opcode chain | standalone | wrapped |
|---|---|---|
| `INST __main__.Evil` | malicious | **malicious** ✓ |
| `OBJ dill.loads` | malicious | **malicious** ✓ |
| `GLOBAL os.system + PUT + STOP` | malicious | **malicious** ✓ |
| `GLOBAL os.system + STOP` | malicious | **malicious** ✓ |
| `GLOBAL + NEWOBJ + STOP` | malicious | **malicious** ✓ |
| `GLOBAL + PERSID + STOP` | malicious | **clean** ✗ |
| `BINPERSID after GLOBAL` | malicious | **malicious** ✓ (BINPERSID is binary, no `\n` parsing issue) |
| `PERSID + GLOBAL` (order swap) | malicious | **malicious** ✓ |

PERSID specifically as the LAST executable opcode before STOP is uniquely bypassed. Concrete remediation: ensure `validate_pickle_stack_effect` models PERSID's real net-zero semantics (pops the line-text id, pushes the resolved object → net zero, not +1), OR add `"PERSID" => *stack_depth += 1; true` explicitly with a comment that documents the parser's intentional simplification, OR have `has_execution_opcode` (line 128) treat PERSID as execution. Either way, the inner DANGEROUS_GLOBAL must reach the outer report.

### Release-mechanics blockers (Test/CI agent)

**N5-P0-WHEEL-MANYLINUX.** `release-please.yml:421` builds the Linux wheel via plain `uv build` on `ubuntu-latest` (Ubuntu 24.04 = GLIBC 2.39). Grep for `manylinux` / `cibuildwheel` / `auditwheel` across the workflow and `packages/modelaudit-picklescan/{pyproject.toml,Cargo.toml}` returns **zero hits**. Maturin produces a wheel tagged with the runner's native GLIBC, **PyPI rejects non-manylinux Linux wheels at upload time**. The new `ubuntu-24.04-arm` aarch64 job has the same problem. The `pypa/gh-action-pypi-publish` step at `release-please.yml:571-575` will fail at upload time. Fix: build inside `quay.io/pypa/manylinux_2_28_x86_64` / `quay.io/pypa/manylinux_2_28_aarch64`, or use `PyO3/maturin-action@v1 manylinux: 2_28`, or pass `--compatibility manylinux_2_28` to maturin.

**N5-P0-RELEASE-PLEASE-EXTRA-FILES-MARKERS.** `release-please-config.json:27-38` declares the standalone package's `pyproject.toml` and `Cargo.toml` as `type: "generic"` extra-files. Generic-type extra-files only bump lines carrying an `x-release-please-version` annotation. Grep both files for `release-please-version` / `x-release-please` returns **zero hits**. Result: release-please will silently leave the standalone package at `0.1.0` forever, regardless of conventional commits touching the package. The dependency pin `modelaudit-picklescan>=0.1.0,<0.2.0` will keep resolving the stale wheel. Fix: add `# x-release-please-version` inline markers next to the version lines, or switch to `type: "toml"` with jsonpath `$.package.version` for `Cargo.toml` and `type: "python"` for `pyproject.toml`.

### High-impact P1 from Rust audit (ad112afbd9e15d72b not yet returned, security-fuzz a0776fb9c2a2c45d7 not yet returned — Rust core a718effb059c03c1a returned with these)

**N5-R1.** `EMPTY_LIST` / `EMPTY_DICT` / `EMPTY_SET` push `StackValue::Primitive { type_name: "tuple", repr: "()" }` (`state.rs:733-737`). Any `MALFORMED_STACK_GLOBAL` finding that quotes such an operand misreports the type as `tuple` in `module_operand` / `name_operand` details. Cosmetic-but-visible bug. Fix: emit `("list","[]")` / `("dict","{}")` / `("set","set()")` per type.

**N5-R2.** `scan_raw_nested_pickle_bytes` truncation branch (`state.rs:1250-1260`) only fires when `probe.first() == Some(&0x80)`. Proto-0 nested pickles (start with `(`/`c`/`d`/`l`/`i`/`I`/`S`/`V`) packed into a SHORT_BINBYTES that exceeds `max_nested_pickle_bytes` produce **neither a finding nor a notice** — silent drop. Combined with N5-EXPLOIT-PERSID-NESTED, this is the second silent-drop path in `scan_raw_nested_pickle_bytes`. Drop the `0x80` constraint and rely on `has_pickle_prefix`.

**N5-R3.** `contains_call_like` in `strings.rs:508-521` lacks left-word-boundary check. `contains_call_like("recompile(x)", "compile") → true`. HF Transformers configs containing `recompile`, `decompile_tree`, `subprocess_eval_guard` etc. will trip false-positive SUSPICIOUS_STRING. Verify `start == 0` or `lower.as_bytes()[start - 1]` is not a Python word char.

**N5-R10.** `has_execution_opcode` in `nested.rs:128-147` doesn't include PERSID/BINPERSID. This drives the benign-nested downgrade: an attacker can construct a nested pickle that contains a dangerous GLOBAL followed by PERSID, and the adapter downgrades to INFO via `_is_benign_nested_payload_detection`. Same root cause as N5-EXPLOIT-PERSID-NESTED above.

**N5-R11.** `consume_top_operands` (`state.rs:1068-1084`) clears the *entire* stack on operand underflow. CPython would raise `IndexError` — not wipe state. A multi-stream pickle where an earlier stream left items on the stack will desync mid-stream and silently mis-attribute the malicious REDUCE on the SECOND stream to the first stream's byte position. Pop only the available count or push back if insufficient.

**N5-R13.** `collapse_top_n` (`state.rs:1007-1020`) can wrap a `StackValue::Mark` inside a `Tuple` when an attacker emits `MARK; TUPLE1`. The Mark is now hidden inside a Tuple and subsequent `POP_MARK` over-pops. Test `values[0]` for Mark and bail.

**N5-R15.** `INST` opcode operand resolution in `state.rs:1036-1048` round-trips `module` and `name` through `format!("{} {}", module, name)` and `splitn(2, ' ')`. A pickle with a space in the module name (impossible in real Python but reachable in a malformed pickle) splits incorrectly. Carry module/name as separate fields or use `\n` separator (which is what CPython's INST serialization actually uses).

**N5-R17.** `scan_follow_on_pickle_streams` increments `nested_depth` for sibling follow-on streams (`state.rs:2068-2076`). A multi-stream pickle is *not* a nested payload — sharing `nested_depth` means an attacker can use multi-stream padding to exhaust the nested-depth budget before the real nested payload is reached. Pass `self.nested_depth` unchanged.

**N5-R18.** `import_references` accumulates without a hard cap (`state.rs:1491-1498`). Bounded by the opcode budget but still up to ~500 MB heap if 1 M distinct globals. Add a 10k entry cap + `import_references_truncated` notice.

**N5-R19.** Mid-string proto-0 hex prefix table accepts lowercase `\x` only (`nested.rs:351-362`). A payload using uppercase `\X80` slips past mid-string detection. Low-impact (CPython and most encoders use lowercase) but still a parity gap.

### Security/fuzzing audit — additional findings (a0776fb9c2a2c45d7)

The security agent's primary finding is N5-CRITICAL-RCE-BYPASS above. Additional items:

**N5-SEC-F4.** `STRUCTURAL_TAMPER` unconditional INFO downgrade (`picklescan_adapter.py:189-190`). Same as N5-PY1-3 from the integration audit — Rust emits at WARNING, adapter rewrites to INFO. Two independent agents flagged this. Fix: remove the unconditional downgrade.

**N5-SEC-F5.** Multi-line wrapping bypasses `encoded_nested_literal_probe_windows` (`nested.rs:308-341, 443-461`). A base64-encoded pickle wrapped in `# this is doc\n# <b64>\n# more` is reported `verdict=clean`. Same `b64` on a single line is correctly detected as MALICIOUS. Defense-in-depth gap for downstream code that base64-decodes string fields after stripping comment prefixes (HF metadata loaders, config preprocessors). Fix: strip ASCII whitespace and `#` line-leaders before re-attempting `is_base64_candidate`, or run `base64_tokens` over the literal.

**N5-SEC-F6.** `_pickle_opcode_summary` memo PUT/MEMOIZE collision with CPython (`pickle_scanner.py:705-715`). After `PUT 5` followed by `MEMOIZE`, CPython stores at slot 1 (`len(memo) == 1`), but the Python summary stores at slot 6 (`max(0, 5+1)`). Subsequent BINGET 1 then resolves wrong in the summary. Affects metadata-only paths (CVE attribution at line 1453, dangerous-globals listing); Rust verdict is unaffected. Fix: track memo as a dict and use `len(memo)` as the next implicit index.

**N5-SEC-F7.** `find_module_attr` lacks left word boundary (`strings.rs:523-559`). `find_module_attr("foos.system(...)")` matches `os.system`. False positive (suspicious-string verdict downgrade), not exploit. Verified: `pickle.dumps('foos.system("id")') → SUSPICIOUS`. Fix: left-boundary check at line 532.

**N5-SEC-F8.** `EMPTY_LIST/EMPTY_DICT/EMPTY_SET` push wrong `type_name="tuple"` (`state.rs:733-738`). Cosmetic — only affects `operand_preview` output in MALFORMED_STACK_GLOBAL details. Same as N5-R1 from the Rust audit. Two agents flagged this independently.

**N5-SEC-F9.** `record_persistent_id` always emits WARNING with per-position dedupe (`state.rs:1559-1568`). A pickle with 10 000 PERSID opcodes emits 10 000 deduped WARNINGs. The buffer-opcode notice was collapsed in N-P1-20; PERSID was not. Fix: track first PERSID position + counter, emit a single notice with `persistent_id_count`.

### Verified-already-mitigated by the security agent (good news)

The security agent confirmed these defenses are working at rev 5:
- PyTorch ZIP multi-`data.pkl` → all members enumerated and scanned.
- `SHORT_BINSTRING`/`BINSTRING` as STACK_GLOBAL operand → caught.
- Memo PUT/GET reuse for STACK_GLOBAL → correctly tracked.
- Multi-stream pickle → outer scan re-enters after STOP.
- `getattr(o, 'system')`/`getattr(o, 'spawn')`/`getattr(o, 'run')` → all caught.
- NEXT_BUFFER stack desync attack → forces MALFORMED_STACK_GLOBAL critical.
- 1-deep encoded nested via `pickle.dumps({'x': base64(pickle(Evil()))})` → CRITICAL.
- 2-deep nested → inner REDUCE still surfaced (`DEFAULT_MAX_NESTED_DEPTH = 2`).
- Symlink to `/etc/passwd` → graceful parse error.
- Truncated pickle without STOP → REDUCE detected before parse error.
- FRAME announcing wrong length → parser ignores length, walks opcodes.
- `__main__.<symbol>` REDUCE → CRITICAL.

### Hands-on QA for security agent's claims

Probed independently of the security agent:
- **URL-encoded payload** (`%63%6f%73...` decodes to `cos\nsystem\n)R.`): wrapped → clean. Scanner doesn't decode URL escapes. Defense-in-depth gap.
- **zlib-compressed inner pickle**: wrapped → clean. Scanner doesn't decompress zlib content. Known limitation.
- **Module name with leading dot** `.evil`: clean. Not a real Python module name.
- **Module name with NUL byte**: clean. CPython rejects at import time.
- **Empty module name**: clean. CPython rejects.
- **Dotted name in single string** `os.system`: malicious ✓ (correctly caught).
- **REDUCE on tuple** (callable is a tuple): clean. CPython would TypeError.
- **PyTorch ZIP with `custom.pkl` member**: malicious ✓.
- **PyTorch ZIP with double `data.pkl`**: malicious ✓.
- **`.txt` file with `\x80\x04` prefix**: malicious ✓ (magic-byte sniffing routes correctly).
- **Symlink to /etc/passwd**: verdict=unknown (parses as text).
- **Recursive symlink (self-loop)**: verdict=unknown (no crash).
- **Long filename (255 chars)**: clean (handled).
- **NEXT_BUFFER spam (100 buffer ops)**: collapsed to 1 notice ✓.

### High-impact P1 from Python integration audit (ad112afbd9e15d72b)

**N5-PY1-1.** **Non-seekable scan_stream silently truncates known-size streams past 8 MB.** `pickle_scanner.py:1031-1049`. When `scan_stream(file_obj, file_size=N)` is called on a non-seekable stream with `N > 8 MB` (default `_ROOT_RAW_SCAN_LIMIT_BYTES`), `_read_stream_payload_for_root` caps the read at 8 MB and passes the prefix to standalone with `rust_stream_size=8MB`. Rust then emits `verdict=clean status=complete` for the truncated prefix because from its perspective it saw a complete 8 MB stream. A WARNING S902 truncation check IS emitted, so the outcome is WARNING + "clean" — not CRITICAL. **Detection asymmetry**: identical pickle content scanned via seekable stream returns full findings, via non-seekable stream returns only 8 MB worth. `ZipExtFile`, HTTP bodies, pipes routinely hit the non-seekable path. Fix: buffer the declared size to a `SpooledTemporaryFile` matching standalone's own semantics, or raise the cap when `file_size` is known.

**N5-PY1-2.** **`scan_stream` binary-tail scan bounded to 8 MB raw window with no file-level fallback.** `pickle_scanner.py:1205-1212, 1713-1718`. When `first_pickle_end_pos > 8 MB` (a `.pt` file with a 20 MB pickle followed by a trailing PE), `tail_start` is past the raw window → `tail = b""` → silent no-op. Only `scan(path)` uses `_scan_file_binary_tail_if_needed` which reads from disk past the window. PyTorchZipScanner, JoblibScanner, ExecuTorchScanner, NumPyScanner all call `scan_stream` and lose binary-tail detection for pickle content > 8 MB.

**N5-PY1-3.** **`STRUCTURAL_TAMPER` severity unconditionally downgraded WARNING→INFO in adapter.** `picklescan_adapter.py:189-190`:
```python
if finding.rule_code == "STRUCTURAL_TAMPER":
    severity = IssueSeverity.INFO
```
Rust emits these findings with `severity: "warning"` (`state.rs:1622,1659`). The adapter flattens them. **Standalone-vs-adapter severity divergence**: standalone reports WARNING for parser-differential tampering, ModelAudit reports INFO. Dashboards filtering `severity >= WARNING` will not see these tamper signals at all. Same class as the now-resolved P1-NESTED-DIVERGENCE. Fix: remove the downgrade and let Rust's warning severity flow through.

**N5-PY1-4.** **Non-seekable unbounded streams (`file_size=None`) silently cap at 8 MB without truncation notice.** `pickle_scanner.py:1040,1047`. When `file_size is None`, `_read_stream_payload_for_root`'s truncation check `file_size is not None and ...` is False regardless of whether the stream had more data. `_add_stream_truncation_check` early-returns on `not read_result.truncated` → no warning emitted. The stream is silently cut at 8 MB. Rev-3 N-P0-1 fixed the known-size case; the unknown-size case has the same failure mode. Fix: probe `file_obj.read(1)` after reading `read_target` bytes to detect more data.

**N5-PY1-5.** **`_legacy_rule_code_for_finding` returns `None` for `DANGEROUS_GLOBAL` with unknown module.** `picklescan_adapter.py:536-560`. A `DANGEROUS_GLOBAL` on an uncommon third-party module (e.g., `dill.load_session`, `my_custom_module.ExecShell`) where opcode mapping doesn't exist and import-rule-code mapping doesn't apply results in `rule_code=None` on the Issue. Downstream consumers filtering by rule code lose visibility. Fix: fall back to `S206` or a dedicated catchall.

**N5-PY1-6.** **Standalone `scan_stream` with known `size` has no absolute DoS ceiling.** `api.py:592-622`, `options.py:13`. The `max_unbounded_stream_read_bytes` option only bounds the `size is None` branch. When `size` is provided, the function reads the full declared size into a `SpooledTemporaryFile`. A caller passing `size=100*1024**3` with a cooperative stream gets 100 GB buffered. The adapter's `_check_scan_stream_size_limit` guards this via `max_file_read_size`, but **standalone users without the adapter have no guard**. Fix: add `max_known_stream_read_bytes` ceiling to `ScanOptions`.

**N5-PY1-7.** **Standalone `_read_stream_payload` raises `_StreamShortReadError` and discards already-read bytes.** `api.py:611-619, 66-74`. When `size=N` is declared but the stream ends early (e.g., a ZIP manifest reporting 10000 bytes when the member contains 800), `_read_stream_payload` raises with bytes already in hand. `scan_stream` converts it to `status=ERROR category=short_read` **with the partial bytes discarded**. The 800 bytes already read are never scanned by Rust. **Exploitable**: a malicious archive with a truncated member but a lying manifest can hide a REDUCE in the first 800 bytes.

**N5-PY1-8.** **PyTorch ZIP member streaming discards partial content on any `Exception`.** `api.py:186-205`. The `except Exception` inside the member loop catches `_StreamShortReadError` and returns an `io_error` report with `bytes_scanned=0`. Combined with N5-PY1-7, a crafted ZIP with a lying ZipInfo manifest is a reliable way to suppress member scanning.

**N5-PY1-9.** **`_should_suppress_parse_failure_escalation` treats empty `import_references` as benign.** `picklescan_adapter.py:480-484, 396-446`. `_has_no_or_only_benign_serialization_tail_imports` returns True when `import_references` is empty/missing. A `.bin`/`.pkl` file that ParseErrors on `\x00` zero-padding before any imports were extracted, with `first_pickle_end_pos >= 0`, will silently suppress parse-failure escalation. Fail-closed depends on `report.has_security_findings` catching the case — works for findings emitted before the ParseError but not for pickles that error on byte 10 with no prior findings.

**N5-PY1-10.** **`_pickle_opcode_summary` walker ignores `SETITEM/SETITEMS/TUPLE/REDUCE/BUILD` stack effects.** `pickle_scanner.py:663-772`. The walker tracks STRING pushes, MEMOIZE/PUT/GET memo slots, GLOBAL, STACK_GLOBAL, POP, and a handful of constants. Does NOT handle TUPLE/TUPLE1/TUPLE2/TUPLE3, LIST, DICT, APPEND, APPENDS, SETITEM, SETITEMS, POP_MARK, DUP, REDUCE. Any pickle using these between MEMOIZE and STACK_GLOBAL (very common in protocol 4/5) has stack desync → missed `dangerous_globals` entry → CVE-2026-24747 S209 attribution at line 1577-1597 fails to fire. Rev-4's `d401c018 memo-aware walker` only addressed memo tracking, not stack-effect tracking. Fix: drive CVE attribution off Rust's `dangerous_globals` metadata directly rather than running a parallel Python walker.

**N5-PY1-11.** **`_rebuild_tensor_indicators_are_documentation_literals` walker is memo-unaware.** `pickle_scanner.py:775-812`. Same class of bug as N5-PY1-10. Hard to actually exploit (any literal containing "_rebuild_tensor" that is NOT doc-like returns False), but the walker is not a faithful model of the pickle VM and could be defeated by a sophisticated attacker.

### High-impact P1 from Test/CI audit (a49b92155ae2d21ed)

**N5-P1-HOT-PATH-DEFEATED-BY-TORCH-SEED.** `_JIT_SCAN_SEEDS` at `pickle_scanner.py:206-222` includes `b"torch"`, `b"eval"`, `b"http"`. **Every realistic PyTorch checkpoint contains the substring `torch`** as part of `torch.nn.Module`, `torch.FloatStorage`, etc. The hot-path skip at `pickle_scanner.py:947-960` then never short-circuits on PyTorch state dicts. **Verified empirically**: a 1.8 MB pickle of `{f"torch.layer.{i}.weight": i / 100.0 for i in range(50000)}` runs **0.89 s** with `pickle_expensive_raw_detectors_skipped=None`. The advertised hot-path skip works only on synthetic `b"A"*N` literals, not real ML pickles. Drop `b"torch"` (already covered by `b"torchscript"` and `b"torch."` is implied but not checked) and tighten `b"http"` to `b"http://"` / `b"https://"`. **The realistic perf claim from rev 4 (16 MB benign = 0.53 s) does not generalize to actual model files.**

**N5-P1-SARIF-DUPLICATE-FINDINGS.** SARIF formatter at `modelaudit/integrations/sarif_formatter.py` does not filter `details.supporting_rule_code=True` rows. Every `builtins.eval/exec/compile/__import__` REDUCE emits two SARIF results (S104 primary + S201 supporting), both at `level: "error"`, identical location/message. Downstream consumers (GitHub Code Scanning, CodeQL, Defender) double-count critical issues for every malicious payload. Fix: filter `details.supporting_rule_code` in the SARIF emitter.

**N5-P1-SARIF-NO-PICKLESCAN-RULE-COVERAGE.** Grep `tests/integrations/test_sarif_formatter.py` for `S209|S211|S212|S213|S601|S604|S902|STRUCTURAL_TAMPER|PICKLE_EXPANSION` returns **zero hits**. The new rule codes have no SARIF output regression coverage. A future refactor that drops `rule_code` from picklescan adapter findings would silently emit `"ruleId": "unknown"` to SARIF.

**N5-P1-DEAD-ADAPTER-NESTED-DOWNGRADE.** `_is_benign_nested_payload_detection` at `picklescan_adapter.py:378-393` is dead code under the current Rust scanner — Rust now emits notices directly for benign nested payloads (`state.rs:1406-1419`). The adapter helper still runs on every finding. Two problems: (1) confusing maintainers about which layer owns the invariant, (2) if a future Rust change re-emits a benign-nested finding through a new path, the adapter will silently swallow it to INFO. Delete the helper + its call site.

**N5-P1-RULE-CODE-CONFLATION-S902.** `picklescan_adapter.py:586-589` maps both `PICKLE_EXPANSION` and `STRUCTURAL_TAMPER` to legacy `S902 "Corrupted file structure"` (severity LOW). `PICKLE_EXPANSION` is a billion-laughs DoS class, not a corruption class. Dashboards filtering by S902 for corruption will misclassify expansion attacks; dashboards looking for DoS won't find them. Register `S214` for pickle DoS or route `PICKLE_EXPANSION` to `S213`.

**N5-P1-DOCKER-SINGLE-STAGE.** `Dockerfile` and `Dockerfile.full` still use a single-stage build. The `apt-get purge --auto-remove` cleanup is cosmetic and leaves leftover `~/.cache/cargo` and `apt` cache in the layer. Multi-stage build (`FROM ... AS builder` → build wheel → `COPY --from=builder /wheel.whl`) would produce a much smaller runtime image with zero Rust toolchain.

### P2 hygiene from Test/CI audit (subset)

- **N5-P2-PACKAGE-CHANGELOG-THIN**: `packages/modelaudit-picklescan/CHANGELOG.md:8-15` has only 2 bullets for the entire 0.1.0 debut. PyPI users will see this as the first-release story. Mirror the 70+ root CHANGELOG entries for the rewrite.
- **N5-P2-CHANGELOG-RULE-CODES**: root `CHANGELOG.md` `[Unreleased]` mentions zero of the new rule codes (S209/S211/S212/S213/S601/S604/S902/STRUCTURAL_TAMPER/PICKLE_EXPANSION). Add a "Rule codes" subsection.
- **N5-P2-PYPROJECT-URLS-CHANGELOG**: `packages/modelaudit-picklescan/pyproject.toml:37` `Changelog` URL points at the **root** CHANGELOG, not `packages/modelaudit-picklescan/CHANGELOG.md`. PyPI users clicking the link see root-modelaudit entries.
- **N5-P2-DOCKERFILE-RUST-VERSION-DRIFT**: `Dockerfile:16` and `Dockerfile.full:23` hardcode `--default-toolchain 1.74.1`. Add a comment "keep in sync with packages/modelaudit-picklescan/Cargo.toml rust-version" or compute from Cargo.toml at build time.
- **N5-P2-PICKLESCAN-PACKAGE-CARGO-TEST-ORDERING**: in `test.yml:926-949`, pytest runs before cargo test. A failed pytest masks any Rust dispatch regression that only `cargo test` would catch. Reorder.

### From hands-on QA at rev 5

- **`empty.pkl`** — now INFO ✅ (was CRITICAL at rev 4).
- **proto 6 magic** — now recognized ✅ (no `S901` file-type-validation FP at rev 4).
- **directory scan** — now INFO ✅ (was CRITICAL at rev 4).
- **realistic HF pickle (10 MB) with `auto_map`/`api_key`/`use_auth_token` keys** — still **1.25 s**, expensive detectors NOT skipped. P2-CONFIRMED-SEEDS-INFLATE-EXPENSIVE persists from rev 4.
- **realistic state dict (1.8 MB) with `torch.layer.X.weight` keys** — **0.89 s**, expensive detectors NOT skipped (N5-P1-HOT-PATH-DEFEATED-BY-TORCH-SEED).
- **lightweight Rust opcode parser fuzz** — 9000 random/mutation/opcode-prefix inputs, **0 crashes**.
- **concurrent scan stress** — 16 parallel threads, 0 errors, 8/8 mal correct, 8/8 ben correct.
- **PERSID nested-pickle bypass** — 24-byte `pickle.dumps({'inner': b'\x80\x04cos\nsystem\nP\nfake_id\n.'})` returns `verdict=clean, findings=0, notices=0` (N5-EXPLOIT-PERSID-NESTED).
- **21 committed exploit fixtures** — 21/21 detected ✅. **24 broader corpus** with 1 false-FN (`simple_nested.pkl`, but verified the inner is genuinely benign per the design — adapter downgrade is intentional).

### Rev 5 release-readiness checklist

| Status | Severity | Item |
|---|---|---|
| ❌ | **P0 RCE BYPASS** | **N5-CRITICAL-RCE-BYPASS** — `subprocess.run` past 1M opcode budget = clean verdict, validated end-to-end with `pickle.loads()` printing PWNED |
| ❌ | P0 RCE BYPASS | N5-EXPLOIT-PERSID-NESTED — 24-byte PERSID nested pickle bypasses recursion |
| ❌ | P0 release | N5-P0-WHEEL-MANYLINUX — no manylinux build; PyPI rejects upload |
| ❌ | P0 release | N5-P0-RELEASE-PLEASE-EXTRA-FILES-MARKERS — standalone package never auto-bumps |
| ❌ | P0 test | 10 `test_api.py` failures (N5-FAIL-1..10) |
| ❌ | P0 test | 2 numpy/joblib regressions (N5-FAIL-11..12) — tests not updated for rev-4 collapse |
| ❌ | P0 test | 2 unenumerated `tests/scanners/test_*.py` failures (N5-FAIL-13/14) |
| ❌ | P1 | N5-SEC-F2 — POST_BUDGET_GLOBAL severity hardcoded WARNING even with REDUCE proximity |
| ❌ | P1 | N5-SEC-F3 — timeout exhaustion skips post-budget tail entirely |
| ❌ | P1 | N5-PY1-3 / N5-SEC-F4 — STRUCTURAL_TAMPER unconditionally downgraded WARNING→INFO (flagged by 2 agents independently) |
| ❌ | P1 | N5-PY1-1/2/4 — non-seekable scan_stream silently truncates / loses binary tail / unbounded streams cap silently |
| ❌ | P1 | N5-PY1-7/8 — `_StreamShortReadError` discards already-read bytes; ZIP member streaming discards on Exception |
| ❌ | P1 | N5-PY1-10 — `_pickle_opcode_summary` walker ignores SETITEM/TUPLE/REDUCE stack effects |
| ❌ | P1 | N5-P1-HOT-PATH-DEFEATED-BY-TORCH-SEED — `b"torch"` defeats hot-path skip on every PyTorch checkpoint (verified empirically) |
| ❌ | P1 | N5-P1-SARIF-DUPLICATE-FINDINGS — SARIF emits duplicate primary+supporting rows |
| ❌ | P1 | N5-P1-SARIF-NO-PICKLESCAN-RULE-COVERAGE — zero SARIF tests for new rule codes |
| ❌ | P1 | N5-P1-DEAD-ADAPTER-NESTED-DOWNGRADE — dead adapter code |
| ❌ | P1 | N5-P1-RULE-CODE-CONFLATION-S902 — PICKLE_EXPANSION mis-classified as corruption |
| ❌ | P1 | 21 P1 Rust correctness/parity gaps (N5-R1..R20) |
| ❌ | P1 | N5-SEC-F5 — multi-line wrapped base64 nested pickles bypass |
| ✅ | — | All five rev-4 residuals confirmed FIXED (empty.pkl INFO, proto 6 recognized, directory severity INFO, wheel matrix expanded, oversized FRAME notice path added — though the path is broken at the PyO3 boundary, see N5-FAIL-1) |

**Verdict: PR is NOT MERGE READY.** N5-CRITICAL-RCE-BYPASS is a confirmed end-to-end RCE bypass that the scanner reports as `verdict=unknown, findings=0`. An attacker who pads a pickle with cheap opcodes past the 1 M-opcode budget can hide ANY dangerous global not in the hardcoded `POST_BUDGET_DANGEROUS_GLOBAL_PATTERNS` table — including `subprocess.run`, `subprocess.check_call`, `importlib.reload`, `__main__.*`, `os.execv*`, and most of the `DANGEROUS_WILDCARD_MODULES` policy table.

**Required before merge:**
1. **N5-CRITICAL-RCE-BYPASS** + N5-SEC-F2 + N5-SEC-F3 — generate the post-budget needle list from `policy.rs`, promote to CRITICAL on REDUCE proximity, scan tail on timeout.
2. **N5-EXPLOIT-PERSID-NESTED** — model PERSID stack semantics correctly in `validate_pickle_stack_effect` OR add PERSID to `has_execution_opcode`.
3. **N5-FAIL-1..14** — fix the 14 test failures (10 wiring gaps + 4 consumer test updates).
4. **N5-P0-WHEEL-MANYLINUX** + **N5-P0-RELEASE-PLEASE-EXTRA-FILES-MARKERS** — release-mechanics.

**Strongly recommended before merge:**
5. N5-PY1-1..10 (scan_stream truncation/binary-tail/walker gaps).
6. N5-P1-HOT-PATH-DEFEATED-BY-TORCH-SEED (perf claim doesn't generalize).
7. N5-P1-SARIF-* (duplicate findings + zero rule-code regression coverage).

The remaining N5-R* / N5-SEC-F4..F9 / N5-P2-* items can be follow-up PRs.

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

## Rev 4 — audit of 80 follow-up commits

Rev 4 lands 80 commits (`aba2c4d7`..`84bb76f3`) explicitly tracking and closing rev-3 findings. Summary of verification:

### FIXED in rev 4 (verified via QA + code read)

All six N-P0 regressions from rev 3:
- **N-P0-1** ✅ `scan_stream` non-seekable > 8 MB now emits WARNING S902 + parse_incomplete notice + `success=False`, no exception escape. Verified with `NonSeekable(pickle.dumps({'pad': b'A'*10_000_000, 'evil': Evil()}))` → 3 issues, no crash.
- **N-P0-2** ✅ Non-seekable truncated branch now passes `len(payload)` to Rust (`pickle_scanner.py:1691`), preventing spurious `short_read` CRITICAL.
- **N-P0-3** ✅ `_is_primarily_documentation` + `_documentation_literal_spans` + `_contains_non_documentation_token` now scope doc gating per-literal span rather than globally. The `{'a': '# line\n' * 64, 'evil': Evil()}` attack still surfaces both S201 REDUCE and S209 CVE-2026-24747 CRITICAL.
- **N-P0-4** ✅ CVE-2026-24747 attribution preserved via the opcode-aware `_pickle_opcode_summary`. A doc-literal + GLOBAL `torch._rebuild_tensor_v2` + REDUCE combo still emits S209 CRITICAL (`366bce83 fix: preserve rebuild tensor CVE attribution`).
- **N-P0-5** ✅ `Duration::from_secs_f64(timeout_s)` is now clamped (`3a68e10b fix: clamp pickle scan timeout values`). Verified with `ScanOptions(timeout_s=1e18)` → status=complete, no panic.
- **N-P0-6** ✅ Hot-path skip is now implemented (`111d0ae7 perf: skip expensive raw scans for clean pickles`). `_should_skip_expensive_raw_detectors` combines `result.has_errors`, `_rust_scan_completed_cleanly(result)`, and shape checks. A 16 MB benign scan drops from 0.65 s → **0.53 s**; metadata includes `pickle_expensive_raw_detectors_skipped=True` for cleanly-scanned benign inputs.

All fifteen N-P1 findings:
- **N-P1-7** ✅ `_pickle_opcode_summary` now memo-aware (`d401c018 fix: make pickle opcode summary memo-aware`).
- **N-P1-8** ✅ `_contains_call_token` regex widened to catch `eval\x00(`, `eval\\\n(`, `eval;(`, `eval/*c*/(` (`2d4f4510 fix: widen raw eval call token matching`).
- **N-P1-9** ✅ `_RAW_PICKLE_GLOBAL_REFERENCES` + `_contains_pickle_global_reference` added for `cos\npopen\n`, `cposix\npopen\n`, etc. (`070db8ab fix: cover protocol0 raw global references`).
- **N-P1-10** ✅ `_scan_file_binary_tail_if_needed` reads file-tail past raw window (`a96cf894 fix: scan file-backed pickle binary tails`).
- **N-P1-11** ✅ Binary tail gate now `_PYTORCH_CONTAINER_EXTENSIONS` (`.bin/.pt/.pth/.ckpt/.pkl`) (`492f752e fix: scan pickle tails for raw checkpoint extensions`).
- **N-P1-12** ✅ `_binary_tail_start` falls back to `bytes_scanned` when `first_pickle_end_pos` missing (same commit).
- **N-P1-13** ✅ `_add_seekable_stream_integrity_check` + `_add_stream_integrity_check` both hash the full payload (`f748a862 fix: hash full seekable pickle streams`).
- **N-P1-14** ✅ `_has_domain_like_dot` enforces alnum.alnum (`2a0be1ea refactor: share pickle raw text shape checks`).
- **N-P1-17** ✅ `_contains_any_seed_lowered` takes a pre-lowercased view; the caller lowercases once per scan (same commit).
- **N-P1-18** ✅ `_legacy_rule_code_for_finding` mapping preserved with explicit fall-through + test pinned at `test_picklescan_adapter.py:315` (`235a7b84 test: pin builtin pickle rule aliases`).
- **N-P1-19** ✅ Triple S104+S201+S115 → now S104+S201 + `details.legacy_rule_aliases=["S115"]` metadata (`24e97188 fix: collapse builtin pickle alias issue noise`).
- **N-P1-20** ✅ `emit_buffer_opcode_notice` emits one counter notice per pickle via `first_buffer_opcode_position` + counts (`eea97769 fix: collapse protocol5 buffer notices`).
- **N-P1-21** ✅ `READONLY_BUFFER` on non-empty stack is now a no-op (`5074c786 fix: preserve readonly buffer stack parity`).

All twelve N-P2 findings:
- **N-P2-22** ✅ Encoded-text S604+S104 twin collapsed (`2fb96b3a fix: collapse encoded raw code aliases`).
- **N-P2-23** ✅ Bare `b"key"` replaced with `api_key`, `secret_key`, `private_key`.
- **N-P2-24** ✅ `-----begin ` split into specific PEM types (`ff71ae0a chore: tighten pickle secret pem seeds`).
- **N-P2-25** ✅ `b"def "` → `b"def main"`, `b"class "` → `b"class meta"`.
- **N-P2-26** ✅ `_contains_non_comment_token` replaced everywhere with `_contains_non_documentation_token` + spans.
- **N-P2-27** ✅ Rust seed table adds `joblib`, `cloudpickle`, `copyreg` via case-insensitive walks (`8062c195 fix: scan pickle loader string literals`).
- **N-P2-28** ✅ Proto-0 base64/hex prefix tests in place (`f355dba3 test: cover encoded binary pickle protocols`).
- **N-P2-29** ✅ Escape-hex prefix table completed (`ab100d86 fix: complete escaped hex pickle prefixes`): `\x80/\x28/\x63/\x64/\x6c/\x6C/\x69/\x49/\x53/\x56`.
- **N-P2-30** ✅ `encoded_nested_literal_probe_windows` bounded (`1f533fac perf: bound encoded pickle window scans`).
- **N-P2-31** ✅ `DANGEROUS_GLOBALS` sorted + binary search + sort-order test (`1930f0cd perf: binary search dangerous globals`).
- **N-P2-32** ✅ Stale `.pyc` cleanup documented (`3762238d docs: close stale picklescan pycache item`).
- **N-P2-33** ✅ `_read_stream_payload_for_root` / `_read_root_raw_scan_window_from_stream` share `_read_stream_payload_into_buffer` (`14dcfd38 refactor: share pickle stream reads`).

Rev 3 residuals that were also addressed:
- **P1-EMPTY** ✅ `record_empty_input_error` now emits `severity: "info"` in Rust (`3238e144 fix: downgrade empty pickle input severity`). Verified: `empty.pkl` → 1 INFO issue, no CRITICAL.
- **P1-DUNDER-WALKER** ✅ Benign user dunders now recognized via `2a5c6dd4 fix: reduce benign dunder pickle string warnings` (allowlist widened; unit tests cover the path).
- **P1-NESTED-DEPTH** ✅ `DEFAULT_MAX_NESTED_DEPTH` raised (`0af41f95 fix: increase default nested pickle depth`) with explicit notice when the cap is hit.
- **P1-SEED-SHAPE** ✅ `_has_domain_like_dot` tightens the "any digit + any letter + dot" heuristic (`1d63cd81 perf: tighten pickle raw detector prefilters`).
- **P1-BINTAIL-SCOPE** ✅ Binary tail scan now gates on `_PYTORCH_CONTAINER_EXTENSIONS`.
- **T-P0-19** ✅ Expansion heuristics restored (`0d902e02 fix: restore pickle expansion heuristics`).
- **T-P0-20** ✅ Post-budget deep scan coverage expanded (`795de4e5 test: cover post-budget dangerous patterns`, `36d85a53`).
- **T-P0-21** ✅ Structural tamper tests restored (`4a3694cd fix: restore pickle structural tamper checks`).
- **T-P0-22** ✅ Binary-tail PE/ELF/Mach-O tests restored.
- **T-P0-18** ✅ Comment-token bypass parametrize covers pip.main, __main__.Evil, torch.load, builtins.eval, builtins.exec, dill.loads (`637ee3f5 test: restore picklescan comment bypass coverage`).
- **T-P1-63** ✅ Missing module callables added via `63da82a5 test: expand high risk pickle callables`.
- **T-P1-65** ✅ EXT coverage expanded (`713f4c01 test: expand copyreg extension coverage`).
- **T-P1-66** ✅ Multi-stream coverage restored (`6a14794a test: restore picklescan multistream coverage`).
- **T-P1-67** ✅ Dill loader coverage restored (`bad01876 test: restore dill loader coverage`).
- **T-P1-51/52/54** ✅ Rust parity verdicts strengthened (`508f8082`), policy checks made functional (`53e0a980`).
- **T-P1-58** ✅ release-please component tracking added.
- **T-P1-62** ✅ Multi-stage Docker build + rust install cleanup.
- **S-D2-28..36** ✅ CHANGELOG, CONTRIBUTING, rewrite plan docs updated.

### Remaining open items at rev 4

> Follow-up note (2026-04-13): items in this rev-4 list were re-checked and closed in the active follow-up tracker below as A-P1-70 through A-P2-79. The historical text is retained for auditability; current QA evidence is in the completed-item log.

**P1-NESTED-DIVERGENCE.** Standalone `modelaudit_picklescan.scan_bytes` reports a benign nested pickle (`{'outer_data': 'legitimate', 'inner_pickle': <bytes of pickle({'malicious': 'data'})>}`) as `verdict=malicious` / S213 CRITICAL, but the ModelAudit adapter downgrades it to INFO via `_is_benign_nested_payload_detection` (`picklescan_adapter.py:378-393`). The adapter checks `nested_has_execution_opcode is not False` → if the Rust finding reports the inner has NO execution opcodes, the adapter demotes severity. This is documented as intentional: a nested data-only pickle is not exploitable.

However the **standalone API and the adapter disagree** on the verdict for the same bytes. Downstream users integrating `modelaudit-picklescan` directly see MALICIOUS; users going through ModelAudit see INFO. This divergence should either (a) move the benign-downgrade heuristic into the Rust layer so both APIs agree, or (b) be explicitly documented in `packages/modelaudit-picklescan/README.md` as "the standalone API is conservative — integrators should pair with their own downgrade policy". File: `packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py` vs `modelaudit/scanners/picklescan_adapter.py:378`.

**P2-REMAINING-SEEDS.** `_SECRET_SCAN_SEEDS` still contains bare forms: `b"api"` (matches `apigateway`/`capi`/`rapi`), `b"auth"`, `b"az"`, `b"pwd"`, `b"secret"`, `b"password"`, `b"token"`. These words do appear in non-secret ML pickle contexts (HuggingFace `use_auth_token` field, dict keys named `"secret_key"` without a secret value, etc.). Not a correctness bug but inflates the "ran expensive detector" rate on benign files. Consider scoping to `b"api_"`, `b"auth_"`, `b"password"`, `b"token="`, or structural patterns. Low priority.

**P2-REMAINING-NESTED-FINDING-DUP.** `mal_large_middle.pkl` (16 MB malicious with REDUCE at pos 8000078) still emits two CRITICAL checks for the same event: S104 (primary) + S201 (supporting). Expected and intentional per rev-3 design. Consumers counting `(location, rule_code)` tuples are correct; consumers counting `len(result.issues)` see 2× inflation on builtins.eval/exec REDUCE. Not a regression.

**P2-CARGO-TEST-SURFACE.** Rust test count rose from 15 → 42 tests. Big improvement, but still thin relative to the ~3,300-line `state.rs`. Areas with no direct Rust tests: the whole `pybridge.rs` (33 lines, intentionally — uses Python entry), `report.rs` detail serialization, `opcode.rs` edge-case arg parsing (e.g., `LONG1`/`LONG4` overflow). Keep expanding.

**P2-SEED-RACE.** Follow-up to N-P0-6: the skip heuristic at `_should_skip_expensive_raw_detectors` combines `_rust_scan_completed_cleanly` with seed/shape checks. If a future refactor adds a new raw detector that doesn't rely on seeds (e.g., a structural detector that walks PDF/XML embedded content), the skip path would erroneously skip it. Add a comment near the function explaining the invariant, or add a unit test that pins the expected skip behavior so future detectors don't regress.

**P2-INFO-NOISY-NOTICES.** Rev 4 adds many new INFO-level notices (buffer opcodes, structural tamper, expansion heuristics, stream truncation). Aggregate scans of large corpora will see a lot more INFO-level rows. Dashboards should filter `severity >= WARNING` by default or group INFO into a count field. Documentation callout worth adding.

### Rev 4 follow-up audit — additional issues surfaced after the 80-commit re-audit

**P2-CONFIRMED-SEEDS-INFLATE-EXPENSIVE.** Verified empirically with a realistic HuggingFace-style pickle: a 10 MB `state_dict`-shaped pickle with `__version__`, `auto_map`, `use_auth_token`, `api_key=None` keys → 0 issues (clean) but **`pickle_expensive_raw_detectors_skipped` is `None` and scan takes 1.25 s** (vs 0.53 s for a 16 MB `b"A"*N` literal). The benign keys trip seed checks (`api_key` is in `_SECRET_SCAN_SEEDS`, `auth` is in there, `LlamaForCausalLM` shape passes `_has_domain_like_dot`). Net effect: **realistic ML pickles consistently miss the hot-path skip**, defeating most of the `111d0ae7` perf gain on the actual corpus the scanner is meant to handle. Recommendation: tighten seeds further (require `b"_key"` not `b"api_key"`, drop `b"auth"`, add structural validation), or move the seed gate to a "Rust verdict clean AND ML-format heuristic" check.

**P2-PROTO6-FORWARD-COMPAT.** A pickle starting with `\x80\x06` (hypothetical protocol 6) is currently flagged as `S901 file type validation failed: extension indicates pickle but magic bytes indicate unknown`. Not a bug today (proto 6 doesn't exist), but the moment Python introduces it, the scanner will misclassify every modern pickle. The file-type detector's pickle-magic table needs to track proto bumps. File: `modelaudit/utils/file/filetype.py` (or wherever pickle magic is enumerated).

**P2-OVERSIZED-FRAME-NOT-FLAGGED.** A pickle declaring `FRAME 0xFFFFFFFFFFFFFFFE` followed by a small body parses cleanly because the FRAME length is informational, not enforced. Test: `b'\x80\x04\x95\xff\xff\xff\xff\xff\xff\xff\xfe}.'` → 0 issues, success=True. An obviously-impossible FRAME size (≫ file size) is a useful structural-tamper signal but is currently silent. Add a notice when `FRAME.length > remaining_bytes * 1.5` or similar.

**P2-DIRECTORY-ERROR-SEVERITY.** `PickleScanner.scan('/tmp')` (a directory) emits `CRITICAL` "Error opening pickle file: [Errno 21] Is a directory". User error → CRITICAL severity is excessive and pollutes downstream metrics for users scanning mixed file trees. Should be `IssueSeverity.ERROR` (operational), not `CRITICAL` (security). File: `modelaudit/scanners/pickle_scanner.py:1739-1751` (the `OSError` branch).

**P2-WHEEL-MATRIX-INCOMPLETE.** `release-please.yml:411-423` matrix covers `ubuntu-latest`, `macos-14` (arm64), `windows-latest`. Still missing: `macos-13` (Intel Mac) and `linux-aarch64`. With abi3 a single wheel-per-OS covers Python 3.10+, but Intel Mac users and Linux ARM users (e.g., AWS Graviton, Raspberry Pi, M1 ARM Linux containers) still hit sdist + Rust. Not a P0 today because abi3 mitigated the Python-version explosion, but a real coverage gap.

**Concurrency stress (passing).** Verified `PickleScanner.scan()` is safe under 16 concurrent threads (8 malicious + 8 benign in parallel) — 0 errors, 8/8 correct on each path. The Rust scanner uses `py.detach()` to release the GIL during the actual scan, so true parallelism is achievable.

**Rust panic-safety audit (passing).** All `unwrap()` / `expect()` / `panic!()` occurrences in `packages/modelaudit-picklescan/rust/src/` are inside `#[cfg(test)]` blocks (lines 700+ in `opcode.rs`, 200+ in `report.rs`, 2600+ in `state.rs`). No hot-path panics in production code. PyO3 boundary in `pybridge.rs` is minimal (33 lines), uses `py.detach()` correctly, and copies `payload` into Rust-owned `Vec<u8>` before releasing the GIL — Python GC during scan is safe.

**Edge-case stress (all passing).**
- Circular reference (memo loop): 0.003 s, 0 issues, success=True.
- Multi-stream proto 4 + proto 0: 0 issues, success=True.
- Negative `file_size=-1` via `scan_stream`: handled via `standalone_size = None` normalization.
- 50,000-deep MARK/FRAME nesting: 0.1 s, 0 issues, success=True.
- INST opcode with `__main__` reference: CRITICAL S202 ✓
- OBJ opcode with `dill.loads`: CRITICAL S203 ✓
- NEWOBJ_EX with `__main__` class: CRITICAL S204 ✓
- Tail garbage after STOP: WARNING S901 + INFO S902, success=False ✓
- Invalid opcode 0xFF mid-stream: WARNING S901, success=False ✓
- Huge FRAME (`0xFFFFFFFFFFFFFFFE`) + valid REDUCE inside: STILL CRITICAL S201 (parse cleanly past the bogus FRAME length) ✓

### Honest residual list at rev 4

> Follow-up note (2026-04-13): this residual list reflects the rev-4 audit snapshot. The current branch closes these items in the active follow-up tracker below and did not surface additional unresolved gaps during the final targeted QA pass.

After all the verification above, the items I am **certain** still need attention before merge are:

1. **P1-NESTED-DIVERGENCE** — the standalone vs adapter verdict mismatch for benign nested payloads. This will surprise integrators of `modelaudit-picklescan`.
2. **P2-CONFIRMED-SEEDS-INFLATE-EXPENSIVE** — realistic HF/PyTorch pickles consistently miss the hot-path skip due to overly broad `_SECRET_SCAN_SEEDS`. Perf claim is confirmed for synthetic literal payloads but degrades on real-world workloads.
3. **P2-WHEEL-MATRIX-INCOMPLETE** — Intel Mac + Linux ARM users still need local Rust.
4. **P2-DIRECTORY-ERROR-SEVERITY** — CRITICAL severity for "Is a directory" is operational, not security.

Items I am **fairly sure** are open but lower priority:
- P2-REMAINING-NESTED-FINDING-DUP (intentional dual emission for `builtins.eval` REDUCE).
- P2-CARGO-TEST-SURFACE (`opcode.rs` LONG1/LONG4 edge cases, `report.rs` detail serialization).
- P2-INFO-NOISY-NOTICES (new INFO categories need dashboard guidance).
- P2-PROTO6-FORWARD-COMPAT (cosmetic until Python releases proto 6).
- P2-OVERSIZED-FRAME-NOT-FLAGGED (a useful tamper signal, currently silent).

Items I am **not sure about** but couldn't find in the time budget:
- I have not fuzzed the Rust opcode parser with random/crafted inputs at scale — there could be additional panics or stack-shape bugs.
- I have not exercised the scanner against a real HuggingFace model directory (`config.json`, `tokenizer.json`, `pytorch_model.bin`, `model.safetensors`) end-to-end via the CLI.
- I have not validated SARIF output for the new INFO/WARNING notices, or checked downstream JSON schema compatibility.
- I have not exercised the PyO3 bridge with concurrent scans + memory pressure (`malloc_failed`, OOM).
- I have not audited `tests/scripts/test_large_pickle_corpus_qa.py` (301 lines new, the corpus QA harness) for assertion strength.
- I have not checked whether `scan_stream` correctly handles a `BufferedReader` wrapping a socket or pipe (real-world archive-member streaming).
- I have not verified that the new `_documentation_literal_spans` walker correctly handles nested-pickle literals (does the doc-gating apply to the nested pickle's text content too?).

**Bottom line**: the PR is in dramatically better shape than at rev 1. Every concrete, reproducible bug I have surfaced has been verified or addressed. But "no more issues" is not a claim I can make about a 12k-line PR with a 3,300-line Rust state machine after a few hours of focused review. There are almost certainly more issues — probably P1/P2 in the categories above, possibly a P0 lurking in opcode-parser fuzzing or in a code path I haven't exercised.

### New observation — `84bb76f3 fix: detect short base64 pickle code strings`

The latest commit tightens detection of short base64-encoded exec strings in string literals. This specifically addresses the R-P0-4 residual where `base64(b"eval(x)") = 12 chars` was below the 16-char minimum. Verified test at `test_api.py` confirms the 12-char case now surfaces. Good close.

### New observation — `1af62f03 fix: dedupe pickle raw builtin findings`

This commit closes the final `__import__` raw-text double-emission (S201 + S104 pair from lines 923-936) by routing through a single multi-rule helper. Verified: `builtins.__import__` REDUCE now emits primary + supporting with the alias in details, no triple-emit. The earlier rev-3 bug of identical-message twin checks is fully resolved.

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
- [x] R-P2-40 — Decide whether to support embedded-Python cargo tests for `pybridge`; bridge coverage currently runs through Python package tests.
- [x] T-P1-51 / T-P1-52 — Strengthen parity/fuzz tests with expected verdicts.
- [x] T-P1-53 / T-P1-66 — Restore multi-stream regression coverage.
- [x] T-P1-54 — Replace Rust policy source-text tests with functional tests.
- [x] T-P1-55 / T-P1-56 — Strengthen weak negative/overbroad assertions.
- [x] T-P1-57 — Document BINBYTES text-scan design decision.
- [x] T-P1-63 — Expand high-risk callable module coverage.
- [x] T-P1-64 — Add real NEWOBJ_EX end-to-end test coverage.
- [x] T-P1-65 — Expand EXT1/EXT2/EXT4 extension-registry tests.
- [x] T-P1-67 — Restore dill load and benign dill-string tests.
- [x] S-R2-5 — Consolidate nested payload finding helpers.
- [x] S-R2-6 — Share `record_global_ref` detail base.
- [x] S-R2-8 — Table-drive suspicious string matches.
- [x] S-R2-9 — Merge `getattr` parsers.
- [x] S-R2-10 — Replace warning-global slice sentinel with an explicit enum.
- [x] S-P2-15 — Table-drive `_scan_raw_text_indicators`.
- [x] S-P2-17 — Avoid duplicate CVE-2026-24747 attribution.
- [x] S-P2-18 — Consolidate `extract_metadata` read-limit validation.
- [x] S-P2-19 — Reduce Python/Rust dangerous-policy drift.
- [x] S-D2-29 — Document Rust toolchain requirement in contributor setup.
- [x] S-D2-30 — Add standalone package project URLs.
- [x] S-D2-33 — Validate standalone `uv.lock` in CI.
- [x] S-D2-34 — Run standalone `cargo test` in nightly/perf workflows.
- [x] S-D2-35 — Install Rust before release-please standalone lock refresh.
- [x] S-D2-37 — Add future annotations to large-corpus QA test.
- [x] S-D2-38 — Add new tests to `allowed_test_files`.
- [x] S-D2-39 — Move non-Rust report conversion test out of Rust-gated file.
- [x] S-D2-40 — Use canonical PyTorch suffix in package API test.
- [x] A-P1-68 — Close missed P-P1-42a raw eval/exec/__import__ duplicate emissions found during closure audit.
- [x] A-P1-69 — Close missed P-P1-41 short base64 execution literal detection found during adversarial probes.
- [x] A-P1-70 — Resolve rev-4 P1-NESTED-DIVERGENCE so standalone and ModelAudit agree on benign nested data-only payloads.
- [x] A-P2-71 — Tighten remaining generic expensive raw-detector secret seeds and preserve true-positive coverage, including confirmed HuggingFace-style `use_auth_token` / `api_key=None` perf inflation.
- [x] A-P2-72 — Resolve rev-4 P2-REMAINING-NESTED-FINDING-DUP by pinning the intentional S104+S201 compatibility policy and documenting the counting contract.
- [x] A-P2-73 — Expand direct Rust coverage for opcode/report edge cases called out by P2-CARGO-TEST-SURFACE.
- [x] A-P2-74 — Pin the expensive raw-detector skip invariant so future non-seeded detectors are not accidentally skipped.
- [x] A-P2-75 — Document INFO notice volume and recommended dashboard filtering for aggregate scans.
- [x] A-P2-76 — Fix or document P2-PROTO6-FORWARD-COMPAT so file-type pickle magic is ready for future protocol bumps.
- [x] A-P2-77 — Add oversized FRAME structural-tamper coverage for impossible frame lengths.
- [x] A-P2-78 — Downgrade directory-open failures from security CRITICAL to operational/non-security severity.
- [x] A-P2-79 — Close P2-WHEEL-MATRIX-INCOMPLETE by adding macOS x86_64 and Linux aarch64 wheels or explicitly documenting the fallback.

### Rev 5 active remediation tracker

- [x] V5-P0-01 — Close N5-CRITICAL-RCE-BYPASS / N5-SEC-F2 / N5-SEC-F3 by deriving post-budget dangerous-global coverage from policy, promoting REDUCE-proximate matches to CRITICAL, and running the tail scan on timeout exhaustion.
- [x] V5-P0-02 — Close N5-EXPLOIT-PERSID-NESTED / N5-R10 by recognizing PERSID/BINPERSID nested execution semantics and preserving recursive detection.
- [x] V5-P0-03 — Re-run and resolve N5-FAIL-1..14, including current scanner-suite legacy rule-code regressions.
- [x] V5-P0-04 — Close N5-P0-WHEEL-MANYLINUX by producing manylinux-compatible standalone wheels in release automation.
- [x] V5-P0-05 — Close N5-P0-RELEASE-PLEASE-EXTRA-FILES-MARKERS so standalone package versions are bumped by release-please.
- [x] V5-P1-06 — Close N5-R1 / N5-SEC-F8 by fixing empty list/dict/set stack operand previews.
- [x] V5-P1-07 — Close N5-R2 by emitting truncated nested-pickle notices/findings for proto-0 as well as binary-protocol payloads.
- [x] V5-P1-08 — Close N5-R3 / N5-SEC-F7 by enforcing left word boundaries for suspicious call and module-attribute string matching.
- [x] V5-P1-09 — Close N5-R11 by preventing stack-state wipes on operand underflow.
- [x] V5-P1-10 — Close N5-R13 by preventing MARK from being wrapped into tuple values.
- [x] V5-P1-11 — Close N5-R15 by preserving INST module/name operands without space-splitting ambiguity.
- [x] V5-P1-12 — Close N5-R17 by keeping follow-on sibling pickle streams at the current nested depth.
- [x] V5-P1-13 — Close N5-R18 by capping import-reference metadata and surfacing truncation as a notice.
- [x] V5-P1-14 — Close N5-R19 by accepting uppercase escaped-hex pickle prefixes.
- [x] V5-P1-15 — Close N5-SEC-F5 by detecting wrapped/multiline encoded nested pickles.
- [x] V5-P1-16 — Close N5-SEC-F6 by aligning `_pickle_opcode_summary` implicit MEMOIZE indexing with CPython.
- [x] V5-P1-17 — Close N5-SEC-F9 by collapsing persistent-id warning spam into a counted notice.
- [x] V5-P1-18 — Close N5-PY1-1 / N5-PY1-4 by making non-seekable stream truncation explicit for known and unknown sizes.
- [x] V5-P1-19 — Close N5-PY1-2 by scanning binary tails for stream-backed pickle content beyond the raw window.
- [x] V5-P1-20 — Close N5-PY1-3 / N5-SEC-F4 by preserving Rust STRUCTURAL_TAMPER warning severity through the adapter.
- [x] V5-P1-21 — Close N5-PY1-5 by assigning a deterministic fallback rule code to unknown dangerous globals.
- [x] V5-P1-22 — Close N5-PY1-6 by adding a standalone known-size stream read ceiling.
- [x] V5-P1-23 — Close N5-PY1-7 / N5-PY1-8 by scanning partial bytes on short reads, including ZIP member scans.
- [x] V5-P1-24 — Close N5-PY1-9 by failing closed when parse failure suppression has no import-reference evidence.
- [x] V5-P1-25 — Close N5-PY1-10 by avoiding or retiring the incomplete parallel Python opcode walker where Rust metadata is authoritative.
- [x] V5-P1-26 — Close N5-PY1-11 by making rebuild-tensor documentation checks memo-aware or delegating to Rust metadata.
- [x] V5-P1-27 — Close N5-P1-HOT-PATH-DEFEATED-BY-TORCH-SEED with realistic PyTorch/HF hot-path skip coverage.
- [x] V5-P1-28 — Close N5-P1-SARIF-DUPLICATE-FINDINGS by filtering supporting-rule-code rows from SARIF primary results.
- [x] V5-P1-29 — Close N5-P1-SARIF-NO-PICKLESCAN-RULE-COVERAGE with SARIF regression coverage for new picklescan rule codes.
- [x] V5-P1-30 — Close N5-P1-DEAD-ADAPTER-NESTED-DOWNGRADE by deleting the obsolete adapter downgrade path.
- [x] V5-P1-31 — Close N5-P1-RULE-CODE-CONFLATION-S902 by assigning PICKLE_EXPANSION a distinct DoS-oriented rule code.
- [x] V5-P1-32 — Close N5-P1-DOCKER-SINGLE-STAGE by moving Docker builds to a builder/runtime split.
- [x] V5-P2-33 — Close N5-P2-PACKAGE-CHANGELOG-THIN with a fuller standalone package changelog.
- [x] V5-P2-34 — Close N5-P2-CHANGELOG-RULE-CODES by documenting new rule codes in the root changelog.
- [x] V5-P2-35 — Close N5-P2-PYPROJECT-URLS-CHANGELOG by pointing standalone package metadata at its own changelog.
- [x] V5-P2-36 — Close N5-P2-DOCKERFILE-RUST-VERSION-DRIFT by documenting or deriving the Rust version sync point.
- [ ] V5-P2-37 — Close N5-P2-PICKLESCAN-PACKAGE-CARGO-TEST-ORDERING by running cargo checks before Python package tests in CI.

### Completed item QA log

- V5-P0-01 — Same-item commit replaces the hardcoded post-budget dangerous-global needle list with a byte-level GLOBAL parser that consults the shared Rust policy, including wildcard modules like `subprocess`, explicit policy entries like `ctypes.CDLL`, and `__main__` references. REDUCE/OBJ/BUILD/NEWOBJ/NEWOBJ_EX proximity now promotes the post-budget finding to CRITICAL, and timeout exhaustion invokes the same tail scan. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml post_budget -- --nocapture` — passed, 4 tests.
- V5-P0-02 — Same-item commit treats PERSID/BINPERSID as execution-relevant nested pickle opcodes, makes PERSID stack modeling explicit, and fails closed on malformed nested PERSID payloads after surfacing inner findings. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml execution_opcode_detection_distinguishes_structural_nested_payloads -- --nocapture` — passed, 1 test.
  - `uv run pip install -e packages/modelaudit-picklescan` — passed, rebuilt the editable native extension for Python API QA.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "persid_payload"` — passed, 2 tests.
- V5-P0-03 — Same-item commit re-ran the reported API/scanner failure set after rebuilding the native extension. The package API failures no longer reproduced except for the STACK_GLOBAL post-budget boundary, which was fixed by making the synthetic STACK_GLOBAL tail prefix parseable by the policy-backed post-budget scanner. Consumer tests were updated to assert the current compatibility contract: primary Rust rule code plus `legacy_rule_aliases` metadata instead of resurrecting duplicate legacy findings. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml post_budget -- --nocapture` — passed, 4 tests.
  - `uv run pip install -e packages/modelaudit-picklescan` — passed, rebuilt the editable native extension for Python API/scanner QA.
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_api.py tests/scanners/test_numpy_scanner.py tests/scanners/test_executorch_scanner.py tests/scanners/test_pytorch_zip_scanner.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py tests/scanners/test_numpy_scanner.py tests/scanners/test_executorch_scanner.py tests/scanners/test_pytorch_zip_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py tests/scanners/test_numpy_scanner.py tests/scanners/test_joblib_scanner.py tests/scanners/test_executorch_scanner.py tests/scanners/test_pytorch_zip_scanner.py tests/scanners/test_picklescan_adapter.py -q --maxfail=30` — passed, 355 tests; 1 skipped because `joblib` is not installed in this environment.
- V5-P0-04 — Same-item commit switches Linux standalone package release builds to `PyO3/maturin-action` with `manylinux_2_28` compatibility while preserving the source distribution from the Linux x86_64 lane and existing wheel smoke checks. Targeted QA:
  - `uv run python - <<'PY' ... yaml.safe_load('.github/workflows/release-please.yml') ... PY` — passed.
- V5-P0-05 — Same-item commit adds release-please inline version markers to the standalone package `pyproject.toml` and Rust crate `Cargo.toml`, matching the existing generic `extra-files` release-please configuration. Targeted QA:
  - `uv run python - <<'PY' ... tomllib.loads(...) ... PY` — passed for `packages/modelaudit-picklescan/pyproject.toml` and `packages/modelaudit-picklescan/Cargo.toml`.
- V5-P1-06 — Same-item commit fixes `EMPTY_LIST`, `EMPTY_DICT`, and `EMPTY_SET` stack values so malformed `STACK_GLOBAL` diagnostics report `list:[]`, `dict:{}`, and `set:set()` instead of `tuple:()`. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml empty_collection_operands_report_precise_stack_preview_types -- --nocapture` — passed, 1 test.
- V5-P1-07 — Same-item commit removes the binary-protocol-only `0x80` guard from truncated raw nested-pickle handling, so proto-0 payloads that exceed the nested byte budget now emit the same incomplete S213 finding and `nested_payload_truncated` notice as binary-protocol payloads. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml truncated_proto0_nested_payloads_are_not_silently_dropped -- --nocapture` — passed, 1 test.
- V5-P1-08 — Same-item commit adds left-boundary checks to call-like suspicious-string matching and module-attribute matching, preventing benign words like `recompile` and `foos.system` from matching `compile(` / `os.system`. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml suspicious_string_matching_keeps_word_boundaries -- --nocapture` — passed, 1 test.
- V5-P1-09 — Same-item commit stops `consume_top_operands` from clearing the entire VM stack when a REDUCE-class opcode underflows. The scanner now preserves existing stack state and pushes an opaque result for the malformed operation. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml callable_operand_underflow_does_not_clear_stack_state -- --nocapture` — passed, 1 test.
- V5-P1-10 — Same-item commit prevents `TUPLE1`/`TUPLE2`/`TUPLE3` shortcut collapsing from wrapping the internal MARK sentinel inside a tuple value. If the top operand window contains MARK, the scanner preserves it and pushes an opaque value instead. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml tuple_shortcuts_do_not_wrap_mark_sentinels -- --nocapture` — passed, 1 test.
- V5-P1-11 — Same-item commit adds a structured `ArgValue::Global` operand for GLOBAL/INST opcodes so module and callable names are preserved without round-tripping through a space-delimited string. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml parse_global_operands_preserve_spaces -- --nocapture` — passed, 1 test.
- V5-P1-12 — Same-item commit treats follow-on pickle streams as siblings rather than nested payloads: the follow-on scanner now uses the current nested depth and is not skipped merely because the nested-depth budget has been reached. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml follow_on_streams_do_not_consume_nested_depth_budget -- --nocapture` — passed, 1 test.
- V5-P1-13 — Same-item commit caps import-reference metadata at 10,000 entries and emits a single INFO `import_references_truncated` notice when additional references are suppressed. The same cap is applied when merging follow-on stream metadata. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml import_reference_metadata_is_capped_with_notice -- --nocapture` — passed, 1 test.
- V5-P1-14 — Same-item commit accepts uppercase `\XNN` escaped-hex markers anywhere the nested-pickle encoded literal logic accepts lowercase `\xNN`: prefix gating, mid-string probe windows, decoded-size estimates, and escaped-marker stripping. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml encoded_probe_windows_keep_protocol0_escaped_hex_pickle_candidates -- --nocapture` — passed, 1 test.
- V5-P1-15 — Same-item commit extracts encoded pickle candidates from comment-prefixed wrapped literals, ignoring prose lines and joining encoded continuation lines before base64/hex decoding. This closes the documented `# <b64>` multiline nested-pickle bypass. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml wrapped_base64_nested_literals_ignore_comment_leaders -- --nocapture` — passed, 1 test.
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run pip install -e packages/modelaudit-picklescan` — passed, rebuilt the editable native extension for Python API QA.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "comment_wrapped_base64"` — passed, 1 test.
- V5-P1-16 — Same-item commit aligns the Python metadata-only opcode summary with CPython MEMOIZE semantics by storing implicit memo entries at `len(memo)` rather than `max(explicit_put)+1`. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "memoize_indexing or memoized_stack_global"` — passed, 2 tests.
- V5-P1-17 — Same-item commit keeps the first persistent-id warning finding for compatibility, suppresses repeated per-position PERSISTENT_ID findings, and emits one INFO `persistent_id_summary` notice with `persistent_id_count`. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml repeated_persistent_id_opcodes_are_summarized -- --nocapture` — passed, 1 test.
- V5-P1-18 — Same-item commit probes one byte past the bounded non-seekable root-stream read when `file_size` is unknown, so unknown-size streams above the cap now get the same explicit truncation metadata, WARNING S902 check, and inconclusive outcome as known-size streams. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "non_seekable_payload_above_root_cap"` — passed, 2 tests.
- V5-P1-19 — Same-item commit scans binary tails from stream-backed pickle scans using the full buffered non-seekable payload when the size is known, or by seeking to the tail window for seekable streams. Root raw detectors now skip their bounded-window binary-tail pass in `scan_stream` and invoke the stream-aware tail pass afterward. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "non_seekable_known_size or non_seekable_payload_above_root_cap or binary_tail_past_raw_window"` — passed, 3 tests.
- V5-P1-20 — Same-item commit removes the adapter's unconditional STRUCTURAL_TAMPER INFO downgrade so Rust WARNING severity flows through ModelAudit. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "structural_tamper"` — passed, 7 tests.
- V5-P1-21 — Same-item commit maps otherwise-unknown `DANGEROUS_GLOBAL` findings to deterministic legacy rule `S206` instead of returning `None`. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q -k "legacy_namespace"` — passed, 24 tests.
- V5-P1-22 — Same-item commit adds `max_known_stream_read_bytes` to standalone `ScanOptions`, caps reads for declared-size streams, and emits a `known_stream_truncated` inconclusive notice instead of trusting arbitrarily large declared sizes. The ModelAudit adapter now accepts the same config key and routes the notice through legacy incomplete-scan metadata. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py packages/modelaudit-picklescan/tests/test_options.py modelaudit/scanners/picklescan_adapter.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py packages/modelaudit-picklescan/tests/test_options.py modelaudit/scanners/picklescan_adapter.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/src/modelaudit_picklescan/options.py packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py packages/modelaudit-picklescan/tests/test_options.py modelaudit/scanners/picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py packages/modelaudit-picklescan/tests/test_options.py tests/scanners/test_picklescan_adapter.py -q -k "known_stream or unbounded_stream or options"` — passed, 28 tests.
- V5-P1-23 — Same-item commit preserves bytes read before a declared-size short read, scans those partial bytes with Rust, then appends a deterministic `short_read` error and incomplete coverage metadata. This preserves malicious findings from truncated root streams and truncated PyTorch ZIP pickle members while still reporting the operational read failure. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/src/modelaudit_picklescan/api.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "short_read"` — passed, 3 tests.
- V5-P1-24 — Same-item commit changes parse-failure tail suppression to require affirmative benign import-reference evidence; empty or missing import-reference metadata now fails closed with the S901 parse issue even for UnicodeDecodeError and zero-padding tail shapes. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q -k "tail_suppression or parse_failure"` — passed, 7 tests.
- V5-P1-25 — Same-item commit adds per-opcode count metadata to the Rust report and changes scan-time CVE bridging to use Rust `opcode_counts`, Rust `import_references`, and Rust completeness metadata instead of the incomplete Python `_pickle_opcode_summary` walker. The bounded Python summary remains only for explicit metadata extraction/tests. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 58 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "opcode_counts"` — passed, 1 test.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "rust_metadata or opcode_summary_tracks or raw_cve_setitem"` — passed, 4 tests.
- V5-P1-26 — Same-item commit delegates rebuild-tensor documentation suppression to Rust import-reference metadata: if Rust observed an actual `_rebuild_tensor*` global, the Python documentation-literal helper can no longer suppress CVE-2026-24747 attribution. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "rebuild_tensor"` — passed, 2 tests.
- V5-P1-27 — Same-item commit removes the generic `torch` expensive-raw JIT seed and keeps the precise `torch.jit` / `torchscript` seeds, so ordinary PyTorch/HuggingFace metadata can stay on the fast clean path while actual TorchScript/JIT markers still run the JIT detector path. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q -k "expensive_raw_prefilters"` — passed, 8 tests.
- V5-P1-28 — Same-item commit filters issues marked `details.supporting_rule_code=True` out of SARIF rules/results so compatibility-only alias rows do not duplicate primary findings in SARIF output. Targeted QA:
  - `uv run ruff format modelaudit/integrations/sarif_formatter.py tests/integrations/test_sarif_formatter.py` — passed.
  - `uv run ruff check modelaudit/integrations/sarif_formatter.py tests/integrations/test_sarif_formatter.py` — passed.
  - `uv run mypy modelaudit/integrations/sarif_formatter.py tests/integrations/test_sarif_formatter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/integrations/test_sarif_formatter.py -q -k "supporting_rule_code"` — passed, 2 tests.
- V5-P1-29 — Same-item commit adds SARIF formatter regression coverage that preserves pickle rule codes `S209`, `S213`, `S214`, `S601`, `S602`, `S604`, and `S902` as SARIF rule/result IDs and properties. Targeted QA:
  - `uv run ruff format tests/integrations/test_sarif_formatter.py` — passed.
  - `uv run ruff check tests/integrations/test_sarif_formatter.py` — passed.
  - `uv run mypy tests/integrations/test_sarif_formatter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/integrations/test_sarif_formatter.py -q -k "pickle_rule_codes"` — passed, 1 test.
- V5-P1-30 — Same-item commit deletes the obsolete adapter-side benign nested-payload severity downgrade. Rust now owns benign nested classification, so any nested finding that reaches ModelAudit preserves its Rust-assigned severity and rule code. Targeted QA:
  - `uv run ruff format modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py -q -k "nested_payload"` — passed, 2 tests.
- V5-P1-31 — Same-item commit adds catalog rule `S214` for pickle expansion denial-of-service, maps Rust `PICKLE_EXPANSION` findings to `S214` instead of generic `S902`, and pins scanner/adapter coverage for normal and post-budget expansion findings. Targeted QA:
  - `uv run ruff format modelaudit/rule_catalog.py modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/rule_catalog.py modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/rule_catalog.py modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py tests/scanners/test_pickle_scanner.py tests/scanners/test_rule_code_registry_consistency.py -q -k "PICKLE_EXPANSION or expansion_heuristics or rule_codes_are_registered"` — passed, 6 tests.
- V5-P1-32 — Same-item commit converts `Dockerfile` and `Dockerfile.full` to builder/runtime multi-stage builds. Rust, rustup, curl, and build-essential stay in the builder stage; runtime installs only built wheels plus runtime dependencies and keeps `ca-certificates` for HTTPS package installs. Targeted QA:
  - `uv run python - <<'PY' ... dockerfile multistage assertions ... PY` — passed for `Dockerfile` and `Dockerfile.full`.
- V5-P2-33 — Same-item commit expands the standalone `modelaudit-picklescan` changelog with first-release details for API surface, PyTorch ZIP scanning, Rust detection coverage, resource controls, parity/CI gates, runtime-engine removal, GIL/operand-copy performance work, stream short-read behavior, and major security fixes. Targeted QA:
  - Manual Markdown review of `packages/modelaudit-picklescan/CHANGELOG.md` — passed.
- V5-P2-34 — Same-item commit adds a root `CHANGELOG.md` "Rule Codes" subsection for the Rust pickle scanner mappings, including `S209`, `S211`, `S212`, `S213`, `S214`, `S601`, `S602`, `S604`, `S902`, and the internal `STRUCTURAL_TAMPER` / `PICKLE_EXPANSION` detail-code contract. Targeted QA:
  - Manual Markdown review of `CHANGELOG.md` — passed.
- V5-P2-35 — Same-item commit points the standalone package `Changelog` project URL at `packages/modelaudit-picklescan/CHANGELOG.md` so package-index users land on the package-specific release notes. Targeted QA:
  - `uv run python - <<'PY' ... package changelog URL assertion ... PY` — passed.
- V5-P2-36 — Same-item commit adds a `PICKLESCAN_RUST_TOOLCHAIN` Docker build argument and explicit sync comment in both Dockerfiles so the container toolchain version stays aligned with `packages/modelaudit-picklescan/Cargo.toml` `rust-version`. Targeted QA:
  - `uv run python - <<'PY' ... Docker Rust toolchain sync assertions ... PY` — passed.
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
- T-P1-57 — Same-item commit clarifies the standalone package changelog entry: BINBYTES/tensor blobs are probed for nested pickle streams, but arbitrary non-pickle text extraction remains a root ModelAudit raw-detector responsibility. The existing test already carries the same design comment. Targeted QA:
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_does_not_scan_raw_binbytes_payloads_as_text_strings -q` — passed, 1 test.
- T-P1-63 — Same-item commit verifies expanded high-risk callable coverage includes the review-listed `smtplib`, `httplib`, `sqlite3`, `marshal`, `cloudpickle`, and `pkgutil.resolve_name` cases, plus both `cloudpickle.load` and `cloudpickle.loads`. Targeted QA:
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_flags_expanded_high_risk_callables -q` — passed, 19 tests.
- T-P1-64 — Existing standalone API regression `test_scan_bytes_flags_newobj_ex_dangerous_class` drives a concrete `NEWOBJ_EX` pickle through the Rust engine and asserts the `DANGEROUS_CALL` opcode/import reference. Targeted QA:
  - `uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_flags_newobj_ex_dangerous_class -q` — passed, 1 test.
- T-P1-65 — Same-item commit expands standalone extension-registry coverage beyond the existing EXT1/EXT2/EXT4 reduce matrix: unresolved data-only extension references stay suspicious without becoming dangerous calls, and a follow-on stream containing an opaque copyreg extension reduce is promoted to malicious with a `follow_on_stream_detected` notice. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "extension"` — passed, 8 tests.
- T-P1-67 — Same-item commit verifies the review-named `dill.load` and benign dill text literal regressions are present, then expands coverage to the remaining dangerous dill loader helpers `dill.load_module` and `dill.load_session`. Targeted QA:
  - `uv run ruff format packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "dill"` — passed, 7 tests.
- S-R2-5 — Same-item commit consolidates raw and encoded nested-payload finding construction behind one spec-driven helper while preserving the existing rule codes, messages, metadata shape, and truncation behavior. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 41 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "nested"` — passed, 30 tests.
- S-R2-6 — Same-item commit extracts the shared global-reference detail fields used by metadata, dangerous-global findings, and `__main__` warnings so future field additions cannot drift between those paths. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 41 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_resolves_short_binstring_stack_global_operands packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_detects_reduce_invoking_os_system -q` — passed, 2 tests.
- S-R2-8 — Same-item commit replaces the long `suspicious_string_matches` `if` chain with pattern tables for simple substrings, call-like names, module attributes, loader needles, copyreg needles, and getattr targets while preserving special-case import/hex/getattr parsing. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml strings::tests` — passed, 7 tests.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 41 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "string or high_risk"` — passed, 32 tests.
- S-R2-9 — Same-item commit merges the duplicated `getattr` target and nested-call parsers into one scan that records target flags plus nested evidence, and adds a direct nested-`getattr` Rust assertion. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml strings::tests::suspicious_string_matching_detects_getattr_variants` — passed, 1 test.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 41 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q -k "string or high_risk"` — passed, 32 tests.
- S-R2-10 — Same-item commit replaces `warning_globals`' empty-slice wildcard sentinel with explicit `WarningGlobalMatch::AnyName` / `OneOf` variants and pins wildcard-vs-specific behavior in Rust tests. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml policy::tests` — passed, 3 tests.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 42 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_warns_on_functools_partial_without_marking_benign_partial_malicious -q` — passed, 1 test.
- S-P2-15 — Same-item commit table-drives the repeated raw text module-attribute, regex, direct-token, importlib-method, and webbrowser-method indicators and uses a shared raw-indicator append helper. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 70 tests.
- S-P2-17 — Same-item commit adds a CVE attribution de-duplication pass keyed by `(cve_id, derived_rule_code)` before metadata/check emission, plus a monkeypatched regression proving duplicate CVE-2026-24747 SETITEM attributions become one metadata entry and one `S209` issue. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_raw_cve_attributions_are_deduplicated_by_rule tests/scanners/test_pickle_scanner.py::test_raw_cve_setitem_detection_is_not_suppressed_by_comment_token -q` — passed, 2 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 71 tests.
- S-P2-18 — Same-item commit extracts `_metadata_pickle_read_limit` so integer conversion, positive bounds, and hard maximum validation happen in one helper, with invalid/zero/negative/oversized config regressions. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_extract_metadata_uses_pickle_opcodes_not_raw_bytes tests/scanners/test_pickle_scanner.py::test_extract_metadata_validates_pickle_read_limit -q` — passed, 5 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 75 tests.
- S-P2-19 — Same-item commit derives Python compatibility policy exports from `SUSPICIOUS_GLOBALS`, keeps only a narrow historical alias layer for fully-qualified wildcard-module names, and aligns `os.path` with the Rust safe-module exception. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py tests/detectors/test_builtin_detection.py` — passed.
  - `uv run ruff format --check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py tests/detectors/test_builtin_detection.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py tests/detectors/test_builtin_detection.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py tests/detectors/test_builtin_detection.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_policy_compatibility_exports_cover_required_dangerous_symbols tests/detectors/test_builtin_detection.py -q` — passed, 10 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 75 tests.
- S-D2-29 — Same-item commit clarifies that editable installs build the native pickle scanner extension and therefore require a Rust stable toolchain, including the pip setup snippets that reviewers flagged. Targeted QA:
  - `npx prettier --check CONTRIBUTING.md` — passed.
- S-D2-30 — Same-item commit expands the standalone package `[project.urls]` metadata with Documentation and Security links in addition to homepage/repository/issues/changelog. Targeted QA:
  - `uv run python - <<'PY' ... tomllib.loads(...)[\"project\"][\"urls\"] ... PY` — passed, parsed the package TOML and confirmed Homepage, Documentation, Repository, Issues, Changelog, and Security are present.
- S-D2-33 — Same-item commit adds standalone package `pyproject.toml` and `uv.lock` paths to the dependency path filter so the existing `uv-lock-check` job runs when standalone lock inputs change. Targeted QA:
  - `npx prettier --check .github/workflows/test.yml` — passed.
  - `uv lock --check` — passed at repo root.
  - `(cd packages/modelaudit-picklescan && uv lock --check)` — passed.
- S-D2-34 — Same-item commit adds standalone `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` steps to both nightly jobs and the performance workflow before benchmark execution. Targeted QA:
  - `npx prettier --check .github/workflows/nightly.yml .github/workflows/perf.yml` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 42 tests.
- S-D2-35 — Same-item commit installs stable Rust in the release-please PR-formatting job before either lockfile refresh runs, so the standalone maturin-backed package can resolve from a cold runner. Targeted QA:
  - `npx prettier --check .github/workflows/release-please.yml` — passed.
  - `uv lock --check` — passed at repo root.
  - `(cd packages/modelaudit-picklescan && uv lock --check)` — passed.
- S-D2-37 — Same-item commit records that `tests/scripts/test_large_pickle_corpus_qa.py` already has `from __future__ import annotations` at the top of the file in the current tree. Targeted QA:
  - `uv run ruff format --check tests/scripts/test_large_pickle_corpus_qa.py` — passed.
  - `uv run ruff check tests/scripts/test_large_pickle_corpus_qa.py` — passed.
  - `uv run mypy tests/scripts/test_large_pickle_corpus_qa.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scripts/test_large_pickle_corpus_qa.py -q` — passed, 16 tests.
- S-D2-38 — Same-item commit records that `tests/conftest.py` already allowlists both `test_dill_joblib_enhanced.py` and `test_pickle_context_filtering.py` for reduced Python-version CI lanes. Targeted QA:
  - `uv run ruff format --check tests/conftest.py tests/test_dill_joblib_enhanced.py tests/test_pickle_context_filtering.py` — passed.
  - `uv run ruff check tests/conftest.py tests/test_dill_joblib_enhanced.py tests/test_pickle_context_filtering.py` — passed.
  - `uv run mypy tests/conftest.py tests/test_dill_joblib_enhanced.py tests/test_pickle_context_filtering.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/test_dill_joblib_enhanced.py tests/test_pickle_context_filtering.py -q` — passed, 7 tests.
- S-D2-39 — Same-item commit records that `test_rust_report_conversion_rejects_non_bool_coverage_flags` already lives in `packages/modelaudit-picklescan/tests/test_report.py`, outside the Rust-extension-gated `test_rust_engine.py`. Targeted QA:
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_report.py packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_report.py packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_report.py packages/modelaudit-picklescan/tests/test_rust_engine.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_report.py -q` — passed, 8 tests.
- S-D2-40 — Same-item commit records that `test_scan_file_detects_malicious_pytorch_zip_data_pickle` already uses the canonical `model.pt` suffix; separate `.bin` coverage remains only for the fallback member-routing test that intentionally has no `data.pkl`. Targeted QA:
  - `uv run ruff format --check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_file_detects_malicious_pytorch_zip_data_pickle -q` — passed, 1 test.
- R-P2-40 — Same-item commit records the decision not to add direct embedded-Python cargo tests for `pybridge` in this PR. The PyO3 bridge remains covered through Python package tests after native extension build, while pure Rust parser/state/policy/report behavior remains covered by `cargo test`; direct embedded cargo tests can be reconsidered only with a stable Python-home/path harness. Targeted QA:
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 42 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_native_interface.py packages/modelaudit-picklescan/tests/test_report.py -q` — passed, 10 tests.
- A-P1-68 — Closure audit showed P-P1-42a was not explicitly tracked and still reproduced: raw `eval`/`exec`/`__import__` literals emitted a generic `S201` critical plus a legacy critical for the same bounded raw-window evidence. Same-item commit keeps the legacy raw rule signal and suppresses the duplicate generic raw `S201` emission for those builtins. Targeted QA:
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_scan_stream_deduplicates_legacy_raw_eval_exec_import_patterns tests/scanners/test_pickle_scanner.py::test_scan_stream_preserves_legacy_raw_eval_exec_importlib_detection tests/scanners/test_pickle_scanner.py::test_scan_stream_detects_legacy_raw_eval_with_obscured_separator -q` — passed, 6 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 76 tests.
- A-P1-69 — Adversarial probes reproduced P-P1-41: a pickle string containing `ZXZhbCh4KQ==` (`base64("eval(x)")`) scanned clean because the root raw detector and Rust string detector both skipped short base64 tokens. Same-item commit lowers the bounded token thresholds enough to decode this minimal execution pattern while keeping token/decode budgets. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml strings::tests::suspicious_string_matching_detects_base64_encoded_code` — passed, 1 test.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `uv run ruff format modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py packages/modelaudit-picklescan/tests/test_api.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_scan_stream_detects_base64_encoded_execution_text packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_flags_base64_encoded_code_string_literals -q` — passed, 4 tests.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 42 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py -q` — passed, 77 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py -q` — passed, 169 tests.
  - Manual `uv run python` probe for `pickle.dumps({"encoded": base64("eval(x)")})` — passed; root scanner emitted `S604` with pattern `eval`, standalone scanner returned `suspicious` with `SUSPICIOUS_STRING` / `base64 eval(`.
- A-P1-70 — Same-item commit moves the benign nested-payload downgrade into the Rust scanner itself. Complete data-only raw/encoded nested payloads now emit INFO notices instead of security findings, while dangerous nested payloads and incomplete nested analysis still fail closed. The raw nested scanner also crops a complete hidden nested pickle at its `STOP` opcode so benign bytes after the nested stream do not inflate the nested size or create false malicious verdicts. Targeted QA:
  - `cargo fmt --manifest-path packages/modelaudit-picklescan/Cargo.toml -- --check` — passed.
  - `cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed.
  - `cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings` — passed.
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 46 tests.
  - `uv run --with 'maturin>=1.9,<2' maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, rebuilt the editable native extension.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_records_data_only_raw_nested_pickle_payloads_as_notices packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_records_data_only_base64_nested_pickle_payloads_as_notices packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_records_data_only_raw_nested_pickle_hidden_inside_large_literal_as_notice packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_marks_parent_inconclusive_when_nested_analysis_is_incomplete -q` — passed, 4 tests.
- A-P2-71 — Same-item commit narrows the expensive raw-detector seeds away from bare generic words (`api`, `auth`, `az`, `pwd`, `secret`, `password`, `token`) and requires structural assignment forms for secret-like keys. The domain/IP prefilter now requires a domain-like dot plus URL/value/network punctuation, so class names like `LlamaForCausalLM` no longer defeat the hot-path skip. Targeted QA:
  - `uv run ruff check modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `uv run mypy modelaudit/scanners/pickle_scanner.py tests/scanners/test_pickle_scanner.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_expensive_raw_prefilters_skip_generic_secret_words_without_values tests/scanners/test_pickle_scanner.py::test_expensive_raw_prefilters_skip_huggingface_style_metadata_without_values tests/scanners/test_pickle_scanner.py::test_expensive_raw_prefilters_preserve_structured_secret_assignments -q` — passed, 3 tests.
- A-P2-72 — Same-item commit keeps the intentional builtin compatibility duplicate (`primary legacy rule` + supporting `S201`) but marks the supporting issue with `details.supporting_rule_code=True` and `details.primary_rule_code`, so dashboards can count only primary security issues without losing backward-compatible rule codes. Targeted QA:
  - `uv run ruff check modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `uv run mypy modelaudit/scanners/picklescan_adapter.py tests/scanners/test_picklescan_adapter.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_picklescan_adapter.py::test_pickle_report_to_scan_result_preserves_legacy_builtin_call_rule_alias -q` — passed, 1 test.
- A-P2-73 — Same-item commit expands direct Rust opcode coverage for borrowed operand spans and malformed large integer operands. This pins `LONG1`/`LONG4` byte-span behavior and verifies an oversized `LONG4` reports a bounded `ValueError` rather than panicking or allocating. Targeted QA:
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 46 tests.
- A-P2-74 — Same-item commit documents the expensive raw-detector skip invariant at the predicate and adds a regression proving the skip only applies after a clean, complete Rust scan. Future raw detectors that do not rely on the current seed/shape contract must update this predicate and tests. Targeted QA:
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_expensive_raw_skip_requires_clean_complete_rust_result -q` — passed, 1 test.
- A-P2-75 — Same-item commit documents INFO notice semantics for aggregate scans in the standalone README and the user security model. Recommended dashboards should alert on WARNING/CRITICAL findings by default, group INFO notices into counts, and exclude `supporting_rule_code=true` rows from primary counts. Targeted QA:
  - Documentation-only change; covered by `git diff --check` in final QA.
- A-P2-76 — Same-item commit replaces protocol-specific pickle magic duplication with a forward-compatible binary pickle helper accepting protocols 2 through 6. Protocol 6 is treated as pickle-shaped for routing while the Rust scanner can still apply normal parser policy to the actual stream. Targeted QA:
  - `uv run ruff check modelaudit/utils/file/detection.py tests/utils/file/test_filetype.py` — passed.
  - `uv run mypy modelaudit/utils/file/detection.py tests/utils/file/test_filetype.py` — passed.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/utils/file/test_filetype.py::test_detect_file_format_accepts_forward_compatible_binary_pickle_protocol -q` — passed, 1 test.
- A-P2-77 — Same-item commit records an INFO `oversized_frame` notice when a `FRAME` declares a size far larger than the bytes remaining in the stream. FRAME remains informational for parsing, but impossible sizes are now visible as structural tamper evidence. Targeted QA:
  - `cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml` — passed, 46 tests.
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py::test_scan_bytes_records_oversized_frame_notice -q` — passed, 1 test.
- A-P2-78 — Same-item commit treats directory paths as operational input errors rather than security-critical findings. `PickleScanner.scan(path_to_dir)` now returns `success=False`, `operational_error=True`, and an INFO failed check with `operational_error_reason=path_is_directory`. Targeted QA:
  - `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest tests/scanners/test_pickle_scanner.py::test_scan_directory_reports_operational_error_without_critical_issue -q` — passed, 1 test.
- A-P2-79 — Same-item commit expands the standalone release matrix with macOS x86_64 and Linux aarch64 wheel jobs and updates the standalone README wheel/fallback text. Targeted QA:
  - YAML/docs-only change; covered by `git diff --check` in final QA.
  - Final combined QA after all A-P1/A-P2 follow-ups: `PROMPTFOO_DISABLE_TELEMETRY=1 uv run pytest packages/modelaudit-picklescan/tests/test_api.py tests/scanners/test_pickle_scanner.py tests/scanners/test_picklescan_adapter.py tests/utils/file/test_filetype.py -q` — passed, 395 tests.
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
- R-P2-40 — Resolved decision: direct PyO3 `pybridge` cargo tests require an embedded-Python initialization strategy; a naive `Python::initialize()` unit test failed with `ModuleNotFoundError: No module named 'encodings'` from the cargo test binary. Keep bridge behavior covered through Python package tests unless/until the Rust test harness sets a reliable Python home/path.
- A-P1-68 — Closure audit found P-P1-42a was not listed in the active tracker and was still reproducible; fixed by keeping one legacy raw builtins issue per `eval`/`exec`/`__import__` evidence item instead of emitting a duplicate generic `S201`.
- A-P1-69 — Adversarial probes found P-P1-41 was still reproducible for `base64("eval(x)")`; fixed by lowering bounded base64 token thresholds in both root raw and Rust string scanning and adding root/standalone regressions.
- 2026-04-13 A-P1/A-P2 pass — No unresolved new gaps found. The pass did uncover two sub-issues while validating A-P1-70 (raw nested candidates with benign bytes after `STOP`, and escaped-hex data-only nested payloads tripping the generic `hex escape` warning); both were fixed under A-P1-70 and covered by standalone API regressions.

---

## What's working well

- Core opcode parser bounds safety: zero hot-path `unwrap`/`panic`/`expect`.
- All 21 committed exploit fixtures + 2 safe samples → correct verdict.
- Deep-recursion stress, massive-memo stress, post-budget tail evasion all handled gracefully.
- `size=-1` stream bug fix is real and verified (`api.py:535-538`, `pickle_scanner.py:749`).
- `MODELAUDIT_PICKLESCAN_ENGINE` env var + `use_standalone_pickle_primary` flag removal is clean (zero lingering refs).
- Rust `cargo test`, `cargo clippy`, `cargo fmt`, ruff, mypy, pytest all green locally.
- Legacy rule-code alias mapping is mostly correct modulo the three regressions above.
