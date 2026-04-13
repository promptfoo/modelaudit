# modelaudit-picklescan Rust Engine

This directory contains the native engine for the standalone
`modelaudit-picklescan` package. The package runtime is Rust-only; historical
Python parity evidence is preserved in tests and QA notes, but the old selector
and fallback runtime are gone.

## Safety Invariants

- Never execute pickle payloads.
- Preserve or strengthen Python detections; do not weaken findings for speed.
- Treat malformed or budget-limited analysis as explicit `inconclusive` or
  `error` reports with coverage notices.
- Keep generated, prefix-truncation, malformed, nested-payload,
  extension-opcode, and protocol-5 buffer regressions stable.
- Keep duplicated policy coverage synchronized with the root ModelAudit pickle
  scanner until all root-only compatibility checks have moved into Rust.

## Local Validation

Run these from the repository root after Rust changes:

```bash
cargo fmt --check --manifest-path packages/modelaudit-picklescan/Cargo.toml
cargo check --manifest-path packages/modelaudit-picklescan/Cargo.toml
cargo clippy --manifest-path packages/modelaudit-picklescan/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path packages/modelaudit-picklescan/Cargo.toml
uv run --with maturin maturin develop --manifest-path packages/modelaudit-picklescan/Cargo.toml
uv run pytest packages/modelaudit-picklescan/tests/test_rust_engine.py -q
uv run pytest packages/modelaudit-picklescan/tests -q
```

For performance-sensitive changes, also run:

```bash
uv run --with pytest-benchmark pytest \
  tests/benchmarks/test_picklescan_benchmarks.py \
  --benchmark-json=/tmp/modelaudit-picklescan-benchmark-rust.json -q
```

## Current Structure

The native crate is split by responsibility:

- `rust/src/lib.rs`: small crate root and `_rust` module registration.
- `rust/src/pybridge.rs`: PyO3 entrypoints and scan invocation boundary.
- `rust/src/state.rs`: stack/memo scan state, opcode handling, finding/report
  assembly, and state-level unit tests.
- `rust/src/strings.rs`: suspicious string literal matching and parser helpers.
- `rust/src/nested.rs`: raw/base64/hex nested-pickle detection and nested
  payload validation helpers.
- `rust/src/opcode.rs`: pickle opcode decoding, argument parsing, escape
  handling, and malformed-read errors.
- `rust/src/policy.rs`: dangerous global policy tables.
- `rust/src/report.rs`: Python report conversion/value types.

Keep future module splits behavior-preserving and guarded by the generated
regression corpus. Prefer one module extraction per change so review stays
sharp.
