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
- It does not redact or mask local evidence, reports, diagnostics, logs, or cache metadata, including secrets and credentials. Raw output is intentional; see the [security policy](../../SECURITY.md#raw-local-output-no-redaction).
- Coverage depends on file format support and installed optional dependencies.

## Operational assumptions

- Artifacts may be untrusted, so scans should run in isolated CI runners or dedicated analysis environments.
- Security decisions should combine scan output with provenance checks (source trust, signatures, checksums, release process).
- High-risk findings should block promotion until reviewed and resolved.

## Metadata extraction safety

- `modelaudit metadata` defaults to non-deserializing extraction for untrusted inputs.
- `--trust-loaders` may deserialize model content and should only be used on trusted artifacts in isolated environments.

## Local scan policy files

- Local `.modelaudit.toml` or `pyproject.toml` policy files are not applied implicitly during scans.
- Interactive text scans may offer to trust a detected local policy file for later scans on that same config directory.
- Remembered trust is stored in the local ModelAudit cache and is invalidated automatically if the config file changes.
- CI and other non-interactive scans should use explicit configuration rather than relying on remembered local trust.

### Reviewed README citations

An operator can attach a review reason to an exact S309 URL occurrence in a complete, non-executable `README.md`. Ordinary README links already report as informational. A matched review records the original detector severity and the operator’s decision in JSON and SARIF. URLs flagged for credential material or incomplete credential inspection stay ineligible. Supply the decision file explicitly in interactive scans and CI.

```bash
modelaudit scan README.md --reviewed-citations /path/to/reviews.json --format json
```

The following decision applies to a one-line README containing `Source (PDF [paper](https://docs.example.com/citation))` and a final LF. The check and its issue retain the URL, detector evidence, original severity and operator's reason. The decision applies to that occurrence in any byte-identical standalone file named `README.md` included in the opted-in scan. A different file role, changed bytes or another URL occurrence requires a separate review. An explicit S309 severity override takes precedence.

Hugging Face repository scans with `--stream` stage regular files under their repository names. A direct download may return a cache symlink. To apply a review locally, copy the complete source to a regular `README.md` and verify its SHA-256 against the decision.

```json
{
  "version": 1,
  "sites": [
    {
      "rule": "S309",
      "type": "url_detected",
      "role": "readme_documentation",
      "sha256": "d982c9db70ea770328a25b55c731195d83bfd9356a31285df049aa204b1daff0",
      "position": 20,
      "fingerprint": "text-doc-network:07eead2d17310844bb73e553",
      "url": "https://docs.example.com/citation",
      "raw_span": "https://docs.example.com/citation))",
      "related_sha256": "a39f4bd227e644d7dcd5072c527ff793596a2fd3b1a59db3a8aac25c877c0989",
      "reason": "Reviewed the paper citation and its associated domain observation."
    }
  ]
}
```

Use the SHA-256 of the complete README bytes. In the JSON report, copy `position`, `evidence_fingerprint` and `url` from the selected S309 check's `details`. Read `raw_span` from those bytes at `evidence_location.span_start:span_end`, including any Markdown punctuation, and decode it as UTF-8. To bind the associated observations, set `related` to `details.get("deduplicated_related_findings", [])` and compute `hashlib.sha256(json.dumps(related, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()`.

## Interpreting scan results

- `CRITICAL`: High-confidence risk indicator. Block release/use by default.
- `WARNING`: Potential risk. Require manual review.
- `INFO`: Context signal. Useful for triage and audit trails.

For dashboards and aggregate corpus scans, filter security-alert views to
`WARNING` and `CRITICAL` findings by default. INFO rows may include benign
explainability notices, budget notes, or structural context; group them by code
or keep them in an audit/detail view rather than counting each row as a blocker.
Some compatibility findings intentionally include a secondary rule-code row for
dashboards that rely on older rule identifiers; these rows carry `supporting_rule_code=true` in details and
should be excluded from primary issue counts when de-duplicating.

In a README, ModelAudit reports documented network activity and public cryptocurrency
receiving addresses as informational. JSON retains each detector's severity in the
finding details alongside the reported severity and source location. Exposed credentials,
including credentials in URLs, can still produce alerts. An incomplete scan can still
exit with code 2.

Exit codes:

- `0`: No issues found
- `1`: Issues found
- `2`: Scan error

## Recommended usage pattern

1. Scan artifacts before loading or serving them.
2. Treat `CRITICAL` findings as release blockers.
3. Keep scanner dependencies current (`modelaudit[all]` for broad portable coverage; ONNX is included on Python 3.10-3.12; add `modelaudit[tensorflow]` on Python 3.11-3.12 only for TensorFlow runtime-dependent paths).
4. Pair scanning with provenance and runtime controls.

## Reporting gaps or misses

If you find a false negative or a false positive, report it with a reproducible sample as described in `CONTRIBUTING.md`.
For sensitive bypass details, use the private reporting flow in `SECURITY.md`.
