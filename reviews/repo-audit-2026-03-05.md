# Repo Audit 2026-03-05

Review scope: bugs, correctness issues, and security weaknesses found during a repository audit.

## Findings

1. Critical: `modelaudit/scanners/oci_layer_scanner.py`
   Absolute OCI layer references were treated as trusted and opened directly. This was resolved by PR `#659`, which rejects absolute layer paths so manifests cannot point to arbitrary readable host tarballs outside the OCI layout.

2. High: `modelaudit/telemetry.py`
   Telemetry payloads include raw local paths, issue locations, and full download URLs in addition to hashed identifiers. This can leak private filesystem structure and presigned query strings.

3. High: `modelaudit/auth/config.py`
   Auth config falls back to `/tmp/promptfoo/promptfoo.yaml` and writes bearer tokens with plain file creation semantics. That exposes secrets to other local users and symlink abuse in a world-writable parent directory.

4. High: `modelaudit/scanners/pytorch_zip_scanner.py`
   Several ZIP members are read into single in-memory `bytes` objects with very large limits, making memory exhaustion possible with crafted archives.

5. High: `modelaudit/scanners/sevenzip_scanner.py`
   `max_extract_size` is enforced only after extraction, so oversized or bomb-like 7z payloads can fill disk before the scanner notices.

6. Medium: `modelaudit/utils/__init__.py`
   `sanitize_archive_path()` resolves the caller-provided base directory on the real filesystem. If predictable temp roots like `/tmp/extract` are symlinked, traversal checks can be bypassed.

7. Medium: `modelaudit/telemetry.py`
   Telemetry transport initialization is cached once per process. If telemetry is first touched while disabled, enabling it later leaves `_posthog_client` unset and telemetry unavailable for the rest of the process.

## Repro Notes

- Telemetry singleton bug:
  `uv run pytest -q tests/test_debug_command.py::TestDebugCommand::test_debug_command_success tests/test_telemetry_decoupling.py::TestTelemetryFunctionalityWhenWorking::test_telemetry_works_when_enabled_and_available -vv --maxfail=1`

- Archive path sanitizer symlink bypass:
  `sanitize_archive_path("../etc/passwd", symlinked_tmp_extract)` returned a safe result when the temp root was a symlink to `/`.
