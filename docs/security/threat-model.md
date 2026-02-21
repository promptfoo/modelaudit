# ModelAudit Threat Model

**Scope:** Static security analysis of AI/ML model files. MIT licensed. Maintained by Promptfoo.

---

## System Overview

ModelAudit performs static analysis on model files before they are loaded into a runtime. It inspects file bytes, opcodes, metadata, and archive contents without executing any model code.

**What it does:**

- Detects dangerous pickle opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL)
- Identifies suspicious globals and imports (os, subprocess, eval, exec, `__import__`)
- Flags path traversal patterns in archive members (`../`, absolute paths to `/etc/passwd`, `/proc/`)
- Detects compression bombs (ratio >100x, per documented thresholds)
- Scans for encoded payloads (base64, hex) and exposed secrets in metadata
- Checks for executable files embedded in archives and unsafe Lambda layers in Keras/TensorFlow models

**What it does not do:** Execute model code, provide runtime sandboxing or dynamic analysis, guarantee detection of all novel attacks, or monitor process behavior.

---

## Trust Boundaries

| Boundary                             | Trust Level           | Notes                                                                |
| ------------------------------------ | --------------------- | -------------------------------------------------------------------- |
| Model files on local disk            | Untrusted             | Primary attack surface; treat all model files as potentially hostile |
| HuggingFace Hub / S3 / GCS downloads | Untrusted             | Supply chain risk; provenance is caller's responsibility             |
| ModelAudit process itself            | Trusted               | Runs with the invoking user's privileges                             |
| ModelAudit dependencies              | Conditionally trusted | Audited via pip-audit and Trivy; see Mitigations                     |

ModelAudit does not make outbound network requests during scanning. Any model file retrieval is performed by the caller before invoking ModelAudit.

---

## Attack Surfaces

**Malicious model files targeting parser bugs.** ModelAudit parses binary formats (pickle, protobuf, ZIP, GGUF) written by an attacker. A crafted file could exploit a vulnerability in Python's `pickle`, `zipfile`, `struct`, or the vendored protobuf stubs.

**Path traversal via archive extraction.** ZIP-based formats (`.keras`, `.zip`) may contain members with `../` or absolute paths. ModelAudit inspects archive members without extracting to disk, but logic errors in path checking could be bypassed.

**Compression bombs.** Highly compressed archives could exhaust memory or disk during size-ratio checks. ModelAudit enforces documented limits based on the >100x ratio threshold.

**Evasion of detection patterns.** Attackers can obfuscate malicious payloads using encoding, polymorphism, or novel pickle opcode sequences not yet covered by detection rules. Static patterns have inherent coverage gaps.

**Supply chain attacks on ModelAudit's own dependencies.** A compromised version of a dependency (e.g., `defusedxml`, `numpy`, `onnx`) could undermine scanner integrity or introduce vulnerabilities during parsing.

---

## Threat Actors

**Model poisoning attackers.** Distribute malicious model files (via HuggingFace Hub, S3 buckets, or direct delivery) targeting users who load them with `torch.load`, `pickle.load`, or similar. Goal: remote code execution on the user's machine.

**Supply chain attackers.** Compromise upstream model repositories or ModelAudit's own dependency graph to insert malicious code that bypasses or subverts scanning.

**Scanner evasion researchers.** Craft inputs that satisfy ModelAudit's checks while still executing malicious code at load time. Goal: build evasion techniques that make ModelAudit results unreliable.

---

## Mitigations

**Static-only analysis.** ModelAudit never calls `pickle.loads`, `torch.load`, or any deserializer on untrusted input. Parsing uses format-specific byte-level readers. This eliminates the largest class of risk.

**defusedxml for XML parsing.** All XML-based formats (ONNX, some TensorFlow variants) use `defusedxml` to prevent XML External Entity (XXE) and billion-laughs attacks.

**Archive member inspection without extraction.** Path traversal checks are applied to member names before any extraction occurs. Archive size ratios are checked against documented bomb thresholds.

**Vendored protobuf stubs.** TensorFlow SavedModel scanning uses vendored `.proto` stubs rather than requiring the ~2 GB TensorFlow package. This reduces the dependency surface and eliminates the TF runtime as an attack vector.

**Dependency auditing.** `pip-audit` runs in CI to detect known CVEs in dependencies. Trivy scans container images. Dependencies are pinned and reviewed on update.

**CodeQL static analysis.** Automated code scanning in CI detects common vulnerability patterns in ModelAudit's own Python source.

**Type checking.** `mypy` enforces type safety across the codebase, reducing the risk of type confusion bugs in binary parsers.

---

## Accepted Risks

**False negatives for novel attack patterns.** Detection rules are based on documented CVEs and known exploits. A new attack technique not yet in detection patterns will pass scanning. Users should not treat a clean scan as a guarantee of safety.

**Parser bugs in binary format readers.** ModelAudit parses GGUF, pickle, and protobuf using custom or third-party code. Bugs in these parsers could cause incorrect results or, in extreme cases, crashes. Fuzzing coverage is incomplete.

**Incomplete format coverage.** Some model formats or serialization variants may not be recognized or may fall through to a generic check. Unrecognized formats produce a warning, not a clean bill of health.

**Privilege of the scanning process.** ModelAudit runs as the invoking user. It does not drop privileges before parsing untrusted files. A parser vulnerability could be exploited at that privilege level.

---

## Security Controls Summary

| Control                            | Tool      | Frequency    |
| ---------------------------------- | --------- | ------------ |
| Dependency CVE scanning            | pip-audit | Every CI run |
| Container image scanning           | Trivy     | Every CI run |
| Static code analysis               | CodeQL    | Every CI run |
| Type safety                        | mypy      | Every CI run |
| Test coverage (unit + integration) | pytest    | Every CI run |
| Format/lint                        | ruff      | Every CI run |
