# ModelAudit Security Rules

## Implementation Status: ✅ INTEGRATED

**Current State**: Rule codes are integrated into scanner output. ModelAudit uses explicit `rule_code` fields where available and message-pattern fallback for legacy checks.

## How It Works

1. **Rule Registry**: 105 rules defined in `modelaudit/rules.py`
2. **Auto-Detection**: Messages are matched to rules via regex patterns
3. **Configuration**: Rules can be suppressed or severity adjusted via `.modelaudit.toml`

## Current Limitations

1. Some legacy checks still rely on message-based fallback matching.
2. Rule taxonomy and severities may evolve as new detections are added.
3. If you find a check without an expected rule code, file an issue with a reproducer.

## All Security Rules (105 Total)

### S100–S199: Module/Import Security

| Code | Severity | Name                     | Pattern                       | Status     |
| ---- | -------- | ------------------------ | ----------------------------- | ---------- |
| S101 | CRITICAL | os module import         | `import os`, `from os import` | ⚠️ Partial |
| S102 | CRITICAL | sys module import        | `import sys`                  | ⚠️ Partial |
| S103 | CRITICAL | subprocess module import | `import subprocess`           | ⚠️ Partial |
| S104 | CRITICAL | eval/exec usage          | `eval(`, `exec(`              | ⚠️ Partial |
| S105 | CRITICAL | compile usage            | `compile(`                    | ⚠️ Partial |
| S106 | CRITICAL | **import** usage         | `__import__(`                 | ⚠️ Partial |
| S107 | HIGH     | importlib usage          | `import importlib`            | ⚠️ Partial |
| S108 | CRITICAL | runpy module usage       | `import runpy`                | ⚠️ Partial |
| S109 | CRITICAL | webbrowser module usage  | `import webbrowser`           | ⚠️ Partial |
| S110 | HIGH     | ctypes module usage      | `import ctypes`               | ⚠️ Partial |

### S200–S299: Execution/Code Injection

| Code | Severity | Name                 | Pattern                            | Status     |
| ---- | -------- | -------------------- | ---------------------------------- | ---------- |
| S201 | CRITICAL | Pickle REDUCE opcode | `pickle.*REDUCE`, `REDUCE.*opcode` | ✅ Working |
| S202 | CRITICAL | Pickle INST opcode   | `pickle.*INST`                     | ✅ Working |
| S203 | CRITICAL | Pickle OBJ opcode    | `pickle.*OBJ`                      | ✅ Working |
| S204 | CRITICAL | Pickle NEWOBJ opcode | `pickle.*NEWOBJ`                   | ✅ Working |
| S205 | HIGH     | Pickle STACK_GLOBAL  | `STACK_GLOBAL`                     | ⚠️ Partial |
| S206 | HIGH     | Pickle GLOBAL        | `GLOBAL.*opcode`                   | ⚠️ Partial |
| S207 | MEDIUM   | Pickle BUILD         | `BUILD.*opcode`                    | ⚠️ Partial |
| S208 | HIGH     | Pickle SETATTR       | `SETATTR`                          | ⚠️ Partial |
| S209 | MEDIUM   | Pickle SETITEM       | `SETITEM`                          | ⚠️ Partial |
| S210 | MEDIUM   | Pickle SETITEMS      | `SETITEMS`                         | ⚠️ Partial |

### S300–S399: Serialization/Deserialization

| Code | Severity | Name                  | Pattern                     | Status        |
| ---- | -------- | --------------------- | --------------------------- | ------------- |
| S301 | HIGH     | socket module usage   | `import socket`             | ❌ No matches |
| S302 | MEDIUM   | requests/urllib usage | `import requests`, `urllib` | ❌ No matches |
| S303 | MEDIUM   | http.client usage     | `http.client`               | ❌ No matches |
| S304 | HIGH     | ftplib usage          | `import ftplib`             | ❌ No matches |
| S305 | HIGH     | telnetlib usage       | `import telnetlib`          | ❌ No matches |
| S306 | MEDIUM   | smtplib usage         | `import smtplib`            | ❌ No matches |
| S307 | MEDIUM   | DNS lookups           | `gethostby`, `dns.`         | ❌ No matches |
| S308 | LOW      | Hardcoded IP          | IP address regex            | ❌ No matches |
| S309 | LOW      | Hardcoded URLs        | `https://`, `http://`       | ❌ No matches |
| S310 | HIGH     | Data exfiltration     | `send.*data`, `upload`      | ❌ No matches |

### S400–S499: File System/Archive Security

| Code | Severity | Name                | Pattern                 | Status        |
| ---- | -------- | ------------------- | ----------------------- | ------------- |
| S401 | MEDIUM   | open() for write    | `open(.*[wax]`          | ❌ No matches |
| S402 | MEDIUM   | pathlib writes      | `Path.*write`           | ❌ No matches |
| S403 | MEDIUM   | shutil operations   | `import shutil`         | ❌ No matches |
| S404 | LOW      | tempfile operations | `import tempfile`       | ❌ No matches |
| S405 | CRITICAL | Path traversal      | `../`, `..\\`           | ⚠️ Partial    |
| S406 | HIGH     | Symlink external    | `symlink.*external`     | ⚠️ Partial    |
| S407 | LOW      | Hidden file access  | `/.`, `\\.`             | ❌ No matches |
| S408 | HIGH     | System file access  | `/etc/`, `\\system32\\` | ❌ No matches |
| S409 | MEDIUM   | Home dir access     | `~/`, `home/`           | ❌ No matches |
| S410 | HIGH     | Archive bomb        | `zip.*bomb`             | ⚠️ Partial    |

### S500–S599: Cryptography/Keys

| Code | Severity | Name                  | Pattern                        | Status        |
| ---- | -------- | --------------------- | ------------------------------ | ------------- |
| S501 | CRITICAL | Windows PE executable | `PE.*executable`, `MZ.*header` | ❌ No matches |
| S502 | CRITICAL | Linux ELF executable  | `ELF.*executable`              | ❌ No matches |
| S503 | CRITICAL | macOS Mach-O          | `Mach-O.*executable`           | ❌ No matches |
| S504 | CRITICAL | Shell script          | `#!/bin/sh`, `#!/bin/bash`     | ❌ No matches |
| S505 | CRITICAL | Batch script          | `.bat`, `.cmd`                 | ❌ No matches |
| S506 | CRITICAL | PowerShell            | `.ps1`, `PowerShell`           | ❌ No matches |
| S507 | HIGH     | Python embedded       | `python.*script`               | ❌ No matches |
| S508 | HIGH     | JavaScript            | `javascript:`, `<script`       | ❌ No matches |
| S509 | HIGH     | WebAssembly           | `.wasm`, `WebAssembly`         | ❌ No matches |
| S510 | MEDIUM   | JIT/TorchScript       | `TorchScript`, `torch.jit`     | ❌ No matches |

### S600–S699: Data/Model Integrity

| Code | Severity | Name            | Pattern                  | Status        |
| ---- | -------- | --------------- | ------------------------ | ------------- |
| S601 | MEDIUM   | Base64 encoded  | `base64`, `b64decode`    | ⚠️ Partial    |
| S602 | MEDIUM   | Hex encoded     | `hex.*decode`, `fromhex` | ❌ No matches |
| S603 | LOW      | zlib compressed | `zlib`, `compress`       | ❌ No matches |
| S604 | HIGH     | Encrypted code  | `encrypt`, `obfuscat`    | ❌ No matches |
| S605 | MEDIUM   | Unicode tricks  | `unicode.*escape`        | ❌ No matches |
| S606 | LOW      | ROT13/Caesar    | `rot13`, `caesar`        | ❌ No matches |
| S607 | MEDIUM   | XOR obfuscation | `xor.*encrypt`           | ❌ No matches |

### S700–S799: Model-Specific Vulnerabilities

| Code | Severity | Name              | Pattern                             | Status        |
| ---- | -------- | ----------------- | ----------------------------------- | ------------- |
| S701 | MEDIUM   | API key           | `api[_-]?key`, `apikey`             | ⚠️ Partial    |
| S702 | HIGH     | Password          | `password`, `passwd`                | ⚠️ Partial    |
| S703 | HIGH     | Private key       | `BEGIN.*PRIVATE`, `private[_-]?key` | ❌ No matches |
| S704 | HIGH     | AWS credentials   | `AKIA[0-9A-Z]{16}`                  | ❌ No matches |
| S705 | HIGH     | Cloud credentials | `azure.*key`, `gcp.*credential`     | ❌ No matches |
| S706 | HIGH     | Database URL      | `mongodb://`, `postgresql://`       | ❌ No matches |
| S707 | MEDIUM   | JWT token         | `eyJ[A-Za-z0-9_-]+\.`               | ❌ No matches |
| S708 | MEDIUM   | OAuth token       | `oauth`, `access[_-]?token`         | ❌ No matches |
| S709 | LOW      | Webhook URL       | `webhook`, `hook.*url`              | ❌ No matches |
| S710 | LOW      | High entropy      | `entropy.*high`                     | ⚠️ Partial    |

### S800–S899: Cloud/Remote Operations

| Code | Severity | Name                 | Pattern                | Status        |
| ---- | -------- | -------------------- | ---------------------- | ------------- |
| S801 | LOW      | Weight distribution  | `weight.*distribution` | ⚠️ Partial    |
| S802 | LOW      | Outlier neurons      | `outlier.*neuron`      | ⚠️ Partial    |
| S803 | LOW      | Dissimilar vectors   | `dissimilar.*weight`   | ⚠️ Partial    |
| S804 | LOW      | Excessive dimensions | `excessive.*dimension` | ❌ No matches |
| S805 | LOW      | Unusual layers       | `unusual.*layer`       | ❌ No matches |
| S806 | MEDIUM   | Hidden layers        | `hidden.*layer`        | ❌ No matches |
| S807 | HIGH     | Backdoor patterns    | `backdoor`, `trojan`   | ❌ No matches |
| S808 | MEDIUM   | Weight tampering     | `weight.*manipulat`    | ❌ No matches |
| S809 | LOW      | Custom activations   | `custom.*activation`   | ❌ No matches |
| S810 | MEDIUM   | Layers with code     | `lambda.*layer`        | ❌ No matches |

### S900–S999: Structural/Format Issues

| Code | Severity | Name                | Pattern                | Status        |
| ---- | -------- | ------------------- | ---------------------- | ------------- |
| S901 | LOW      | File type mismatch  | `type.*mismatch`       | ⚠️ Partial    |
| S902 | LOW      | Corrupted structure | `corrupt`, `malformed` | ❌ No matches |
| S903 | LOW      | Invalid magic bytes | `magic.*bytes`         | ❌ No matches |
| S904 | LOW      | Excessive file size | `file.*too.*large`     | ⚠️ Partial    |
| S905 | LOW      | Suspicious metadata | `suspicious.*metadata` | ❌ No matches |
| S906 | LOW      | Unknown extension   | `unknown.*extension`   | ❌ No matches |
| S907 | MEDIUM   | Multiple formats    | `multiple.*format`     | ❌ No matches |
| S908 | HIGH     | Polyglot file       | `polyglot`             | ❌ No matches |

### S1000–S1110: Network/Communication

| Code  | Severity | Name               | Pattern                         | Status        |
| ----- | -------- | ------------------ | ------------------------------- | ------------- |
| S1001 | CRITICAL | Blacklisted model  | `blacklist`, `malicious.*model` | ⚠️ Partial    |
| S1002 | CRITICAL | Malicious hash     | `malicious.*hash`               | ❌ No matches |
| S1003 | HIGH     | Typosquatting      | `typosquat`                     | ❌ No matches |
| S1004 | LOW      | Unsigned model     | `unsigned`, `no.*signature`     | ❌ No matches |
| S1005 | HIGH     | Invalid signature  | `invalid.*signature`            | ❌ No matches |
| S1006 | LOW      | Expired cert       | `expired.*cert`                 | ❌ No matches |
| S1007 | MEDIUM   | Untrusted source   | `untrusted.*source`             | ❌ No matches |
| S1008 | LOW      | License issue      | `license.*incompatib`           | ❌ No matches |
| S1009 | LOW      | GPL violation      | `GPL.*proprietary`              | ❌ No matches |
| S1010 | LOW      | Missing provenance | `missing.*provenance`           | ❌ No matches |

| Code  | Severity | Name             | Pattern                         | Status        |
| ----- | -------- | ---------------- | ------------------------------- | ------------- |
| S1101 | HIGH     | PyTorch unsafe   | `torch.load`, `unsafe.*pytorch` | ❌ No matches |
| S1102 | MEDIUM   | TF SavedModel    | `savedmodel`                    | ❌ No matches |
| S1103 | MEDIUM   | Keras Lambda     | `Lambda.*layer`                 | ❌ No matches |
| S1104 | LOW      | ONNX version     | `onnx.*version`                 | ❌ No matches |
| S1105 | MEDIUM   | JAX compilation  | `jax.*compilation`              | ❌ No matches |
| S1106 | MEDIUM   | MXNet custom ops | `mxnet.*custom`                 | ❌ No matches |
| S1107 | MEDIUM   | PaddlePaddle     | `paddle.*dynamic`               | ❌ No matches |
| S1108 | MEDIUM   | CoreML custom    | `coreml.*custom`                | ❌ No matches |
| S1109 | MEDIUM   | TensorRT plugins | `tensorrt.*plugin`              | ❌ No matches |
| S1110 | LOW      | GGUF/GGML        | `gguf`, `ggml`                  | ❌ No matches |

## Status Summary

- ✅ Rule codes are emitted in scanner output and supported by CLI suppression/severity overrides.
- ⚠️ Pattern fallback remains in place for legacy message-only detections.
- 🔄 Coverage tuning is ongoing as new scanners and CVE checks are added.

## Configuration

Rule configuration is supported:

```toml
# .modelaudit.toml
suppress = ["S710", "S801"]  # Suppress rules (if they match)

[severity]
S301 = "HIGH"  # Change severity

[ignore]
"tests/**" = ["S101"]  # File-specific suppression
```

## CLI Commands

```bash
modelaudit rules          # List all rules
modelaudit rules S101     # Explain specific rule
modelaudit scan --suppress S101 --severity S301=HIGH
```

## Next Steps

1. Expand explicit `rule_code` coverage where fallback matching is still used.
2. Add targeted regression tests for newly added rule mappings.
3. Keep rule descriptions and examples aligned with scanner output text.

## Conclusion

The rule system is integrated and configurable today. Coverage and tuning continue as detection logic evolves.
