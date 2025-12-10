# Security Check Guidelines

**CRITICAL: Only implement checks that represent real, documented security threats.**

## Acceptable Checks

Keep these security checks:

- **CVE-documented vulnerabilities**: Any check with a specific CVE number
  - CVE-2025-32434: PyTorch pickle RCE
  - CVE-2025-54412/54413/54886: skops RCE
- **Real-world attacks**: Documented exploits that have compromised systems
- **Code execution vectors**: eval, exec, os.system, subprocess, \_\_import\_\_, compile
- **Path traversal**: ../, absolute paths to sensitive files (/etc/passwd, /proc/)
- **Compression bombs**: Documented thresholds (compression ratio >100x)
- **Dangerous opcodes**: Pickle REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL
- **Exposed secrets**: API keys, passwords, tokens in model metadata

## Unacceptable Checks - Remove These

- **Arbitrary thresholds**: "More than N items could be a DoS" without CVE
- **Format validation**: Checking alignment, field counts, block sizes, version numbers
- **"Seems suspicious" heuristics**: Large dimensions, deep nesting, long strings without exploit evidence
- **Theoretical DoS**: "This could potentially be slow" without documented attacks
- **Defensive programming**: "Better safe than sorry" checks that generate false positives

## Uncertain Cases - Downgrade to INFO

- Large counts/sizes that might indicate issues but have no CVE (e.g., >100k files in archive)
- Unusual patterns that could be legitimate (e.g., unexpected metadata keys)
- Informational warnings that don't indicate actual compromise

## The Standard

**If challenged with "Show me the CVE or documented attack", you must be able to provide evidence. No evidence = remove the check.**

## Security Detection Focus

### Dangerous Patterns

- Dangerous imports (os, sys, subprocess, eval, exec)
- Pickle opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL)
- Encoded payloads (base64, hex)
- Unsafe Lambda layers (Keras/TensorFlow)
- Executable files in archives
- Blacklisted model names
- Weight distribution anomalies (outlier neurons, dissimilar weight vectors)
- Model metadata security issues (exposed secrets, suspicious URLs, dangerous code references)

### Common Suspicious Patterns

```python
SUSPICIOUS_GLOBALS = {
    "os": "*",
    "subprocess": "*",
    "eval": "*",
    "exec": "*",
    "__import__": "*"
}

DANGEROUS_OPCODES = ["REDUCE", "INST", "OBJ", "NEWOBJ", "STACK_GLOBAL"]
```
