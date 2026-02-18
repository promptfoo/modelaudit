# Security Check Guidelines

**CRITICAL: Only implement checks that represent real, documented security threats.**

## Acceptable Checks

Keep these security checks:

- **CVE-documented vulnerabilities**: Any check with a specific CVE number
- **Real-world attacks**: Documented exploits that have compromised systems
- **Code execution vectors**: Known dangerous imports and function calls
- **Path traversal**: Directory traversal and sensitive file access
- **Compression bombs**: Documented thresholds (compression ratio >100x)
- **Dangerous opcodes**: Known pickle deserialization attack patterns
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

Refer to the source code in `modelaudit/scanners/` for current detection patterns and implementations. Scanners cover:

- Pickle deserialization attacks (dangerous imports and opcodes)
- Encoded/obfuscated payloads
- Unsafe Keras/TensorFlow layer serialization
- Executable files in archives
- Weight distribution anomalies
- Model metadata security issues
- Blacklisted model names
