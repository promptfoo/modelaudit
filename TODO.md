# ModelAudit Security Improvements TODO

Based on scanning known malicious models, here are critical security gaps that need to be addressed.

## 1. Add webbrowser.open Detection as CRITICAL

### Problem
Models containing `webbrowser.open` (like drhyrum/bert-tiny-torch-picklebomb) are only flagged as WARNING despite being able to open malicious URLs on model load.

### Implementation
- Add `b"webbrowser"` to the dangerous_patterns list in `_scan_for_dangerous_patterns()`
- Ensure it triggers CRITICAL severity
- Check for variations: `webbrowser.open`, `webbrowser.open_new`, `webbrowser.open_new_tab`

### Validation
```bash
# Should detect as CRITICAL
rye run modelaudit hf://drhyrum/bert-tiny-torch-picklebomb
rye run modelaudit hf://Frase/tiny-bert-model-unsafe

# Expected: CRITICAL issue for "webbrowser" pattern
```

## 2. Add runpy Module Detection

### Problem
Models using `runpy.run_module` or `runpy.run_path` (like mkiani/gpt2-runpy) show 0 issues.

### Implementation
- Add `b"runpy"` to dangerous_patterns
- Detect specific methods: `run_module`, `run_path`, `_run_module_as_main`
- Flag as CRITICAL (arbitrary code execution)

### Validation
```bash
# Should detect as CRITICAL
rye run modelaudit hf://mkiani/gpt2-runpy

# Expected: CRITICAL issue for "runpy" pattern
```

## 3. Add importlib Detection

### Problem
Dynamic imports via `importlib` can be used to load malicious modules.

### Implementation
- Add `b"importlib"` to dangerous_patterns
- Detect: `import_module`, `__import__`, `reload`
- Consider context to reduce false positives

### Validation
```bash
# Test with models that use importlib for attacks
# Create test pickle with importlib.import_module('os').system('echo pwned')
```

## 4. Improve os/subprocess Detection

### Problem
mkiani/gpt2-system shows 0 issues despite using system calls.

### Implementation
- Enhance detection for:
  - `os.system`, `os.popen`, `os.spawn*`
  - `subprocess.call`, `subprocess.run`, `subprocess.Popen`
  - `commands.getoutput` (Python 2 legacy)
- Check for obfuscated variants

### Validation
```bash
# Should detect as CRITICAL
rye run modelaudit hf://mkiani/gpt2-system

# Expected: CRITICAL issue for "system" or "subprocess" patterns
```

## 5. Fix PyTorch ZIP Scanner File Detection

### Problem
When scanning pytorch_model.bin files directly, they show as "Clean" with 0 bytes scanned.

### Implementation
- Fix the PyTorchZipScanner's can_handle() method for .bin files
- Ensure ZIP detection works for PyTorch archives
- Properly extract and scan embedded pickles

### Validation
```bash
# Should properly scan the file
rye run modelaudit /path/to/pytorch_model.bin

# Expected: Should scan >0 bytes and detect issues in embedded pickles
```

## 6. Add compile() and eval() Variants Detection

### Problem
Not detecting all code execution patterns comprehensively.

### Implementation
- Detect `compile()` with `exec` mode
- Detect `eval()` with `__builtins__` access
- Detect `type()` usage for class creation with malicious methods
- Detect `globals()` and `locals()` manipulation

### Validation
```bash
# Test with models using eval/exec variants
rye run modelaudit hf://mkiani/gpt2-exec

# Expected: CRITICAL issues for code execution patterns
```

## 7. Enhance TensorFlow SavedModel Scanner

### Problem
mkiani/unsafe-saved-model shows 0 issues despite being documented as unsafe.

### Implementation
- Create or enhance SavedModel scanner
- Detect custom ops with execution capabilities
- Check for unsafe function definitions
- Scan for Lambda layers with arbitrary code

### Validation
```bash
# Should detect issues
rye run modelaudit hf://mkiani/unsafe-saved-model

# Expected: Issues detected in SavedModel format
```

## 8. Improve Keras Scanner for .keras Files

### Problem
mkiani/unsafe-keras only shows file type mismatch warning, not security issues.

### Implementation
- Handle both HDF5 and ZIP-based .keras formats
- Detect unsafe Lambda layers
- Detect custom objects with __call__ methods
- Check for arbitrary code in layer configs

### Validation
```bash
# Should detect unsafe patterns
rye run modelaudit hf://mkiani/unsafe-keras

# Expected: CRITICAL issues for unsafe Lambda layers or custom objects
```

## 9. Add Timeout Configuration

### Problem
Large models (like mkiani/gpt2-exec) timeout during scanning.

### Implementation
- Add --timeout flag to CLI
- Implement progressive scanning for large files
- Add ability to skip large files with warning
- Implement chunked scanning for huge models

### Validation
```bash
# Should complete within timeout
rye run modelaudit hf://mkiani/gpt2-exec --timeout 60

# Expected: Either completes or provides partial results with timeout warning
```

## 10. Add Comprehensive GLOBAL Opcode Analysis

### Problem
Not catching all dangerous GLOBAL opcodes that reference malicious modules.

### Implementation
- Expand SUSPICIOUS_GLOBALS dictionary
- Add pattern matching for GLOBAL opcodes:
  - `nt.system`, `posix.system`, `posix.popen`
  - `urllib.request.urlopen`, `requests.get`
  - `socket.socket`, `ssl.wrap_socket`
- Check GLOBAL + REDUCE combinations

### Validation
```bash
# Test with known pickle bombs
rye run modelaudit hf://drhyrum/bert-tiny-torch-picklebomb

# Expected: CRITICAL issues for dangerous GLOBAL opcodes
```

## 11. Add Base64/Hex Encoded Payload Detection

### Problem
Malicious payloads can be hidden in base64/hex encoded strings.

### Implementation
- Detect large base64/hex strings in pickles
- Attempt to decode and scan decoded content
- Flag suspicious encoded content patterns
- Check for `base64.b64decode`, `binascii.unhexlify`

### Validation
```bash
# Test with models containing encoded payloads
# Create test case with base64.b64decode(malicious_payload)

# Expected: WARNING or CRITICAL for encoded suspicious content
```

## 12. Create Blacklist for Known Malicious Models

### Problem
Known malicious models should be immediately flagged.

### Implementation
- Maintain a list of known malicious model hashes
- Check SHA256 of scanned files against blacklist
- Add option to update blacklist from threat intelligence
- Flag blacklisted models as CRITICAL immediately

### Validation
```bash
# Test with known malicious models
rye run modelaudit hf://drhyrum/bert-tiny-torch-picklebomb

# Expected: CRITICAL issue "Known malicious model (blacklisted)"
```

## 13. Add URL/Domain Severity Escalation

### Problem
URLs are only flagged as WARNING, but malicious URLs should be CRITICAL.

### Implementation
- Check URLs against threat intelligence feeds
- Escalate to CRITICAL for:
  - Known malicious domains
  - Suspicious URL patterns (/hack, /exploit, /shell)
  - URLs with IP addresses instead of domains
  - URLs with suspicious ports

### Validation
```bash
# Test with model containing suspicious URL
rye run modelaudit hf://drhyrum/bert-tiny-torch-picklebomb
# Contains: https://pramuwaskito.org/hacker/q

# Expected: CRITICAL issue for suspicious URL pattern (/hacker/)
```

## 14. Add exec/eval String Detection

### Problem
Our fix added pattern detection, but models might use string-based execution.

### Implementation
- Detect string literals containing code patterns
- Look for: `"exec("`, `"eval("`, `"compile("`, `"__import__("` 
- Check for obfuscated strings that decode to these patterns
- Scan for chr() sequences building malicious strings

### Validation
```bash
# Test with models using string-based execution
rye run modelaudit hf://mkiani/gpt2-exec

# Expected: CRITICAL issues for code execution strings
```

## 15. Improve Smart Detection Override

### Problem
ML context confidence is allowing some malicious patterns to be downgraded.

### Implementation
- Add explicit bypass list for patterns that should ALWAYS be CRITICAL
- Never downgrade: `eval`, `exec`, `system`, `subprocess`, `webbrowser`
- Add --strict flag to disable smart detection
- Log when smart detection downgrades a finding

### Validation
```bash
# Test with --strict flag
rye run modelaudit hf://ykilcher/totally-harmless-model --strict

# Expected: All dangerous patterns flagged as CRITICAL without downgrading
```

## Testing Strategy

### Create Test Suite
1. Create a comprehensive test suite with minimal malicious pickles for each attack vector
2. Each test should be <1KB to avoid timeouts
3. Test both direct patterns and obfuscated variants

### Validation Script
```python
# test_malicious_detection.py
test_cases = [
    ("webbrowser_test.pkl", "CRITICAL", "webbrowser"),
    ("runpy_test.pkl", "CRITICAL", "runpy"),
    ("eval_exec_test.pkl", "CRITICAL", "eval"),
    ("subprocess_test.pkl", "CRITICAL", "subprocess"),
    ("importlib_test.pkl", "CRITICAL", "importlib"),
]

for filename, expected_severity, expected_pattern in test_cases:
    result = scan_file(filename)
    assert any(i.severity == expected_severity and expected_pattern in i.message 
              for i in result.issues)
```

### Performance Requirements
- Scanning should complete within 30 seconds for models <1GB
- Memory usage should stay under 2GB for typical models
- Should handle malformed files gracefully without crashing

## Priority Order

### High Priority (Security Critical)
1. Add webbrowser.open detection ⚨
2. Add runpy module detection ⚨
3. Improve os/subprocess detection ⚨
4. Fix PyTorch ZIP scanner ⚨

### Medium Priority (Coverage)
5. Add importlib detection
6. Enhance TensorFlow SavedModel scanner
7. Improve Keras scanner
8. Add comprehensive GLOBAL opcode analysis

### Low Priority (Enhancements)
9. Add timeout configuration
10. Add base64/hex payload detection
11. Create model blacklist
12. Add URL severity escalation

## Success Metrics

- **Detection Rate**: Should detect 100% of known malicious models from models.md
- **False Positive Rate**: Should remain <5% on legitimate models
- **Performance**: Should scan 95% of models within 30 seconds
- **Coverage**: Should support all major ML formats (pickle, PyTorch, Keras, SavedModel, ONNX)

## Notes

- Each feature should include unit tests
- Document new detection patterns in the README
- Consider adding a --explain flag to show why something was flagged
- Maintain backwards compatibility with existing scans