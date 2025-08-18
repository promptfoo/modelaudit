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

---

# False Positive & False Negative Fixes

## Critical False Positive Fixes

### FP-1: Hardcoded Password False Positive in Binary Data
**Issue**: Safe BERT models trigger "Hardcoded Password" detection on random binary data
- **Root Cause**: Pattern `pwd\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?` matches random bytes in model weights
- **Affected Files**: google/bert_uncased_L-2_H-128_A-2 (and other legitimate models)
- **Location**: `modelaudit/secrets_detector.py:54`

**Fix Implementation**:
```python
# In secrets_detector.py, add context validation
def is_likely_text_context(data: bytes, position: int, window: int = 50) -> bool:
    """Check if surrounding context looks like text, not binary weights"""
    start = max(0, position - window)
    end = min(len(data), position + window)
    context = data[start:end]
    
    # Count printable ASCII characters
    ascii_count = sum(1 for b in context if 32 <= b < 127)
    text_ratio = ascii_count / len(context) if context else 0
    
    # Also check for null bytes (common in binary but not text)
    null_count = context.count(b'\x00')
    
    return text_ratio > 0.7 and null_count < 2

def validate_password_detection(match, data, position):
    """Additional validation for password patterns"""
    # Skip if in binary context
    if not is_likely_text_context(data, position):
        return False
    
    # Check entropy (real passwords have moderate entropy)
    value = match.group(1) if hasattr(match, 'group') else match
    entropy = calculate_shannon_entropy(value)
    
    # Binary data has very high or very low entropy
    # Passwords typically have entropy between 2.5 and 4.0
    if entropy < 2.0 or entropy > 4.5:
        return False
    
    return True
```

**Validation**:
```bash
# Should NOT trigger false positives
rye run modelaudit hf://google/bert_uncased_L-2_H-128_A-2
# Expected: No "Hardcoded Password" issues

# Should still detect real passwords
echo 'password="mysecretpass123"' > test_password.txt
rye run modelaudit test_password.txt
# Expected: CRITICAL issue for hardcoded password
```

### FP-2: Excessive MANY_DANGEROUS_OPCODES Warnings
**Issue**: Safe models trigger warnings for having >20 dangerous opcodes
- **Root Cause**: Threshold of 20 is too low for legitimate models
- **Affected**: hf-internal-testing/tiny-random-bert (10 warnings), prajjwal1/bert-tiny (5 warnings)
- **Location**: `modelaudit/scanners/pickle_scanner.py:692-696`

**Fix Implementation**:
```python
# In pickle_scanner.py
# Current code around line 692:
# if dangerous_opcode_count > 20:  # CHANGE THIS

# New implementation:
DANGEROUS_OPCODE_WARNING_THRESHOLD = 100  # Increase from 20
DANGEROUS_OPCODE_RATIO_THRESHOLD = 0.15   # Add ratio check

def should_warn_dangerous_opcodes(opcodes_data):
    """Smarter detection of suspicious opcode patterns"""
    dangerous_count = opcodes_data.get('dangerous_opcode_count', 0)
    total_count = opcodes_data.get('total_opcodes', 0)
    ml_confidence = opcodes_data.get('ml_confidence', 0)
    
    # Don't warn if ML confidence is low
    if ml_confidence < 0.6:  # Increase from 0.3
        return False
    
    # Check absolute count
    if dangerous_count < DANGEROUS_OPCODE_WARNING_THRESHOLD:
        return False
    
    # Check ratio (dangerous should be significant portion)
    if total_count > 0:
        ratio = dangerous_count / total_count
        if ratio < DANGEROUS_OPCODE_RATIO_THRESHOLD:
            return False
    
    # Check for specific malicious patterns
    if has_malicious_opcode_sequence(opcodes_data):
        return True
    
    return dangerous_count > DANGEROUS_OPCODE_WARNING_THRESHOLD

def has_malicious_opcode_sequence(opcodes_data):
    """Check for known malicious sequences"""
    sequences = opcodes_data.get('sequences', [])
    
    MALICIOUS_SEQUENCES = [
        ['GLOBAL', 'exec'],
        ['GLOBAL', 'eval'],
        ['GLOBAL', 'system'],
        ['GLOBAL', 'subprocess'],
        ['GLOBAL', 'webbrowser'],
    ]
    
    for mal_seq in MALICIOUS_SEQUENCES:
        if any(all(op in seq for op in mal_seq) for seq in sequences):
            return True
    
    return False
```

**Validation**:
```bash
# Should NOT trigger warnings for safe models
rye run modelaudit hf://hf-internal-testing/tiny-random-bert
# Expected: No MANY_DANGEROUS_OPCODES warnings

# Should still detect real threats
rye run modelaudit hf://drhyrum/bert-tiny-torch-picklebomb
# Expected: CRITICAL issues for actual malicious patterns
```

## Critical False Negative Fixes

### FN-1: HuggingFace Adapter Not Downloading Model Files
**Issue**: mkiani/gpt2-exec shows 0 issues because only config.json is downloaded
- **Root Cause**: HF adapter doesn't explicitly request weight files
- **Location**: `modelaudit/utils/huggingface.py:132`

**Fix Implementation**:
```python
# In huggingface.py, modify download_model function
from huggingface_hub import list_repo_files

def download_model(url: str, cache_dir: Optional[Path] = None, show_progress: bool = True) -> Path:
    """Download model ensuring we get actual model files"""
    
    # Parse URL to get repo_id
    repo_id, revision = parse_huggingface_url(url)
    
    # List all files in repo
    try:
        repo_files = list_repo_files(repo_id)
    except Exception:
        repo_files = []
    
    # Identify model weight files
    MODEL_EXTENSIONS = {'.bin', '.pt', '.pth', '.pkl', '.safetensors', 
                       '.onnx', '.pb', '.h5', '.keras', '.tflite', '.ckpt'}
    
    model_files = [f for f in repo_files 
                   if any(f.endswith(ext) for ext in MODEL_EXTENSIONS)]
    
    # Download with explicit file patterns
    if model_files:
        # Download specific model files
        local_path = snapshot_download(
            repo_id=repo_id,
            revision=revision,
            cache_dir=cache_dir,
            allow_patterns=model_files,  # Explicitly request model files
            tqdm_class=tqdm if show_progress else None,
        )
    else:
        # Fallback: download everything if no model files identified
        logger.warning(f"No model files found in {repo_id}, downloading all files")
        local_path = snapshot_download(
            repo_id=repo_id,
            revision=revision,
            cache_dir=cache_dir,
            tqdm_class=tqdm if show_progress else None,
        )
    
    # Validate we got model files
    downloaded_path = Path(local_path)
    found_models = False
    for ext in MODEL_EXTENSIONS:
        if list(downloaded_path.glob(f"*{ext}")):
            found_models = True
            break
    
    if not found_models:
        logger.warning(f"No model files found after download for {repo_id}")
    
    return downloaded_path
```

**Validation**:
```bash
# Should now detect issues in exec variant models
rye run modelaudit hf://mkiani/gpt2-exec
# Expected: CRITICAL issues detected

rye run modelaudit hf://mkiani/gpt2-runpy
# Expected: CRITICAL issues detected

rye run modelaudit hf://mkiani/gpt2-system
# Expected: CRITICAL issues detected
```

### FN-2: Missing exec/eval Detection Patterns
**Issue**: Some exec variants not detected even when files are scanned
- **Root Cause**: Patterns might be obfuscated or use alternative methods
- **Location**: `modelaudit/scanners/pickle_scanner.py`

**Fix Implementation**:
```python
# Add to dangerous_patterns in pickle_scanner.py
ENHANCED_DANGEROUS_PATTERNS = [
    # Direct patterns
    b"exec",
    b"eval",
    b"compile",
    b"__import__",
    
    # Alternative execution methods
    b"runpy",
    b"importlib",
    b"execfile",
    
    # Obfuscated patterns (hex for 'exec')
    b"\x65\x78\x65\x63",
    
    # Common obfuscation techniques
    b"chr(101)",  # Building 'e' in exec
    b"chr(120)",  # Building 'x' in exec
    
    # Base64 variants of 'exec' and 'eval'
    b"ZXhlYw",  # base64('exec')
    b"ZXZhbA",  # base64('eval')
]

def detect_obfuscated_execution(data: bytes) -> List[Issue]:
    """Detect obfuscated code execution attempts"""
    issues = []
    
    # Check for string concatenation building dangerous commands
    concat_patterns = [
        rb"['\"]e['\"].*?['\"]x['\"].*?['\"]e['\"].*?['\"]c['\"]",  # "e"+"x"+"e"+"c"
        rb"['\"]e['\"].*?['\"]v['\"].*?['\"]a['\"].*?['\"]l['\"]",  # "e"+"v"+"a"+"l"
    ]
    
    for pattern in concat_patterns:
        if re.search(pattern, data):
            issues.append(create_critical_issue(
                "Obfuscated code execution pattern detected",
                pattern=pattern.decode('utf-8', errors='ignore')
            ))
    
    # Check for chr() building
    if b"chr(101)" in data and b"chr(120)" in data:
        issues.append(create_critical_issue(
            "Character code obfuscation detected (likely building 'exec')"
        ))
    
    return issues
```

**Validation**:
```bash
# Test all exec variants
for model in mkiani/gpt2-exec mkiani/gpt2-runpy mkiani/gpt2-system; do
    echo "Testing $model..."
    rye run modelaudit hf://$model
done

# Expected: All three should show CRITICAL issues
```

## Testing Strategy for Fixes

### Create Test Suite
```python
# tests/test_false_positives.py
import pytest
from modelaudit.core import scan_file

class TestFalsePositives:
    """Test that legitimate models don't trigger false positives"""
    
    SAFE_MODELS = [
        "google/bert_uncased_L-2_H-128_A-2",
        "hf-internal-testing/tiny-random-bert",
        "prajjwal1/bert-tiny",
        "distilbert/distilbert-base-uncased",
        "google/flan-t5-small",
    ]
    
    @pytest.mark.parametrize("model", SAFE_MODELS)
    def test_no_false_positives(self, model):
        """Safe models should not trigger critical issues"""
        result = scan_file(f"hf://{model}")
        
        # No critical issues
        critical_issues = [i for i in result.issues if i.severity == "critical"]
        assert len(critical_issues) == 0, f"False positive in {model}: {critical_issues}"
        
        # Limited warnings acceptable
        warnings = [i for i in result.issues if i.severity == "warning"]
        assert len(warnings) < 5, f"Too many warnings in {model}: {len(warnings)}"

# tests/test_false_negatives.py  
class TestFalseNegatives:
    """Test that malicious models are detected"""
    
    MALICIOUS_MODELS = [
        ("mkiani/gpt2-exec", "exec"),
        ("mkiani/gpt2-runpy", "runpy"),
        ("mkiani/gpt2-system", "system"),
        ("drhyrum/bert-tiny-torch-picklebomb", "webbrowser"),
    ]
    
    @pytest.mark.parametrize("model,expected_pattern", MALICIOUS_MODELS)
    def test_detects_malicious(self, model, expected_pattern):
        """Malicious models should be detected"""
        result = scan_file(f"hf://{model}")
        
        # Should have critical issues
        critical_issues = [i for i in result.issues if i.severity == "critical"]
        assert len(critical_issues) > 0, f"Failed to detect {model}"
        
        # Should detect expected pattern
        patterns_found = [i.message for i in critical_issues]
        assert any(expected_pattern in msg for msg in patterns_found)
```

## Implementation Priority

1. **Immediate (This Week)**:
   - Fix FN-1: HuggingFace download issue (blocks testing)
   - Fix FP-1: Hardcoded password false positive (most disruptive)

2. **Next Sprint**:
   - Fix FP-2: Opcode threshold tuning
   - Fix FN-2: Enhanced exec/eval detection

3. **Following Sprint**:
   - Add comprehensive test suite
   - Performance optimizations
   - Documentation updates

## Success Metrics

- **False Positive Rate**: < 5% on safe models (currently 100%)
- **Detection Rate**: > 95% on malicious models (currently ~89%)
- **Performance**: < 5 seconds average scan time
- **No Regressions**: All currently detected threats still detected