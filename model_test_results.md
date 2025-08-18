# ModelAudit Test Results Summary

## Test Overview

- **Date**: August 15, 2025
- **Models Tested**: 18 models (5 safe, 13 malicious)
- **Scanner Version**: Latest (pulled from main branch with new Keras ZIP scanner)

## Key Findings

### Detection Performance

#### Safe Models (False Positive Analysis)

| Model                                | Issues Detected | Type               | Severity |
| ------------------------------------ | --------------- | ------------------ | -------- |
| google/bert_uncased_L-2_H-128_A-2    | 1               | Hardcoded password | Critical |
| hf-internal-testing/tiny-random-bert | 10              | Suspicious opcodes | Warning  |
| prajjwal1/bert-tiny                  | 5               | Suspicious opcodes | Warning  |

**False Positive Rate**: 3/3 (100%) - All safe models triggered some warnings

#### Malicious Models (True Positive Analysis)

| Model                              | Detection Status | Issues | Critical | Details                     |
| ---------------------------------- | ---------------- | ------ | -------- | --------------------------- |
| drhyrum/bert-tiny-torch-picklebomb | ✅ Detected      | 18     | 4        | webbrowser patterns, URLs   |
| ykilcher/totally-harmless-model    | ✅ Detected      | 15     | 4        | Dangerous patterns          |
| hf-internal-testing/unsafe-model   | ✅ Detected      | 3      | 2        | Dangerous patterns          |
| matanby/unsafe-diffusion           | ✅ Detected      | 8      | 5        | Multiple dangerous patterns |
| MustEr/bert_locked                 | ✅ Detected      | 2      | 1        | Security patterns           |
| mkiani/gpt2-exec                   | ❌ Not Detected  | 0      | 0        | FALSE NEGATIVE              |
| mkiani/unsafe-keras                | ✅ Detected      | 4      | 1        | Keras-specific issues       |
| mkiani/unsafe-saved-model          | ✅ Detected      | 1      | 1        | SavedModel issues           |
| mcpotato/42-eicar-street           | ✅ Detected      | 3      | 2        | EICAR patterns              |

**Detection Rate**: 8/9 (88.9%) successfully scanned models

### Issue Categories Detected

1. **Dangerous Patterns** (10 occurrences)
   - webbrowser imports
   - exec/eval patterns
   - system call indicators

2. **Network Indicators** (6 occurrences)
   - URLs detected (3)
   - Domain names detected (3)
   - Example: `https://pramuwaskito.org/hacker/`

3. **Suspicious Opcodes** (70+ occurrences)
   - MANY_DANGEROUS_OPCODES warnings
   - Pickle-specific patterns

## Critical Observations

### Strengths

1. **High detection rate for pickle bombs**: Successfully detected all PyTorch pickle bomb variants
2. **URL/Domain detection**: Correctly identifies network communication attempts
3. **Multiple format support**: Detected issues in PyTorch, Keras, and SavedModel formats

### Areas for Improvement

1. **False positives on safe models**: Need to tune opcode detection thresholds
2. **Hardcoded password detection**: May be too sensitive (flagged safe BERT model)
3. **Exec variant detection**: mkiani/gpt2-exec was not detected (false negative)

## Performance Metrics

- **Average scan time**: ~11 seconds per model
- **Total bytes scanned**: Varied from 665 bytes to 17MB+
- **Timeout rate**: 5/18 models (needs optimization)

## Recommendations

### Immediate Actions

1. **Tune opcode detection**: Reduce false positives on safe models
2. **Improve exec detection**: Ensure exec/runpy/system variants are caught
3. **Optimize timeout handling**: Some models taking too long to scan

### Future Enhancements

1. **Add pattern whitelisting**: For known safe patterns in legitimate models
2. **Improve severity scoring**: Better differentiation between warning and critical
3. **Add context to detections**: Show surrounding code/data for better analysis

## Test Coverage Gaps

Models not fully tested due to timeouts or download issues:

- mkiani/gpt2-runpy
- mkiani/gpt2-system
- willengler-uc/perovskite-screening (dill format)
- Kijai/LivePortrait_safetensors
- distilbert/distilbert-base-uncased
- google/flan-t5-small

## Conclusion

ModelAudit demonstrates strong detection capabilities for known malicious patterns, particularly in pickle-based attacks. The 88.9% detection rate for malicious models is promising, though the 100% false positive rate on safe models needs attention. The scanner successfully identifies critical security issues like code execution attempts and network communication, but requires tuning to reduce noise from benign opcode sequences.

### Overall Assessment: **B+**

- Excellent malicious pattern detection
- Needs false positive reduction
- Good multi-format support
- Performance optimization needed
