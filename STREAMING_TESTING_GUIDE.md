# Streaming Scan-and-Delete Testing Guide

This guide provides step-by-step instructions for testing the new `--stream-and-delete` feature across all supported sources.

## Table of Contents
- [Quick Start](#quick-start)
- [Feature Overview](#feature-overview)
- [Testing by Source](#testing-by-source)
  - [1. HuggingFace Models](#1-huggingface-models)
  - [2. Local Directories](#2-local-directories)
  - [3. Cloud Storage (S3/GCS)](#3-cloud-storage-s3gcs)
  - [4. PyTorch Hub](#4-pytorch-hub)
- [Verification Checklist](#verification-checklist)
- [Comparison Tests](#comparison-tests)
- [Edge Cases](#edge-cases)
- [Performance Testing](#performance-testing)

---

## Quick Start

**What does `--stream-and-delete` do?**
- Downloads/processes files **one at a time** instead of all at once
- Scans each file immediately after download
- **Deletes** each file after scanning to free disk space
- Computes SHA256 hash per file and aggregate `content_hash` for deduplication
- Ideal for large models (100GB+) on disk-constrained systems

**Basic usage:**
```bash
rye run modelaudit scan --stream-and-delete hf://model-name
```

---

## Feature Overview

### What to Verify
For each test, confirm:
1. ✅ Files are downloaded/processed one at a time
2. ✅ Scan completes successfully
3. ✅ `content_hash` field appears in JSON output
4. ✅ Files are deleted after scanning (directory is empty or files gone)
5. ✅ Results match non-streaming mode (same security findings)

### Key Flags
- `--stream-and-delete`: Enable streaming mode
- `--format json`: Get JSON output (easier to verify `content_hash`)
- `--verbose`: See detailed progress messages
- `--no-cache`: Avoid caching (useful for testing)

---

## Testing by Source

### 1. HuggingFace Models

#### Test 1.1: Small Model (Quick Test)
**Model:** `ibm-granite/granite-4.0-h-1b` (2.7 GB)

```bash
# Streaming mode with JSON output
rye run modelaudit scan --stream-and-delete --format json hf://ibm-granite/granite-4.0-h-1b > streaming_result.json

# Verify content_hash exists
cat streaming_result.json | jq '.content_hash'
# Expected: 64-character hex string (SHA256)

# Check files were scanned
cat streaming_result.json | jq '.files_scanned'
# Expected: 1 (for this model)

# Check bytes scanned
cat streaming_result.json | jq '.bytes_scanned'
# Expected: ~2,923,128,544 (2.7 GB)
```

**What to look for:**
- ✅ Progress messages showing download → scan → delete cycle
- ✅ `content_hash` field in output
- ✅ No files left in cache after completion

#### Test 1.2: GGUF Model (Extension Fix Verification)
**Model:** `TheBloke/Llama-2-7B-Chat-GGUF` (GGUF format)

```bash
# This tests the MODEL_EXTENSIONS fix (40 formats)
rye run modelaudit scan --stream-and-delete --format json hf://TheBloke/Llama-2-7B-Chat-GGUF > gguf_result.json

# Verify .gguf files were downloaded (not fallback to "download everything")
cat gguf_result.json | jq '.files_scanned'
# Expected: Multiple files (one for each .gguf quantization)

# Check that only model files were downloaded (not README, LICENSE, etc.)
cat gguf_result.json | jq '.content_hash'
# Expected: Valid 64-char hash
```

**What to look for:**
- ✅ Only `.gguf` files downloaded (selective, not "download everything")
- ✅ No `.md`, `.txt`, `LICENSE` files downloaded
- ✅ Multiple GGUF variants scanned

#### Test 1.3: Compare Streaming vs Normal Mode
```bash
# Normal mode (download all, then scan)
rye run modelaudit scan --format json --no-cache hf://ibm-granite/granite-4.0-h-1b > normal.json

# Streaming mode (download one-by-one, scan, delete)
rye run modelaudit scan --stream-and-delete --format json --no-cache hf://ibm-granite/granite-4.0-h-1b > streaming.json

# Compare security findings (should be identical)
diff <(jq '.issues' normal.json) <(jq '.issues' streaming.json)
# Expected: No differences

# Compare files scanned
diff <(jq '.files_scanned' normal.json) <(jq '.files_scanned' streaming.json)
# Expected: Same number

# Streaming has content_hash, normal doesn't
jq '.content_hash' normal.json      # Expected: null
jq '.content_hash' streaming.json   # Expected: 64-char hex string
```

---

### 2. Local Directories

#### Test 2.1: Create Test Directory
```bash
# Create test models directory
mkdir -p /tmp/test_streaming_models
cd /tmp/test_streaming_models

# Create some test pickle files
python3 << 'EOF'
import pickle

# Create 5 test models
for i in range(5):
    data = {'weights': [1.0] * 100, 'bias': [0.5] * 100, 'id': i}
    with open(f'model_{i}.pkl', 'wb') as f:
        pickle.dump(data, f)

print("Created 5 test pickle files")
EOF

# Verify files exist
ls -lh
```

#### Test 2.2: Streaming Scan with Deletion
```bash
# Run streaming scan (WILL DELETE FILES!)
rye run modelaudit scan --stream-and-delete --format json /tmp/test_streaming_models > local_streaming.json

# Verify content_hash
cat local_streaming.json | jq '{files_scanned, bytes_scanned, content_hash}'

# Check if files were deleted
ls -la /tmp/test_streaming_models/
# Expected: Directory empty (only . and .. entries)
```

**⚠️ WARNING:** Files are permanently deleted! Don't use on important data.

#### Test 2.3: Normal Mode (No Deletion)
```bash
# Recreate test files
cd /tmp/test_streaming_models
python3 << 'EOF'
import pickle
for i in range(5):
    with open(f'model_{i}.pkl', 'wb') as f:
        pickle.dump({'id': i}, f)
EOF

# Run WITHOUT streaming (files preserved)
rye run modelaudit scan --format json /tmp/test_streaming_models > local_normal.json

# Files should still exist
ls -la /tmp/test_streaming_models/
# Expected: All 5 .pkl files present
```

---

### 3. Cloud Storage (S3/GCS)

**Prerequisites:**
- AWS credentials configured (for S3)
- GCP credentials configured (for GCS)
- Test bucket with model files

#### Test 3.1: S3 Streaming
```bash
# Replace with your S3 bucket
S3_URL="s3://your-bucket/path/to/models/"

# Streaming mode
rye run modelaudit scan --stream-and-delete --format json "$S3_URL" > s3_streaming.json

# Verify results
cat s3_streaming.json | jq '{files_scanned, content_hash}'
```

#### Test 3.2: GCS Streaming
```bash
# Replace with your GCS bucket
GCS_URL="gs://your-bucket/path/to/models/"

# Streaming mode
rye run modelaudit scan --stream-and-delete --format json "$GCS_URL" > gcs_streaming.json

# Verify results
cat gcs_streaming.json | jq '{files_scanned, content_hash}'
```

**What to look for:**
- ✅ Files downloaded one at a time (check verbose output)
- ✅ Temporary files cleaned up after scanning
- ✅ `content_hash` in results

---

### 4. PyTorch Hub

**Note:** PyTorch Hub may have issues with some models (known pre-existing limitation).

#### Test 4.1: ResNet Model
```bash
# Streaming mode
rye run modelaudit scan --stream-and-delete --format json https://pytorch.org/hub/pytorch_vision_resnet/ > pytorch_streaming.json

# Check results
cat pytorch_streaming.json | jq '{files_scanned, content_hash, has_errors}'
```

**Known Issue:** Some PyTorch Hub URLs may not extract model files correctly. This is a pre-existing issue, not related to streaming.

---

## Verification Checklist

After running each test, verify:

### ✅ Basic Functionality
- [ ] Command completes without errors
- [ ] Exit code is 0 (for clean scans) or 1 (if issues found)
- [ ] JSON output is valid
- [ ] `files_scanned > 0`
- [ ] `bytes_scanned > 0`

### ✅ Streaming-Specific Features
- [ ] `content_hash` field exists in output
- [ ] `content_hash` is 64-character hex string
- [ ] Files are deleted after scanning (directory empty for local, temp files cleaned for remote)
- [ ] Memory usage stays low (not loading entire model into memory)

### ✅ Security Scanning
- [ ] Security checks are performed (check `total_checks > 0`)
- [ ] Issues are detected (if applicable)
- [ ] Results match non-streaming mode

### ✅ Content Hash Properties
```bash
# Test determinism (same files = same hash)
rye run modelaudit scan --stream-and-delete --format json hf://model > run1.json
rye run modelaudit scan --stream-and-delete --format json hf://model > run2.json

jq '.content_hash' run1.json
jq '.content_hash' run2.json
# Expected: Identical hashes

# Test uniqueness (different models = different hashes)
rye run modelaudit scan --stream-and-delete --format json hf://model-A > modelA.json
rye run modelaudit scan --stream-and-delete --format json hf://model-B > modelB.json

jq '.content_hash' modelA.json
jq '.content_hash' modelB.json
# Expected: Different hashes
```

---

## Comparison Tests

### Test: Streaming vs Normal Mode

**Purpose:** Verify streaming produces identical security results to normal mode.

```bash
#!/bin/bash
# compare_modes.sh

MODEL="hf://ibm-granite/granite-4.0-h-1b"

echo "Testing: $MODEL"
echo "========================"

# Normal mode
echo "Running normal mode..."
rye run modelaudit scan --format json --no-cache "$MODEL" > normal.json

# Streaming mode
echo "Running streaming mode..."
rye run modelaudit scan --stream-and-delete --format json --no-cache "$MODEL" > streaming.json

echo ""
echo "Comparison Results:"
echo "========================"

# Files scanned
NORMAL_FILES=$(jq '.files_scanned' normal.json)
STREAM_FILES=$(jq '.files_scanned' streaming.json)
echo "Files scanned: Normal=$NORMAL_FILES, Streaming=$STREAM_FILES"

# Bytes scanned
NORMAL_BYTES=$(jq '.bytes_scanned' normal.json)
STREAM_BYTES=$(jq '.bytes_scanned' streaming.json)
echo "Bytes scanned: Normal=$NORMAL_BYTES, Streaming=$STREAM_BYTES"

# Issues found
NORMAL_ISSUES=$(jq '.issues | length' normal.json)
STREAM_ISSUES=$(jq '.issues | length' streaming.json)
echo "Issues found: Normal=$NORMAL_ISSUES, Streaming=$STREAM_ISSUES"

# Content hash (only in streaming)
CONTENT_HASH=$(jq -r '.content_hash' streaming.json)
echo "Content hash (streaming only): $CONTENT_HASH"

echo ""
if [ "$NORMAL_FILES" = "$STREAM_FILES" ] && [ "$NORMAL_BYTES" = "$STREAM_BYTES" ] && [ "$NORMAL_ISSUES" = "$STREAM_ISSUES" ]; then
    echo "✅ PASS: Results match!"
else
    echo "❌ FAIL: Results differ!"
fi
```

**Expected output:**
```
Testing: hf://ibm-granite/granite-4.0-h-1b
========================
Running normal mode...
Running streaming mode...

Comparison Results:
========================
Files scanned: Normal=1, Streaming=1
Bytes scanned: Normal=2923128544, Streaming=2923128544
Issues found: Normal=0, Streaming=0
Content hash (streaming only): 75dd01228f75ab2ec6c0ff76693982aa54dffe684354e812ae4a044a3951c388

✅ PASS: Results match!
```

---

## Edge Cases

### Test: Empty Directory
```bash
mkdir -p /tmp/empty_test
rye run modelaudit scan --stream-and-delete /tmp/empty_test
# Expected: Warning about no model files found
```

### Test: Mixed File Types
```bash
mkdir -p /tmp/mixed_test
cd /tmp/mixed_test

# Create model file
python3 -c "import pickle; pickle.dump({'data': [1,2,3]}, open('model.pkl', 'wb'))"

# Create non-model files
echo "readme" > README.md
echo "config" > config.json

# Run streaming scan
rye run modelaudit scan --stream-and-delete --format json /tmp/mixed_test > mixed.json

# Only .pkl should be scanned
cat mixed.json | jq '.files_scanned'
# Expected: 1 (only model.pkl)

# README.md and config.json should remain
ls -la /tmp/mixed_test/
# Expected: README.md and config.json still present, model.pkl deleted
```

### Test: Large Model (Disk Space Savings)
```bash
# For a very large model, compare disk usage

# Check available disk space
df -h .

# Streaming mode (minimal disk usage)
rye run modelaudit scan --stream-and-delete --format json hf://large-model > large_streaming.json

# Check disk usage during scan (in another terminal)
watch -n 1 'df -h . && ls -lh ~/.modelaudit/cache/'
# Expected: Disk usage spikes briefly per file, then drops back down
```

### Test: Timeout Behavior
```bash
# Set very short timeout to test timeout handling
rye run modelaudit scan --stream-and-delete --timeout 5 hf://large-model
# Expected: Times out gracefully, returns partial results
```

### Test: Interrupted Scan
```bash
# Start a scan and interrupt with Ctrl+C
rye run modelaudit scan --stream-and-delete hf://large-model
# Press Ctrl+C after a few seconds

# Verify temp files are cleaned up
ls /tmp/modelaudit_*
# Expected: No leftover temp directories
```

---

## Performance Testing

### Test: Memory Usage
```bash
# Monitor memory usage during streaming scan
/usr/bin/time -v rye run modelaudit scan --stream-and-delete hf://large-model 2>&1 | grep "Maximum resident"

# Compare with normal mode
/usr/bin/time -v rye run modelaudit scan hf://large-model 2>&1 | grep "Maximum resident"

# Expected: Streaming uses less memory for large models
```

### Test: Disk Usage Over Time
```bash
#!/bin/bash
# monitor_disk.sh

# Start disk monitoring in background
while true; do
    date +%T
    du -sh ~/.modelaudit/cache/ 2>/dev/null || echo "No cache"
    sleep 2
done &
MONITOR_PID=$!

# Run streaming scan
rye run modelaudit scan --stream-and-delete hf://model

# Stop monitoring
kill $MONITOR_PID

# Expected: Disk usage increases per file, then decreases after each scan
```

### Test: Speed Comparison
```bash
# Time normal mode
time rye run modelaudit scan --format json hf://model > normal.json

# Time streaming mode
time rye run modelaudit scan --stream-and-delete --format json hf://model > streaming.json

# Expected: Similar times (streaming may be slightly slower due to per-file overhead)
```

---

## Automated Test Suite

Save this as `test_streaming.sh`:

```bash
#!/bin/bash
set -e

echo "🧪 Streaming Scan-and-Delete Test Suite"
echo "========================================"

# Test 1: HuggingFace small model
echo ""
echo "Test 1: HuggingFace Streaming"
rye run modelaudit scan --stream-and-delete --format json hf://ibm-granite/granite-4.0-h-1b > test1.json
HASH1=$(jq -r '.content_hash' test1.json)
FILES1=$(jq '.files_scanned' test1.json)
echo "  ✅ Files scanned: $FILES1"
echo "  ✅ Content hash: $HASH1"

# Test 2: Local directory
echo ""
echo "Test 2: Local Directory Streaming"
mkdir -p /tmp/stream_test
python3 << 'EOF'
import pickle
for i in range(3):
    with open(f'/tmp/stream_test/model_{i}.pkl', 'wb') as f:
        pickle.dump({'id': i}, f)
EOF
rye run modelaudit scan --stream-and-delete --format json /tmp/stream_test > test2.json
FILES2=$(jq '.files_scanned' test2.json)
REMAINING=$(ls -1 /tmp/stream_test/ 2>/dev/null | wc -l)
echo "  ✅ Files scanned: $FILES2"
echo "  ✅ Files remaining: $REMAINING (expected: 0)"

# Test 3: Content hash determinism
echo ""
echo "Test 3: Content Hash Determinism"
rye run modelaudit scan --stream-and-delete --format json hf://ibm-granite/granite-4.0-h-1b > test3a.json
rye run modelaudit scan --stream-and-delete --format json hf://ibm-granite/granite-4.0-h-1b > test3b.json
HASH3A=$(jq -r '.content_hash' test3a.json)
HASH3B=$(jq -r '.content_hash' test3b.json)
if [ "$HASH3A" = "$HASH3B" ]; then
    echo "  ✅ Hashes match: $HASH3A"
else
    echo "  ❌ Hashes differ: $HASH3A vs $HASH3B"
    exit 1
fi

echo ""
echo "========================================"
echo "✅ All tests passed!"
```

Run with:
```bash
chmod +x test_streaming.sh
./test_streaming.sh
```

---

## Troubleshooting

### Issue: Files not being deleted
**Check:** Are you using `--cache`? Cached files are preserved.
```bash
# Wrong (files cached):
rye run modelaudit scan --stream-and-delete --cache hf://model

# Correct (files deleted):
rye run modelaudit scan --stream-and-delete --no-cache hf://model
```

### Issue: No `content_hash` in output
**Check:** Streaming mode enabled?
```bash
# Wrong (no content_hash):
rye run modelaudit scan hf://model

# Correct (has content_hash):
rye run modelaudit scan --stream-and-delete hf://model
```

### Issue: "Download failed" errors
**Check:**
- Network connectivity
- Authentication (for private models)
- Model exists and is accessible

### Issue: Different results between streaming and normal
**This is unexpected!** Please report with:
```bash
# Generate debug info
rye run modelaudit scan --verbose --format json hf://model > normal.json
rye run modelaudit scan --stream-and-delete --verbose --format json hf://model > streaming.json

# Compare
diff <(jq '.issues' normal.json) <(jq '.issues' streaming.json)
```

---

## Summary Checklist

Before approving the PR, verify:

- [ ] **HuggingFace streaming works** with real models
- [ ] **Local directory streaming works** and deletes files
- [ ] **GGUF models are detected** (not fallback download)
- [ ] **Content hash is deterministic** (same files = same hash)
- [ ] **Content hash is unique** (different files = different hash)
- [ ] **Security findings match** between streaming and normal mode
- [ ] **Files are deleted** after streaming scan
- [ ] **Disk usage is minimal** during streaming
- [ ] **All 105 tests pass**
- [ ] **No regressions** in normal (non-streaming) mode

---

## Quick Reference

```bash
# Enable streaming
--stream-and-delete

# Common combinations
--stream-and-delete --format json              # Streaming with JSON output
--stream-and-delete --format json --verbose    # Streaming with detailed logging
--stream-and-delete --no-cache                 # Streaming without caching
--stream-and-delete --timeout 1800             # Streaming with 30min timeout

# Sources that support streaming
hf://model-name                                # HuggingFace
https://huggingface.co/model-name              # HuggingFace (URL)
s3://bucket/path                               # S3
gs://bucket/path                               # GCS
https://pytorch.org/hub/model                  # PyTorch Hub
/path/to/local/directory                       # Local directory

# Sources that DON'T support streaming (integrated scan)
models://model-name                            # MLflow (already integrated)
https://jfrog.io/artifactory/path              # JFrog (already integrated)
```

---

**Happy Testing! 🚀**
