# JFrog Folder Support Testing Guide

This guide covers testing the new JFrog folder support functionality in ModelAudit, including unit tests, integration tests, and end-to-end testing with real JFrog instances.

## Overview

The JFrog implementation now supports both individual files and entire folders/repositories, matching the functionality of S3/GCS implementations. This testing guide ensures comprehensive coverage of:

- JFrog Storage API integration
- Folder detection and listing
- Recursive file traversal
- Selective model file filtering
- Batch downloading
- Error handling and authentication
- End-to-end workflows

## Running Tests

### Quick Unit Tests

Run fast unit tests during development:

```bash
# Run only JFrog-related tests
rye run pytest tests/test_jfrog.py tests/test_jfrog_integration.py -v

# Run specific test classes
rye run pytest tests/test_jfrog.py::TestJFrogFolderDetection -v
rye run pytest tests/test_jfrog.py::TestJFrogFolderListing -v
```

### Full Test Suite

```bash
# Run all tests (includes JFrog folder functionality)
rye run pytest -n auto -m "not slow and not integration"

# Run with coverage to see test coverage
rye run pytest --cov=modelaudit tests/test_jfrog*.py
```

### Integration Tests

Integration tests require a real JFrog Artifactory instance:

```bash
# Skip integration tests (default behavior)
rye run pytest tests/test_jfrog_integration.py -v

# Run integration tests (requires JFrog setup - see below)
rye run pytest tests/test_jfrog_integration.py --run-integration-tests -v
```

## Test Categories

### 1. Unit Tests (`tests/test_jfrog.py`)

**Storage API Tests:**

- URL conversion to Storage API endpoints
- File size formatting
- Scannable file filtering
- Error handling for invalid URLs

**Folder Detection Tests:**

- File vs folder detection using Storage API
- Authentication error handling (401, 403, 404)
- JSON response parsing

**Folder Listing Tests:**

- Simple folder listing
- Recursive traversal of nested folders
- Selective filtering to model files only
- Error handling for non-folder targets

**Folder Download Tests:**

- Batch downloading of multiple files
- Progress reporting
- Error handling for empty folders
- File path calculation and organization

### 2. Integration Tests (`tests/test_jfrog_integration.py`)

**Mocked Integration Tests:**

- End-to-end scanning workflow for files
- End-to-end scanning workflow for folders
- Proper metadata attachment
- Error propagation and cleanup

**Real JFrog Integration Tests:**

- Tests against live JFrog instances (optional)
- Require authentication and test data setup
- Skipped by default, enabled with `--run-integration-tests`

## Setting Up Integration Tests

### Prerequisites

1. **JFrog Artifactory Instance**
   - Local Docker instance, cloud instance, or enterprise installation
   - Admin access to create repositories and upload test files

2. **Authentication**
   - API token or access token with read permissions
   - Set as environment variables

3. **Test Data**
   - Sample model files uploaded to your instance
   - Organized in both individual files and folder structures

### JFrog Docker Setup (for testing)

```bash
# Start JFrog Artifactory locally
docker run -d \
  --name artifactory \
  -p 8081:8081 \
  -p 8082:8082 \
  releases-docker.jfrog.io/jfrog/artifactory-oss:latest

# Wait for startup (check http://localhost:8082/ui/)
# Default credentials: admin/password
```

### Environment Variables

```bash
# Required for integration tests
export JFROG_API_TOKEN="your-api-token-here"

# Optional: specific test URLs (replace with your paths)
export JFROG_TEST_FILE_URL="http://localhost:8082/artifactory/generic-local/models/test-model.pkl"
export JFROG_TEST_FOLDER_URL="http://localhost:8082/artifactory/generic-local/models/"
```

### Creating Test Data

Upload sample model files to your JFrog instance:

```bash
# Upload individual files
curl -u admin:password -X PUT \
  "http://localhost:8082/artifactory/generic-local/models/test-model.pkl" \
  -T /path/to/your/test-model.pkl

# Upload folder structure
curl -u admin:password -X PUT \
  "http://localhost:8082/artifactory/generic-local/models/pytorch/model1.pt" \
  -T /path/to/model1.pt

curl -u admin:password -X PUT \
  "http://localhost:8082/artifactory/generic-local/models/tensorflow/model2.h5" \
  -T /path/to/model2.h5
```

## Manual End-to-End Testing

### Test Case 1: Single File Scanning

```bash
# Set credentials
export JFROG_API_TOKEN="your-token"

# Scan a single model file
rye run modelaudit "https://your-jfrog.com/artifactory/repo/model.pkl"

# Expected:
# - File detected and downloaded
# - Model scanned successfully
# - JFrog metadata in results
```

### Test Case 2: Folder Scanning

```bash
# Scan entire folder (new functionality)
rye run modelaudit "https://your-jfrog.com/artifactory/repo/models/"

# Expected:
# - Folder detected via Storage API
# - All model files discovered recursively
# - Only scannable files downloaded
# - Progress shown during download
# - All files scanned
# - JFrog metadata shows "folder" type
```

### Test Case 3: Authentication Testing

```bash
# Test without credentials (should attempt anonymous access)
unset JFROG_API_TOKEN
rye run modelaudit "https://your-jfrog.com/artifactory/public/model.pkl"

# Test with invalid credentials (should fail gracefully)
export JFROG_API_TOKEN="invalid-token"
rye run modelaudit "https://your-jfrog.com/artifactory/private/model.pkl"
```

### Test Case 4: Error Handling

```bash
# Test non-existent file
rye run modelaudit "https://your-jfrog.com/artifactory/repo/nonexistent.pkl"

# Test non-existent folder
rye run modelaudit "https://your-jfrog.com/artifactory/repo/nonexistent-folder/"

# Test folder with no model files
rye run modelaudit "https://your-jfrog.com/artifactory/repo/text-files-only/"
```

## Comparing with S3/GCS

The JFrog implementation should behave identically to S3/GCS:

```bash
# These should produce equivalent results:

# S3 folder scanning
rye run modelaudit "s3://bucket/models/"

# GCS folder scanning
rye run modelaudit "gs://bucket/models/"

# JFrog folder scanning (new)
rye run modelaudit "https://company.jfrog.io/artifactory/repo/models/"
```

## Performance Testing

### Large Repository Testing

```bash
# Test with timeout for large repositories
rye run modelaudit "https://jfrog.com/artifactory/large-repo/" --timeout 1800

# Test with verbose output for progress tracking
rye run modelaudit "https://jfrog.com/artifactory/large-repo/" --verbose
```

### Memory and Resource Testing

```bash
# Monitor resource usage during large folder scans
pip install memory-profiler
mprof run rye run modelaudit "https://jfrog.com/artifactory/large-repo/"
mprof plot
```

## Troubleshooting Integration Tests

### Common Issues

**Tests Skip with "Integration tests disabled":**

```bash
# Solution: Enable integration tests
pytest --run-integration-tests tests/test_jfrog_integration.py
```

**"JFrog integration test credentials not available":**

```bash
# Solution: Set environment variables
export JFROG_API_TOKEN="your-token"
export JFROG_TEST_FILE_URL="http://localhost:8082/artifactory/repo/test.pkl"
```

**Authentication errors:**

```bash
# Check token validity
curl -H "X-JFrog-Art-Api: $JFROG_API_TOKEN" \
  "https://your-jfrog.com/artifactory/api/system/ping"
```

**Storage API errors:**

```bash
# Test Storage API access manually
curl -H "X-JFrog-Art-Api: $JFROG_API_TOKEN" \
  "https://your-jfrog.com/artifactory/api/storage/repo/path/"
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Run with debug logging
MODELAUDIT_LOG_LEVEL=DEBUG rye run modelaudit "https://jfrog.com/artifactory/repo/"

# Or in tests
MODELAUDIT_LOG_LEVEL=DEBUG pytest tests/test_jfrog_integration.py -v -s
```

## Test Coverage Goals

The test suite aims for:

- **Unit Tests:** >90% coverage of `utils/jfrog.py` functions
- **Integration Tests:** Cover all major user workflows
- **Error Handling:** Test all authentication and network error cases
- **Performance:** Ensure folder scanning scales to 100+ files
- **Compatibility:** Verify feature parity with S3/GCS implementations

## Continuous Integration

In CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Test JFrog Functionality
  run: |
    # Run unit tests (always)
    rye run pytest tests/test_jfrog.py -v

    # Run integration tests only if JFrog is available
    if [ ! -z "$JFROG_API_TOKEN" ]; then
      rye run pytest tests/test_jfrog_integration.py --run-integration-tests -v
    fi
  env:
    JFROG_API_TOKEN: ${{ secrets.JFROG_API_TOKEN }}
    JFROG_TEST_FILE_URL: ${{ secrets.JFROG_TEST_FILE_URL }}
```

This ensures comprehensive testing while allowing CI to pass even without JFrog infrastructure.
