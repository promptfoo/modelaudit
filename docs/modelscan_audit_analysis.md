# ModelScan vs ModelAudit: Critical Audit Analysis

## Executive Summary

This analysis identifies critical gaps in ProtectAI's modelscan detection capabilities compared to ModelAudit. Based on code review and scanner comparison, modelscan has significant blind spots that could allow malicious models to pass undetected.

## Key Findings

### 🚨 Critical Missing Detection Capabilities in modelscan

1. **GGUF Template Injection (CVE-2024-34359)**
   - **Impact**: CRITICAL - Remote code execution via Jinja2 templates
   - **Status**: ModelAudit detects, modelscan BLIND
   - **Attack Vector**: SSTI in GGUF chat_template metadata

2. **ONNX Model Scanning**
   - **Impact**: HIGH - No scanning of ONNX models
   - **Status**: ModelAudit detects, modelscan BLIND
   - **Attack Vector**: Malicious ops/custom functions in ONNX graphs

3. **Advanced Configuration Exploits**
   - **Impact**: HIGH - trust_remote_code and auto_map attacks
   - **Status**: ModelAudit detects, modelscan BLIND
   - **Attack Vector**: Config-based remote code execution

4. **Framework-Specific Scanners**
   - **TensorRT**: ModelAudit ✅, modelscan ❌
   - **OpenVINO**: ModelAudit ✅, modelscan ❌
   - **PaddlePaddle**: ModelAudit ✅, modelscan ❌
   - **CoreML**: ModelAudit ✅, modelscan ❌
   - **TFLite**: ModelAudit ✅, modelscan ❌

5. **Advanced Archive Analysis**
   - **Impact**: MEDIUM-HIGH - OCI layers, complex archives
   - **Status**: ModelAudit detects, modelscan PARTIAL
   - **Attack Vector**: Nested malicious files in containers

## Scanner Comparison Matrix

| Detection Category          | ModelAudit  | modelscan | Risk Level   |
| --------------------------- | ----------- | --------- | ------------ |
| **Pickle/PyTorch**          | ✅ Advanced | ✅ Basic  | LOW          |
| **GGUF Template Injection** | ✅          | ❌        | **CRITICAL** |
| **ONNX Scanning**           | ✅          | ❌        | **HIGH**     |
| **Config Exploits**         | ✅          | ❌        | **HIGH**     |
| **Jinja2 Templates**        | ✅          | ❌        | **HIGH**     |
| **Weight Distribution**     | ✅          | ❌        | **MEDIUM**   |
| **Network Communication**   | ✅          | ❌        | **MEDIUM**   |
| **JIT Script Detection**    | ✅          | ❌        | **MEDIUM**   |
| **Manifest Analysis**       | ✅          | ❌        | **MEDIUM**   |

## High-Priority Test Models

### 1. GGUF Template Injection Models

**CRITICAL GAP**: modelscan cannot detect CVE-2024-34359

- `nono31/malicious-models-repo` (malicious_sample.gguf)
- `microsoft/Phi-3-mini-4k-instruct-gguf`
- `gorilla-llm/gorilla-openfunctions-v0-gguf`

### 2. ONNX Models with Potential Issues

**HIGH GAP**: modelscan has NO ONNX scanning

- `Xenova/clip-vit-base-patch16` (benign baseline)
- `onnx-community/mobilenet_v2_1.0_224` (benign baseline)
- Custom ONNX with malicious operators (need to create)

### 3. Configuration-based Exploits

**HIGH GAP**: modelscan doesn't check configs

- `internlm/internlm2-chat-7b` (auto_map)
- `chandar-lab/NeoBERT` (trust_remote_code)
- `deepseek-ai/DeepSeek-V3` (auto_map)

### 4. Framework-Specific Models

**MEDIUM-HIGH GAP**: Many frameworks unsupported

- `OpenVINO/bert-base-uncased-sst2-unstructured80-int8-ov`
- `PaddlePaddle/PP-OCRv5_server_det`
- Any TensorRT models (.plan, .engine files)

## Comparative Testing Plan

### Phase 1: Critical GGUF Vulnerability

```bash
# Test CVE-2024-34359 detection
rye run modelaudit nono31/malicious-models-repo  # Should detect
pip install modelscan && modelscan -p nono31/malicious-models-repo  # Will miss

# Test benign GGUF models
rye run modelaudit microsoft/Phi-3-mini-4k-instruct-gguf
modelscan -p microsoft/Phi-3-mini-4k-instruct-gguf
```

### Phase 2: ONNX Blind Spot

```bash
# Test ONNX models (modelscan will skip entirely)
rye run modelaudit Xenova/clip-vit-base-patch16
modelscan -p Xenova/clip-vit-base-patch16  # Will skip/miss
```

### Phase 3: Configuration Exploits

```bash
# Test auto_map configurations
rye run modelaudit internlm/internlm2-chat-7b
modelscan -p internlm/internlm2-chat-7b  # Will miss config issues
```

## Evidence Generation Strategy

1. **Document False Negatives**: Run both tools on known malicious models
2. **Create PoC Models**: Generate test cases that exploit modelscan gaps
3. **Performance Analysis**: Compare detection rates and false positive rates
4. **Report Generation**: Compile evidence of missed detections

## Recommended Test Models for Comparison

### Definite ModelAudit Advantages:

- **GGUF**: `nono31/malicious-models-repo` (SSTI)
- **ONNX**: `Xenova/clip-vit-base-patch16` (any ONNX)
- **Config**: `chandar-lab/NeoBERT` (trust_remote_code)
- **Jinja2**: Any tokenizer_config.json with templates

### Edge Cases to Test:

- **Nested Archives**: Complex zip structures
- **Large Models**: >8GB files with streaming
- **Custom Operators**: Framework-specific extensions

## Expected Results

Based on this analysis, ModelAudit should demonstrate superior detection capabilities across multiple attack vectors that modelscan completely misses, particularly:

1. **100% of GGUF template injection attacks** (CRITICAL)
2. **100% of ONNX-based attacks** (HIGH)
3. **Configuration-based RCE attempts** (HIGH)
4. **Advanced framework-specific exploits** (MEDIUM-HIGH)

This represents a significant security advantage for ModelAudit in real-world deployment scenarios.
