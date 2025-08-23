# Expanded Test Models List for ModelAudit vs modelscan Comparison

## 🏆 Tier 1: Guaranteed ModelAudit Wins (Always Demo These)

### ONNX Complete Blind Spot (CRITICAL Impact)

| Model                                                   | Files                  | modelscan Result | ModelAudit Advantage         |
| ------------------------------------------------------- | ---------------------- | ---------------- | ---------------------------- |
| `Xenova/clip-vit-base-patch16`                          | 9 .onnx files (67.8MB) | ❌ Skips all     | ✅ Full graph analysis       |
| `Xenova/clip-vit-large-patch14`                         | Multiple .onnx files   | ❌ Skips all     | ✅ Custom operator detection |
| `onnx-community/mobilenet_v2_1.0_224`                   | MobileNet ONNX         | ❌ Skips all     | ✅ Architecture analysis     |
| `onnx-community/mobilenetv4_conv_small.e2400_r224_in1k` | Modern ONNX            | ❌ Skips all     | ✅ Modern opset validation   |
| `Kalray/resnet50`                                       | Quantized ONNX         | ❌ Skips all     | ✅ Quantization analysis     |
| `webnn/yolov8m`                                         | YOLO in ONNX           | ❌ Skips all     | ✅ YOLO-ONNX validation      |

### GGUF Complete Blind Spot (CRITICAL Impact)

| Model                                        | Features              | modelscan Result   | ModelAudit Advantage            |
| -------------------------------------------- | --------------------- | ------------------ | ------------------------------- |
| `microsoft/Phi-3-mini-4k-instruct-gguf`      | Chat templates        | ❌ No GGUF scanner | ✅ Template injection detection |
| `gorilla-llm/gorilla-openfunctions-v0-gguf`  | Function templates    | ❌ No GGUF scanner | ✅ Complex template parsing     |
| `TheBloke/Mistral-7B-Instruct-v0.2-GGUF`     | Instruction templates | ❌ No GGUF scanner | ✅ SSTI vulnerability detection |
| `QuantFactory/Meta-Llama-3-8B-Instruct-GGUF` | Large GGUF            | ❌ No GGUF scanner | ✅ Large file template analysis |

### Configuration Exploits (HIGH Impact)

| Model                                | Config Type       | modelscan Result      | ModelAudit Advantage     |
| ------------------------------------ | ----------------- | --------------------- | ------------------------ |
| `internlm/internlm2-chat-7b`         | auto_map exploit  | ❌ No config analysis | ✅ Remote code detection |
| `chandar-lab/NeoBERT`                | trust_remote_code | ❌ No config analysis | ✅ Trust validation      |
| `deepseek-ai/DeepSeek-V3`            | Custom modules    | ❌ No config analysis | ✅ Module path analysis  |
| `microsoft/Phi-3-mini-128k-instruct` | auto_map patterns | ❌ No config analysis | ✅ Pattern recognition   |

## 🥇 Tier 2: Advanced Detection Differences (Strong Advantages)

### Advanced PyTorch Analysis

| Model                                | Attack Type    | modelscan Result   | ModelAudit Advantage       |
| ------------------------------------ | -------------- | ------------------ | -------------------------- |
| `drhyrum/bert-tiny-torch-picklebomb` | Pickle bomb    | ⚠️ Basic detection | ✅ CVE-2025-32434 patterns |
| `nono31/malicious-models-repo`       | Multi-format   | ⚠️ 3 issues        | ✅ 12+ distinct issues     |
| `kojino/bert-tiny-torch-picklebomb`  | Pickle exploit | ⚠️ Basic detection | ✅ Opcode analysis         |
| `ykilcher/totally-harmless-model`    | Builtin eval   | ⚠️ Basic detection | ✅ Advanced eval detection |
| `TencentAIGC/poisoned-model`         | System calls   | ⚠️ Basic detection | ✅ Comprehensive analysis  |

### CVE-Specific Detection

| Model                        | CVE            | modelscan Result      | ModelAudit Advantage      |
| ---------------------------- | -------------- | --------------------- | ------------------------- |
| `Retr0REG/CVE-2024-3568-poc` | CVE-2024-3568  | ❌ "No issues found!" | ✅ 5+ CRITICAL detections |
| GGUF templates               | CVE-2024-34359 | ❌ No GGUF scanner    | ✅ Jinja2 SSTI detection  |

### Keras & TensorFlow Advanced

| Model                           | Features        | modelscan Result  | ModelAudit Advantage             |
| ------------------------------- | --------------- | ----------------- | -------------------------------- |
| `mkiani/unsafe-keras`           | Lambda layers   | ⚠️ 1 MEDIUM       | ✅ CRITICAL + config analysis    |
| `Anggads01/trashnet-classifier` | Multiple .keras | ⚠️ Basic Lambda   | ✅ Advanced serialization checks |
| `mkiani/unsafe-saved-model`     | SavedModel      | ⚠️ Basic analysis | ✅ Comprehensive TF analysis     |

## 🥈 Tier 3: Framework Coverage Gaps (Medium-High Impact)

### Advanced Frameworks (100% Missed by modelscan)

| Framework        | Test Model                                               | modelscan Support | ModelAudit Support     |
| ---------------- | -------------------------------------------------------- | ----------------- | ---------------------- |
| **TensorRT**     | Any .plan/.engine file                                   | ❌ No scanner     | ✅ Engine analysis     |
| **OpenVINO**     | `OpenVINO/bert-base-uncased-sst2-unstructured80-int8-ov` | ❌ No scanner     | ✅ IR analysis         |
| **PaddlePaddle** | `PaddlePaddle/PP-OCRv5_server_det`                       | ❌ No scanner     | ✅ Model analysis      |
| **CoreML**       | Any .mlmodel file                                        | ❌ No scanner     | ✅ Model analysis      |
| **TFLite**       | Any .tflite file                                         | ❌ No scanner     | ✅ FlatBuffer analysis |
| **Flax/JAX**     | MessagePack models                                       | ❌ No scanner     | ✅ JAX analysis        |

### YOLO Advanced Analysis

| Model                                   | Type         | modelscan Result | ModelAudit Advantage          |
| --------------------------------------- | ------------ | ---------------- | ----------------------------- |
| `echo840/MonkeyOCR`                     | YOLO .pt     | ⚠️ Basic pickle  | ✅ 33 import analysis         |
| `guon/hand-eyes`                        | YOLOv8 seg   | ⚠️ Basic pickle  | ✅ Segmentation path analysis |
| `keremberke/yolov8m-hard-hat-detection` | Multiple .pt | ⚠️ Basic pickle  | ✅ Real-world import lists    |

## 📋 Comprehensive Demo Script

```bash
#!/bin/bash
# ModelAudit vs modelscan Comprehensive Comparison

echo "🚨 CRITICAL: Complete Blind Spots"
echo "=================================="

echo "1. ONNX Files (100% Skipped by modelscan)"
modelaudit hf://Xenova/clip-vit-base-patch16 --no-large-model-support
modelscan -p ~/.modelaudit/cache/huggingface/Xenova/clip-vit-base-patch16

echo "2. GGUF Templates (No Scanner in modelscan)"
modelaudit hf://microsoft/Phi-3-mini-4k-instruct-gguf --timeout 300
# modelscan has no GGUF support at all

echo "3. Configuration Exploits (No Analysis in modelscan)"
modelaudit hf://chandar-lab/NeoBERT
# modelscan doesn't analyze config files

echo "🔍 ADVANCED: Detection Quality Differences"
echo "=========================================="

echo "4. CVE Detection (modelscan Misses Known CVEs)"
modelaudit ~/.modelaudit/cache/huggingface/Retr0REG/CVE-2024-3568-poc/pickle.pkl
modelscan -p ~/.modelaudit/cache/huggingface/Retr0REG/CVE-2024-3568-poc/pickle.pkl

echo "5. Advanced Malicious Analysis"
modelaudit hf://nono31/malicious-models-repo
modelscan -p ~/.modelaudit/cache/huggingface/nono31/malicious-models-repo

echo "6. Framework Coverage"
# ModelAudit supports 20+ formats, modelscan supports 6 formats
```

## 📊 Expected Results Summary

### Guaranteed Outcomes:

- **ONNX Models**: modelscan skips 100%, ModelAudit analyzes 100%
- **GGUF Models**: modelscan has no scanner, ModelAudit detects template injection
- **Config Exploits**: modelscan has no analysis, ModelAudit detects RCE patterns
- **Known CVEs**: modelscan misses CVE PoCs, ModelAudit detects them
- **Framework Coverage**: 70% gap in format support

### Competitive Positioning:

This evidence demonstrates ModelAudit's **overwhelming technical superiority** across:

1. **Modern ML Security Threats** (GGUF, ONNX, configs)
2. **Comprehensive Detection** (20+ formats vs 6)
3. **Advanced Analysis** (CVE-specific, deep inspection)
4. **Real-World Coverage** (production ML pipelines)

## 🎯 Sales/Demo Strategy

1. **Lead with ONNX** - Most dramatic visual impact (67.8MB completely ignored)
2. **Follow with CVE Miss** - Known vulnerability completely missed
3. **Show Framework Gap** - 70% of formats unsupported
4. **Demonstrate Depth** - 12+ vs 3 issues on same malicious model

This creates an **undeniable case** for ModelAudit's technical superiority in production ML security.
