# Model Audit Testing

## Overview

This document catalogs models used for testing the ModelAudit security scanner across various ML frameworks and potential threat vectors.

### Testing Objectives

1. Verify legitimate models scan clean without false positives
2. Ensure malicious models are properly identified and flagged
3. Test across PyTorch, TensorFlow, Keras, ONNX, and other formats
4. Cover pickle exploits, Lambda layers, config-based attacks, and more

### Statistics

- Total Models: 82 models cataloged
- Safe Models: 18 legitimate models (baseline testing)
- Malicious Models: 64 models with attack vectors
- Frameworks: PyTorch, TensorFlow, Keras, YOLO, Scikit-learn, GGUF, Paddle
- Attack Types: 7+ distinct exploitation methods

## Safe Models (Baseline Testing)

These models should scan clean and serve as negative controls for false positive detection.

| #   | Model Name                              | Type            | Source       | Status | Scan Results                                        |
| --- | --------------------------------------- | --------------- | ------------ | ------ | --------------------------------------------------- |
| 1   | `vikhyatk/moondream-2`                  | Computer Vision | Hugging Face | Failed | Repository not found                                |
| 2   | `openai/clip-vit-base-patch32`          | Computer Vision | Hugging Face | Clean  | `scan_results/openai-clip-vit-base-patch32.txt`     |
| 3   | `google/vit-base-patch16-224`           | Computer Vision | Hugging Face | Clean  | `scan_results/google-vit-base-patch16-224.txt`      |
| 4   | `facebook/detr-resnet-50`               | Computer Vision | Hugging Face | Clean  | `scan_results/facebook-detr-resnet-50.txt`          |
| 5   | `microsoft/beit-base-patch16-224`       | Computer Vision | Hugging Face | Clean  | `scan_results/microsoft-beit-base-patch16-224.txt`  |
| 6   | `ultralytics/yolov5n`                   | Computer Vision | PyTorch Hub  | Clean  | `scan_results/ultralytics-yolov5n.txt`              |
| 7   | `pytorch/vision:v0.13.0-mobilenet_v2`   | Computer Vision | PyTorch Hub  | Clean  | `scan_results/pytorch-mobilenet_v2.txt`             |
| 8   | `scikit-learn/logistic-regression`      | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-logistic_regression.txt` |
| 9   | `scikit-learn/decision-tree`            | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 10  | `scikit-learn/svm`                      | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 11  | `scikit-learn/random-forest`            | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 12  | `scikit-learn/gradient-boosting`        | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 13  | `scikit-learn/k-means`                  | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 14  | `scikit-learn/linear-regression`        | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 15  | `scikit-learn/ridge`                    | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 16  | `scikit-learn/lasso`                    | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 17  | `scikit-learn/pca`                      | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |
| 18  | `scikit-learn/agglomerative-clustering` | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                 |

## Malicious Models (Threat Detection Testing)

These models contain various attack vectors and should be detected as unsafe.

### PyTorch Pickle Bombs (On-load RCE)

Classic pickle deserialization attacks in PyTorch model files.

| #   | Model Name                           | Attack Vector | Source       | Primary Artifact     | Detection Notes                                     |
| --- | ------------------------------------ | ------------- | ------------ | -------------------- | --------------------------------------------------- |
| 19  | `drhyrum/bert-tiny-torch-picklebomb` | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Recommended test - Explicit picklebomb demo         |
| 20  | `Frase/tiny-bert-model-unsafe`       | Pickle RCE    | Hugging Face | `archive/data.pkl`   | Contains webbrowser.open and torch rebuild helpers  |
| 21  | `kojino/bert-tiny-torch-picklebomb`  | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Fork of picklebomb PoC                              |
| 22  | `drhyrum/bert-tiny-torch-vuln`       | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Flagged unsafe in HF UI                             |
| 23  | `ykilcher/totally-harmless-model`    | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Contains `__builtin__.eval` imports                 |
| 24  | `hf-internal-testing/unsafe-model`   | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Recommended test - Known-bad control model          |
| 25  | `matanby/unsafe-diffusion`           | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Dummy model demonstrating unsafe pickle loading     |
| 26  | `MustEr/bert_locked`                 | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Labeled "Security Research - Do NOT download"       |
| 27  | `MustEr/gpt2-elite`                  | Pickle RCE    | Hugging Face | `pytorch_model.bin`  | Flagged with suspicious imports, real-world example |
| 28  | `TencentAIGC/poisoned-model`         | Pickle RCE    | Hugging Face | `poisoned_model.pth` | Explicit `posix.system` import detection            |
| 29  | `DSfsdasgaa/shell`                   | Pickle RCE    | Hugging Face | `kcp.pth`, `ws.pth`  | `.pth` files with `posix.system`, includes ELF      |
| 30  | `nono31/malicious-models-repo`       | Multi-format  | Hugging Face | Multiple files       | Multiple unsafe files: PyTorch, GGUF, TensorFlow    |

### Alternative Execution Vectors

Different methods of achieving code execution beyond standard pickle.

| #   | Model Name           | Attack Vector  | Source       | Primary Artifact    | Detection Notes                 |
| --- | -------------------- | -------------- | ------------ | ------------------- | ------------------------------- |
| 31  | `mkiani/gpt2-exec`   | `exec()` call  | Hugging Face | `pytorch_model.bin` | Code injected using exec        |
| 32  | `mkiani/gpt2-runpy`  | `runpy` module | Hugging Face | `pytorch_model.bin` | Code injected using runpy       |
| 33  | `mkiani/gpt2-system` | System calls   | Hugging Face | `pytorch_model.bin` | Code injected using system call |

### YOLO Model Exploits (.pt/.pth files)

YOLO and PyTorch model files with embedded malicious pickle payloads.

| #   | Model Name                           | Attack Vector | Source       | Primary Artifact          | Detection Notes                             |
| --- | ------------------------------------ | ------------- | ------------ | ------------------------- | ------------------------------------------- |
| 34  | `echo840/MonkeyOCR`                  | YOLO pickle   | Hugging Face | `Structure/layout_zh.pt`  | Flagged "Detected Pickle imports (33)"      |
| 35  | `Uminosachi/FastSAM`                 | YOLO pickle   | Hugging Face | `FastSAM-s.pt`            | YOLO .pt with pickle imports                |
| 36  | `jags/yolov8_model_segmentation-set` | YOLO pickle   | Hugging Face | `face_yolov8n-seg2_60.pt` | YOLOv8 .pt flagged unsafe                   |
| 37  | `StableDiffusionVN/yolo`             | YOLO pickle   | Hugging Face | `yolo-human-parse-v2.pt`  | YOLO .pt flagged unsafe                     |
| 38  | `Zhao-Xuanxiang/yolov7-seg`          | YOLO pickle   | Hugging Face | `yolov7-seg.pt`           | YOLO .pt flagged unsafe                     |
| 39  | `ashllay/YOLO_Models`                | YOLO pickle   | Hugging Face | `segm/unwanted-3x.pt`     | YOLO .pt flagged unsafe                     |
| 40  | `hfmaster/models-moved/face-restore` | Mixed formats | Hugging Face | Mixed files               | Mixed files with dill and torch pickle sigs |

### Keras & TensorFlow Exploits

Malicious Keras models with Lambda layer exploits and TensorFlow SavedModel attacks.

| #   | Model Name                            | Attack Vector | Source       | Primary Artifact                      | Detection Notes                          |
| --- | ------------------------------------- | ------------- | ------------ | ------------------------------------- | ---------------------------------------- |
| 41  | `mkiani/unsafe-keras`                 | Keras Lambda  | Hugging Face | `unsafe_model.keras`                  | Recommended test - HF marks unsafe       |
| 42  | `mkiani/unsafe-saved-model`           | TF SavedModel | Hugging Face | `saved_model.pb`                      | Unsafe SavedModel example                |
| 43  | `mkiani/keras-unsafe-models`          | Keras Lambda  | Hugging Face | `unsafe_model.h5`                     | Keras H5 unsafe format                   |
| 44  | `Juna190825/github_jeffprosise_model` | Keras Lambda  | Hugging Face | `*.keras`                             | Keras serialization flagged unsafe by HF |
| 45  | `warmiros/unsafe_models`              | Keras Lambda  | Hugging Face | `unsafe.h5`, `unsafe.keras`           | Tiny PoCs for fast tests                 |
| 46  | `Sag1012/machine-translation`         | Keras Lambda  | Hugging Face | `BiLSTM/my_model (1).keras`           | Flagged with PAIT-KERAS-301              |
| 47  | `ScanMe/test-models`                  | Keras Lambda  | Hugging Face | `eval_lambda.keras`, `eval_lambda.h5` | Keras Lambda serialization PoCs          |

### Sklearn/Joblib/Pickle Exploits

Malicious pickled models from various ML libraries and serialization formats.

| #   | Model Name                                    | Attack Vector | Source       | Primary Artifact       | Detection Notes                                  |
| --- | --------------------------------------------- | ------------- | ------------ | ---------------------- | ------------------------------------------------ |
| 48  | `willengler-uc/perovskite-screening`          | Dill pickle   | Hugging Face | `model.dill`           | Flagged PAIT-PKL-100, good dill coverage         |
| 49  | `Iredteam/joblib-payload-chatbot`             | Joblib pickle | Hugging Face | `*.joblib`             | Explicit PoC repo for joblib RCE                 |
| 50  | `MasterShomya/Tweets_Sentiment_Analyzer`      | Joblib pickle | Hugging Face | `tokenizer.joblib`     | Joblib model flagged unsafe, plus unsafe Keras   |
| 51  | `faaza/house-price-pipeline`                  | Joblib pickle | Hugging Face | joblib model           | Small joblib example, test low-signal repos      |
| 52  | `ankush-new-org/safe-model`                   | Mixed pickle  | Hugging Face | `model.pkl`            | Flags include posix.system and XGBoost classes   |
| 53  | `Devishetty100/neoguardianai`                 | Joblib pickle | Hugging Face | `xgboost_model.joblib` | Flagged PAIT-PKL-100, dill and xgboost imports   |
| 54  | `cis5190/SVM_model`                           | Joblib pickle | Hugging Face | `BiLSTM_CNN.joblib`    | Marked "Protect AI Unsafe"                       |
| 55  | `Yuchan5386/Kode`                             | Joblib pickle | Hugging Face | `joblib` file          | Sklearn imports flagged unsafe                   |
| 56  | `hauson-fan/RagReuse`                         | Raw pickle    | Hugging Face | `psgs_w100.tsv.pkl`    | `posix.system` in pickle imports                 |
| 57  | `timotejKralik/hate_speech_correction_slovak` | Raw pickle    | Hugging Face | small pickle           | Small pickle with `posix.system`                 |
| 58  | `zpbrent/test`                                | Raw pickle    | Hugging Face | micro pickles          | Micro pickles exercising different torch opcodes |
| 59  | `ankushvangari-org2/unsafe-model`             | Raw pickle    | Hugging Face | `unsafe_model.pkl`     | Unsafe pickle                                    |
| 60  | `Ankush-Organization/safe-model`              | Raw pickle    | Hugging Face | `model.pkl`            | Includes `posix.system` plus XGBoost classes     |

### Demonstration & Mixed Attack Models

Educational demonstrations and models with multiple attack vectors.

| #   | Model Name                       | Attack Vector | Source       | Primary Artifact                        | Detection Notes                                  |
| --- | -------------------------------- | ------------- | ------------ | --------------------------------------- | ------------------------------------------------ |
| 61  | `sheigel/best-llm`               | PyTorch RCE   | Hugging Face | `pytorch_model.bin`                     | Demo for model binary exploitation               |
| 62  | `mcpotato/42-eicar-street`       | Multi-format  | Hugging Face | Multiple files                          | EICAR-style test content, multiple flagged files |
| 63  | `linhdo/checkbox-detector`       | PyTorch RCE   | HF Space     | `classifier-model.pt`                   | Space with unsafe model file                     |
| 64  | `Bingsu/adetailer`               | YOLO pickle   | Hugging Face | `person_yolov8n-seg.pt`                 | Common YOLO .pt test case                        |
| 65  | `Anzhc/Anzhcs_YOLOs`             | YOLO pickle   | Hugging Face | Multiple `*.pt`                         | Multiple .pt files marked unsafe                 |
| 66  | `liangjun1987/realtime-chat-llm` | Multi-format  | Hugging Face | `malicious_gguf.gguf`, `chat_model.pkl` | GGUF metadata and pickle in one repo             |

### CVE Demonstrations & Scanner Challenges

Models specifically designed to test scanner capabilities and known CVE exploits.

| #   | Model Name                        | Attack Vector  | Source       | Primary Artifact                      | Detection Notes                                     |
| --- | --------------------------------- | -------------- | ------------ | ------------------------------------- | --------------------------------------------------- |
| 67  | `Retr0REG/CVE-2024-3568-poc`      | Pickle CVE     | Hugging Face | `extra_data.pickle`, `pickle.pkl`     | CVE PoC with posix.system, opcode signature tests   |
| 68  | `ppradyoth/pickle_test_0.0.20_7z` | Scanner test   | Hugging Face | `danger.dat`                          | Flagged PAIT-PKL-100, exercises Protect AI Guardian |
| 69  | `ScanMe/test-models`              | False positive | Hugging Face | `eval.pkl`, `THIS_MODEL_IS_BENIGN...` | Minimal pickle with builtins.eval, FP challenge     |

### GGUF & Template Injection Attacks

Novel attack vectors using GGUF metadata and template injection.

| #   | Model Name                     | Attack Vector | Source       | Primary Artifact        | Detection Notes                                                             |
| --- | ------------------------------ | ------------- | ------------ | ----------------------- | --------------------------------------------------------------------------- |
| 70  | `nono31/malicious-models-repo` | GGUF SSTI     | Hugging Face | `malicious_sample.gguf` | GGUF chat-template SSTI, pair with JFrog's write-up                         |
| 83  | **CVE-2024-34359 Test Case**   | Jinja2 SSTI   | Local Test   | `tokenizer_config.json` | **✅ CONFIRMED** - retr0reg payload detected by ModelAudit's Jinja2 scanner |

### Configuration-based Exploits

Attacks leveraging model configuration files to execute remote code.

| #   | Model Name           | Attack Vector  | Source       | Primary Artifact | Detection Notes                                                   |
| --- | -------------------- | -------------- | ------------ | ---------------- | ----------------------------------------------------------------- |
| 71  | `cpack3z/NeoBERT-4x` | Config exploit | Hugging Face | `config.json`    | Config includes `trust_remote_code=True` for AutoConfig/AutoModel |

### Real-world Suspicious Models

Models found in the wild that trigger security scanners - mix of false positives and real threats.

| #   | Model Name                       | Attack Vector   | Source       | Primary Artifact     | Detection Notes                                  |
| --- | -------------------------------- | --------------- | ------------ | -------------------- | ------------------------------------------------ |
| 72  | `Kijai/LivePortrait_safetensors` | Mixed unsafe    | Hugging Face | `landmark_model.pth` | Legit project with unsafe file, Picklescan flags |
| 73  | `danielritchie/test-yolo-model`  | YOLO pickle     | Hugging Face | flagged file         | Simple YOLO test repo that trips unsafe scans    |
| 74  | `LovrOP/model_zavrsni_18`        | Unknown exploit | Hugging Face | flagged file         | Small repo to broaden corpus                     |
| 75  | `ComfyUI_LayerStyle`             | Multi-format    | Hugging Face | Multiple files       | Model pack with multiple unsafe files            |
| 76  | `F5AI-Resources/Setup-SD-model`  | Multi-format    | Hugging Face | Multiple files       | Several unsafe files in setup-style repo         |

### Paddle & Alternative Frameworks

Exploits in less common ML frameworks like PaddlePaddle.

| #   | Model Name                        | Attack Vector | Source       | Primary Artifact | Detection Notes                                   |
| --- | --------------------------------- | ------------- | ------------ | ---------------- | ------------------------------------------------- |
| 77  | `HuggingWorm/PaddleNLP-ErnieTiny` | Paddle pickle | Hugging Face | `*.pdparams`     | Unsafe Pickle.loads, links to Black Hat Asia talk |
| 78  | `hfishtest/PaddleNLP-ErnieTiny`   | Paddle pickle | Hugging Face | model files      | Small Paddle model with pickle import detection   |

### Backdoor & Data Poisoning Models

Models with trained-in malicious behaviors rather than code execution exploits.

| #   | Model Name               | Attack Vector | Source        | Primary Artifact | Detection Notes                                       |
| --- | ------------------------ | ------------- | ------------- | ---------------- | ----------------------------------------------------- |
| 79  | BackdoorBench Model Zoo  | Model poison  | External      | Various          | BadNets, Blended, WaNet, SSBA models for CIFAR-10/100 |
| 80  | NIST IARPA TrojAI Rounds | Model poison  | NIST/Data.gov | Various          | Hundreds of models with 50% poisoned by triggers      |

### Advanced Template & Config Exploits

Sophisticated attacks using template injection and configuration manipulation.

| #   | Model Name                        | Attack Vector   | Source       | Primary Artifact        | Detection Notes                                           |
| --- | --------------------------------- | --------------- | ------------ | ----------------------- | --------------------------------------------------------- |
| 81  | GGUF-SSTI Demo                    | Template inject | JFrog        | GGUF with chat_template | Jinja2 SSTI in chat_template metadata                     |
| 82  | `microsoft/Dayhoff-170m-UR50-BRq` | Config exploit  | Hugging Face | `config.json`           | auto_map pointing to remote code, needs trust_remote_code |

## Model Discovery & Intelligence

### Automated Discovery Queries

For ongoing identification of new suspicious models on Hugging Face:

```bash
# General vulnerability search
site:huggingface.co "This file is vulnerable" pickle

# YOLO .pt files with pickle imports
site:huggingface.co ".pt" "Detected Pickle imports"

# Keras Lambda exploits
site:huggingface.co ".keras" PAIT-KERAS

# Joblib serialization issues
site:huggingface.co "joblib" "Unsafe"

# CVE-specific searches
site:huggingface.co "CVE-2024" pickle
```

### Testing Recommendations

#### Safe Models for Baseline Testing

- `openai/clip-vit-base-patch32` - Established computer vision model
- `google/vit-base-patch16-224` - Google Vision Transformer
- Any of the scikit-learn models (#8-17) - Local, known-safe algorithms

#### Unsafe Models for Threat Detection

- `drhyrum/bert-tiny-torch-picklebomb` - Best for PyTorch pickle testing
- `hf-internal-testing/unsafe-model` - Best control model - known malicious
- `mkiani/unsafe-keras` - Best for Keras Lambda layer testing

### Attack Vector Summary

| Attack Type             | Count | Key Examples                              | Detection Focus                    |
| ----------------------- | ----- | ----------------------------------------- | ---------------------------------- |
| PyTorch Pickle RCE      | 12    | bert-tiny-torch-picklebomb                | `REDUCE`, `INST`, `NEWOBJ` opcodes |
| YOLO .pt Exploits       | 7     | MonkeyOCR, FastSAM                        | Pickle imports in .pt files        |
| Keras Lambda RCE        | 7     | unsafe-keras, eval_lambda.keras           | Lambda layer serialization         |
| Sklearn/Joblib          | 13    | joblib-payload-chatbot                    | Joblib/pickle deserialization      |
| GGUF Template Injection | 3     | malicious_sample.gguf, **CVE-2024-34359** | **Jinja2 SSTI in chat_template**   |
| Configuration Exploits  | 2     | NeoBERT-4x                                | trust_remote_code, auto_map        |
| Alternative Frameworks  | 2     | PaddleNLP models                          | Paddle pickle.loads                |

These queries and models provide comprehensive coverage for testing ModelAudit across the full spectrum of ML security threats.
