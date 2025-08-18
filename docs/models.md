# Test Models for ModelAudit

This document contains a curated list of models with known security issues that can be used to test and validate ModelAudit's detection capabilities. These models are publicly available on HuggingFace and contain various types of security vulnerabilities.

**⚠️ WARNING**: These models contain actual malicious code and security vulnerabilities. They should ONLY be used for testing security scanners and research purposes. Never use these models in production or execute them without proper sandboxing.

## PyTorch Pickle Bombs

Models that exploit pickle serialization vulnerabilities in PyTorch:

| Model                                | Issue Type | Description                                            |
| ------------------------------------ | ---------- | ------------------------------------------------------ |
| `drhyrum/bert-tiny-torch-picklebomb` | webbrowser | Picklebomb demonstration that attempts to open browser |
| `Frase/tiny-bert-model-unsafe`       | webbrowser | Contains `webbrowser.open()` in pickle                 |
| `kojino/bert-tiny-torch-picklebomb`  | pickle     | Fork of picklebomb demonstration                       |
| `drhyrum/bert-tiny-torch-vuln`       | vulnerable | Flagged as unsafe by HuggingFace                       |
| `ykilcher/totally-harmless-model`    | eval       | Contains `__builtin__.eval`                            |
| `hf-internal-testing/unsafe-model`   | exec       | Runs exec, known-bad control model                     |
| `matanby/unsafe-diffusion`           | pickle     | Unsafe pickle loading demonstration                    |
| `MustEr/bert_locked`                 | security   | Security research model - DO NOT DOWNLOAD              |
| `MustEr/gpt2-elite`                  | suspicious | Real-world model with suspicious imports               |

## Code Execution Variants

Models demonstrating various code execution techniques:

| Model                | Issue Type | Description                        |
| -------------------- | ---------- | ---------------------------------- |
| `mkiani/gpt2-exec`   | exec       | Code injected using `exec()`       |
| `mkiani/gpt2-runpy`  | runpy      | Code injected using `runpy` module |
| `mkiani/gpt2-system` | system     | Code injected using system call    |

## Keras/TensorFlow Vulnerabilities

Models with unsafe Keras/TensorFlow serialization:

| Model                                 | Issue Type | Description                           |
| ------------------------------------- | ---------- | ------------------------------------- |
| `mkiani/unsafe-keras`                 | keras      | Unsafe Keras serialization            |
| `mkiani/unsafe-saved-model`           | savedmodel | Unsafe TensorFlow SavedModel          |
| `mkiani/keras-unsafe-models`          | h5         | Keras H5 format with unsafe layers    |
| `Juna190825/github_jeffprosise_model` | keras      | Keras serialization flagged as unsafe |

## Joblib/Sklearn/Dill Exploits

Models exploiting joblib, sklearn, and dill serialization:

| Model                                    | Issue Type | Description                          |
| ---------------------------------------- | ---------- | ------------------------------------ |
| `willengler-uc/perovskite-screening`     | dill       | PAIT-PKL-100, dill coverage test     |
| `Iredteam/joblib-payload-chatbot`        | joblib     | Explicit joblib RCE proof-of-concept |
| `MasterShomya/Tweets_Sentiment_Analyzer` | joblib     | Joblib model flagged as unsafe       |
| `faaza/house-price-pipeline`             | joblib     | Small joblib test case               |
| `ankush-new-org/safe-model`              | posix      | Uses `posix.system` and XGBoost      |

## Miscellaneous Unsafe Models

Various other types of security issues:

| Model                      | Issue Type | Description                         |
| -------------------------- | ---------- | ----------------------------------- |
| `sheigel/best-llm`         | hack       | Demo for binary hacking             |
| `mcpotato/42-eicar-street` | eicar      | EICAR-style test content            |
| `linhdo/checkbox-detector` | space      | HuggingFace Space with unsafe model |
| `Bingsu/adetailer`         | yolo       | YOLO .pt test case                  |
| `Anzhc/Anzhcs_YOLOs`       | yolo       | Multiple unsafe .pt files           |

## CVE Demonstrations

Models demonstrating specific CVEs:

| Model                             | Issue Type | Description                         |
| --------------------------------- | ---------- | ----------------------------------- |
| `Retr0REG/CVE-2024-3568-poc`      | posix      | Shows `posix.system` in pickle      |
| `ppradyoth/pickle_test_0.0.20_7z` | pait       | PAIT-PKL-100 test                   |
| `ScanMe/test-models`              | eval       | Minimal pickle with `builtins.eval` |

## In-the-Wild Examples

Real models found in the wild with security issues:

| Model                            | Issue Type | Description                         |
| -------------------------------- | ---------- | ----------------------------------- |
| `Kijai/LivePortrait_safetensors` | unsafe     | Legitimate project with unsafe file |
| `danielritchie/test-yolo-model`  | yolo       | YOLO model that triggers scans      |
| `LovrOP/model_zavrsni_18`        | misc       | Small repository test               |

## PaddlePaddle Framework

Models with PaddlePaddle-specific vulnerabilities:

| Model                             | Issue Type | Description                |
| --------------------------------- | ---------- | -------------------------- |
| `HuggingWorm/PaddleNLP-ErnieTiny` | paddle     | Unsafe `Pickle.loads`      |
| `hfishtest/PaddleNLP-ErnieTiny`   | paddle     | Paddle with pickle imports |

## Safe Models for Comparison

These are legitimate, safe models that should NOT trigger security warnings:

| Model                                | Description                      |
| ------------------------------------ | -------------------------------- |
| `google-bert/bert-base-uncased`      | Standard BERT model              |
| `distilbert/distilbert-base-uncased` | DistilBERT model                 |
| `gpt2`                               | OpenAI GPT-2 model               |
| `t5-small`                           | Google T5 model                  |
| `facebook/bart-base`                 | Facebook BART model              |
| `meta-llama/Llama-3.2-1B`            | Meta Llama model (requires auth) |

## Usage

To scan any of these models with ModelAudit:

```bash
# Scan a single model
modelaudit hf://MODEL_NAME

# Scan with verbose output
modelaudit hf://MODEL_NAME --verbose

# Scan with JSON output
modelaudit hf://MODEL_NAME --format json --output results.json

# Example: Scan a known malicious model
modelaudit hf://ykilcher/totally-harmless-model
```

## Testing Script

A comprehensive testing script is available that scans all malicious models:

```bash
python scan_all_malicious_models.py
```

This will:

1. Scan all models in this list
2. Check if security issues are properly detected
3. Generate a summary report with detection rates
4. Save detailed results to `malicious_model_scan_results.json`

## Expected Detection Rates

A properly functioning ModelAudit should achieve:

- **95%+** detection rate for PyTorch pickle bombs
- **90%+** detection rate for code execution variants
- **85%+** detection rate for Keras/TensorFlow vulnerabilities
- **90%+** detection rate for joblib/sklearn exploits
- **100%** pass rate for safe models (no false positives)

## Contributing

If you find new models with security issues that should be added to this list:

1. Verify the security issue exists
2. Add the model to the appropriate category
3. Include a clear description of the vulnerability
4. Update the testing script if needed

## Disclaimer

These models are provided for security research and testing purposes only. The ModelAudit team and contributors are not responsible for any misuse of these models. Always handle potentially malicious models in isolated, sandboxed environments.
