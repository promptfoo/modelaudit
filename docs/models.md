# Model Audit Testing

## Overview

This document catalogs models used for testing the ModelAudit security scanner across various ML frameworks and potential threat vectors.

> **Safety Notice**
>
> - Do not import or execute model artifacts listed here. Use an isolated scanning environment.
> - Comply with the respective platform's terms and local laws.
> - Some entries are benign and included to exercise parsers; inclusion does not imply maliciousness.

### Testing Objectives

1. Verify legitimate models scan clean without false positives
2. Ensure malicious models are properly identified and flagged
3. Test across PyTorch, TensorFlow, Keras, ONNX, and other formats
4. Cover pickle exploits, Lambda layers, config-based attacks, and more

### Statistics

- Total Models: 135 active models + 10 archived models = 145 total cataloged
- Safe Models: 46 legitimate models (baseline testing)
- Malicious Models: 89 models with attack vectors
- Archived Models: 10 models no longer available (moved to bottom for historical reference)
- Frameworks: PyTorch, TensorFlow, Keras, YOLO, Scikit-learn, GGUF, Paddle
- Attack Types: 7+ distinct exploitation methods

## Safe Models (Baseline Testing)

These models should scan clean and serve as negative controls for false positive detection.

| #   | Model Name                                                        | Type            | Source       | Status | Scan Results                                                                                               |
| --- | ----------------------------------------------------------------- | --------------- | ------------ | ------ | ---------------------------------------------------------------------------------------------------------- |
| 1   | `openai/clip-vit-base-patch32`                                    | Computer Vision | Hugging Face | Clean  | `scan_results/openai-clip-vit-base-patch32.txt`                                                            |
| 2   | `google/vit-base-patch16-224`                                     | Computer Vision | Hugging Face | Clean  | `scan_results/google-vit-base-patch16-224.txt`                                                             |
| 3   | `facebook/detr-resnet-50`                                         | Computer Vision | Hugging Face | Clean  | `scan_results/facebook-detr-resnet-50.txt`                                                                 |
| 4   | `microsoft/beit-base-patch16-224`                                 | Computer Vision | Hugging Face | Clean  | `scan_results/microsoft-beit-base-patch16-224.txt`                                                         |
| 5   | `ultralytics/yolov5n`                                             | Computer Vision | PyTorch Hub  | Clean  | `scan_results/ultralytics-yolov5n.txt`                                                                     |
| 6   | `pytorch/vision:v0.13.0-mobilenet_v2`                             | Computer Vision | PyTorch Hub  | Clean  | `scan_results/pytorch-mobilenet_v2.txt`                                                                    |
| 7   | `scikit-learn/logistic-regression`                                | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-logistic_regression.txt`                                                        |
| 8   | `scikit-learn/decision-tree`                                      | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 9   | `scikit-learn/svm`                                                | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 10  | `scikit-learn/random-forest`                                      | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 11  | `scikit-learn/gradient-boosting`                                  | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 12  | `scikit-learn/k-means`                                            | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 13  | `scikit-learn/linear-regression`                                  | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 14  | `scikit-learn/ridge`                                              | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 15  | `scikit-learn/lasso`                                              | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 16  | `scikit-learn/pca`                                                | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 17  | `scikit-learn/agglomerative-clustering`                           | ML Algorithm    | Local        | Clean  | `scan_results/scikit-learn-all.txt`                                                                        |
| 18  | `sentence-transformers/all-MiniLM-L6-v2`                          | Text Embeddings | Hugging Face | Clean  | Safetensors format - no pickle execution risk                                                              |
| 19  | `timm/resnet50.a1_in1k`                                           | Computer Vision | Hugging Face | Clean  | Timm model with safetensors - validates timm coverage                                                      |
| 20  | `facebook/dinov2-base`                                            | Computer Vision | Hugging Face | Clean  | Vision backbone with safetensors - large file handling                                                     |
| 21  | `microsoft/resnet-50`                                             | Computer Vision | Hugging Face | Clean  | Classic ResNet with safetensors - ResNet repo validation                                                   |
| 22  | `google-bert/bert-base-uncased`                                   | NLP             | Hugging Face | Clean  | Base BERT with safetensors and ONNX - core NLP baseline                                                    |
| 23  | `distilbert/distilbert-base-uncased`                              | NLP             | Hugging Face | Clean  | DistilBERT with safetensors - minimal transformer control                                                  |
| 24  | `FacebookAI/roberta-base`                                         | NLP             | Hugging Face | Clean  | RoBERTa with safetensors - confirms RoBERTa configs clean                                                  |
| 25  | `google-t5/t5-small`                                              | NLP             | Hugging Face | Clean  | T5 with safetensors - encoder-decoder validation                                                           |
| 26  | `facebook/wav2vec2-base-960h`                                     | Audio ASR       | Hugging Face | Clean  | Wav2Vec2 with safetensors - audio feature extractors                                                       |
| 27  | `openai/whisper-tiny`                                             | Audio ASR       | Hugging Face | Clean  | Whisper with safetensors - small ASR baseline                                                              |
| 28  | `Xenova/clip-vit-base-patch16`                                    | ONNX            | Hugging Face | Clean  | CLIP vision-text ONNX - transformer ONNX validation                                                        |
| 29  | `Xenova/clip-vit-large-patch14`                                   | ONNX            | Hugging Face | Clean  | Large CLIP ONNX - bigger graph handling                                                                    |
| 30  | `onnx-community/mobilenet_v2_1.0_224`                             | ONNX            | Hugging Face | Clean  | MobileNetV2 ONNX - mobile CNN baseline                                                                     |
| 31  | `onnx-community/mobilenetv4_conv_small.e2400_r224_in1k`           | ONNX            | Hugging Face | Clean  | MobileNetV4 ONNX - modern opsets validation                                                                |
| 32  | `Kalray/resnet50`                                                 | ONNX            | Hugging Face | Clean  | ResNet50 ONNX with INT8 - quantized ONNX validation                                                        |
| 33  | `Kalray/deeplabv3plus-resnet50`                                   | ONNX            | Hugging Face | Clean  | Segmentation ONNX - segmentation graph coverage                                                            |
| 34  | `webnn/yolov8m`                                                   | ONNX            | Hugging Face | Clean  | YOLOv8 ONNX - confirms YOLO-in-ONNX doesn't FP like .pt                                                    |
| 35  | `OpenVINO/bert-base-uncased-sst2-unstructured80-int8-ov`          | OpenVINO        | Hugging Face | Clean  | OpenVINO IR (XML+BIN) - mixed asset repo validation                                                        |
| 36  | `helenai/distilbert-base-uncased-finetuned-sst-2-english-ov-int8` | OpenVINO        | Hugging Face | Clean  | OpenVINO IR INT8 - INT8 IR handling                                                                        |
| 37  | `TheBloke/Mistral-7B-Instruct-v0.2-GGUF`                          | GGUF LLM        | Hugging Face | Clean  | Safe GGUF baseline - template parsing validation                                                           |
| 38  | `QuantFactory/Meta-Llama-3-8B-Instruct-GGUF`                      | GGUF LLM        | Hugging Face | Clean  | Llama3 GGUF - large file and template parsing                                                              |
| 39  | `meta-llama/Llama-3.2-1B`                                         | PyTorch ZIP     | Hugging Face | Clean  | Llama-3.2-1B PyTorch model - tests improved CVE-2025-32434 density-based detection (2.3 GB, 294 opcodes)   |
| 40  | `PaddlePaddle/PP-OCRv5_server_det`                                | Paddle          | Hugging Face | Clean  | Paddle inference format - deployment assets                                                                |
| 41  | `PaddlePaddle/PP-OCRv3_mobile_det`                                | Paddle          | Hugging Face | Clean  | Paddle mobile inference - smaller inference bundles                                                        |
| 42  | `PaddlePaddle/PP-DocLayout-M`                                     | Paddle          | Hugging Face | Clean  | Paddle layout detection - inference packaging validation                                                   |
| 43  | `Mobilenet V3 Small 0.75 224`                                     | TensorFlow      | TF Hub       | Clean  | Clean feature extractor SavedModel - tfhub.dev/google/imagenet/mobilenet_v3_small_075_224/feature_vector/5 |
| 44  | `EfficientNetV2-B1 classification`                                | TensorFlow      | TF Hub       | Clean  | Standard TF2 SavedModel - tfhub.dev/google/imagenet/efficientnet_v2_imagenet1k_b1/classification/2         |
| 45  | `Universal Sentence Encoder (USE)`                                | TensorFlow      | TF Hub       | Clean  | Text embedding SavedModel - tfhub.dev/google/universal-sentence-encoder/2                                  |
| 46  | `SSD Mobilenet V2 (Open Images)`                                  | TensorFlow      | TF Hub       | Clean  | Object detection SavedModel - tfhub.dev/google/openimages_v4/ssd/mobilenet_v2/1                            |

## Malicious Models (Threat Detection Testing)

These models contain various attack vectors and should be detected as unsafe.

### PyTorch Pickle Bombs (On-load RCE)

Classic pickle deserialization attacks in PyTorch model files.

| #   | Model Name                              | Attack Vector | Source       | Primary Artifact                               | Detection Notes                                                                                                                    |
| --- | --------------------------------------- | ------------- | ------------ | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 46  | `drhyrum/bert-tiny-torch-picklebomb`    | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Recommended test - Explicit picklebomb demo                                                                                        |
| 47  | `Frase/tiny-bert-model-unsafe`          | Pickle RCE    | Hugging Face | `archive/data.pkl`                             | Contains webbrowser.open and torch rebuild helpers                                                                                 |
| 48  | `kojino/bert-tiny-torch-picklebomb`     | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Fork of picklebomb PoC                                                                                                             |
| 49  | `drhyrum/bert-tiny-torch-vuln`          | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Flagged unsafe in HF UI                                                                                                            |
| 50  | `ykilcher/totally-harmless-model`       | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Contains `__builtin__.eval` imports                                                                                                |
| 51  | `hf-internal-testing/unsafe-model`      | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Recommended test - Known-bad control model                                                                                         |
| 52  | `matanby/unsafe-diffusion`              | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Dummy model demonstrating unsafe pickle loading                                                                                    |
| 53  | `MustEr/bert_locked`                    | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Labeled "Security Research - Do NOT download"                                                                                      |
| 54  | `MustEr/gpt2-elite`                     | Pickle RCE    | Hugging Face | `pytorch_model.bin`                            | Flagged with suspicious imports, real-world example                                                                                |
| 55  | `TencentAIGC/poisoned-model`            | Pickle RCE    | Hugging Face | `poisoned_model.pth`                           | Explicit `posix.system` import detection                                                                                           |
| 56  | `DSfsdasgaa/shell`                      | Pickle RCE    | Hugging Face | `kcp.pth`, `ws.pth`                            | `.pth` files with `posix.system`, includes ELF                                                                                     |
| 57  | `YuhengSSS/VSSD`                        | Pickle RCE    | Hugging Face | `mask_rcnn_vssd_fpn_coco_micro.pth`            | "Detected Pickle imports (11)" in File Security Scans. Good for opcode coverage.                                                   |
| 58  | `XavierJiezou/ktda-models`              | Pickle RCE    | Hugging Face | `checkpoints/fcn.pth`                          | "Detected Pickle imports (11)." Useful for PyTorch load path test.                                                                 |
| 59  | `trackinglaboratory/CAMELTrack`         | Pickle RCE    | Hugging Face | `states/mot17-val.pklz`                        | Marked **Unsafe**. Exercises compressed pickle handling.                                                                           |
| 60  | `LiheYoung/Depth-Anything`              | Pickle RCE    | HF Space     | `checkpoints_semseg/ade20k_vitl_mIoU_59.4.pth` | File Security Scans mark file **Unsafe**. "Detected Pickle imports (11)" listed.                                                   |
| 61  | `rodrigomiranda98/tweet-eval-emotion`   | Raw pickle    | Hugging Face | `model.pkl`                                    | File page shows **Unsafe** status for the pickle file. Good for generic pickle‑load path tests.                                    |
| 62  | `cesaenv/rottenTomatoes`                | Raw pickle    | Hugging Face | `model.pkl`                                    | **Unsafe** with "Detected Pickle imports (97)" including FastAI, spaCy, and torch rebuild opcodes. Stresses large import surfaces. |
| 63  | `luisvarona/intel-image-classification` | Raw pickle    | Hugging Face | `model.pkl`                                    | **Unsafe** with "Detected Pickle imports (94)". Useful FastAI‑style pickle corpus.                                                 |

### Alternative Execution Vectors

Different methods of achieving code execution beyond standard pickle.

| #   | Model Name           | Attack Vector  | Source       | Primary Artifact    | Detection Notes                 |
| --- | -------------------- | -------------- | ------------ | ------------------- | ------------------------------- |
| 64  | `mkiani/gpt2-exec`   | `exec()` call  | Hugging Face | `pytorch_model.bin` | Code injected using exec        |
| 65  | `mkiani/gpt2-runpy`  | `runpy` module | Hugging Face | `pytorch_model.bin` | Code injected using runpy       |
| 66  | `mkiani/gpt2-system` | System calls   | Hugging Face | `pytorch_model.bin` | Code injected using system call |

### YOLO Model Exploits (.pt/.pth files)

YOLO and PyTorch model files with embedded malicious pickle payloads.

| #   | Model Name                              | Attack Vector | Source       | Primary Artifact            | Detection Notes                                                                                        |
| --- | --------------------------------------- | ------------- | ------------ | --------------------------- | ------------------------------------------------------------------------------------------------------ |
| 67  | `echo840/MonkeyOCR`                     | YOLO pickle   | Hugging Face | `Structure/layout_zh.pt`    | Flagged "Detected Pickle imports (33)"                                                                 |
| 68  | `Uminosachi/FastSAM`                    | YOLO pickle   | Hugging Face | `FastSAM-s.pt`              | YOLO .pt with pickle imports                                                                           |
| 69  | `jags/yolov8_model_segmentation-set`    | YOLO pickle   | Hugging Face | `face_yolov8n-seg2_60.pt`   | YOLOv8 .pt flagged unsafe                                                                              |
| 70  | `StableDiffusionVN/yolo`                | YOLO pickle   | Hugging Face | `yolo-human-parse-v2.pt`    | YOLO .pt flagged unsafe                                                                                |
| 71  | `Zhao-Xuanxiang/yolov7-seg`             | YOLO pickle   | Hugging Face | `yolov7-seg.pt`             | YOLO .pt flagged unsafe                                                                                |
| 72  | `ashllay/YOLO_Models`                   | YOLO pickle   | Hugging Face | `segm/unwanted-3x.pt`       | YOLO .pt flagged unsafe                                                                                |
| 73  | `guon/hand-eyes`                        | YOLO pickle   | Hugging Face | `PitHandDetailer-v1-seg.pt` | **Unsafe** with "Detected Pickle imports (33)". Exercises YOLOv8 seg task deserialization path.        |
| 74  | `keremberke/yolov8m-hard-hat-detection` | YOLO pickle   | Hugging Face | `*.pt` in repo root         | "Detected Pickle imports (24)" on scanned YOLO weights. Good for real‑world YOLO import lists.         |
| 75  | `deepghs/imgutils-models`               | YOLO pickle   | Hugging Face | `person_detect/*.pt`        | "Detected Pickle imports (24)" across person detection checkpoints. Useful for multiple file coverage. |
| 76  | `JCTN/adetailer`                        | YOLO pickle   | Hugging Face | `*.pt` in repo              | "Detected Pickle imports (33)". Alternative ADetailer variants beyond `Bingsu/adetailer`.              |

### Keras & TensorFlow Exploits

Malicious Keras models with Lambda layer exploits and TensorFlow SavedModel attacks.

| #   | Model Name                                | Attack Vector | Source       | Primary Artifact                                   | Detection Notes                                                                                                             |
| --- | ----------------------------------------- | ------------- | ------------ | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| 77  | `mkiani/unsafe-keras`                     | Keras Lambda  | Hugging Face | `unsafe_model.keras`                               | Recommended test - HF marks unsafe                                                                                          |
| 78  | `mkiani/unsafe-saved-model`               | TF SavedModel | Hugging Face | `saved_model.pb`                                   | Unsafe SavedModel example                                                                                                   |
| 79  | `mkiani/keras-unsafe-models`              | Keras Lambda  | Hugging Face | `unsafe_model.h5`                                  | Keras H5 unsafe format                                                                                                      |
| 80  | `Juna190825/github_jeffprosise_model`     | Keras Lambda  | Hugging Face | `*.keras`                                          | Keras serialization flagged unsafe by HF                                                                                    |
| 81  | `warmiros/unsafe_models`                  | Keras Lambda  | Hugging Face | `unsafe.h5`, `unsafe.keras`                        | Tiny PoCs for fast tests                                                                                                    |
| 82  | `Sag1012/machine-translation`             | Keras Lambda  | Hugging Face | `BiLSTM/my_model (1).keras`                        | Flagged with PAIT-KERAS-301                                                                                                 |
| 83  | `ScanMe/test-models`                      | Keras Lambda  | Hugging Face | `eval_lambda.keras`, `eval_lambda.h5`              | Keras Lambda serialization PoCs                                                                                             |
| 84  | `JackVines/ds_saliency_inference`         | TF SavedModel | Hugging Face | `saved_model.pb`                                   | File Security Scans mark the SavedModel **Unsafe**. Use to validate SavedModel handling and scanner verdicts.               |
| 85  | `alexanderkroner/MSI-Net`                 | TF SavedModel | Hugging Face | `saved_model.pb`                                   | File Security Scans mark the SavedModel **Unsafe**. Good real‑world SavedModel test.                                        |
| 86  | `dini15/Skin_Type`                        | Keras         | Hugging Face | `model_aug.keras`                                  | `.keras` file flagged **Unsafe** in File Security Scans. Useful for Lambda‑layer serialization checks.                      |
| 87  | `m7142yosuke/english2kana`                | Keras         | Hugging Face | `english2kana-v1.keras`                            | `.keras` file flagged **Unsafe**. Simple repro for Keras payload detection.                                                 |
| 88  | `ckavili/totally_harmless_no_scan_needed` | TF SavedModel | Hugging Face | `saved_model.pb`                                   | Marked **Unsafe**. Model card even jokes "totally harmless," making it a nice red‑team control.                             |
| 89  | `Anggads01/trashnet-classifier`           | Keras         | Hugging Face | `best_model.keras` or `DenseNet121_02_model.keras` | File Security Scans show **Unsafe** with `PAIT-KERAS-301` on multiple `.keras` files. Good for Lambda serialization checks. |

### Sklearn/Joblib/Pickle Exploits

Malicious pickled models from various ML libraries and serialization formats.

| #   | Model Name                                          | Attack Vector | Source       | Primary Artifact                   | Detection Notes                                                |
| --- | --------------------------------------------------- | ------------- | ------------ | ---------------------------------- | -------------------------------------------------------------- |
| 53  | `willengler-uc/perovskite-screening`                | Dill pickle   | Hugging Face | `model.dill`                       | Flagged PAIT-PKL-100, good dill coverage                       |
| 54  | `Iredteam/joblib-payload-chatbot`                   | Joblib pickle | Hugging Face | `*.joblib`                         | Explicit PoC repo for joblib RCE                               |
| 55  | `MasterShomya/Tweets_Sentiment_Analyzer`            | Joblib pickle | Hugging Face | `tokenizer.joblib`                 | Joblib model flagged unsafe, plus unsafe Keras                 |
| 56  | `faaza/house-price-pipeline`                        | Joblib pickle | Hugging Face | joblib model                       | Small joblib example, test low-signal repos                    |
| 57  | `ankush-new-org/safe-model`                         | Mixed pickle  | Hugging Face | `model.pkl`                        | Flags include posix.system and XGBoost classes                 |
| 58  | `Devishetty100/neoguardianai`                       | Joblib pickle | Hugging Face | `xgboost_model.joblib`             | Flagged PAIT-PKL-100, dill and xgboost imports                 |
| 59  | `cis5190/SVM_model`                                 | Joblib pickle | Hugging Face | `BiLSTM_CNN.joblib`                | Marked "Protect AI Unsafe"                                     |
| 61  | `hauson-fan/RagReuse`                               | Raw pickle    | Hugging Face | `psgs_w100.tsv.pkl`                | `posix.system` in pickle imports                               |
| 62  | `timotejKralik/hate_speech_correction_slovak`       | Raw pickle    | Hugging Face | small pickle                       | Small pickle with `posix.system`                               |
| 63  | `zpbrent/test`                                      | Raw pickle    | Hugging Face | micro pickles                      | Micro pickles exercising different torch opcodes               |
| 64  | `ankushvangari-org2/unsafe-model`                   | Raw pickle    | Hugging Face | `unsafe_model.pkl`                 | Unsafe pickle                                                  |
| 65  | `Ankush-Organization/safe-model`                    | Raw pickle    | Hugging Face | `model.pkl`                        | Includes `posix.system` plus XGBoost classes                   |
| 66  | `cis5190/transformer_model`                         | Joblib pickle | Hugging Face | `transformer_model.joblib`         | Protect AI marks **PAIT‑PKL‑100**. Good for joblib path.       |
| 67  | `bertin-project/bertin-base-stepwise`               | Joblib pickle | Hugging Face | `outputs/data_collator.joblib`     | **PAIT‑PKL‑100** with Tokenizers classes in imports.           |
| 68  | `bertin-project/bertin-base-gaussian-exp-512seqlen` | Joblib pickle | Hugging Face | `outputs/.../data_collator.joblib` | **PAIT‑PKL‑100**. Similar to above, different checkpoint path. |

### Demonstration & Mixed Attack Models

Educational demonstrations and models with multiple attack vectors.

| #   | Model Name                       | Attack Vector | Source       | Primary Artifact                        | Detection Notes                                  |
| --- | -------------------------------- | ------------- | ------------ | --------------------------------------- | ------------------------------------------------ |
| 71  | `sheigel/best-llm`               | PyTorch RCE   | Hugging Face | `pytorch_model.bin`                     | Demo for model binary exploitation               |
| 72  | `mcpotato/42-eicar-street`       | Multi-format  | Hugging Face | Multiple files                          | EICAR-style test content, multiple flagged files |
| 73  | `linhdo/checkbox-detector`       | PyTorch RCE   | HF Space     | `classifier-model.pt`                   | Space with unsafe model file                     |
| 74  | `Bingsu/adetailer`               | YOLO pickle   | Hugging Face | `person_yolov8n-seg.pt`                 | Common YOLO .pt test case                        |
| 75  | `Anzhc/Anzhcs_YOLOs`             | YOLO pickle   | Hugging Face | Multiple `*.pt`                         | Multiple .pt files marked unsafe                 |
| 76  | `liangjun1987/realtime-chat-llm` | Multi-format  | Hugging Face | `malicious_gguf.gguf`, `chat_model.pkl` | GGUF metadata and pickle in one repo             |

### CVE Demonstrations & Scanner Challenges

Models specifically designed to test scanner capabilities and known CVE exploits.

| #   | Model Name                   | Attack Vector | Source       | Primary Artifact                  | Detection Notes                                   |
| --- | ---------------------------- | ------------- | ------------ | --------------------------------- | ------------------------------------------------- |
| 78  | `Retr0REG/CVE-2024-3568-poc` | Pickle CVE    | Hugging Face | `extra_data.pickle`, `pickle.pkl` | CVE PoC with posix.system, opcode signature tests |

### GGUF & Template Injection Attacks

Novel attack vectors using GGUF metadata and template injection.

| #   | Model Name                                  | Attack Vector | Source       | Primary Artifact                  | Detection Notes                                                                                                                                                   |
| --- | ------------------------------------------- | ------------- | ------------ | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 81  | `nono31/malicious-models-repo`              | GGUF SSTI     | Hugging Face | `malicious_sample.gguf`           | GGUF chat-template SSTI, pair with JFrog's write-up                                                                                                               |
| 82  | **CVE-2024-34359 Test Case**                | Jinja2 SSTI   | Local Test   | `tokenizer_config.json`           | **✅ CONFIRMED** - retr0reg payload detected by ModelAudit's Jinja2 scanner                                                                                       |
| 83  | `LGAI-EXAONE/EXAONE-4.0-1.2B-GGUF`          | Jinja2 SSTI   | Hugging Face | `chat_template.jinja`             | Explicit Jinja chat template present. Use to ensure template scanning.                                                                                            |
| 84  | `meetkai/functionary-7b-v1.4-GGUF`          | Jinja2 SSTI   | Hugging Face | tokenizer `chat_template` commit  | Commit shows embedded Jinja template in config. Useful for scanner diff‑based detection.                                                                          |
| 85  | `openai/gpt-oss-20b`                        | Jinja2 SSTI   | Hugging Face | `chat_template.jinja`             | Large Jinja template. Good for edge‑case parsing and filter evasion tests.                                                                                        |
| 110 | `microsoft/Phi-3-mini-4k-instruct-gguf`     | Jinja2 SSTI   | Hugging Face | `*.gguf`                          | GGUF metadata includes `tokenizer.chat_template` string. Use to validate GGUF template scanning and SSTI guards. Presence ≠ exploit, but required for SSTI tests. |
| 111 | `gorilla-llm/gorilla-openfunctions-v0-gguf` | Jinja2 SSTI   | Hugging Face | `gorilla-openfunctions-v0-*.gguf` | Model card shows embedded `chat_template` Jinja. Good for tool‑calling templates and edge parsing.                                                                |

### Configuration-based Exploits

Attacks leveraging model configuration files to execute remote code.

| #   | Model Name                           | Attack Vector  | Source       | Primary Artifact | Detection Notes                                                                                                                       |
| --- | ------------------------------------ | -------------- | ------------ | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 87  | `internlm/internlm2-chat-7b`         | Config exploit | Hugging Face | `config.json`    | `auto_map` points to custom code. Transformers requires `trust_remote_code=True`. Use for remote‑code gating tests.                   |
| 88  | `deepseek-ai/DeepSeek-V3`            | Config exploit | Hugging Face | `config.json`    | Uses `auto_map` to custom modules. Validates your "no remote code" default.                                                           |
| 89  | `microsoft/Phi-3-mini-128k-instruct` | Config exploit | Hugging Face | `config.json`    | `auto_map` present. Known pattern that requires `trust_remote_code=True` when not natively supported.                                 |
| 112 | `chandar-lab/NeoBERT`                | Config exploit | Hugging Face | `config.json`    | Config includes `auto_map` to custom modules and `"trust_remote_code": true`. Use to ensure remote code is hard‑gated by your loader. |

### Real-world Suspicious Models

Models found in the wild that trigger security scanners - mix of false positives and real threats.

| #   | Model Name                       | Attack Vector   | Source       | Primary Artifact     | Detection Notes                                  |
| --- | -------------------------------- | --------------- | ------------ | -------------------- | ------------------------------------------------ |
| 90  | `Kijai/LivePortrait_safetensors` | Mixed unsafe    | Hugging Face | `landmark_model.pth` | Legit project with unsafe file, Picklescan flags |
| 91  | `danielritchie/test-yolo-model`  | YOLO pickle     | Hugging Face | flagged file         | Simple YOLO test repo that trips unsafe scans    |
| 92  | `LovrOP/model_zavrsni_18`        | Unknown exploit | Hugging Face | flagged file         | Small repo to broaden corpus                     |
| 94  | `F5AI-Resources/Setup-SD-model`  | Multi-format    | Hugging Face | Multiple files       | Several unsafe files in setup-style repo         |

### Paddle & Alternative Frameworks

Exploits in less common ML frameworks like PaddlePaddle.

| #   | Model Name                        | Attack Vector | Source       | Primary Artifact | Detection Notes                                   |
| --- | --------------------------------- | ------------- | ------------ | ---------------- | ------------------------------------------------- |
| 95  | `HuggingWorm/PaddleNLP-ErnieTiny` | Paddle pickle | Hugging Face | `*.pdparams`     | Unsafe Pickle.loads, links to Black Hat Asia talk |
| 96  | `hfishtest/PaddleNLP-ErnieTiny`   | Paddle pickle | Hugging Face | model files      | Small Paddle model with pickle import detection   |

### Backdoor & Data Poisoning Models

Models with trained-in malicious behaviors rather than code execution exploits.

| #   | Model Name               | Attack Vector | Source        | Primary Artifact | Detection Notes                                       |
| --- | ------------------------ | ------------- | ------------- | ---------------- | ----------------------------------------------------- |
| 97  | BackdoorBench Model Zoo  | Model poison  | External      | Various          | BadNets, Blended, WaNet, SSBA models for CIFAR-10/100 |
| 98  | NIST IARPA TrojAI Rounds | Model poison  | NIST/Data.gov | Various          | Hundreds of models with 50% poisoned by triggers      |

### Advanced Template & Config Exploits

Sophisticated attacks using template injection and configuration manipulation.

| #   | Model Name                        | Attack Vector   | Source       | Primary Artifact        | Detection Notes                                           |
| --- | --------------------------------- | --------------- | ------------ | ----------------------- | --------------------------------------------------------- |
| 99  | GGUF-SSTI Demo                    | Template inject | JFrog        | GGUF with chat_template | Jinja2 SSTI in chat_template metadata                     |
| 100 | `microsoft/Dayhoff-170m-UR50-BRq` | Config exploit  | Hugging Face | `config.json`           | auto_map pointing to remote code, needs trust_remote_code |

### KerasHub Config Files flagged by Protect AI

Keras configuration files with dynamic module references flagged by security scanners.

| #   | Model Name                        | Attack Vector | Source       | Primary Artifact    | Detection Notes                                                                                                                    |
| --- | --------------------------------- | ------------- | ------------ | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 113 | `keras/siglip2_large_patch16_256` | Keras config  | Hugging Face | `tokenizer.json`    | Protect AI marks file **Unsafe** with `PAIT-KERAS-301` due to dynamic module references. Useful to test config‑parsing allowlists. |
| 114 | `yuto-urushima/my_gemma2_pt`      | Keras config  | Hugging Face | `preprocessor.json` | Protect AI flags **PAIT-KERAS-301**. Tests resilience to KerasHub JSON with module paths.                                          |

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

## CVE-2025-32434 Improved Detection

**Update**: ModelAudit now uses advanced density-based analysis for CVE-2025-32434 detection, dramatically reducing false positives for large legitimate models while maintaining high security detection accuracy.

### Key Improvements

- **Dynamic Thresholds**: Detection thresholds scale with model file size
- **Density Analysis**: Uses opcodes-per-MB instead of absolute counts
- **Context Awareness**: Distinguishes between legitimate large models and malicious files
- **Graduated Severity**: Critical/Warning/Info levels based on risk context

### Threshold Matrix

| File Size    | Threshold (opcodes/MB) | Sensitivity | Example Models               |
| ------------ | ---------------------- | ----------- | ---------------------------- |
| < 10 MB      | 80                     | High        | Small custom models          |
| 10 MB – 1 GB | 200                    | Medium      | Standard models              |
| > 1 GB       | 500                    | Contextual  | Large LLMs (Llama, GPT-like) |

### Before vs. After

**Before**: `meta-llama/Llama-3.2-1B` → **CRITICAL** (294 opcodes > 80 threshold)  
**After**: `meta-llama/Llama-3.2-1B` → **SAFE** (294 opcodes ÷ 2,300 MB = 0.13 opcodes/MB < 500 threshold)

**Real malicious model** (1 MB, 80 opcodes): Still **CRITICAL** (80 opcodes ÷ 1 MB = 80 opcodes/MB > 80 threshold)

This improvement eliminates alert fatigue for legitimate large models while maintaining security effectiveness.

## ModelAudit vs modelscan: Comparative Testing

The following models are recommended for demonstrating ModelAudit's superior detection capabilities compared to ProtectAI's modelscan. These models highlight critical blind spots in modelscan where ModelAudit provides comprehensive security analysis.

### Models that Demonstrate ModelAudit's Advantages

**Test context**: modelscan submodule commit 8b8ed4b (as of August 23, 2025). Results reflect this commit and our standard test corpus.

| Category                    | Model                                   | ModelAudit Detection           | modelscan Result          | Impact       |
| --------------------------- | --------------------------------------- | ------------------------------ | ------------------------- | ------------ |
| **GGUF Template Injection** | `microsoft/Phi-3-mini-4k-instruct-gguf` | ✅ Chat template analysis      | ❌ No GGUF scanner        | **CRITICAL** |
| **ONNX Blind Spot**         | `Xenova/clip-vit-base-patch16`          | ✅ Full ONNX graph analysis    | ❌ Skips all .onnx files  | **HIGH**     |
| **ONNX Blind Spot**         | `onnx-community/mobilenet_v2_1.0_224`   | ✅ Custom operator detection   | ❌ Skips all .onnx files  | **HIGH**     |
| **Config Exploits**         | `internlm/internlm2-chat-7b`            | ✅ auto_map detection          | ❌ No config analysis     | **HIGH**     |
| **Config Exploits**         | `chandar-lab/NeoBERT`                   | ✅ trust_remote_code detection | ❌ No config analysis     | **HIGH**     |
| **Advanced PyTorch**        | `drhyrum/bert-tiny-torch-picklebomb`    | ✅ CVE-2025-32434 patterns     | ⚠️ Basic pickle detection | **MEDIUM**   |
| **Multi-format**            | `nono31/malicious-models-repo`          | ✅ 12+ distinct issues         | ⚠️ 3 basic issues         | **MEDIUM**   |

### Quick Comparison Commands

```bash
# Test ONNX blind spot (modelscan skips entirely)
modelaudit hf://Xenova/clip-vit-base-patch16 --no-large-model-support
modelscan -p ~/.modelaudit/cache/huggingface/Xenova/clip-vit-base-patch16

# Test GGUF template analysis
modelaudit hf://microsoft/Phi-3-mini-4k-instruct-gguf --timeout 300
# modelscan has no GGUF support

# Test configuration analysis
modelaudit hf://internlm/internlm2-chat-7b
# modelscan has no config analysis

# Test advanced malicious detection
modelaudit hf://nono31/malicious-models-repo
modelscan -p ~/.modelaudit/cache/huggingface/nono31/malicious-models-repo
```

### Key Findings Summary

1. **ONNX Models**: in our tests (commit 8b8ed4b), modelscan skipped ONNX files (0% coverage on the listed corpus)
2. **GGUF Models**: as of commit 8b8ed4b, modelscan had no GGUF scanner or template injection checks
3. **Configuration Files**: as tested, modelscan did not analyze config.json/tokenizer_config.json
4. **Advanced Frameworks**: missing scanners observed for TensorRT, OpenVINO, PaddlePaddle, CoreML, TFLite in our tests

### Recommended Test Sequence for Demos

1. **Start with ONNX**: `Xenova/clip-vit-base-patch16` - Shows complete modelscan blind spot
2. **GGUF Templates**: `microsoft/Phi-3-mini-4k-instruct-gguf` - Shows missing GGUF support
3. **Config Exploits**: `chandar-lab/NeoBERT` - Shows missing configuration analysis
4. **Advanced Detection**: `nono31/malicious-models-repo` - Shows ModelAudit's deeper analysis

In these tests, ModelAudit detected issues that modelscan (commit 8b8ed4b) missed, indicating material gaps in coverage on the evaluated corpus and date.

## Archived Models (No Longer Available)

The following models were previously cataloged but are no longer available on their original platforms. They are kept here for archival purposes and historical reference.

### Safe Models (Archived)

| #   | Model Name              | Type            | Source       | Status               | Original Notes                                 |
| --- | ----------------------- | --------------- | ------------ | -------------------- | ---------------------------------------------- |
| 1   | `vikhyatk/moondream-2`  | Computer Vision | Hugging Face | Repository not found | Repository not found                           |
| 35  | `Qualcomm/MobileNet-v2` | ONNX            | Hugging Face | Repository not found | Vendor ONNX reference - vendor-packaged graphs |

### Malicious Models (Archived)

| #   | Model Name                                  | Attack Vector  | Source       | Status               | Original Notes                                                                   |
| --- | ------------------------------------------- | -------------- | ------------ | -------------------- | -------------------------------------------------------------------------------- |
| 43  | `hfmaster/models-moved/face-restore`        | Mixed formats  | Hugging Face | Repository not found | Mixed files with dill and torch pickle sigs                                      |
| 60  | `Yuchan5386/Kode`                           | Joblib pickle  | Hugging Face | Repository not found | Sklearn imports flagged unsafe                                                   |
| 69  | `luo3300612/MLB_Score_2014_2019`            | Raw pickle     | Hugging Face | Repository not found | Marked **Unsafe / PAIT‑PKL‑100**. Small, fast to scan.                           |
| 70  | `noor-aakba/NN-Classifier`                  | Raw pickle     | Hugging Face | Repository not found | Marked **Unsafe / PAIT‑PKL‑100**. Handy minimal pickle case.                     |
| 77  | `PrunaAI/maxvit_base_tf_512_32_unet_preact` | Raw pickle     | Hugging Face | Repository not found | Protect AI flags **PAIT‑PKL‑100**. Shows dill/pickle mix and non‑sklearn pickle. |
| 79  | `ppradyoth/pickle_test_0.0.20_7z`           | Scanner test   | Hugging Face | Repository not found | Flagged PAIT-PKL-100, exercises Protect AI Guardian                              |
| 86  | `cpack3z/NeoBERT-4x`                        | Config exploit | Hugging Face | Repository not found | Config includes `trust_remote_code=True` for AutoConfig/AutoModel                |
| 93  | `ComfyUI_LayerStyle`                        | Multi-format   | Hugging Face | Repository not found | Model pack with multiple unsafe files                                            |
