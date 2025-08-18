# Model Audit Testing: Scanning a Diverse Set of Models

## Objective

The goal of this task is to test the `model-audit` tool by scanning a diverse set of machine learning models. This process involves:

1.  **Curating a List:** Compiling a list of 20 models from various sources, focusing on smaller computer vision and scikit-learn models.
2.  **Downloading:** Downloading each model from its source (e.g., Hugging Face Hub).
3.  **Scanning:** Running `model-audit` on each downloaded model.
4.  **Analyzing:** Saving the scan results and analyzing them for potential false positives or other issues.
5.  **Reporting:** Documenting any findings to improve the `model-audit` tool.

## Model List

| #   | Model Name                              | Type            | Source       | Status      | Notes                                                 |
| --- | --------------------------------------- | --------------- | ------------ | ----------- | ----------------------------------------------------- |
| 1   | `vikhyatk/moondream-2`                  | Computer Vision | Hugging Face | Failed      | Repository not found.                                 |
| 2   | `openai/clip-vit-base-patch32`          | Computer Vision | Hugging Face | Scanned     | See scan_results/openai-clip-vit-base-patch32.txt     |
| 3   | `google/vit-base-patch16-224`           | Computer Vision | Hugging Face | Scanned     | See scan_results/google-vit-base-patch16-224.txt      |
| 4   | `facebook/detr-resnet-50`               | Computer Vision | Hugging Face | Scanned     | See scan_results/facebook-detr-resnet-50.txt          |
| 5   | `microsoft/beit-base-patch16-224`       | Computer Vision | Hugging Face | Scanned     | See scan_results/microsoft-beit-base-patch16-224.txt  |
| 6   | `ultralytics/yolov5n`                   | Computer Vision | PyTorch Hub  | Scanned     | See scan_results/ultralytics-yolov5n.txt              |
| 7   | `pytorch/vision:v0.13.0-mobilenet_v2`   | Computer Vision | PyTorch Hub  | Scanned     | See scan_results/pytorch-mobilenet_v2.txt             |
| 8   | `scikit-learn/logistic-regression`      | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-logistic_regression.txt |
| 9   | `scikit-learn/decision-tree`            | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 10  | `scikit-learn/svm`                      | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 11  | `scikit-learn/random-forest`            | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 12  | `scikit-learn/gradient-boosting`        | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 13  | `scikit-learn/k-means`                  | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 14  | `scikit-learn/linear-regression`        | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 15  | `scikit-learn/ridge`                    | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 16  | `scikit-learn/lasso`                    | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 17  | `scikit-learn/pca`                      | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |
| 18  | `scikit-learn/agglomerative-clustering` | Scikit-learn    | Local        | Scanned     | See scan_results/scikit-learn-all.txt                 |

## Malicious Model Test Cases

### On-load RCE PyTorch Pickle Bombs

| #   | Model Name                           | Type        | Source       | Artifact            | Notes                                               |
| --- | ------------------------------------ | ----------- | ------------ | ------------------- | --------------------------------------------------- |
| 21  | `drhyrum/bert-tiny-torch-picklebomb` | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Explicitly demonstrates picklebomb payload          |
| 22  | `Frase/tiny-bert-model-unsafe`       | PyTorch RCE | Hugging Face | `archive/data.pkl`  | Contains webbrowser.open and torch rebuild helpers  |
| 23  | `kojino/bert-tiny-torch-picklebomb`  | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Fork of picklebomb PoC                              |
| 24  | `drhyrum/bert-tiny-torch-vuln`       | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Flagged unsafe in HF UI                             |
| 25  | `ykilcher/totally-harmless-model`    | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Contains **builtin**.eval imports                   |
| 26  | `hf-internal-testing/unsafe-model`   | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Model card says it runs exec, known-bad control     |
| 27  | `matanby/unsafe-diffusion`           | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Dummy model demonstrating unsafe pickle loading     |
| 28  | `MustEr/bert_locked`                 | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Labeled "Security Research - Do NOT download"       |
| 29  | `MustEr/gpt2-elite`                  | PyTorch RCE | Hugging Face | `pytorch_model.bin` | Flagged with suspicious imports, real-world example |
| 30  | `TencentAIGC/poisoned-model`         | PyTorch RCE | Hugging Face | `poisoned_model.pth` | Explicit `posix.system` import detection           |
| 31  | `DSfsdasgaa/shell`                   | PyTorch RCE | Hugging Face | `kcp.pth`, `ws.pth` | `.pth` files with `posix.system`, includes ELF      |
| 32  | `nono31/malicious-models-repo`       | Multi RCE   | Hugging Face | Multiple files      | Multiple unsafe files: pytorch_model.bin, GGUF, TF |

### Exec Mechanism Variants

| #   | Model Name           | Type           | Source       | Artifact            | Notes                           |
| --- | -------------------- | -------------- | ------------ | ------------------- | ------------------------------- |
| 33  | `mkiani/gpt2-exec`   | Exec variant   | Hugging Face | `pytorch_model.bin` | Code injected using exec        |
| 34  | `mkiani/gpt2-runpy`  | Runpy variant  | Hugging Face | `pytorch_model.bin` | Code injected using runpy       |
| 35  | `mkiani/gpt2-system` | System variant | Hugging Face | `pytorch_model.bin` | Code injected using system call |

### YOLO and PyTorch .pt/.pth Models

| #   | Model Name                          | Type        | Source       | Artifact                       | Notes                                           |
| --- | ----------------------------------- | ----------- | ------------ | ------------------------------ | ----------------------------------------------- |
| 36  | `echo840/MonkeyOCR`                 | YOLO RCE    | Hugging Face | `Structure/layout_zh.pt`       | YOLO .pt flagged "Detected Pickle imports (33)" |
| 37  | `Uminosachi/FastSAM`                | YOLO RCE    | Hugging Face | `FastSAM-s.pt`                 | YOLO .pt with pickle imports                    |
| 38  | `jags/yolov8_model_segmentation-set`| YOLO RCE    | Hugging Face | `face_yolov8n-seg2_60.pt`      | YOLOV8 .pt flagged unsafe                       |
| 39  | `StableDiffusionVN/yolo`            | YOLO RCE    | Hugging Face | `yolo-human-parse-v2.pt`       | YOLO .pt flagged unsafe                         |
| 40  | `Zhao-Xuanxiang/yolov7-seg`         | YOLO RCE    | Hugging Face | `yolov7-seg.pt`                | YOLO .pt flagged unsafe                         |
| 41  | `ashllay/YOLO_Models`               | YOLO RCE    | Hugging Face | `segm/unwanted-3x.pt`          | YOLO .pt flagged unsafe                         |
| 42  | `hfmaster/models-moved/face-restore`| Mixed RCE   | Hugging Face | Mixed files                    | Mixed files with dill and torch pickle sigs    |

### Keras and TensorFlow RCE PoCs

| #   | Model Name                            | Type          | Source       | Artifact             | Notes                                             |
| --- | ------------------------------------- | ------------- | ------------ | -------------------- | ------------------------------------------------- |
| 43  | `mkiani/unsafe-keras`                 | Keras RCE     | Hugging Face | `unsafe_model.keras` | HF marks file unsafe, Keras serialization exploit |
| 44  | `mkiani/unsafe-saved-model`           | TF SavedModel | Hugging Face | `saved_model.pb`     | Unsafe SavedModel example                         |
| 45  | `mkiani/keras-unsafe-models`          | Keras RCE     | Hugging Face | `unsafe_model.h5`    | Keras H5 unsafe format                            |
| 46  | `Juna190825/github_jeffprosise_model` | Keras RCE     | Hugging Face | `*.keras`            | Keras serialization flagged unsafe by HF scans    |
| 47  | `warmiros/unsafe_models`              | Keras RCE     | Hugging Face | `unsafe.h5`, `unsafe.keras` | Tiny PoCs for fast tests                      |
| 48  | `Sag1012/machine-translation`         | Keras RCE     | Hugging Face | `BiLSTM/my_model (1).keras` | Flagged with PAIT-KERAS-301                  |
| 49  | `ScanMe/test-models`                  | Keras RCE     | Hugging Face | `eval_lambda.keras`, `eval_lambda.h5` | Keras Lambda serialization PoCs         |

### Joblib/Dill/Sklearn Artifacts

| #   | Model Name                               | Type         | Source       | Artifact     | Notes                                          |
| --- | ---------------------------------------- | ------------ | ------------ | ------------ | ---------------------------------------------- |
| 50  | `willengler-uc/perovskite-screening`     | Dill RCE     | Hugging Face | `model.dill` | Flagged PAIT-PKL-100, good dill coverage       |
| 51  | `Iredteam/joblib-payload-chatbot`        | Joblib RCE   | Hugging Face | `*.joblib`   | Explicit PoC repo for joblib RCE               |
| 52  | `MasterShomya/Tweets_Sentiment_Analyzer` | Joblib RCE   | Hugging Face | `tokenizer.joblib` | Joblib model flagged unsafe, plus unsafe Keras |
| 53  | `faaza/house-price-pipeline`             | Joblib RCE   | Hugging Face | joblib model | Small joblib example, test low-signal repos    |
| 54  | `ankush-new-org/safe-model`              | Mixed pickle | Hugging Face | `model.pkl`  | Flags include posix.system and XGBoost classes |
| 55  | `Devishetty100/neoguardianai`            | Joblib RCE   | Hugging Face | `xgboost_model.joblib` | Flagged PAIT-PKL-100, imports include dill and xgboost |
| 56  | `cis5190/SVM_model`                      | Joblib RCE   | Hugging Face | `BiLSTM_CNN.joblib` | Marked "Protect AI Unsafe"                    |
| 57  | `Yuchan5386/Kode`                        | Joblib RCE   | Hugging Face | `joblib` file | Sklearn imports flagged unsafe                |
| 58  | `hauson-fan/RagReuse`                    | Pickle RCE   | Hugging Face | `psgs_w100.tsv.pkl` | `posix.system` in pickle imports              |
| 59  | `timotejKralik/hate_speech_correction_slovak` | Pickle RCE | Hugging Face | small pickle | Small pickle with `posix.system`              |
| 60  | `zpbrent/test`                           | Pickle RCE   | Hugging Face | micro pickles | Micro pickles exercising different torch opcodes |
| 61  | `ankushvangari-org2/unsafe-model`        | Pickle RCE   | Hugging Face | `unsafe_model.pkl` | Unsafe pickle                                |
| 62  | `Ankush-Organization/safe-model`         | Pickle RCE   | Hugging Face | `model.pkl`  | Includes `posix.system` plus XGBoost classes  |

### Misc Unsafe Demo Models

| #   | Model Name                 | Type         | Source       | Artifact                | Notes                                                   |
| --- | -------------------------- | ------------ | ------------ | ----------------------- | ------------------------------------------------------- |
| 63  | `sheigel/best-llm`         | PyTorch RCE  | Hugging Face | `pytorch_model.bin`     | Demo for how model binaries can be used for hacking     |
| 64  | `mcpotato/42-eicar-street` | Multiple RCE | Hugging Face | Multiple files          | EICAR-style test content, multiple flagged files        |
| 65  | `linhdo/checkbox-detector` | PyTorch RCE  | HF Space     | `classifier-model.pt`   | Space with unsafe model file                            |
| 66  | `Bingsu/adetailer`         | YOLO RCE     | Hugging Face | `person_yolov8n-seg.pt` | Common YOLO .pt test case                               |
| 67  | `Anzhc/Anzhcs_YOLOs`       | YOLO RCE     | Hugging Face | Multiple `*.pt`         | Multiple .pt files marked unsafe, variants without dill |
| 68  | `liangjun1987/realtime-chat-llm` | Mixed RCE | Hugging Face | `malicious_gguf.gguf`, `chat_model.pkl` | Exercises GGUF metadata and pickle in one repo |

### CVE and Scanner Challenge Artifacts

| #   | Model Name                        | Type           | Source       | Artifact            | Notes                                                |
| --- | --------------------------------- | -------------- | ------------ | ------------------- | ---------------------------------------------------- |
| 69  | `Retr0REG/CVE-2024-3568-poc`      | Pickle CVE     | Hugging Face | `extra_data.pickle`, `pickle.pkl` | Shows posix.system in pickle, opcode signature tests |
| 70  | `ppradyoth/pickle_test_0.0.20_7z` | Pickle test    | Hugging Face | `danger.dat`        | Flagged PAIT-PKL-100, exercises Protect AI Guardian  |
| 71  | `ScanMe/test-models`              | Minimal pickle | Hugging Face | `eval.pkl`, `THIS_MODEL_IS_BENIGN_ANY_DETECTION_IS_AN_FP.pkl` | Minimal pickle with builtins.eval, FP challenge model |

### GGUF and Template-based Attacks

| #   | Model Name                          | Type        | Source       | Artifact                 | Notes                                                     |
| --- | ----------------------------------- | ----------- | ------------ | ------------------------ | --------------------------------------------------------- |
| 72  | `nono31/malicious-models-repo`      | GGUF SSTI   | Hugging Face | `malicious_sample.gguf`  | GGUF chat-template SSTI, pair with JFrog's write-up      |

### Config-based Remote Code Flags

| #   | Model Name                        | Type        | Source       | Artifact       | Notes                                                     |
| --- | --------------------------------- | ----------- | ------------ | -------------- | --------------------------------------------------------- |
| 73  | `cpack3z/NeoBERT-4x`              | Remote code | Hugging Face | `config.json`  | Config changes include `trust_remote_code=True` for AutoConfig/AutoModel mapping |

### In-the-Wild Suspicious Files

| #   | Model Name                       | Type            | Source       | Artifact             | Notes                                                   |
| --- | -------------------------------- | --------------- | ------------ | -------------------- | ------------------------------------------------------- |
| 74  | `Kijai/LivePortrait_safetensors` | Mixed unsafe    | Hugging Face | `landmark_model.pth` | Legit project with unsafe file, Picklescan marks unsafe |
| 75  | `danielritchie/test-yolo-model`  | YOLO unsafe     | Hugging Face | flagged file         | Simple YOLO test repo that trips unsafe scans           |
| 76  | `LovrOP/model_zavrsni_18`        | Misc unsafe     | Hugging Face | flagged file         | Small repo to broaden corpus                            |
| 77  | `ComfyUI_LayerStyle`             | Multiple unsafe | Hugging Face | Multiple files       | Model pack with multiple unsafe files                   |
| 78  | `F5AI-Resources/Setup-SD-model`  | Multiple unsafe | Hugging Face | Multiple files       | Several unsafe files in setup-style repo                |

### Paddle and Mixed Format Models

| #   | Model Name                        | Type          | Source       | Artifact     | Notes                                             |
| --- | --------------------------------- | ------------- | ------------ | ------------ | ------------------------------------------------- |
| 79  | `HuggingWorm/PaddleNLP-ErnieTiny` | Paddle unsafe | Hugging Face | `*.pdparams` | Unsafe Pickle.loads, links to Black Hat Asia talk |
| 80  | `hfishtest/PaddleNLP-ErnieTiny`   | Paddle unsafe | Hugging Face | model files  | Small Paddle model with pickle import detection   |

### Backdoored Behavior Benchmarks

| #   | Model Name               | Type       | Source        | Artifact | Notes                                                  |
| --- | ------------------------ | ---------- | ------------- | -------- | ------------------------------------------------------ |
| 81  | BackdoorBench Model Zoo  | Backdoored | External      | Various  | BadNets, Blended, WaNet, SSBA models for CIFAR-10/100  |
| 82  | NIST IARPA TrojAI Rounds | Backdoored | NIST/Data.gov | Various  | Hundreds of models with 50% poisoned by known triggers |

### Template Injection and Config-based Attacks

| #   | Model Name                        | Type        | Source       | Artifact                | Notes                                                     |
| --- | --------------------------------- | ----------- | ------------ | ----------------------- | --------------------------------------------------------- |
| 83  | GGUF-SSTI Demo                    | GGUF SSTI   | JFrog        | GGUF with chat_template | Jinja2 SSTI in chat_template metadata                     |
| 84  | `microsoft/Dayhoff-170m-UR50-BRq` | Remote code | Hugging Face | `config.json`           | auto_map pointing to remote code, needs trust_remote_code |

## Model Discovery Queries

For ongoing discovery of new suspicious models on Hugging Face:

- General vulnerability search: `site:huggingface.co "This file is vulnerable" pickle`
- YOLO .pt files: `site:huggingface.co ".pt" "Detected Pickle imports"`
- Keras PoCs: `site:huggingface.co ".keras" PAIT-KERAS`
- Joblib files: `site:huggingface.co "joblib" "Unsafe"`

These queries help identify newly uploaded models flagged by security scanners and can feed the corpus with fresh, diverse samples as scanners and repositories evolve.
