# Model Audit Scan Findings

This document tracks the findings from the `model-audit` scans performed on the models listed in `MODELS.md`.

## False Positives

### 1. Suspicious Configuration Patterns in `config.json`

- **Issue:** The manifest scanner is flagging keys in the `label2id` dictionary of Hugging Face `config.json` files as security risks (e.g., execution, network access, file access).
- **Models Affected:**
  - `openai/clip-vit-base-patch32`
  - `google/vit-base-patch16-224`
  - `microsoft/beit-base-patch16-224`
- **Details:** The scanner is misinterpreting the descriptive labels in the `label2id` mapping as commands or code. For example, the label "hog, pig, grunter, squealer, Sus scrofa" was flagged as an execution risk.
- **Recommendation:** The manifest scanner should be improved to differentiate between configuration values that are executable and those that are simple strings or labels. It should likely ignore the `label2id` field altogether.

### 2. Suspicious Data Structure in `flax_model.msgpack`

- **Issue:** The scanner is reporting a "Suspicious data structure" for `flax_model.msgpack` files in some Hugging Face models.
- **Models Affected:**
  - `openai/clip-vit-base-patch32`
  - `google/vit-base-patch16-224`
  - `microsoft/beit-base-patch16-224`
- **Details:** The scanner reports that the data structure does not match known ML model patterns. This is likely a false positive, as these are standard Flax model files from Hugging Face.
- **Recommendation:** The scanner's detection logic for Flax models should be reviewed and improved to correctly identify valid Flax model structures.

### 3. Suspicious Opcode Sequence in PyTorch Models

- **Issue:** The scanner is flagging a large number of "Suspicious opcode sequence: MANY_DANGEROUS_OPCODES" warnings in the `data.pkl` file of a PyTorch model downloaded from PyTorch Hub.
- **Models Affected:**
  - `ultralytics/yolov5n`
  - `pytorch/vision:v0.13.0-mobilenet_v2`
- **Details:** The scanner is flagging a high concentration of opcodes that can execute code, such as `REDUCE`, `INST`, `OBJ`, and `NEWOBJ`. Given the popularity of the model, it's likely that these are false positives and that the scanner is being overly sensitive.
- **Recommendation:** The pickle scanner's sensitivity to these opcodes should be reviewed. It may need to be adjusted to better distinguish between malicious and benign uses of these opcodes.

### 4. Suspicious Opcodes in Scikit-learn Models

- **Issue:** The pickle scanner is flagging `NEWOBJ` and `REDUCE` opcodes in a simple scikit-learn model saved with pickle.
- **Models Affected:**
  - `scikit-learn/logistic-regression` (locally created)
  - All other scikit-learn models created locally (see `MODELS.md`)
- **Details:** The scanner is flagging these opcodes as potential security risks. While these opcodes can be used for malicious purposes, they are also essential for serializing and deserializing Python objects, including scikit-learn models.
- **Recommendation:** The pickle scanner should be improved to better differentiate between benign and malicious use of these opcodes. This could involve checking the context in which the opcodes are used.

## Next Steps

- Continue scanning the remaining models in `MODELS.md` to gather more data.
- Report these findings to the `model-audit` development team.
