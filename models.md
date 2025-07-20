# Model Audit Testing: Scanning a Diverse Set of Models

## Objective

The goal of this task is to test the `model-audit` tool by scanning a diverse set of machine learning models. This process involves:

1.  **Curating a List:** Compiling a list of 20 models from various sources, focusing on smaller computer vision and scikit-learn models.
2.  **Downloading:** Downloading each model from its source (e.g., Hugging Face Hub).
3.  **Scanning:** Running `model-audit` on each downloaded model.
4.  **Analyzing:** Saving the scan results and analyzing them for potential false positives or other issues.
5.  **Reporting:** Documenting any findings to improve the `model-audit` tool.

## Model List

| #   | Model Name                               | Type              | Source        | Status      | Notes                               |
| --- | ---------------------------------------- | ----------------- | ------------- | ----------- | ----------------------------------- |
| 1   | `vikhyatk/moondream-2`                   | Computer Vision   | Hugging Face  | Failed      | Repository not found.               |
| 2   | `openai/clip-vit-base-patch32`           | Computer Vision   | Hugging Face  | Scanned     | See scan_results/openai-clip-vit-base-patch32.txt |
| 3   | `google/vit-base-patch16-224`            | Computer Vision   | Hugging Face  | Scanned     | See scan_results/google-vit-base-patch16-224.txt |
| 4   | `facebook/detr-resnet-50`                | Computer Vision   | Hugging Face  | Scanned     | See scan_results/facebook-detr-resnet-50.txt |
| 5   | `microsoft/beit-base-patch16-224`        | Computer Vision   | Hugging Face  | Scanned     | See scan_results/microsoft-beit-base-patch16-224.txt |
| 6   | `ultralytics/yolov5n`                    | Computer Vision   | PyTorch Hub   | Scanned     | See scan_results/ultralytics-yolov5n.txt |
| 7   | `pytorch/vision:v0.13.0-mobilenet_v2`    | Computer Vision   | PyTorch Hub   | Scanned     | See scan_results/pytorch-mobilenet_v2.txt |
| 8   | `scikit-learn/logistic-regression`       | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-logistic_regression.txt |
| 9   | `scikit-learn/decision-tree`             | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 10  | `scikit-learn/svm`                       | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 11  | `scikit-learn/random-forest`             | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 12  | `scikit-learn/gradient-boosting`         | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 13  | `scikit-learn/k-means`                   | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 14  | `scikit-learn/linear-regression`         | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 15  | `scikit-learn/ridge`                     | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 16  | `scikit-learn/lasso`                     | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 17  | `scikit-learn/pca`                       | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 18  | `scikit-learn/agglomerative-clustering`  | Scikit-learn      | Local         | Scanned     | See scan_results/scikit-learn-all.txt |
| 19  | `scikit-learn/pca`                       | Scikit-learn      | Hugging Face  | Not Started | Principal Component Analysis        |
| 20  | `scikit-learn/agglomerative-clustering`  | Scikit-learn      | Hugging Face  | Not Started | Agglomerative Clustering            |