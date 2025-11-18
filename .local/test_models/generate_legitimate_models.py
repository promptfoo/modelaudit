#!/usr/bin/env python3
"""
Generate LEGITIMATE model files using actual ML libraries.
This creates real models, not hand-crafted byte sequences.
"""

import io
import json
import pickle
import struct
import tarfile
import warnings
import zipfile
from pathlib import Path

import numpy as np

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

OUTPUT_DIR = Path(__file__).parent
OUTPUT_DIR.mkdir(exist_ok=True)

print("=" * 80)
print("Generating LEGITIMATE Model Files Using Real ML Libraries")
print("=" * 80)
print()


def log_success(filename, description):
    print(f"✓ {filename:<45} {description}")


def log_skip(filename, reason):
    print(f"⊘ {filename:<45} SKIPPED: {reason}")


# ============================================================================
# 1. SCIKIT-LEARN MODELS (Pickle formats)
# ============================================================================
print("🔬 SCIKIT-LEARN MODELS")
print("-" * 80)

try:
    from sklearn.datasets import make_classification
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    import joblib

    # Create simple dataset
    X, y = make_classification(n_samples=100, n_features=4, n_classes=2, random_state=42)

    # Train LogisticRegression
    lr_model = LogisticRegression(random_state=42)
    lr_model.fit(X, y)

    # Save as different pickle formats
    with open(OUTPUT_DIR / "sklearn_logistic.pkl", "wb") as f:
        pickle.dump(lr_model, f)
    log_success("sklearn_logistic.pkl", "Scikit-learn LogisticRegression")

    with open(OUTPUT_DIR / "sklearn_logistic.pickle", "wb") as f:
        pickle.dump(lr_model, f)
    log_success("sklearn_logistic.pickle", "Same model, .pickle extension")

    # Train RandomForest
    rf_model = RandomForestClassifier(n_estimators=10, random_state=42)
    rf_model.fit(X, y)

    # Save with joblib
    joblib.dump(rf_model, OUTPUT_DIR / "sklearn_rf.joblib")
    log_success("sklearn_rf.joblib", "Scikit-learn RandomForest")

except ImportError as e:
    log_skip("sklearn_*.pkl", "scikit-learn not installed")

print()


# ============================================================================
# 2. PYTORCH MODELS
# ============================================================================
print("🔥 PYTORCH MODELS")
print("-" * 80)

try:
    import torch
    import torch.nn as nn

    # Define simple model
    class SimpleNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(4, 10)
            self.fc2 = nn.Linear(10, 2)
            self.relu = nn.ReLU()

        def forward(self, x):
            x = self.relu(self.fc1(x))
            return self.fc2(x)

    # Create and save model
    model = SimpleNN()

    # Save full model (.pt)
    torch.save(model, OUTPUT_DIR / "pytorch_full_model.pt")
    log_success("pytorch_full_model.pt", "PyTorch full model")

    # Save state dict (.pth)
    torch.save(model.state_dict(), OUTPUT_DIR / "pytorch_state_dict.pth")
    log_success("pytorch_state_dict.pth", "PyTorch state dict")

    # Save checkpoint (.ckpt)
    checkpoint = {
        "epoch": 10,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": None,
        "loss": 0.5,
    }
    torch.save(checkpoint, OUTPUT_DIR / "pytorch_checkpoint.ckpt")
    log_success("pytorch_checkpoint.ckpt", "PyTorch training checkpoint")

except ImportError:
    log_skip("pytorch_*.pt", "PyTorch not installed")

print()


# ============================================================================
# 3. TENSORFLOW/KERAS MODELS
# ============================================================================
print("🧠 TENSORFLOW/KERAS MODELS")
print("-" * 80)

try:
    import tensorflow as tf
    from tensorflow import keras

    # Create simple Keras model
    model = keras.Sequential(
        [
            keras.layers.Dense(10, activation="relu", input_shape=(4,)),
            keras.layers.Dense(2, activation="softmax"),
        ]
    )

    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy")

    # Generate dummy data and train briefly
    X_train = np.random.randn(100, 4).astype(np.float32)
    y_train = np.random.randint(0, 2, 100)
    model.fit(X_train, y_train, epochs=1, verbose=0)

    # Save as HDF5 (.h5)
    model.save(OUTPUT_DIR / "keras_model.h5")
    log_success("keras_model.h5", "Keras model (HDF5 format)")

    # Save as Keras format (.keras)
    model.save(OUTPUT_DIR / "keras_model.keras")
    log_success("keras_model.keras", "Keras model (Keras format)")

    # Save as SavedModel directory
    model.save(OUTPUT_DIR / "tf_saved_model")
    log_success("tf_saved_model/", "TensorFlow SavedModel directory")

    # Convert to TFLite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    (OUTPUT_DIR / "keras_model.tflite").write_bytes(tflite_model)
    log_success("keras_model.tflite", "TensorFlow Lite model")

except ImportError:
    log_skip("keras_*.h5", "TensorFlow not installed")

print()


# ============================================================================
# 4. ONNX MODELS
# ============================================================================
print("🔄 ONNX MODELS")
print("-" * 80)

try:
    import torch
    import torch.nn as nn
    import torch.onnx

    # Create simple PyTorch model
    class SimpleNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc = nn.Linear(4, 2)

        def forward(self, x):
            return self.fc(x)

    model = SimpleNet()
    model.eval()

    # Export to ONNX
    dummy_input = torch.randn(1, 4)
    torch.onnx.export(
        model,
        dummy_input,
        OUTPUT_DIR / "pytorch_model.onnx",
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}},
    )
    log_success("pytorch_model.onnx", "PyTorch exported to ONNX")

except (ImportError, Exception) as e:
    log_skip("*.onnx", f"ONNX export failed: {type(e).__name__}")

print()


# ============================================================================
# 5. PMML MODELS
# ============================================================================
print("📈 PMML MODELS")
print("-" * 80)

try:
    from sklearn.datasets import load_iris
    from sklearn.tree import DecisionTreeClassifier
    from sklearn2pmml import sklearn2pmml
    from sklearn2pmml.pipeline import PMMLPipeline

    # Load iris dataset
    iris = load_iris()
    X, y = iris.data, iris.target

    # Create PMML pipeline
    pipeline = PMMLPipeline([("classifier", DecisionTreeClassifier(max_depth=3, random_state=42))])

    pipeline.fit(X, y)

    # Export to PMML
    sklearn2pmml(pipeline, OUTPUT_DIR / "iris_decision_tree.pmml", with_repr=True)
    log_success("iris_decision_tree.pmml", "Decision tree exported to PMML")

except (ImportError, RuntimeError) as e:
    log_skip("*.pmml", f"PMML export failed: {type(e).__name__} (requires Java)")

print()


# ============================================================================
# 6. NUMPY ARRAYS
# ============================================================================
print("🔢 NUMPY ARRAYS")
print("-" * 80)

# Generate weight arrays
weights = np.random.randn(100, 50).astype(np.float32)
biases = np.random.randn(50).astype(np.float32)

# Save as .npy
np.save(OUTPUT_DIR / "model_weights.npy", weights)
log_success("model_weights.npy", "NumPy array file")

# Save as .npz (compressed)
np.savez(OUTPUT_DIR / "model_params.npz", weights=weights, biases=biases)
log_success("model_params.npz", "Compressed NumPy arrays")

print()


# ============================================================================
# 7. SAFETENSORS
# ============================================================================
print("🔐 SAFETENSORS")
print("-" * 80)

try:
    from safetensors.torch import save_file

    import torch

    # Create tensors
    tensors = {
        "weight": torch.randn(10, 10),
        "bias": torch.randn(10),
    }

    # Save as SafeTensors
    save_file(tensors, OUTPUT_DIR / "model.safetensors")
    log_success("model.safetensors", "SafeTensors format")

except ImportError:
    log_skip("*.safetensors", "safetensors not installed")

print()


# ============================================================================
# 8. ARCHIVES
# ============================================================================
print("📦 ARCHIVE FORMATS")
print("-" * 80)

# Create ZIP archive
with zipfile.ZipFile(OUTPUT_DIR / "model_archive.zip", "w") as zf:
    zf.writestr("config.json", json.dumps({"model": "test", "version": "1.0"}))
    zf.writestr("weights.bin", np.random.randn(100).astype(np.float32).tobytes())
log_success("model_archive.zip", "ZIP archive with model files")

# Create TAR archive
with tarfile.open(OUTPUT_DIR / "model_archive.tar", "w") as tar:
    # Add config
    config_data = json.dumps({"model": "test"}).encode()
    config_info = tarfile.TarInfo("config.json")
    config_info.size = len(config_data)
    tar.addfile(config_info, io.BytesIO(config_data))
log_success("model_archive.tar", "TAR archive")

# Create compressed TAR
with tarfile.open(OUTPUT_DIR / "model_archive.tar.gz", "w:gz") as tar:
    config_data = json.dumps({"model": "test"}).encode()
    config_info = tarfile.TarInfo("config.json")
    config_info.size = len(config_data)
    tar.addfile(config_info, io.BytesIO(config_data))
log_success("model_archive.tar.gz", "Compressed TAR archive")

print()


# ============================================================================
# 9. OPENVINO (XML + BIN)
# ============================================================================
print("⚡ OPENVINO IR")
print("-" * 80)

# Create proper OpenVINO XML
openvino_xml = """<?xml version="1.0"?>
<net name="simple_net" version="11">
    <layers>
        <layer id="0" name="input" type="Input" version="opset1">
            <data element_type="f32" shape="1,3,224,224"/>
            <output>
                <port id="0" precision="FP32">
                    <dim>1</dim>
                    <dim>3</dim>
                    <dim>224</dim>
                    <dim>224</dim>
                </port>
            </output>
        </layer>
        <layer id="1" name="output" type="Result" version="opset1">
            <input>
                <port id="0">
                    <dim>1</dim>
                    <dim>3</dim>
                    <dim>224</dim>
                    <dim>224</dim>
                </port>
            </input>
        </layer>
    </layers>
    <edges>
        <edge from-layer="0" from-port="0" to-layer="1" to-port="0"/>
    </edges>
</net>
"""

(OUTPUT_DIR / "openvino_model.xml").write_text(openvino_xml)
log_success("openvino_model.xml", "OpenVINO IR XML")

# Companion .bin file (dummy weights)
(OUTPUT_DIR / "openvino_model.bin").write_bytes(np.zeros(1000, dtype=np.float32).tobytes())
log_success("openvino_model.bin", "OpenVINO IR weights")

print()


# ============================================================================
# SUMMARY
# ============================================================================
print("=" * 80)
print("✅ Legitimate Model Generation Complete!")
print("=" * 80)
print()

# Count files
model_files = [f for f in OUTPUT_DIR.glob("*") if f.is_file() and f.suffix != ".py" and f.name != "README.md" and f.name != "SCAN_RESULTS.md"]
model_dirs = [d for d in OUTPUT_DIR.glob("*") if d.is_dir() and not d.name.startswith(".")]

print(f"📊 Generated:")
print(f"   - {len(model_files)} model files")
print(f"   - {len(model_dirs)} model directories")
print()
print("🔍 Next step: Scan with ModelAudit")
print(f"   rye run modelaudit {OUTPUT_DIR}")
print()
