#!/usr/bin/env python3
"""
Generate legitimate examples of all model file formats supported by ModelAudit.
This creates a comprehensive test dataset for validation and testing.
"""

import io
import json
import pickle
import struct
import tarfile
import zipfile
from pathlib import Path

import numpy as np

# Create output directory
OUTPUT_DIR = Path(__file__).parent
OUTPUT_DIR.mkdir(exist_ok=True)

print("=" * 80)
print("Generating ModelAudit Test Dataset")
print("=" * 80)
print()


def save_file(filename: str, content: bytes, description: str):
    """Helper to save binary content to file."""
    filepath = OUTPUT_DIR / filename
    filepath.write_bytes(content)
    print(f"✓ Generated: {filename:<40} ({description})")
    return filepath


# ============================================================================
# 1. PICKLE FORMATS
# ============================================================================
print("📦 PICKLE FORMATS")
print("-" * 80)

# Simple dictionary data
simple_data = {"model": "test", "version": "1.0", "weights": [1.0, 2.0, 3.0]}

# .pkl - Standard pickle
save_file("simple_model.pkl", pickle.dumps(simple_data, protocol=4), "Standard pickle file")

# .pickle - Alternative extension
save_file("simple_model.pickle", pickle.dumps(simple_data, protocol=4), "Pickle with .pickle extension")

# .dill - Dill format (same as pickle for simple objects)
save_file("simple_model.dill", pickle.dumps(simple_data, protocol=4), "Dill serialized object")

# .pt - PyTorch pickle format
save_file("pytorch_model.pt", pickle.dumps(simple_data, protocol=4), "PyTorch .pt file")

# .pth - PyTorch weights
save_file("pytorch_weights.pth", pickle.dumps(simple_data, protocol=4), "PyTorch .pth file")

# .ckpt - Checkpoint file
save_file("checkpoint.ckpt", pickle.dumps(simple_data, protocol=4), "Model checkpoint file")

# .joblib - Joblib serialization (pickle-based)
save_file("sklearn_model.joblib", pickle.dumps(simple_data, protocol=4), "Joblib serialized model")

print()


# ============================================================================
# 2. HDF5 FORMATS
# ============================================================================
print("📊 HDF5 FORMATS")
print("-" * 80)

# HDF5 magic bytes + minimal structure
hdf5_magic = b"\x89HDF\r\n\x1a\n"
hdf5_content = hdf5_magic + b"\x00" * 512  # Minimal HDF5 file

save_file("keras_model.h5", hdf5_content, "Keras HDF5 model")
save_file("keras_model.hdf5", hdf5_content, "HDF5 format model")
save_file("keras_model.keras", hdf5_content, "Keras native format")

print()


# ============================================================================
# 3. NUMPY FORMATS
# ============================================================================
print("🔢 NUMPY FORMATS")
print("-" * 80)

# .npy - NumPy array
arr = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
npy_buffer = io.BytesIO()
np.save(npy_buffer, arr)
save_file("weights.npy", npy_buffer.getvalue(), "NumPy array file")

# .npz - Compressed NumPy arrays
npz_buffer = io.BytesIO()
np.savez(npz_buffer, weights=arr, biases=np.array([0.1, 0.2]))
save_file("model_weights.npz", npz_buffer.getvalue(), "Compressed NumPy arrays")

print()


# ============================================================================
# 4. ONNX FORMAT
# ============================================================================
print("🔄 ONNX FORMAT")
print("-" * 80)

# ONNX protobuf magic bytes + minimal structure
# ONNX files start with protobuf message indicator
onnx_magic = b"\x08\x01\x12\x00"  # Minimal ONNX protobuf header
onnx_content = onnx_magic + b"onnx" + b"\x00" * 100

save_file("simple_model.onnx", onnx_content, "ONNX model file")

print()


# ============================================================================
# 5. SAFETENSORS FORMAT
# ============================================================================
print("🔐 SAFETENSORS FORMAT")
print("-" * 80)

# SafeTensors format: 8-byte length header + JSON metadata + tensor data
metadata = {"model.weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}}
metadata_json = json.dumps(metadata).encode("utf-8")
metadata_len = struct.pack("<Q", len(metadata_json))  # Little-endian 8-byte length
tensor_data = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32).tobytes()
safetensors_content = metadata_len + metadata_json + tensor_data

save_file("model.safetensors", safetensors_content, "SafeTensors format")

print()


# ============================================================================
# 6. TENSORFLOW FORMATS
# ============================================================================
print("🧠 TENSORFLOW FORMATS")
print("-" * 80)

# .pb - TensorFlow protobuf (minimal)
pb_content = b"\x08\x01\x12\x04test"  # Minimal protobuf structure
save_file("frozen_model.pb", pb_content, "TensorFlow frozen graph")

# .tflite - TensorFlow Lite (minimal magic bytes)
# TFLite files have specific magic bytes "TFL3"
tflite_magic = b"TFL3"
tflite_content = tflite_magic + b"\x00" * 100
save_file("mobile_model.tflite", tflite_content, "TensorFlow Lite model")

# SavedModel directory structure
savedmodel_dir = OUTPUT_DIR / "saved_model"
savedmodel_dir.mkdir(exist_ok=True)
(savedmodel_dir / "saved_model.pb").write_bytes(pb_content)
(savedmodel_dir / "variables").mkdir(exist_ok=True)
print(f"✓ Generated: saved_model/                           (TensorFlow SavedModel directory)")

print()


# ============================================================================
# 7. OPENVINO FORMAT
# ============================================================================
print("⚡ OPENVINO FORMAT")
print("-" * 80)

openvino_xml = b"""<?xml version="1.0"?>
<net name="simple_model" version="11">
    <layers>
        <layer id="0" name="input" type="Input">
            <output>
                <port id="0" precision="FP32">
                    <dim>1</dim>
                    <dim>3</dim>
                    <dim>224</dim>
                    <dim>224</dim>
                </port>
            </output>
        </layer>
    </layers>
</net>
"""

save_file("openvino_model.xml", openvino_xml, "OpenVINO IR model")

print()


# ============================================================================
# 8. PMML FORMAT
# ============================================================================
print("📈 PMML FORMAT")
print("-" * 80)

pmml_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PMML xmlns="http://www.dmg.org/PMML-4_4" version="4.4">
    <Header>
        <Application name="Test" version="1.0"/>
        <Timestamp>2025-11-18T12:00:00Z</Timestamp>
    </Header>
    <DataDictionary>
        <DataField name="input" optype="continuous" dataType="double"/>
        <DataField name="output" optype="continuous" dataType="double"/>
    </DataDictionary>
    <RegressionModel functionName="regression">
        <MiningSchema>
            <MiningField name="input"/>
            <MiningField name="output" usageType="target"/>
        </MiningSchema>
        <RegressionTable intercept="0.5">
            <NumericPredictor name="input" coefficient="2.0"/>
        </RegressionTable>
    </RegressionModel>
</PMML>
"""

save_file("regression_model.pmml", pmml_xml, "PMML regression model")

print()


# ============================================================================
# 9. GGUF/GGML FORMATS
# ============================================================================
print("🦙 GGUF/GGML FORMATS (LLM)")
print("-" * 80)

# GGUF format - New format with "GGUF" magic
gguf_magic = b"GGUF"
gguf_version = struct.pack("<I", 3)  # Version 3
gguf_content = gguf_magic + gguf_version + b"\x00" * 200

save_file("llama_model.gguf", gguf_content, "GGUF quantized model")

# GGML format - Legacy with "GGML" magic
ggml_content = b"GGML" + b"\x00" * 200
save_file("legacy_model.ggml", ggml_content, "Legacy GGML format")

# GGMF variant
save_file("legacy_model.ggmf", b"GGMF" + b"\x00" * 200, "GGMF variant")

# GGJT variant
save_file("legacy_model.ggjt", b"GGJT" + b"\x00" * 200, "GGJT variant")

print()


# ============================================================================
# 10. ARCHIVE FORMATS
# ============================================================================
print("📦 ARCHIVE FORMATS")
print("-" * 80)

# .zip - ZIP archive with model files
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "w") as zf:
    zf.writestr("model_config.json", '{"model": "test"}')
    zf.writestr("weights.bin", b"\x00" * 100)
save_file("model_archive.zip", zip_buffer.getvalue(), "ZIP archive with model")

# .tar - TAR archive
tar_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_buffer, mode="w") as tf:
    # Add config file
    config_data = b'{"model": "test"}'
    config_info = tarfile.TarInfo(name="config.json")
    config_info.size = len(config_data)
    tf.addfile(config_info, io.BytesIO(config_data))
save_file("model_archive.tar", tar_buffer.getvalue(), "TAR archive with model")

# .tar.gz - Compressed TAR
tar_gz_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_gz_buffer, mode="w:gz") as tf:
    config_data = b'{"model": "test"}'
    config_info = tarfile.TarInfo(name="config.json")
    config_info.size = len(config_data)
    tf.addfile(config_info, io.BytesIO(config_data))
save_file("model_archive.tar.gz", tar_gz_buffer.getvalue(), "Gzip compressed TAR")

print()


# ============================================================================
# 11. PYTORCH BINARY
# ============================================================================
print("⚡ PYTORCH BINARY FORMAT")
print("-" * 80)

# .bin - Raw binary weights (can be various formats)
# As ZIP (PyTorch format)
bin_zip_buffer = io.BytesIO()
with zipfile.ZipFile(bin_zip_buffer, "w") as zf:
    zf.writestr("data.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0]}))
save_file("pytorch_model.bin", bin_zip_buffer.getvalue(), "PyTorch binary (ZIP-based)")

# As raw binary
raw_binary = struct.pack("f" * 10, *[float(i) for i in range(10)])
save_file("raw_weights.bin", raw_binary, "Raw binary weights")

print()


# ============================================================================
# 12. EXECUTORCH FORMAT
# ============================================================================
print("📱 EXECUTORCH FORMAT")
print("-" * 80)

# ExecuTorch files are ZIP archives
et_buffer = io.BytesIO()
with zipfile.ZipFile(et_buffer, "w") as zf:
    zf.writestr("model.pte", b"executorch_data")
    zf.writestr("metadata.json", '{"version": "1.0"}')
save_file("mobile_model.pte", et_buffer.getvalue(), "ExecuTorch model")
save_file("mobile_model.ptl", et_buffer.getvalue(), "ExecuTorch legacy format")

print()


# ============================================================================
# 13. SPECIALIZED FORMATS (Minimal stubs)
# ============================================================================
print("🔧 SPECIALIZED FORMATS")
print("-" * 80)

# TensorRT - Complex binary format (minimal stub)
tensorrt_stub = b"TensorRT" + b"\x00" * 200
save_file("optimized_model.engine", tensorrt_stub, "TensorRT engine (stub)")
save_file("optimized_model.plan", tensorrt_stub, "TensorRT plan (stub)")

# Paddle - Baidu PaddlePaddle (minimal protobuf-like)
paddle_stub = b"\x08\x01" + b"\x00" * 100
save_file("paddle_model.pdmodel", paddle_stub, "PaddlePaddle model (stub)")
save_file("paddle_model.pdiparams", paddle_stub, "PaddlePaddle params (stub)")

# Flax/JAX - MessagePack format
msgpack_header = b"\x81"  # MessagePack map with 1 element
msgpack_content = msgpack_header + b"\xa5model" + b"\xa4test"  # {"model": "test"}
save_file("jax_model.msgpack", msgpack_content, "Flax/JAX msgpack")
save_file("jax_model.flax", msgpack_content, "Flax model file")

print()


# ============================================================================
# SUMMARY
# ============================================================================
print("=" * 80)
print("✅ Test Dataset Generation Complete!")
print("=" * 80)
print()
print(f"📁 Output directory: {OUTPUT_DIR.absolute()}")
print(f"📊 Total files generated: {len(list(OUTPUT_DIR.glob('*.*')))} files")
print()
print("💡 Usage:")
print(f"   rye run modelaudit {OUTPUT_DIR}/")
print()
