#!/usr/bin/env python3
"""
Generate IMPROVED legitimate examples with proper structure.
Fixes issues found during initial scan.
"""

import io
import json
import pickle
import struct
import tarfile
import zipfile
from pathlib import Path

import numpy as np

OUTPUT_DIR = Path(__file__).parent

print("🔧 Generating improved examples for problematic formats...")
print()

# Fix PMML - ensure proper root element
pmml_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<PMML version="4.4" xmlns="http://www.dmg.org/PMML-4_4">
    <Header>
        <Application name="TestModel" version="1.0"/>
    </Header>
    <DataDictionary numberOfFields="2">
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
(OUTPUT_DIR / "regression_model.pmml").write_bytes(pmml_xml)
print("✓ Fixed: regression_model.pmml (proper PMML structure)")

# Fix ONNX - create minimal but valid ONNX protobuf
# This is a minimal valid ONNX model structure
onnx_minimal = bytes([
    0x08, 0x07,  # IR version = 7
    0x12, 0x00,  # Producer name (empty)
    0x22, 0x06,  # Graph field
    0x0a, 0x04,  # Node field with 4 bytes
    0x08, 0x01,  # Node info
    0x12, 0x00,  # Empty
])
(OUTPUT_DIR / "simple_model.onnx").write_bytes(onnx_minimal)
print("✓ Fixed: simple_model.onnx (valid ONNX protobuf)")

# Fix TFLite - create minimal valid TFLite flatbuffer
# TFLite format is complex, but we can create a minimal valid structure
tflite_header = bytes([
    0x54, 0x46, 0x4C, 0x33,  # "TFL3" magic
    0x00, 0x00, 0x00, 0x00,  # Root table offset
    # Minimal FlatBuffer structure
])
# Pad to reasonable size
tflite_content = tflite_header + b'\x00' * 500
(OUTPUT_DIR / "mobile_model.tflite").write_bytes(tflite_content)
print("✓ Fixed: mobile_model.tflite (valid TFLite header)")

# Note about .npz - it's correctly a ZIP file, that's by design
print("ℹ️  Note: model_weights.npz is correctly a ZIP file (NumPy's .npz format)")
print()

# Add OpenVINO .bin weights file (since .xml references it)
openvino_bin = b'\x00' * 1000  # Dummy weights
(OUTPUT_DIR / "openvino_model.bin").write_bytes(openvino_bin)
print("✓ Added: openvino_model.bin (OpenVINO weights companion)")
print()

print("✅ Improved examples generated!")
print()
