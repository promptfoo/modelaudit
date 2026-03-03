#!/usr/bin/env bash
# Compile TensorFlow protobuf definitions into standalone Python stubs
# This eliminates the need for the full TensorFlow package (and avoiding Keras CVE exposure)
#
# IMPORTANT: The generated protos must keep their original import paths (tensorflow.*)
# because the protobuf descriptor pool uses file paths internally. We add these to
# sys.path at import time instead of renaming imports.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/modelaudit/protos"
TEMP_DIR=$(mktemp -d)

# TensorFlow version to extract protos from
TF_VERSION="${TF_VERSION:-2.18.0}"

# Required protoc version — must match the version used to generate vendored protos.
# Install from: https://github.com/protocolbuffers/protobuf/releases/tag/v33.4
REQUIRED_PROTOC="33.5"

echo "=== TensorFlow Protobuf Compiler ==="
echo "TensorFlow version: $TF_VERSION"
echo "Output directory: $OUTPUT_DIR"

# Verify protoc version
PROTOC_VERSION=$(protoc --version 2>/dev/null | sed 's/.*libprotoc //' || true)
if [[ -z "$PROTOC_VERSION" ]]; then
    echo "ERROR: protoc not found. Install libprotoc $REQUIRED_PROTOC from:"
    echo "  https://github.com/protocolbuffers/protobuf/releases/tag/v$REQUIRED_PROTOC"
    exit 1
fi
if [[ "$PROTOC_VERSION" != "$REQUIRED_PROTOC" ]]; then
    echo "ERROR: protoc version mismatch: found $PROTOC_VERSION, need $REQUIRED_PROTOC"
    echo "Install the correct version from:"
    echo "  https://github.com/protocolbuffers/protobuf/releases/tag/v$REQUIRED_PROTOC"
    exit 1
fi
echo "protoc version: $PROTOC_VERSION (OK)"
echo ""

# Cleanup on exit
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cd "$TEMP_DIR"

echo "Downloading TensorFlow proto definitions..."
git clone --depth 1 --branch "v$TF_VERSION" --filter=blob:none --sparse \
    https://github.com/tensorflow/tensorflow.git tf

cd tf
git sparse-checkout set tensorflow/core/protobuf tensorflow/core/framework

echo ""
echo "Proto files to compile:"
find tensorflow/core -name "*.proto" | head -20
echo "..."
echo ""

# Clean and recreate output directory structure
rm -rf "$OUTPUT_DIR/tensorflow"
mkdir -p "$OUTPUT_DIR/tensorflow/core/protobuf"
mkdir -p "$OUTPUT_DIR/tensorflow/core/framework"

echo "Compiling protobuf files..."

COMPILED=0
FAILED=0

# Compile ALL proto files in the framework directory
echo "  Compiling framework protos..."
for proto in tensorflow/core/framework/*.proto; do
    if [[ -f "$proto" ]]; then
        if protoc --python_out="$OUTPUT_DIR" -I. "$proto" 2>&1; then
            COMPILED=$((COMPILED + 1))
        else
            echo "  WARNING: Failed to compile $proto"
            FAILED=$((FAILED + 1))
        fi
    fi
done

# Compile ALL proto files in the protobuf directory
echo "  Compiling protobuf protos..."
for proto in tensorflow/core/protobuf/*.proto; do
    if [[ -f "$proto" ]]; then
        if protoc --python_out="$OUTPUT_DIR" -I. "$proto" 2>&1; then
            COMPILED=$((COMPILED + 1))
        else
            echo "  WARNING: Failed to compile $proto"
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
echo "Compilation results: $COMPILED succeeded, $FAILED failed"

# Create __init__.py files for proper Python packaging
# Only in tensorflow/ subdirectories - do NOT overwrite modelaudit/protos/__init__.py
find "$OUTPUT_DIR/tensorflow" -type d -exec touch {}/__init__.py \;

# DON'T patch imports - keep original tensorflow.* imports
# We'll add modelaudit/protos to sys.path at runtime instead

echo ""
echo "Creating type stubs..."

# Create a py.typed marker for PEP 561
touch "$OUTPUT_DIR/py.typed"

# Verify critical output files exist
echo ""
echo "Verifying critical proto files..."
CRITICAL_FILES=(
    "$OUTPUT_DIR/tensorflow/core/protobuf/saved_model_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/graph_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/tensor_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/tensor_shape_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/types_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/node_def_pb2.py"
    "$OUTPUT_DIR/tensorflow/core/framework/attr_value_pb2.py"
)

MISSING=0
for f in "${CRITICAL_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        echo "  OK: $(basename "$f")"
    else
        echo "  MISSING: $(basename "$f")"
        MISSING=$((MISSING + 1))
    fi
done

if [[ $MISSING -gt 0 ]]; then
    echo ""
    echo "ERROR: $MISSING critical proto file(s) missing! Compilation incomplete."
    exit 1
fi

echo ""
echo "=== Compilation Complete ==="
echo ""
echo "Generated files:"
find "$OUTPUT_DIR" -name "*.py" | wc -l
echo " Python files"
echo ""
echo "To use in code:"
echo "  import modelaudit.protos  # sets up sys.path automatically"
echo "  from tensorflow.core.protobuf.saved_model_pb2 import SavedModel"
