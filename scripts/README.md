# Scripts Directory

This directory contains utility scripts for development and testing purposes. These scripts are not part of the main ModelAudit package and are not published to PyPI.

## Files

### `check_circular_imports.py` / `minimal_circular_check.py`

Development utilities for detecting circular import issues in the codebase.

### `compile_tensorflow_protos.sh`

Script to regenerate vendored TensorFlow protobuf stubs from `.proto` files.

### `fetch_hf_org_models.py` / `fetch_hf_top_models.py`

Utilities for fetching model metadata from HuggingFace for testing and validation.

### `jax_flax_scanning_demo.py`

Demonstrates JAX/Flax model scanning capabilities including Msgpack-based checkpoints, Orbax format, and JAX-specific threat detection.

### `verify_models.py`

Model verification and validation utility.

## Development Use Only

These scripts are intended for development, testing, and research purposes. They should not be used in production environments.
