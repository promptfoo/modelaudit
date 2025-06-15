# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ModelAudit is a security scanner for AI/ML model files that detects potential security risks before deployment. It scans for malicious code, suspicious operations, unsafe configurations, and blacklisted model names.

## Key Commands

```bash
# Setup
rye sync --features all        # Install all dependencies

# Running the scanner
rye run modelaudit scan model.pkl
rye run modelaudit scan --format json --output results.json model.pkl

# Testing
rye run pytest                          # Run all tests
rye run pytest tests/test_pickle_scanner.py  # Run specific test file
rye run pytest -k "test_pickle"         # Run tests matching pattern

# Linting and Formatting
rye run ruff format modelaudit/ tests/   # Format code (ALWAYS run before committing)
rye run ruff check --fix modelaudit/ tests/  # Fix linting issues
rye run mypy modelaudit/                 # Type checking
```

## Architecture

### Scanner System

- All scanners inherit from `BaseScanner` in `modelaudit/scanners/base.py`
- Scanners implement `can_handle(file_path)` and `scan(file_path, timeout)` methods
- Scanner registration happens via `SCANNER_REGISTRY` in `modelaudit/scanners/__init__.py`
- Each scanner returns a `ScanResult` containing `Issue` objects

### Core Components

- `cli.py`: Click-based CLI interface
- `core.py`: Main scanning logic and file traversal
- `risk_scoring.py`: Normalizes issues to 0.0-1.0 risk scores
- `scanners/`: Format-specific scanner implementations
- `utils/filetype.py`: File type detection utilities

### Adding New Scanners

1. Create scanner class inheriting from `BaseScanner`
2. Implement `can_handle()` and `scan()` methods
3. Register in `SCANNER_REGISTRY`
4. Add tests in `tests/test_<scanner_name>.py`

### Security Detection Focus

- Dangerous imports (os, sys, subprocess, eval, exec)
- Pickle opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL)
- Encoded payloads (base64, hex)
- Unsafe Lambda layers (Keras/TensorFlow)
- Executable files in archives
- Blacklisted model names

## Exit Codes

- 0: No security issues found
- 1: Security issues detected
- 2: Scan errors occurred
