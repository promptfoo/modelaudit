# Security Test Assets

This directory contains test assets organized for comprehensive security testing.

## Structure

### samples/
Individual test files organized by type:
- `pickles/` - Pickle serialization security tests
- `keras/` - Keras/H5 model security tests  
- `pytorch/` - PyTorch model security tests
- `tensorflow/` - TensorFlow SavedModel security tests
- `manifests/` - JSON/YAML manifest security tests
- `archives/` - ZIP/TAR archive security tests

### scenarios/
Multi-file security test scenarios:
- `security_scenarios/` - Complex attack scenarios

## Asset Types

### Malicious Assets (Should be detected):
- `samples/pickles/malicious_system_call.pkl` - OS command execution
- `samples/keras/malicious_lambda.h5` - Lambda layer with eval()  
- `samples/pytorch/malicious_eval.pt` - Eval-based code execution
- `samples/tensorflow/malicious_pyfunc/` - PyFunc node exploitation
- `samples/manifests/suspicious_config.json` - API key/URL leakage
- `samples/archives/path_traversal.zip` - Directory traversal attack

### Safe Assets (Should pass):
- `samples/pickles/safe_data.pkl` - Clean serialized data
- `samples/keras/safe_model.h5` - Standard Keras model
- `samples/pytorch/safe_model.pt` - Clean PyTorch weights
- `samples/tensorflow/safe_savedmodel/` - Standard SavedModel
- `samples/manifests/safe_config.json` - Benign configuration
- `samples/archives/safe_model.zip` - Clean model archive

## Usage

```python
from pathlib import Path
from modelaudit.core import scan_model_directory_or_file

# Test malicious detection
assets_dir = Path(__file__).parent / "assets"
malicious_file = assets_dir / "samples/pickles/malicious_system_call.pkl"
result = scan_model_directory_or_file(str(malicious_file))
assert result["has_errors"]  # Should detect threat

# Test safe file handling  
safe_file = assets_dir / "samples/pickles/safe_data.pkl"
result = scan_model_directory_or_file(str(safe_file))
assert not result["has_errors"]  # Should be clean
```

## Regeneration

To regenerate these assets:
```bash
cd tests/assets/generators
python generate_security_assets.py
```

Assets are created only if they don't already exist to avoid overwriting customizations.
