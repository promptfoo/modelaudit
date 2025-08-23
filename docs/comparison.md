# ModelScan vs ModelAudit: File Format and Exploit Detection Comparison

## Executive Summary

This analysis focuses specifically on **file format coverage** and **exploit detection capabilities** of both security scanners, highlighting areas where ModelScan has detection capabilities that ModelAudit currently lacks.

**Key Finding**: ModelScan demonstrates **more focused and comprehensive exploit detection** in specific areas, particularly TensorFlow operations and advanced pickle analysis, while ModelAudit offers **broader file format coverage** but with some detection gaps.

## 1. File Format Coverage Comparison

### ModelScan Supported Formats (8 Core Types)

```python
# From ModelScan settings.py
SUPPORTED_FORMATS = {
    ".pkl", ".pickle", ".joblib", ".dill", ".dat", ".data",  # Pickle formats
    ".h5",                                                   # Keras H5
    ".keras",                                               # Keras ZIP format
    ".pb",                                                  # TensorFlow SavedModel
    ".npy",                                                 # NumPy arrays
    ".bin", ".pt", ".pth", ".ckpt",                        # PyTorch formats
    ".zip", ".npz"                                         # Archive formats
}
```

### ModelAudit Supported Formats (22+ Types)

```python
# From ModelAudit scanner registry
SUPPORTED_FORMATS = {
    # Core formats (shared with ModelScan)
    ".pkl", ".pickle", ".dill", ".pt", ".pth", ".ckpt",    # Pickle/PyTorch
    ".h5", ".hdf5", ".keras",                              # Keras
    ".pb",                                                 # TensorFlow
    ".npy", ".npz",                                        # NumPy

    # Extended formats (ModelAudit exclusive)
    ".onnx",                                               # ONNX models
    ".mlmodel",                                            # Core ML
    ".xml",                                                # OpenVINO IR
    ".safetensors",                                        # SafeTensors
    ".gguf", ".ggml",                                      # GGUF/GGML (LLMs)
    ".joblib",                                             # Joblib (separate scanner)
    ".ptl", ".pte",                                        # ExecuTorch
    ".msgpack", ".flax", ".orbax", ".jax",                # JAX/Flax
    ".tflite",                                             # TensorFlow Lite
    ".engine", ".plan",                                    # TensorRT
    ".pdmodel", ".pdiparams",                             # PaddlePaddle
    ".pmml",                                              # PMML
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",      # TAR archives
    ".json", ".yaml", ".yml", ".toml", ".xml",            # Configuration files
    ".txt", ".md", ".markdown", ".rst"                    # Text files
}
```

## 2. Critical Detection Gaps: Where ModelScan Excels

### 2.1 Advanced TensorFlow Operation Detection

**ModelScan's TensorFlow Scanner** detects dangerous operations that **ModelAudit currently misses**:

```python
# ModelScan's comprehensive TF operation detection
UNSAFE_TF_OPERATORS = {
    "ReadFile": "HIGH",        # File system read access
    "WriteFile": "HIGH",       # File system write access
    "PyFunc": "CRITICAL",      # Python function execution in TF graph
    "PyCall": "CRITICAL",      # Python code execution
    "ShellExecute": "CRITICAL", # Shell command execution
}
```

**Gap Analysis**: ModelAudit's TF scanner focuses primarily on Lambda layers but **lacks detection** for these critical TF operations:

- `ReadFile`/`WriteFile` operations (file system access)
- `PyFunc`/`PyCall` operations (arbitrary Python code execution)
- Shell execution operations

**Security Impact**: These operations can enable:

- **Data exfiltration** via ReadFile
- **System compromise** via WriteFile to critical paths
- **Remote code execution** via PyFunc embedding malicious Python

### 2.2 Sophisticated Pickle Opcode Analysis

**ModelScan's Pickle Analysis** includes advanced opcode parsing that **ModelAudit lacks**:

```python
# ModelScan's comprehensive pickle opcode handling
def _list_globals(data: IO[bytes]) -> Set[Tuple[str, str]]:
    for op in pickletools.genops(data):
        if op[0].name == "STACK_GLOBAL":
            # Complex STACK_GLOBAL parsing with memo handling
            values = self._extract_stack_values(ops, n, memo)
            globals.add((values[1], values[0]))
        elif op[0].name in ("GLOBAL", "INST"):
            globals.add(tuple(op[1].split(" ", 1)))
```

**Detection Capabilities ModelScan Has That ModelAudit Lacks**:

1. **STACK_GLOBAL Opcode Analysis**: ModelScan can parse complex STACK_GLOBAL operations that build module references dynamically
2. **Memo Object Tracking**: Tracks pickle memo objects to resolve references
3. **Multiple Pickle Stream Support**: Can handle multiple pickle objects in single file

**Real-World Attack Vector Example**:

```python
# This attack uses STACK_GLOBAL to obfuscate malicious imports
# ModelScan detects this, ModelAudit may miss it
import pickle
import pickletools

class MaliciousPayload:
    def __reduce__(self):
        # Uses STACK_GLOBAL to dynamically build os.system reference
        return (getattr, (__import__('os'), 'system')), ('rm -rf /',)
```

### 2.3 Granular Severity Classification

**ModelScan's Risk Classification** provides more granular threat assessment:

```python
# ModelScan's detailed severity mapping
UNSAFE_GLOBALS = {
    "CRITICAL": {
        "os": "*",                    # Complete system access
        "subprocess": "*",            # Process control
        "eval": ["eval", "exec"],     # Code execution
    },
    "HIGH": {
        "webbrowser": "*",            # Network access
        "requests.api": "*",          # HTTP requests
        "socket": "*",                # Network sockets
    },
    "MEDIUM": {
        # Context-dependent risks
    },
    "LOW": {
        # Informational findings
    }
}
```

**ModelAudit's Current Approach**: Uses binary "suspicious/not suspicious" classification without graduated risk levels.

## 3. ModelScan-Specific Exploit Detection Capabilities

### 3.1 Keras Lambda Layer Detection

**ModelScan** has dedicated scanners for detecting malicious Keras Lambda layers in multiple formats:

```python
# H5 Lambda Detection
class H5LambdaDetectScan:
    def _get_keras_h5_operator_names(self, model):
        lambda_layers = [
            layer.get("config", {}).get("function", {})
            for layer in model_config.get("config", {}).get("layers", {})
            if layer.get("class_name") == "Lambda"
        ]
```

**Real Attack Vector**: Lambda layers can contain arbitrary Python code:

```python
# Malicious Keras model with Lambda layer
model.add(Lambda(lambda x: eval("__import__('os').system('malicious_command')")))
```

**ModelAudit Status**: Has basic Lambda detection but not as comprehensive across all Keras formats.

### 3.2 Advanced Pickle Global Reference Detection

**ModelScan** detects sophisticated module reference patterns:

```python
# Detects these dangerous patterns that ModelAudit might miss:
CRITICAL_MODULES = {
    "nt": "*",           # Windows os alias
    "posix": "*",        # Unix os alias
    "operator": ["attrgetter"],  # Attribute access bypass
    "pty": "*",          # Pseudo-terminal spawning
    "bdb": "*",          # Python debugger access
    "asyncio": "*",      # Asynchronous execution
}
```

### 3.3 Multiple Pickle Stream Support

**ModelScan Capability**: Can scan files containing multiple pickle objects:

```python
def _list_globals(data, multiple_pickles=True):
    while last_byte != b"":
        try:
            ops = list(pickletools.genops(data))
            # Process each pickle stream independently
        except Exception as e:
            # Handle partial pickle streams gracefully
```

**ModelAudit Gap**: Typically processes single pickle streams, may miss additional malicious pickles in the same file.

## 4. File Format Gaps: What ModelScan Lacks

### 4.1 Modern ML Format Support

**ModelAudit Exclusive Formats**:

- **GGUF/GGML**: Large language model format (Llama, etc.)
- **SafeTensors**: Hugging Face's secure tensor format
- **ExecuTorch**: Mobile-optimized PyTorch format
- **JAX/Flax**: Google's ML research framework formats
- **TensorRT**: NVIDIA's optimized inference format

### 4.2 Container and Archive Formats

**ModelAudit's Superior Archive Support**:

```python
# TAR format support that ModelScan lacks
ARCHIVE_FORMATS = [
    ".tar", ".tar.gz", ".tgz", ".tar.bz2",
    ".tbz2", ".tar.xz", ".txz"
]
```

### 4.3 Configuration and Manifest Analysis

**ModelAudit's Manifest Scanner** analyzes ML-specific configuration files:

```python
MANIFEST_PATTERNS = [
    "config.json", "model.json", "tokenizer.json",
    "hyperparams.yaml", "training_args.json"
]
```

## 5. Exploit Type Comparison

### ModelScan's Exploit Focus

| Exploit Type           | Detection Method                    | Coverage      |
| ---------------------- | ----------------------------------- | ------------- |
| Pickle RCE             | GLOBAL/STACK_GLOBAL opcode analysis | Comprehensive |
| TensorFlow File I/O    | Operation-level scanning            | Strong        |
| Keras Lambda injection | Layer-specific analysis             | Good          |
| NumPy object arrays    | Dtype object detection              | Basic         |

### ModelAudit's Exploit Focus

| Exploit Type          | Detection Method                               | Coverage |
| --------------------- | ---------------------------------------------- | -------- |
| Pickle RCE            | String pattern matching + some opcode analysis | Good     |
| Binary code injection | Hex pattern detection                          | Strong   |
| Jinja2 SSTI           | Template injection patterns                    | Unique   |
| Weight tampering      | Statistical analysis                           | Unique   |
| License violations    | License database matching                      | Unique   |

## 6. Critical Recommendations for ModelAudit

### 6.1 Immediate Security Improvements

1. **Implement TensorFlow Operation Scanning**:

   ```python
   # Add to TF scanner
   DANGEROUS_TF_OPS = {
       "ReadFile": IssueSeverity.HIGH,
       "WriteFile": IssueSeverity.HIGH,
       "PyFunc": IssueSeverity.CRITICAL,
       "PyCall": IssueSeverity.CRITICAL
   }
   ```

2. **Enhance Pickle STACK_GLOBAL Detection**:

   ```python
   # Add sophisticated opcode parsing
   def parse_stack_global(ops, position, memo):
       # Implement ModelScan's STACK_GLOBAL parsing logic
   ```

3. **Add Graduated Severity Levels**:
   ```python
   class ThreatLevel(Enum):
       CRITICAL = "critical"  # RCE, data exfiltration
       HIGH = "high"         # File system access
       MEDIUM = "medium"     # Suspicious patterns
       LOW = "low"          # Informational
   ```

### 6.2 Specific Detection Patterns to Adopt

1. **Windows/Unix OS Aliases**: Detect `nt`, `posix` module references
2. **Operator Module Exploitation**: Flag `operator.attrgetter` usage
3. **Memo Object Tracking**: Implement pickle memo resolution
4. **Multiple Pickle Streams**: Support scanning multiple pickles per file

## 7. Conclusion

**ModelScan's Key Advantages in Exploit Detection**:

- **More comprehensive TensorFlow operation detection** (ReadFile, WriteFile, PyFunc)
- **Advanced pickle opcode analysis** (STACK_GLOBAL, memo tracking)
- **Graduated threat severity classification**
- **Multiple pickle stream support**

**ModelAudit's Broader Security Scope**:

- **22+ file formats** vs ModelScan's 8 formats
- **Unique attack vectors**: Jinja2 SSTI, weight distribution anomalies
- **Non-security analysis**: License checking, asset extraction

**Strategic Recommendation**: ModelAudit should adopt ModelScan's sophisticated TensorFlow and pickle analysis techniques while maintaining its broader format support. The combination would create the most comprehensive ML security scanner available.

**Implementation Priority**:

1. **P1**: TensorFlow operation detection (ReadFile, WriteFile, PyFunc)
2. **P1**: Enhanced pickle STACK_GLOBAL parsing
3. **P2**: Graduated severity classification system
4. **P3**: Multiple pickle stream support

This focused analysis on detection capabilities reveals that while ModelAudit has broader format coverage, ModelScan has deeper exploit detection in core formats that handle the majority of real-world threats.
