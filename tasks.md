# ModelAudit Enhancement Tasks

Based on comprehensive codebase analysis, these tasks will improve ModelAudit's security detection, usability, and maintainability. Tasks are prioritized by impact and organized into Security Enhancements, Refactoring, Infrastructure Fixes, and CLI Usability improvements.

## Task Status Summary

### ✅ Completed Tasks _(removed - focusing on active work)_

Tasks 2, 5, 6, 9, and 10 have been removed from this file as they are already implemented in the current codebase.

### 🔄 Active Security Enhancement Tasks

- **Task 1**: Complete TensorFlow operation detection (ReadFile, WriteFile, ShellExecute)
- **Task 3**: Graduated severity classification system (HIGH/MEDIUM/LOW)
- **Task 4**: Configuration-driven security rules
- **Task 7**: Better error handling and graceful degradation
- **Task 8**: PickleScan safety level classification
- **Task 11**: 7-Zip archive support

### 🔧 Critical Refactoring Tasks

- **Task R-1**: Refactor 1,026-line monster function in pickle_scanner.py
- **Task R-2**: Refactor god classes (BaseScanner with 35 methods)
- **Task R-3**: Refactor large scanner methods (498-line PyTorch ZIP scan)

### 🏗️ Infrastructure Tasks

- **Task I-1**: Fix circular import dependencies
- **Task I-2**: Thread-safe cache manager
- **Task I-3**: Consolidate duplicate caching logic
- **Task I-4**: Improve exception handling specificity
- **Task I-5**: Performance optimization

### 🎯 CLI Usability Tasks

- **Task U-1**: Eliminate CLI flag explosion (24+ → ~12 flags)
- **Task U-2**: Implement smart CLI defaults
- **Task U-3**: Add modern usability features

---

# SECURITY ENHANCEMENT TASKS

## Task 1: Complete Advanced TensorFlow Operation Detection

**Priority**: P2 - Security Enhancement (PyFunc/PyCall already implemented)
**Estimated Effort**: 1-2 days
**Dependencies**: None

### Objective

Complete detection for remaining dangerous TensorFlow operations (ReadFile, WriteFile, ShellExecute) - PyFunc and PyCall detection is already implemented in the current codebase.

### Files to Modify

- `modelaudit/scanners/tf_savedmodel_scanner.py` - Main TF scanner
- `modelaudit/suspicious_symbols.py` - Add TF operation patterns
- `tests/test_tf_savedmodel_scanner.py` - Add comprehensive tests

### Implementation Details

1. **Enhance TF Scanner** (`modelaudit/scanners/tf_savedmodel_scanner.py`):

   ```python
   # Add after existing imports
   DANGEROUS_TF_OPERATIONS = {
       "ReadFile": IssueSeverity.HIGH,        # File system read access
       "WriteFile": IssueSeverity.HIGH,       # File system write access
       "PyFunc": IssueSeverity.CRITICAL,      # Python function execution
       "PyCall": IssueSeverity.CRITICAL,      # Python code execution
       "ShellExecute": IssueSeverity.CRITICAL, # Shell command execution
       "MergeV2Checkpoints": IssueSeverity.HIGH, # Checkpoint manipulation
       "Save": IssueSeverity.MEDIUM,          # Save operations
       "SaveV2": IssueSeverity.MEDIUM,        # SaveV2 operations
   }

   def _scan_tf_operations(self, model_pb):
       """Scan TensorFlow graph for dangerous operations"""
       dangerous_ops = []

       # Parse the saved_model.pb file
       try:
           saved_model = saved_model_pb2.SavedModel()
           saved_model.ParseFromString(model_pb)

           for meta_graph in saved_model.meta_graphs:
               graph_def = meta_graph.graph_def
               for node in graph_def.node:
                   if node.op in DANGEROUS_TF_OPERATIONS:
                       dangerous_ops.append({
                           'operation': node.op,
                           'node_name': node.name,
                           'severity': DANGEROUS_TF_OPERATIONS[node.op]
                       })
       except Exception as e:
           logger.warning(f"Failed to parse TensorFlow graph: {e}")

       return dangerous_ops
   ```

2. **Update suspicious_symbols.py**:

   ```python
   # Add to SUSPICIOUS_OPS section
   TENSORFLOW_DANGEROUS_OPS = {
       # File system operations - HIGH RISK
       "ReadFile": "Can read arbitrary files from the system",
       "WriteFile": "Can write arbitrary files to the system",
       "MergeV2Checkpoints": "Can manipulate checkpoint files",
       "Save": "Can save data to arbitrary locations",
       "SaveV2": "Can save data to arbitrary locations",

       # Code execution - CRITICAL RISK
       "PyFunc": "Can execute arbitrary Python functions",
       "PyCall": "Can call arbitrary Python code",

       # System operations - CRITICAL RISK
       "ShellExecute": "Can execute shell commands",
       "ExecuteOp": "Can execute arbitrary operations",
       "SystemConfig": "Can access system configuration",
   }
   ```

### Test Assets Required

Create test files in `tests/assets/tensorflow/`:

```
tests/assets/tensorflow/
├── malicious_readfile/
│   ├── saved_model.pb          # Contains ReadFile operation
│   └── variables/
├── malicious_writefile/
│   ├── saved_model.pb          # Contains WriteFile operation
│   └── variables/
├── malicious_pyfunc/
│   ├── saved_model.pb          # Contains PyFunc operation
│   └── variables/
└── safe_model/
    ├── saved_model.pb          # Clean TF model
    └── variables/
```

### Validation Steps

1. **Unit Tests** (`tests/test_tf_savedmodel_scanner.py`):

   ```python
   def test_detect_readfile_operation():
       scanner = TensorFlowSavedModelScanner()
       result = scanner.scan("tests/assets/tensorflow/malicious_readfile/saved_model.pb")

       assert len(result.issues) > 0
       readfile_issues = [i for i in result.issues if "ReadFile" in i.message]
       assert len(readfile_issues) > 0
       assert readfile_issues[0].severity == IssueSeverity.HIGH

   def test_detect_pyfunc_operation():
       scanner = TensorFlowSavedModelScanner()
       result = scanner.scan("tests/assets/tensorflow/malicious_pyfunc/saved_model.pb")

       assert len(result.issues) > 0
       pyfunc_issues = [i for i in result.issues if "PyFunc" in i.message]
       assert len(pyfunc_issues) > 0
       assert pyfunc_issues[0].severity == IssueSeverity.CRITICAL
   ```

2. **Integration Tests**:

   ```bash
   # Test with real TensorFlow models
   rye run pytest tests/test_tf_savedmodel_scanner.py::test_detect_readfile_operation -v
   rye run pytest tests/test_tf_savedmodel_scanner.py::test_detect_pyfunc_operation -v

   # Full scanner test
   rye run modelaudit tests/assets/tensorflow/malicious_readfile/
   ```

### Acceptance Criteria

- [ ] Scanner detects all 8 dangerous TF operations
- [ ] Proper severity classification (CRITICAL for PyFunc/PyCall, HIGH for file operations)
- [ ] Comprehensive test coverage (>95%)
- [ ] No false positives on clean TensorFlow models
- [ ] Clear, actionable issue messages explaining the security risk

---

## Task 3: Implement Graduated Severity Classification System

**Priority**: P1 - Critical Security Gap
**Estimated Effort**: 2-3 days
**Dependencies**: None

### Objective

Replace binary "suspicious/not suspicious" classification with ModelScan's graduated CRITICAL/HIGH/MEDIUM/LOW severity system for better risk assessment.

### Files to Modify

- `modelaudit/scanners/base.py` - Update Issue and severity enums
- `modelaudit/suspicious_symbols.py` - Add severity mappings
- `modelaudit/cli.py` - Update output formatting
- All scanner files - Update to use new severity levels
- `tests/test_severity_classification.py` - New comprehensive tests

### Implementation Details

1. **Enhance Base Scanner** (`modelaudit/scanners/base.py`):

   ```python
   class IssueSeverity(Enum):
       """Graduated severity levels matching industry standards"""
       CRITICAL = "critical"  # RCE, data exfiltration, system compromise
       HIGH = "high"         # File system access, network operations
       MEDIUM = "medium"     # Suspicious patterns, potential issues
       LOW = "low"          # Informational findings, best practices
       DEBUG = "debug"      # Debug information (keep existing)
       INFO = "info"        # Informational (keep existing)
       WARNING = "warning"  # Rename to MEDIUM for consistency

   # Add severity scoring for risk calculations
   SEVERITY_SCORES = {
       IssueSeverity.CRITICAL: 10.0,
       IssueSeverity.HIGH: 7.5,
       IssueSeverity.MEDIUM: 5.0,
       IssueSeverity.LOW: 2.5,
       IssueSeverity.INFO: 1.0,
       IssueSeverity.DEBUG: 0.0,
   }

   def get_severity_score(severity: IssueSeverity) -> float:
       """Get numeric score for severity level"""
       return SEVERITY_SCORES.get(severity, 0.0)
   ```

2. **Create Severity Mapping** (`modelaudit/suspicious_symbols.py`):

   ```python
   # Graduated severity mapping for pickle globals
   PICKLE_SEVERITY_MAP = {
       "CRITICAL": {
           # Direct code execution - immediate RCE risk
           "builtins": ["eval", "exec", "compile", "__import__"],
           "__builtin__": ["eval", "exec", "compile", "__import__"],
           "runpy": "*",
           "os": "*",
           "subprocess": "*",
           "sys": "*",
           "nt": "*",     # Windows os alias
           "posix": "*",  # Unix os alias
           "socket": "*",
           "pty": "*",
           "_pickle": "*",
       },
       "HIGH": {
           # File system and network access
           "webbrowser": "*",
           "shutil": ["rmtree", "copy", "move"],
           "tempfile": "*",
           "pickle": ["loads", "load"],
           "requests.api": "*",
           "httplib": "*",
           "aiohttp.client": "*",
       },
       "MEDIUM": {
           # Encoding and potential obfuscation
           "base64": ["b64decode", "decode"],
           "codecs": ["decode", "encode"],
           "operator": ["attrgetter"],
           "importlib": "*",
       },
       "LOW": {
           # Informational findings
           "warnings": "*",
           "logging": "*",
       }
   }

   # TensorFlow operation severity mapping
   TENSORFLOW_SEVERITY_MAP = {
       "CRITICAL": ["PyFunc", "PyCall", "ShellExecute"],
       "HIGH": ["ReadFile", "WriteFile", "MergeV2Checkpoints"],
       "MEDIUM": ["Save", "SaveV2"],
       "LOW": []
   }
   ```

3. **Update CLI Output** (`modelaudit/cli.py`):

   ```python
   def format_severity_output(severity: IssueSeverity) -> str:
       """Format severity with color coding"""
       colors = {
           IssueSeverity.CRITICAL: "red",
           IssueSeverity.HIGH: "bright_red",
           IssueSeverity.MEDIUM: "yellow",
           IssueSeverity.LOW: "blue",
           IssueSeverity.INFO: "cyan",
           IssueSeverity.DEBUG: "white"
       }

       symbols = {
           IssueSeverity.CRITICAL: "🔴",
           IssueSeverity.HIGH: "🟠",
           IssueSeverity.MEDIUM: "🟡",
           IssueSeverity.LOW: "🔵",
           IssueSeverity.INFO: "ℹ️",
           IssueSeverity.DEBUG: "🐛"
       }

       if should_use_color():
           return click.style(f"{symbols[severity]} {severity.value.upper()}", fg=colors[severity])
       return f"{symbols[severity]} {severity.value.upper()}"
   ```

### Validation Steps

1. **Severity Classification Tests** (`tests/test_severity_classification.py`):

   ```python
   def test_critical_severity_assignment():
       """Test that RCE patterns get CRITICAL severity"""
       scanner = PickleScanner()

       # Test critical patterns
       test_cases = [
           ("os.system", IssueSeverity.CRITICAL),
           ("eval", IssueSeverity.CRITICAL),
           ("subprocess.call", IssueSeverity.CRITICAL),
       ]

       for pattern, expected_severity in test_cases:
           # Create test pickle with pattern
           result = scanner._classify_severity(pattern)
           assert result == expected_severity

   def test_severity_scoring():
       """Test numeric severity scoring"""
       assert get_severity_score(IssueSeverity.CRITICAL) == 10.0
       assert get_severity_score(IssueSeverity.HIGH) == 7.5
       assert get_severity_score(IssueSeverity.MEDIUM) == 5.0
       assert get_severity_score(IssueSeverity.LOW) == 2.5

   def test_output_formatting():
       """Test CLI severity formatting"""
       output = format_severity_output(IssueSeverity.CRITICAL)
       assert "CRITICAL" in output
       assert "🔴" in output
   ```

2. **Integration Tests**:

   ```bash
   # Test severity output in CLI
   rye run modelaudit tests/assets/pickles/malicious_eval.pkl | grep "🔴 CRITICAL"
   rye run modelaudit tests/assets/pickles/suspicious_base64.pkl | grep "🟡 MEDIUM"

   # JSON output should include severity
   rye run modelaudit --format json tests/assets/pickles/ | jq '.issues[].severity'
   ```

### Acceptance Criteria

- [ ] Four clear severity levels: CRITICAL, HIGH, MEDIUM, LOW
- [ ] Consistent severity assignment across all scanners
- [ ] Clear visual indicators in CLI output (colors, symbols)
- [ ] Numeric scoring for risk calculations
- [ ] Backward compatibility with existing severity levels
- [ ] Comprehensive test coverage for all severity mappings

---

## Task 4: Add Configuration-Driven Security Rules

**Priority**: P2 - Enterprise Feature
**Estimated Effort**: 3-4 days
**Dependencies**: Task 3 (Severity System)

### Objective

Implement external TOML configuration files for security rules, allowing enterprises to customize detection patterns without code changes (matching ModelScan's approach).

### Files to Modify

- `modelaudit/config/` - New directory for configuration handling
- `modelaudit/config/security_config.py` - Configuration loader
- `modelaudit/cli.py` - Add --config flag
- `default-security-config.toml` - Default configuration template

### Implementation Details

1. **Create Configuration Structure**:

   ```bash
   mkdir -p modelaudit/config
   touch modelaudit/config/__init__.py
   touch modelaudit/config/security_config.py
   ```

2. **Configuration Loader** (`modelaudit/config/security_config.py`):

   ```python
   import toml
   from pathlib import Path
   from typing import Dict, Any, Optional
   from dataclasses import dataclass

   @dataclass
   class SecurityRuleConfig:
       """Configuration for security detection rules"""
       pickle_rules: Dict[str, Dict[str, Any]]
       tensorflow_rules: Dict[str, str]
       keras_rules: Dict[str, str]
       custom_patterns: list[str]
       severity_thresholds: Dict[str, float]

   class SecurityConfigLoader:
       def __init__(self, config_path: Optional[str] = None):
           self.config_path = config_path or self._find_default_config()
           self.config: Optional[SecurityRuleConfig] = None

       def _find_default_config(self) -> str:
           """Find default config file in standard locations"""
           search_paths = [
               "./modelaudit-security.toml",
               "~/.config/modelaudit/security.toml",
               "/etc/modelaudit/security.toml"
           ]

           for path in search_paths:
               expanded_path = Path(path).expanduser()
               if expanded_path.exists():
                   return str(expanded_path)

           # Return default template path
           return str(Path(__file__).parent.parent / "default-security-config.toml")

       def load(self) -> SecurityRuleConfig:
           """Load configuration from TOML file"""
           try:
               with open(self.config_path, 'r') as f:
                   config_data = toml.load(f)

               self.config = SecurityRuleConfig(
                   pickle_rules=config_data.get('pickle_rules', {}),
                   tensorflow_rules=config_data.get('tensorflow_rules', {}),
                   keras_rules=config_data.get('keras_rules', {}),
                   custom_patterns=config_data.get('custom_patterns', []),
                   severity_thresholds=config_data.get('severity_thresholds', {})
               )

               return self.config

           except Exception as e:
               logger.error(f"Failed to load security config from {self.config_path}: {e}")
               return self._get_default_config()

       def _get_default_config(self) -> SecurityRuleConfig:
           """Return hardcoded default configuration"""
           from ..suspicious_symbols import PICKLE_SEVERITY_MAP, TENSORFLOW_SEVERITY_MAP

           return SecurityRuleConfig(
               pickle_rules=PICKLE_SEVERITY_MAP,
               tensorflow_rules=TENSORFLOW_SEVERITY_MAP,
               keras_rules={"Lambda": "MEDIUM"},
               custom_patterns=[],
               severity_thresholds={
                   "CRITICAL": 10.0,
                   "HIGH": 7.5,
                   "MEDIUM": 5.0,
                   "LOW": 2.5
               }
           )
   ```

3. **Default Configuration Template** (`default-security-config.toml`):

   ```toml
   # ModelAudit Security Configuration
   # Customize detection rules for your environment

   [pickle_rules.CRITICAL]
   # Direct code execution - immediate RCE risk
   "builtins" = ["eval", "exec", "compile", "__import__"]
   "__builtin__" = ["eval", "exec", "compile", "__import__"]
   "os" = "*"
   "subprocess" = "*"
   "sys" = "*"
   "runpy" = "*"
   "socket" = "*"

   [pickle_rules.HIGH]
   # File system and network access
   "webbrowser" = "*"
   "shutil" = ["rmtree", "copy", "move"]
   "requests.api" = "*"
   "pickle" = ["loads", "load"]

   [pickle_rules.MEDIUM]
   # Encoding and obfuscation
   "base64" = ["b64decode", "decode"]
   "codecs" = ["decode", "encode"]
   "operator" = ["attrgetter"]

   [pickle_rules.LOW]
   "warnings" = "*"
   "logging" = "*"

   [tensorflow_rules]
   "PyFunc" = "CRITICAL"
   "PyCall" = "CRITICAL"
   "ReadFile" = "HIGH"
   "WriteFile" = "HIGH"
   "Save" = "MEDIUM"
   "SaveV2" = "MEDIUM"

   [keras_rules]
   "Lambda" = "MEDIUM"

   [custom_patterns]
   # Add your organization's custom detection patterns
   # patterns = ["your_custom_pattern"]

   [severity_thresholds]
   CRITICAL = 10.0
   HIGH = 7.5
   MEDIUM = 5.0
   LOW = 2.5
   ```

4. **CLI Integration** (`modelaudit/cli.py`):

   ```python
   @click.option(
       "--config",
       type=click.Path(exists=True),
       help="Path to security configuration file (TOML format)"
   )
   def scan(paths, config, **kwargs):
       # Load security configuration
       config_loader = SecurityConfigLoader(config)
       security_config = config_loader.load()

       # Pass config to scanners
       scan_config = ScanConfigModel(
           security_rules=security_config,
           **kwargs
       )
   ```

### Validation Steps

1. **Configuration Tests** (`tests/test_security_config.py`):

   ```python
   def test_load_default_config():
       loader = SecurityConfigLoader()
       config = loader.load()

       assert "CRITICAL" in config.pickle_rules
       assert "os" in config.pickle_rules["CRITICAL"]
       assert config.pickle_rules["CRITICAL"]["os"] == "*"

   def test_custom_config_override():
       # Create custom config
       custom_config = """
       [pickle_rules.CRITICAL]
       "custom_dangerous_module" = "*"
       """

       with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
           f.write(custom_config)
           f.flush()

           loader = SecurityConfigLoader(f.name)
           config = loader.load()

           assert "custom_dangerous_module" in config.pickle_rules["CRITICAL"]

   def test_cli_config_flag():
       # Test CLI with custom config
       result = runner.invoke(cli, ['--config', 'test-config.toml', 'model.pkl'])
       assert result.exit_code == 0
   ```

### Acceptance Criteria

- [ ] TOML configuration file support
- [ ] CLI --config flag functionality
- [ ] Default configuration template
- [ ] Backward compatibility when no config provided
- [ ] Configuration validation and error handling
- [ ] Documentation for configuration options

---

## Task 7: Implement Better Error Handling and Graceful Degradation

**Priority**: P3 - Reliability Enhancement
**Estimated Effort**: 2-3 days  
**Dependencies**: None

### Objective

Implement ModelScan's approach to graceful degradation where missing dependencies disable specific scanners but don't break the entire tool.

### Files to Modify

- `modelaudit/scanners/__init__.py` - Registry error handling
- `modelaudit/scanners/base.py` - Scanner error handling
- `modelaudit/cli.py` - CLI error reporting

### Implementation Details

1. **Enhanced Scanner Registry** (`modelaudit/scanners/__init__.py`):

   ```python
   class ScannerRegistry:
       def __init__(self):
           self._failed_scanners: Dict[str, str] = {}
           self._dependency_errors: Dict[str, List[str]] = {}

       def _load_scanner_safe(self, scanner_id: str) -> Optional[type[BaseScanner]]:
           """Load scanner with comprehensive error handling"""
           try:
               scanner_class = self._load_scanner(scanner_id)
               return scanner_class

           except ImportError as e:
               # Missing dependency - provide helpful message
               scanner_info = self._scanners[scanner_id]
               dependencies = scanner_info.get("dependencies", [])

               if dependencies:
                   error_msg = (
                       f"Scanner {scanner_id} requires dependencies: {dependencies}. "
                       f"Install with 'pip install modelaudit[{','.join(dependencies)}]'"
                   )
               else:
                   error_msg = f"Scanner {scanner_id} import failed: {e}"

               self._failed_scanners[scanner_id] = error_msg
               logger.info(error_msg)  # Info level - expected for optional deps
               return None

           except Exception as e:
               # Unexpected error - log as warning
               error_msg = f"Scanner {scanner_id} failed to load: {e}"
               self._failed_scanners[scanner_id] = error_msg
               logger.warning(error_msg)
               return None

       def get_available_scanners_summary(self) -> Dict[str, Any]:
           """Get summary of scanner availability for diagnostics"""
           loaded_scanners = [s for s in self._scanners.keys() if s not in self._failed_scanners]

           return {
               "total_scanners": len(self._scanners),
               "loaded_scanners": len(loaded_scanners),
               "failed_scanners": len(self._failed_scanners),
               "loaded_scanner_list": loaded_scanners,
               "failed_scanner_details": self._failed_scanners.copy()
           }
   ```

2. **CLI Diagnostics Command** (`modelaudit/cli.py`):

   ```python
   @cli.command("doctor")
   def doctor():
       """Diagnose scanner availability and dependencies"""
       from .scanners import _registry

       click.echo("ModelAudit Scanner Diagnostic Report")
       click.echo("=" * 40)

       summary = _registry.get_available_scanners_summary()

       click.echo(f"Total scanners: {summary['total_scanners']}")
       click.echo(f"Loaded successfully: {summary['loaded_scanners']}")
       click.echo(f"Failed to load: {summary['failed_scanners']}")

       if summary['failed_scanners'] > 0:
           click.echo("\n" + style_text("Failed Scanners:", fg="red"))
           for scanner, error in summary['failed_scanner_details'].items():
               click.echo(f"  ❌ {scanner}: {error}")

       if summary['loaded_scanner_list']:
           click.echo("\n" + style_text("Available Scanners:", fg="green"))
           for scanner in summary['loaded_scanner_list']:
               click.echo(f"  ✅ {scanner}")
   ```

### Validation Steps

```python
def test_graceful_degradation():
    """Test that missing dependencies don't crash the scanner"""
    # Mock missing tensorflow
    with patch('tensorflow', None):
        registry = ScannerRegistry()
        scanners = registry.get_scanner_classes()

        # Should still load other scanners
        assert len(scanners) > 0

        # Should track failed scanner
        summary = registry.get_available_scanners_summary()
        assert summary['failed_scanners'] > 0
        assert 'tf_savedmodel' in summary['failed_scanner_details']

def test_doctor_command():
    """Test diagnostic command"""
    result = runner.invoke(cli, ['doctor'])
    assert result.exit_code == 0
    assert "Scanner Diagnostic Report" in result.output
    assert "Total scanners:" in result.output
```

### Acceptance Criteria

- [ ] Missing dependencies never crash the application
- [ ] Clear error messages with installation instructions
- [ ] Diagnostic command shows scanner status
- [ ] Core functionality works even with missing optional dependencies
- [ ] Helpful error messages guide users to solutions

---

## General Testing and Validation Framework

### Comprehensive Test Suite Requirements

Each task should include:

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test end-to-end scanner functionality
3. **Performance Tests**: Ensure no significant performance regression
4. **Security Tests**: Validate that improvements actually catch attacks
5. **Regression Tests**: Ensure existing functionality isn't broken

### Test Asset Generation

Create a comprehensive test asset generation script:

```bash
# tests/assets/generators/generate_all_test_assets.py
python generate_all_test_assets.py --comprehensive
```

### Performance Benchmarks

Establish baseline performance metrics:

```bash
rye run pytest tests/test_performance_benchmarks.py --benchmark
```

### Security Validation

Test against known attack vectors:

```bash
rye run pytest tests/test_security_validation.py --security-focus
```

### Documentation Requirements

Each task should update:

- [ ] Inline code documentation
- [ ] CLI help text
- [ ] README.md feature descriptions
- [ ] CHANGELOG.md entries
- [ ] Security scanner comparison documentation

---

## Task 8: Implement PickleScan's Safety Level Classification System

**Priority**: P2 - UX Enhancement
**Estimated Effort**: 2-3 days
**Dependencies**: Task 3 (Severity System)

### Objective

Implement PickleScan's three-tier safety classification (Innocuous, Suspicious, Dangerous) alongside the existing severity system to provide more nuanced risk assessment and reduce false positives.

### Files to Modify

- `modelaudit/scanners/base.py` - Add SafetyLevel enum
- `modelaudit/scanners/pickle_scanner.py` - Implement safety classification
- `modelaudit/suspicious_symbols.py` - Add safe globals whitelist
- `tests/test_safety_classification.py` - Comprehensive tests

### Implementation Details

1. **Add Safety Classification** (`modelaudit/scanners/base.py`):

   ```python
   class SafetyLevel(Enum):
       """PickleScan-style safety classification"""
       INNOCUOUS = "innocuous"      # Known safe operations (torch.FloatStorage, collections.OrderedDict)
       SUSPICIOUS = "suspicious"    # Unknown imports that should be reviewed
       DANGEROUS = "dangerous"      # Confirmed malicious patterns

   class Enhanced Issue(Issue):
       """Enhanced issue with both severity and safety level"""
       safety_level: Optional[SafetyLevel] = None
   ```

2. **Implement Safe Globals Whitelist** (`modelaudit/suspicious_symbols.py`):

   ```python
   # From PickleScan analysis - known safe operations that should not trigger alerts
   SAFE_GLOBALS = {
       "collections": {"OrderedDict", "defaultdict", "Counter", "deque"},
       "torch": {
           "LongStorage", "FloatStorage", "HalfStorage", "DoubleStorage",
           "QUInt2x4Storage", "QUInt4x2Storage", "QInt32Storage",
           "QInt8Storage", "QUInt8Storage", "ComplexFloatStorage",
           "ComplexDoubleStorage", "BFloat16Storage", "BoolStorage",
           "CharStorage", "ShortStorage", "IntStorage", "ByteStorage"
       },
       "numpy": {"dtype", "ndarray"},
       "numpy._core.multiarray": {"_reconstruct"},
       "numpy.core.multiarray": {"_reconstruct"},
       "torch._utils": {"_rebuild_tensor_v2"},
   }

   # Enhanced dangerous patterns from PickleScan
   PICKLESCAN_DANGEROUS_GLOBALS = {
       "functools": {"partial"},  # functools.partial(os.system, "echo pwned")
       "numpy.testing._private.utils": "*",  # runstring() is synonym for exec()
       "ssl": "*",  # DNS exfiltration via ssl.get_server_certificate()
       "pip": "*",  # Package installation
       "pydoc": {"pipepager"},  # pydoc.pipepager('help','echo pwned')
       "timeit": "*",  # Code execution via timeit
       "venv": "*",  # Virtual environment manipulation

       # PyTorch-specific dangerous patterns
       "torch._dynamo.guards": {"GuardBuilder.get"},
       "torch._inductor.codecache": {"compile_file"},
       "torch.fx.experimental.symbolic_shapes": {"ShapeEnv.evaluate_guards_expression"},
       "torch.jit.unsupported_tensor_ops": {"execWrapper"},
       "torch.serialization": {"load"},
       "torch.utils._config_module": {"ConfigModule.load_config"},
       "torch.utils.bottleneck.__main__": {"run_cprofile"},
       "torch.utils.collect_env": {"run"},
       "torch.utils.data.datapipes.utils.decoder": {"basichandlers"},
   }
   ```

3. **Enhanced Classification Logic** (`modelaudit/scanners/pickle_scanner.py`):

   ```python
   def _classify_global_safety(self, module: str, name: str) -> Tuple[SafetyLevel, IssueSeverity]:
       """Classify global import using PickleScan's safety logic"""

       # Check if it's a known safe operation
       safe_filter = SAFE_GLOBALS.get(module)
       if safe_filter and (safe_filter == "*" or name in safe_filter):
           return SafetyLevel.INNOCUOUS, IssueSeverity.INFO

       # Check if it's definitely dangerous
       dangerous_filter = PICKLESCAN_DANGEROUS_GLOBALS.get(module)
       if dangerous_filter and (dangerous_filter == "*" or name in dangerous_filter):
           return SafetyLevel.DANGEROUS, IssueSeverity.CRITICAL

       # Check legacy dangerous patterns with severity mapping
       for severity_level in ["CRITICAL", "HIGH", "MEDIUM"]:
           severity_map = PICKLE_SEVERITY_MAP.get(severity_level, {})
           pattern_filter = severity_map.get(module)
           if pattern_filter and (pattern_filter == "*" or name in pattern_filter):
               severity = getattr(IssueSeverity, severity_level)
               return SafetyLevel.DANGEROUS, severity

       # Unknown import - mark as suspicious for manual review
       return SafetyLevel.SUSPICIOUS, IssueSeverity.MEDIUM
   ```

### Test Assets Required

```python
# tests/assets/generators/generate_safety_classification_tests.py
def generate_innocuous_pickle():
    """Generate pickle with only safe torch operations"""
    import torch
    tensor = torch.FloatTensor([1, 2, 3])
    with open('tests/assets/pickles/innocuous_torch.pkl', 'wb') as f:
        pickle.dump(tensor, f)

def generate_suspicious_pickle():
    """Generate pickle with unknown but not obviously malicious imports"""
    class SuspiciousClass:
        def __reduce__(self):
            # Unknown module - should be flagged as suspicious, not dangerous
            return (__import__('unknown_module').unknown_function, ())

    with open('tests/assets/pickles/suspicious_unknown.pkl', 'wb') as f:
        pickle.dump(SuspiciousClass(), f)
```

### Validation Steps

```python
def test_innocuous_classification():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/innocuous_torch.pkl")

    # Should have no dangerous issues, only innocuous findings
    dangerous_issues = [i for i in result.issues if i.safety_level == SafetyLevel.DANGEROUS]
    assert len(dangerous_issues) == 0

    innocuous_findings = [i for i in result.issues if i.safety_level == SafetyLevel.INNOCUOUS]
    assert len(innocuous_findings) > 0

def test_suspicious_vs_dangerous_classification():
    scanner = PickleScanner()

    # Unknown imports should be suspicious, not dangerous
    result1 = scanner.scan("tests/assets/pickles/suspicious_unknown.pkl")
    suspicious_issues = [i for i in result1.issues if i.safety_level == SafetyLevel.SUSPICIOUS]
    assert len(suspicious_issues) > 0

    # Known malicious patterns should be dangerous
    result2 = scanner.scan("tests/assets/pickles/malicious_eval.pkl")
    dangerous_issues = [i for i in result2.issues if i.safety_level == SafetyLevel.DANGEROUS]
    assert len(dangerous_issues) > 0
```

### Acceptance Criteria

- [ ] Three-tier safety classification: Innocuous, Suspicious, Dangerous
- [ ] Comprehensive safe globals whitelist prevents false positives on legitimate models
- [ ] Suspicious classification for unknown imports (requires manual review)
- [ ] Dangerous classification only for confirmed malicious patterns
- [ ] Compatible with existing severity system (both classifications available)
- [ ] Reduced false positive rate on common ML frameworks

---

## Task 11: Add 7-Zip Archive Support

**Priority**: P3 - Format Extension
**Estimated Effort**: 2-3 days
**Dependencies**: None

### Objective

Implement PickleScan's 7-Zip archive scanning capability to detect malicious content in 7z archives, which are sometimes used to distribute models.

### Files to Modify

- `modelaudit/scanners/` - Add 7z scanner or extend archive scanner
- `modelaudit/scanners/sevenzip_scanner.py` - New 7z-specific scanner
- `pyproject.toml` - Add py7zr optional dependency

### Implementation Details

1. **7-Zip Scanner** (`modelaudit/scanners/sevenzip_scanner.py`):

   ```python
   import tempfile
   import os
   from typing import Optional

   try:
       import py7zr
       HAS_PY7ZR = True
   except ImportError:
       HAS_PY7ZR = False

   class SevenZipScanner(BaseScanner):
       """Scanner for 7-Zip archive files"""

       name = "sevenzip"
       description = "Scans 7-Zip archives for malicious model files"
       supported_extensions = [".7z"]

       @classmethod
       def can_handle(cls, path: str) -> bool:
           if not HAS_PY7ZR:
               return False

           # Check extension
           if not path.lower().endswith('.7z'):
               return False

           # Check magic bytes
           try:
               with open(path, 'rb') as f:
                   magic = f.read(6)
                   return magic == b"7z\xbc\xaf\x27\x1c"
           except Exception:
               return False

       def scan(self, path: str) -> ScanResult:
           if not HAS_PY7ZR:
               result = self._create_result()
               result.add_check(
                   name="7-Zip Library Check",
                   passed=False,
                   message="py7zr not installed. Install with 'pip install modelaudit[7z]'",
                   severity=IssueSeverity.CRITICAL,
                   location=path
               )
               return result

           result = self._create_result()

           try:
               with py7zr.SevenZipFile(path, mode='r') as archive:
                   file_names = archive.getnames()
                   scannable_files = [
                       f for f in file_names
                       if any(f.endswith(ext) for ext in ['.pkl', '.pickle', '.pt', '.pth', '.bin'])
                   ]

                   if not scannable_files:
                       result.add_check(
                           name="Archive Content Check",
                           passed=True,
                           message=f"No scannable files found in 7z archive (found {len(file_names)} total files)",
                           location=path
                       )
                       return result

                   with tempfile.TemporaryDirectory() as tmp_dir:
                       # Extract scannable files
                       archive.extract(path=tmp_dir, targets=scannable_files)

                       for file_name in scannable_files:
                           extracted_path = os.path.join(tmp_dir, file_name)
                           if os.path.isfile(extracted_path):
                               # Scan extracted file
                               from . import get_scanner_for_file
                               file_scanner = get_scanner_for_file(extracted_path)

                               if file_scanner:
                                   file_result = file_scanner.scan(extracted_path)
                                   # Adjust issue locations to show archive context
                                   for issue in file_result.issues:
                                       issue.location = f"{path}:{file_name}"
                                   result.issues.extend(file_result.issues)
                                   result.checks.extend(file_result.checks)

           except Exception as e:
               result.add_check(
                   name="7-Zip Archive Scan",
                   passed=False,
                   message=f"Failed to scan 7z archive: {e}",
                   severity=IssueSeverity.WARNING,
                   location=path
               )

           result.finish(success=True)
           return result
   ```

2. **Update Dependencies** (`pyproject.toml`):

   ```toml
   [project.optional-dependencies]
   # ... existing dependencies ...
   sevenzip = ["py7zr>=0.20.0"]
   ```

3. **Registry Integration** (`modelaudit/scanners/__init__.py`):
   ```python
   # Add to scanner registry
   "sevenzip": {
       "module": "modelaudit.scanners.sevenzip_scanner",
       "class": "SevenZipScanner",
       "description": "Scans 7-Zip archive files",
       "extensions": [".7z"],
       "priority": 97,  # Before generic zip scanner
       "dependencies": ["py7zr"],
       "numpy_sensitive": False,
   }
   ```

### Test Assets Required

```python
# tests/assets/generators/generate_7z_test_assets.py
import py7zr
import pickle

def generate_malicious_7z():
    """Create 7z archive containing malicious pickle"""
    # Create malicious pickle
    class Attack:
        def __reduce__(self):
            return (eval, ("__import__('os').system('7z_attack')",))

    with open('temp_malicious.pkl', 'wb') as f:
        pickle.dump(Attack(), f)

    # Create 7z archive
    with py7zr.SevenZipFile('tests/assets/archives/malicious.7z', 'w') as archive:
        archive.write('temp_malicious.pkl', 'model.pkl')

    os.unlink('temp_malicious.pkl')

def generate_safe_7z():
    """Create 7z archive with safe content"""
    safe_data = {'weights': [1.0, 2.0, 3.0]}

    with open('temp_safe.pkl', 'wb') as f:
        pickle.dump(safe_data, f)

    with py7zr.SevenZipFile('tests/assets/archives/safe.7z', 'w') as archive:
        archive.write('temp_safe.pkl', 'model.pkl')

    os.unlink('temp_safe.pkl')
```

### Validation Steps

```python
def test_7z_malicious_detection():
    """Test detection of malicious content in 7z archives"""
    scanner = SevenZipScanner()
    result = scanner.scan("tests/assets/archives/malicious.7z")

    assert len(result.issues) > 0
    # Issues should reference the archive context
    eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
    assert len(eval_issues) > 0
    assert "malicious.7z:" in eval_issues[0].location

def test_7z_safe_content():
    """Test that safe 7z archives don't trigger false positives"""
    scanner = SevenZipScanner()
    result = scanner.scan("tests/assets/archives/safe.7z")

    # Should have no dangerous issues
    dangerous_issues = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
    assert len(dangerous_issues) == 0
```

### Acceptance Criteria

- [ ] Support for 7-Zip archive format detection and scanning
- [ ] Extraction and scanning of nested pickle/model files
- [ ] Proper error handling for corrupted or password-protected archives
- [ ] Clear indication of archive context in issue reporting
- [ ] Optional dependency handling (graceful degradation when py7zr unavailable)
- [ ] Memory-efficient temporary file handling

---

This comprehensive task breakdown provides engineers with independent, actionable work items that will significantly enhance ModelAudit's security detection capabilities while maintaining its broader format support advantage.

---

# Infrastructure & Codebase Health Tasks

The following tasks address critical infrastructure issues identified in the codebase audit. These should be completed alongside or before the security enhancement tasks above to ensure a stable foundation.

---

## TASK R-1: Refactor Monster Functions 🔴 **CRITICAL**

### Problem Description

The codebase contains several extremely large functions that are unmaintainable, untestable, and error-prone:

- `_scan_pickle_bytes`: **1,026 lines** (should be <50)
- `scan_command` (CLI): **903 lines** (should be <100)
- `scan_model_directory_or_file`: **565 lines** (should be <200)

These massive functions violate single responsibility principle and are major technical debt.

### Files to Modify

- `modelaudit/scanners/pickle_scanner.py` - `_scan_pickle_bytes` method
- `modelaudit/cli.py` - `scan_command` function
- `modelaudit/core.py` - `scan_model_directory_or_file` function

### Specific Changes Required

#### Step 1: Break Down `_scan_pickle_bytes` (1,026 lines)

Split into logical components:

```python
# Create separate methods in pickle_scanner.py:
def _scan_pickle_bytes(self, data: BinaryIO, context: str = "") -> ScanResult:
    """Main entry point - orchestrates the scan process."""
    result = self._create_result()

    # Delegate to specialized methods
    self._analyze_pickle_structure(data, result)
    self._extract_and_validate_globals(data, result)
    self._detect_malicious_patterns(data, result)
    self._analyze_torch_references(data, result)
    self._perform_entropy_analysis(data, result)

    return result

def _analyze_pickle_structure(self, data: BinaryIO, result: ScanResult) -> None:
    """Analyze pickle opcodes and structure (200-300 lines)."""
    # Move opcode analysis logic here

def _extract_and_validate_globals(self, data: BinaryIO, result: ScanResult) -> None:
    """Extract globals and validate against known dangerous patterns (200-300 lines)."""
    # Move global extraction and validation here

def _detect_malicious_patterns(self, data: BinaryIO, result: ScanResult) -> None:
    """Detect specific malicious patterns and CVEs (200-300 lines)."""
    # Move pattern detection here

def _analyze_torch_references(self, data: BinaryIO, result: ScanResult) -> None:
    """Analyze PyTorch-specific patterns (100-200 lines)."""
    # Move PyTorch analysis here

def _perform_entropy_analysis(self, data: BinaryIO, result: ScanResult) -> None:
    """Perform entropy and semantic analysis (100-200 lines)."""
    # Move entropy analysis here
```

#### Step 2: Break Down `scan_command` (903 lines)

Split CLI logic into focused functions:

```python
# In cli.py:
def scan_command(paths, **kwargs):
    """Main scan command - delegates to specialized handlers."""
    # Input validation and setup (50 lines)
    scan_config = _prepare_scan_configuration(**kwargs)

    if kwargs.get('url'):
        return _handle_url_scan(kwargs['url'], scan_config)
    elif kwargs.get('huggingface'):
        return _handle_huggingface_scan(kwargs['huggingface'], scan_config)
    else:
        return _handle_local_scan(paths, scan_config)

def _prepare_scan_configuration(**kwargs) -> dict:
    """Prepare and validate scan configuration (100-150 lines)."""
    # Move config preparation logic here

def _handle_url_scan(url: str, config: dict) -> None:
    """Handle URL-based scanning (150-200 lines)."""
    # Move URL scanning logic here

def _handle_huggingface_scan(model_id: str, config: dict) -> None:
    """Handle HuggingFace model scanning (150-200 lines)."""
    # Move HF scanning logic here

def _handle_local_scan(paths: list, config: dict) -> None:
    """Handle local file/directory scanning (200-300 lines)."""
    # Move local scanning logic here

def _format_and_output_results(results, config: dict) -> None:
    """Format and output scan results (200-300 lines)."""
    # Move output formatting here
```

#### Step 3: Break Down `scan_model_directory_or_file` (565 lines)

Refactor core scanning logic:

```python
# In core.py:
def scan_model_directory_or_file(path: str, config: dict = None) -> ScanResult:
    """Main scanning entry point - coordinates the process."""
    scanner_coordinator = ScannerCoordinator(config)
    return scanner_coordinator.scan(path)

class ScannerCoordinator:
    """Coordinates scanning across multiple scanners and handles complex logic."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.progress_tracker = self._setup_progress_tracking()

    def scan(self, path: str) -> ScanResult:
        """Coordinate the scanning process."""
        return self._scan_with_validation_and_progress(path)

    def _scan_with_validation_and_progress(self, path: str) -> ScanResult:
        """Handle validation, progress tracking, and error recovery (150-200 lines)."""
        # Move validation and progress logic here

    def _coordinate_scanner_execution(self, path: str) -> ScanResult:
        """Execute appropriate scanners and aggregate results (150-200 lines)."""
        # Move scanner coordination here

    def _handle_scan_errors_and_timeouts(self, path: str) -> ScanResult:
        """Handle errors, timeouts, and edge cases (100-150 lines)."""
        # Move error handling here
```

### Success Criteria

1. ✅ No function longer than 200 lines
2. ✅ `_scan_pickle_bytes` split into 5+ focused methods
3. ✅ `scan_command` split into 6+ focused functions
4. ✅ `scan_model_directory_or_file` refactored using coordinator pattern
5. ✅ All existing tests pass
6. ✅ New unit tests for each extracted function
7. ✅ Improved code coverage and maintainability metrics

### Test Requirements

Each extracted function needs focused unit tests:

```python
# tests/test_pickle_scanner_refactored.py
def test_analyze_pickle_structure():
    """Test pickle structure analysis in isolation."""
    scanner = PickleScanner()
    result = ScanResult("pickle")

    with io.BytesIO(create_test_pickle_bytes()) as data:
        scanner._analyze_pickle_structure(data, result)

    # Verify specific structure analysis results
    assert len(result.checks) > 0
    assert any("opcode" in check.name.lower() for check in result.checks)

def test_extract_and_validate_globals():
    """Test global extraction and validation in isolation."""
    scanner = PickleScanner()
    result = ScanResult("pickle")

    with io.BytesIO(create_malicious_pickle_bytes()) as data:
        scanner._extract_and_validate_globals(data, result)

    # Verify globals were extracted and validated
    assert len(result.issues) > 0
    assert any("eval" in issue.message.lower() for issue in result.issues)
```

### Validation Steps

1. **Complexity Analysis**:

   ```bash
   # Before refactoring
   python -c "
   import ast
   with open('modelaudit/scanners/pickle_scanner.py') as f:
       tree = ast.parse(f.read())
   for node in ast.walk(tree):
       if isinstance(node, ast.FunctionDef) and node.name == '_scan_pickle_bytes':
           print(f'Lines: {node.end_lineno - node.lineno}')
   "

   # After refactoring - should be <100 lines per function
   ```

2. **Test Coverage**:

   ```bash
   # Ensure coverage doesn't decrease
   rye run pytest --cov=modelaudit.scanners.pickle_scanner --cov-report=html
   rye run pytest --cov=modelaudit.cli --cov-report=html
   rye run pytest --cov=modelaudit.core --cov-report=html
   ```

3. **Performance Verification**:

   ```bash
   # Ensure refactoring doesn't impact performance
   rye run python -c "
   import time
   import tempfile
   from modelaudit.scanners.pickle_scanner import PickleScanner

   scanner = PickleScanner()

   # Time before/after refactoring
   start = time.time()
   result = scanner.scan('tests/assets/large_pickle.pkl')
   duration = time.time() - start

   print(f'Scan time: {duration:.3f}s')
   assert duration < 5.0, 'Refactoring caused performance regression'
   "
   ```

---

## TASK R-2: Refactor God Classes 🟡 **HIGH**

### Problem Description

Several classes have too many responsibilities:

- `BaseScanner`: **35 methods** (should be <20)
- `ScanResultsCache`: **19 methods** (should be <15)

### Files to Modify

- `modelaudit/scanners/base.py` - BaseScanner class
- `modelaudit/cache/scan_results_cache.py` - ScanResultsCache class

### Specific Changes Required

#### Step 1: Extract Mixins from BaseScanner

```python
# Create scanners/mixins/
class ValidationMixin:
    """Handles path validation, file access, size checks."""
    def validate_path(self, path: str) -> ScanResult: ...
    def check_file_access(self, path: str) -> bool: ...
    def validate_file_size(self, path: str) -> bool: ...

class ProgressMixin:
    """Handles progress tracking and timeout management."""
    def setup_progress_tracking(self): ...
    def update_progress(self, bytes_scanned: int): ...
    def handle_timeout(self): ...

class AnalysisMixin:
    """Handles ML context and semantic analysis integration."""
    def analyze_ml_context(self, data): ...
    def run_semantic_analysis(self, content): ...

class BaseScanner(ValidationMixin, ProgressMixin, AnalysisMixin):
    """Focused on core scanning orchestration - ~15 methods."""
    # Core scanning methods only
```

#### Step 2: Split ScanResultsCache

```python
# Create cache/components/
class CacheKeyGenerator:
    """Responsible only for cache key generation."""
    def generate_key(self, file_path: str) -> str: ...
    def hash_file_content(self, path: str) -> str: ...

class CacheValidator:
    """Responsible only for cache validation."""
    def is_entry_valid(self, entry: dict, path: str) -> bool: ...
    def validate_cache_integrity(self, entry: dict) -> bool: ...

class CacheStorage:
    """Responsible only for cache storage operations."""
    def store_entry(self, key: str, data: dict): ...
    def retrieve_entry(self, key: str) -> dict: ...

class ScanResultsCache:
    """Coordinates cache operations - ~10 methods."""
    def __init__(self):
        self.key_generator = CacheKeyGenerator()
        self.validator = CacheValidator()
        self.storage = CacheStorage()
```

### Success Criteria

1. ✅ No class with more than 20 methods
2. ✅ Clear separation of concerns
3. ✅ Improved testability
4. ✅ All existing functionality preserved

---

## TASK R-3: Refactor Large Scanner Methods 🟡 **HIGH**

### Problem Description

Several scanner classes have excessively long methods that violate the single responsibility principle and are hard to test and maintain.

### Critical Functions to Refactor

1. **PyTorch ZIP Scanner** (`modelaudit/scanners/pytorch_zip_scanner.py:56-553`)
   - `scan()` method: 498 lines
   - Handles ZIP extraction, pickle analysis, version detection, CVE checking
   - Should be split into 8-10 focused methods

2. **CLI Format Output** (`modelaudit/cli.py` - around line 328)
   - `format_text_output()` method: ~328 lines
   - Handles multiple output formats and styling
   - Should be split into format-specific methods

3. **Flax Msgpack Scanner** (multiple large methods)
   - Several methods over 100 lines each
   - Complex nested analysis logic

### Files to Modify

- `modelaudit/scanners/pytorch_zip_scanner.py`
- `modelaudit/cli.py`
- `modelaudit/scanners/flax_msgpack_scanner.py`

### Refactoring Strategy

**PyTorch ZIP Scanner breakdown:**

```python
# Current 498-line scan() method should become:
def scan(self, path: str) -> ScanResult:
    """Main scan orchestrator - keep under 50 lines"""
    result = ScanResult(path)

    try:
        with ZipFile(path, 'r') as zip_file:
            safe_entries = self._validate_zip_entries(zip_file, result)
            self._scan_pickle_files(zip_file, safe_entries, result)
            self._extract_and_validate_metadata(zip_file, safe_entries, result)
            self._check_vulnerabilities(zip_file, result)
    except Exception as e:
        self._handle_scan_error(e, result)

    return result

# Split into focused methods:
def _validate_zip_entries(self, zip_file, result) -> list[str]
def _scan_pickle_files(self, zip_file, entries, result) -> None
def _extract_and_validate_metadata(self, zip_file, entries, result) -> None
def _check_vulnerabilities(self, zip_file, result) -> None
def _handle_scan_error(self, error, result) -> None
```

### Success Criteria

1. ✅ No method over 100 lines (target: <80 lines each)
2. ✅ Each method has single responsibility
3. ✅ All existing functionality preserved
4. ✅ Test coverage maintained/improved
5. ✅ Performance not degraded

### Validation Steps

```bash
# Check method lengths
python -c "
import ast
import inspect
from modelaudit.scanners.pytorch_zip_scanner import PyTorchZipScanner
for name, method in inspect.getmembers(PyTorchZipScanner, inspect.ismethod):
    if hasattr(method, '__func__'):
        source = inspect.getsource(method.__func__)
        lines = len(source.splitlines())
        if lines > 80:
            print(f'❌ {name}: {lines} lines (too long)')
        else:
            print(f'✅ {name}: {lines} lines')
"

# Test functionality
rye run pytest tests/test_pytorch_zip_scanner.py -v
rye run modelaudit tests/assets/pytorch/malicious_pickle.zip
```

---

# CLI USABILITY ENHANCEMENT TASKS

## TASK U-1: Eliminate CLI Flag Explosion 🔴 **CRITICAL USABILITY**

### Problem Description

The CLI currently has **24+ flags** making it overwhelming and unusable for most users. The help output is massive, options are confusing, and there are multiple redundant ways to accomplish similar tasks.

**Current flag count**: 24+ flags in scan command alone
**User impact**: Overwhelming, hard to discover features, analysis paralysis

### Files to Modify

- `modelaudit/cli.py` - Remove/consolidate redundant flags
- Update help text and documentation

### Specific Changes Required

#### 1. **ELIMINATE: Redundant Size Controls** (Remove 2 of 3)

```python
# CURRENT (confusing):
--max-file-size INTEGER         # Individual file size limit
--max-total-size INTEGER        # Total scan size limit
--max-download-size TEXT        # Cloud download size limit

# PROPOSED (simple):
--max-size TEXT                 # Single size limit for all operations
```

#### 2. **ELIMINATE: Progress Control Overkill** (Remove 3 of 4)

```python
# CURRENT (overkill):
--progress/--no-progress
--progress-log FILE
--progress-format [tqdm|simple|json]
--progress-interval FLOAT

# PROPOSED (simple):
--progress/--no-progress        # Keep only on/off toggle
```

#### 3. **ELIMINATE: Authentication Confusion** (Remove 1 of 2)

```python
# CURRENT (redundant):
--jfrog-api-token TEXT
--jfrog-access-token TEXT

# PROPOSED (single):
--jfrog-token TEXT              # Single unified token option
```

#### 4. **ELIMINATE: Double Negative Confusion**

```python
# CURRENT (confusing):
--no-skip-files/--skip-files    # Double negative is confusing
--selective/--all-files         # Overlaps with above

# PROPOSED (clear):
--include-all-files            # Single positive flag
```

#### 5. **ELIMINATE: Experimental/Internal Flags**

```python
# REMOVE ENTIRELY:
--stream                       # Experimental - hide until stable
--progress-log                 # Internal debugging - not user-facing
--progress-format              # Too granular for most users
--progress-interval            # Too granular for most users
```

### Success Criteria

1. ✅ **Reduce flags from 24+ to ~12** (50% reduction)
2. ✅ **Help output fits on single screen** without scrolling
3. ✅ **No redundant functionality** - one way to do each task
4. ✅ **Clear, positive flag names** - no double negatives
5. ✅ **Maintain all core functionality** - same capabilities, simpler interface

### Validation Steps

```bash
# Test flag reduction
modelaudit scan --help | wc -l    # Should be <40 lines

# Test functionality preservation
modelaudit scan model.pkl --max-size 1GB --jfrog-token TOKEN --include-all-files

# Verify no double negatives
modelaudit scan --help | grep -E "(no-.*-.*|not-.*-.*)" # Should be empty
```

---

## TASK U-2: Implement Smart CLI Defaults 🟡 **HIGH USABILITY**

### Problem Description

Many flags require explicit configuration that should be automatic. Users shouldn't need to think about cache directories, progress formats, or timeout values for 90% of use cases.

### Files to Modify

- `modelaudit/cli.py` - Implement intelligent defaults
- `modelaudit/core.py` - Auto-detection logic

### Smart Defaults to Implement

#### 1. **Auto-detect Large Model Support**

```python
# CURRENT: User must specify
--large-model-support/--no-large-model-support

# PROPOSED: Auto-detect based on file size
# Automatically enable for files >1GB, disable otherwise
```

#### 2. **Auto-detect Progress Display**

```python
# CURRENT: User must specify format
--progress-format [tqdm|simple|json]

# PROPOSED: Auto-detect based on terminal capabilities
# tqdm if terminal supports, simple if pipe/CI, json if --format json
```

#### 3. **Intelligent Cache Management**

```python
# CURRENT: User must specify cache dir
--cache-dir DIRECTORY

# PROPOSED: Smart default locations
# ~/.modelaudit/cache (Linux/Mac), %APPDATA%/modelaudit/cache (Windows)
```

#### 4. **Smart Timeout Scaling**

```python
# CURRENT: Fixed 3600 second timeout
--timeout 3600

# PROPOSED: Scale timeout based on detected file size
# Small files: 60s, Medium: 300s, Large: 3600s, Huge: 7200s
```

### Success Criteria

1. ✅ **90% of scans work without any flags** beyond the file path
2. ✅ **Auto-detection works correctly** in different environments
3. ✅ **Performance improves** due to better defaults
4. ✅ **Power users can still override** when needed

---

## TASK U-3: Add CLI Usability Features 🟢 **MEDIUM USABILITY**

### Problem Description

CLI lacks modern usability features that users expect from contemporary tools.

### Features to Add

#### 1. **Interactive Mode for Complex Scans**

```bash
# For users who don't want to learn all flags
modelaudit scan --interactive
? What would you like to scan? /path/to/model
? Output format? (text/json) text
? Include all file types? (Y/n) n
? Enable verbose output? (y/N) n
```

#### 2. **Configuration File Support**

```toml
# ~/.modelaudit/config.toml
[scan]
format = "json"
output-dir = "~/scan-results"
max-size = "5GB"
include-all-files = false
```

#### 3. **Scan Presets for Common Use Cases**

```bash
modelaudit scan --preset security      # High security, strict settings
modelaudit scan --preset fast         # Quick scan, skip expensive checks
modelaudit scan --preset compliance   # Generate SBOM, detailed reporting
```

#### 4. **Better Error Messages with Suggestions**

```bash
# Current:
Error: Cannot access file

# Proposed:
Error: Cannot access '/path/to/model.pkl'
Suggestions:
  • Check if file exists: ls -la /path/to/model.pkl
  • Check permissions: stat /path/to/model.pkl
  • Try with sudo if needed: sudo modelaudit scan /path/to/model.pkl
```

### Success Criteria

1. ✅ **Interactive mode works** for complex scenarios
2. ✅ **Config file reduces common flag usage** by 80%
3. ✅ **Presets cover 3 major use cases**
4. ✅ **Error messages are actionable**

---

## TASK I-1: Fix Circular Import Dependencies 🔴 **CRITICAL**

### Problem Description

Circular import dependency between `modelaudit/scanners/base.py` and `modelaudit/core.py` causes potential import failures and makes testing difficult.

### Files to Modify

- `modelaudit/scanners/base.py` (lines 405)
- `modelaudit/core.py` (lines 419-456)
- Create new file: `modelaudit/utils/result_conversion.py`

### Specific Changes Required

#### Step 1: Create Result Conversion Utility

Create `modelaudit/utils/result_conversion.py`:

```python
"""Utilities for converting between ScanResult objects and dictionaries."""

import time
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def scan_result_from_dict(result_dict: Dict[str, Any]) -> "ScanResult":
    """
    Convert a dictionary representation back to a ScanResult object.
    This is used when retrieving cached scan results that were stored as dictionaries.

    Args:
        result_dict: Dictionary representation of a ScanResult
    Returns:
        Reconstructed ScanResult object
    """
    from ..scanners.base import ScanResult, Check, CheckStatus, Issue, IssueSeverity

    # Create new ScanResult with the same scanner name
    scanner_name = result_dict.get("scanner", "cached")
    result = ScanResult(scanner_name=scanner_name)

    # Restore basic properties
    result.success = result_dict.get("success", True)
    result.bytes_scanned = result_dict.get("bytes_scanned", 0)
    result.start_time = result_dict.get("start_time", time.time())
    result.end_time = result_dict.get("end_time", time.time())
    result.metadata.update(result_dict.get("metadata", {}))

    # Restore issues from cached data
    for issue_dict in result_dict.get("issues", []):
        result.add_issue(
            message=issue_dict.get("message", ""),
            severity=IssueSeverity(issue_dict.get("severity", "warning")),
            location=issue_dict.get("location"),
            details=issue_dict.get("details", {}),
            why=issue_dict.get("why"),
        )

    # Restore checks from cached data
    for check_dict in result_dict.get("checks", []):
        try:
            check = Check(
                name=check_dict.get("name", "Unknown Check"),
                status=CheckStatus(check_dict.get("status", "passed")),
                message=check_dict.get("message", ""),
                severity=check_dict.get("severity"),
                location=check_dict.get("location"),
                details=check_dict.get("details", {}),
                why=check_dict.get("why"),
                timestamp=check_dict.get("timestamp", time.time()),
            )
            result.checks.append(check)
        except Exception as e:
            # If we can't reconstruct a check, log and continue
            logger.debug(f"Could not reconstruct check from cache: {e}")

    return result
```

#### Step 2: Update Scanner Base Class

In `modelaudit/scanners/base.py`, replace the import on line 405:

```python
# REMOVE this line:
from ..core import _scan_result_from_dict

# REPLACE with:
from ..utils.result_conversion import scan_result_from_dict

# UPDATE the function call from:
return _scan_result_from_dict(result_dict)

# TO:
return scan_result_from_dict(result_dict)
```

#### Step 3: Update Core Module

In `modelaudit/core.py`, replace the function definition (lines 419-456):

```python
# REMOVE the entire _scan_result_from_dict function
# REPLACE the function call from:
return _scan_result_from_dict(result_dict)

# TO:
from .utils.result_conversion import scan_result_from_dict
return scan_result_from_dict(result_dict)
```

### Success Criteria

1. ✅ No circular import warnings when running `python -c "import modelaudit"`
2. ✅ All existing tests pass: `rye run pytest -n auto`
3. ✅ Import graph is acyclic (verify with `pydeps modelaudit --show-cycles`)
4. ✅ Cache functionality works identical to before changes

### Validation Steps

```bash
# Install pydeps if not available
pip install pydeps

# Check for circular imports
pydeps modelaudit --show-cycles  # Should output: "No cycles found"

# Test imports
python -c "
import sys
import modelaudit
from modelaudit.scanners.base import BaseScanner
from modelaudit.core import scan_file
print('✅ All imports successful, no circular dependencies')
"

# Run tests
rye run pytest tests/test_cache_cli.py -v
rye run pytest -n auto -m "not slow and not integration"
```

---

## TASK I-2: Fix Thread-Safe Cache Manager 🟡 **HIGH**

### Problem Description

Global cache manager singleton is not thread-safe, causing potential race conditions in multi-threaded environments.

### Files to Modify

- `modelaudit/cache/cache_manager.py` (lines 149-174)

### Specific Changes Required

Replace the global cache manager implementation:

```python
# Thread-safe singleton implementation
import threading

_cache_manager_lock = threading.RLock()
_global_cache_manager: Optional[CacheManager] = None


def get_cache_manager(cache_dir: Optional[str] = None, enabled: bool = True) -> CacheManager:
    """
    Get global cache manager instance (thread-safe).

    Args:
        cache_dir: Optional cache directory path
        enabled: Whether caching should be enabled

    Returns:
        Global cache manager instance
    """
    global _global_cache_manager

    # Double-checked locking pattern for thread safety
    if _global_cache_manager is None:
        with _cache_manager_lock:
            # Check again inside the lock
            if _global_cache_manager is None:
                _global_cache_manager = CacheManager(cache_dir, enabled)

    return _global_cache_manager


def reset_cache_manager() -> None:
    """Reset global cache manager (mainly for testing) - thread-safe."""
    global _global_cache_manager
    with _cache_manager_lock:
        _global_cache_manager = None
```

### Success Criteria

1. ✅ All existing cache tests pass: `rye run pytest tests/test_cache_cli.py -v`
2. ✅ No race conditions in concurrent cache access
3. ✅ Performance impact is negligible (< 5% overhead)

### Validation Steps

```bash
# Test thread safety (manual)
rye run python -c "
import threading
import time
from modelaudit.cache import get_cache_manager, reset_cache_manager

reset_cache_manager()
results = []
barrier = threading.Barrier(10)

def get_manager_concurrent():
    barrier.wait()
    manager = get_cache_manager(enabled=True)
    results.append(id(manager))

threads = [threading.Thread(target=get_manager_concurrent) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()

assert len(set(results)) == 1, f'Multiple managers created: {results}'
print('✅ Thread safety verified')
"

# Performance test
rye run pytest tests/test_cache_cli.py tests/test_cli_cache_dir.py -v
```

---

## TASK I-3: Consolidate Duplicate Caching Logic 🟡 **HIGH**

### Problem Description

Caching logic is duplicated between core-level (`modelaudit/core.py`) and scanner-level (`modelaudit/scanners/base.py`), leading to maintenance issues and potential double-caching.

### Files to Modify

- `modelaudit/core.py` (lines 520-548)
- `modelaudit/scanners/base.py` (lines 380-413)
- Create new file: `modelaudit/utils/cache_decorator.py`

### Specific Changes Required

#### Step 1: Create Cache Decorator

Create `modelaudit/utils/cache_decorator.py`:

```python
"""Unified caching decorator for ModelAudit scanning operations."""

import logging
import functools
from typing import Any, Callable, Dict, Optional, TypeVar

logger = logging.getLogger(__name__)
F = TypeVar('F', bound=Callable[..., Any])


def cached_scan(
    cache_enabled_key: str = "cache_enabled",
    cache_dir_key: str = "cache_dir"
) -> Callable[[F], F]:
    """
    Cache decorator for scan functions that take (path, config) arguments.
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract config from arguments
            config = None
            if len(args) >= 2 and isinstance(args[1], (dict, type(None))):
                config = args[1] or {}
            else:
                config = kwargs.get("config", {})

            # Check cache configuration
            cache_enabled = config.get(cache_enabled_key, True)
            cache_dir = config.get(cache_dir_key)

            # If caching is disabled, call function directly
            if not cache_enabled:
                return func(*args, **kwargs)

            # Get file path (assume first argument is path)
            file_path = args[0] if args else kwargs.get('path', '')
            if not file_path:
                return func(*args, **kwargs)

            # Use cache manager for cache-enabled operations
            try:
                from ..cache import get_cache_manager
                cache_manager = get_cache_manager(cache_dir, enabled=True)

                def cached_func_wrapper(fpath: str) -> dict:
                    result = func(*args, **kwargs)
                    if hasattr(result, 'to_dict'):
                        return result.to_dict()
                    elif isinstance(result, dict):
                        return result
                    else:
                        return {"result": str(result), "success": True}

                result_dict = cache_manager.cached_scan(file_path, cached_func_wrapper)

                # Convert back to original type if needed
                if hasattr(result_dict, 'get') and 'scanner' in result_dict:
                    from .result_conversion import scan_result_from_dict
                    return scan_result_from_dict(result_dict)

                return result_dict

            except Exception as e:
                logger.warning(f"Cache system error for {file_path}: {e}. Falling back to direct execution.")
                return func(*args, **kwargs)

        return wrapper
    return decorator
```

#### Step 2: Update Core Module and Scanner Base Class

In `modelaudit/core.py`:

```python
from .utils.cache_decorator import cached_scan

@cached_scan()
def scan_file(path: str, config: Optional[dict[str, Any]] = None) -> ScanResult:
    """Scan a single file with caching support."""
    return _scan_file_internal(path, config)
```

In `modelaudit/scanners/base.py`:

```python
from ..utils.cache_decorator import cached_scan

@cached_scan()
def scan_with_cache(self, path: str) -> ScanResult:
    """Scan with optional caching support."""
    return self.scan(path)
```

### Success Criteria

1. ✅ All existing cache tests pass
2. ✅ No double-caching occurs (verified via logging)
3. ✅ Code duplication reduced by 80+ lines
4. ✅ Cache performance is maintained or improved

### Validation Steps

```bash
# Count lines of caching code before/after
grep -n "cache_enabled\|get_cache_manager\|cached_scan" modelaudit/core.py modelaudit/scanners/base.py | wc -l

# Test functionality
rye run python -c "
import time
import tempfile
import pickle
from modelaudit.core import scan_file
from modelaudit.cache import reset_cache_manager

with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
    pickle.dump({'test': 'data'}, f)
    test_file = f.name

reset_cache_manager()

start = time.time()
result1 = scan_file(test_file, {'cache_enabled': True})
first_time = time.time() - start

start = time.time()
result2 = scan_file(test_file, {'cache_enabled': True})
second_time = time.time() - start

print(f'First scan: {first_time:.3f}s, Cached scan: {second_time:.3f}s')
print(f'Speedup: {first_time/second_time:.1f}x')

assert second_time < first_time * 0.3, 'Cache not providing speedup'
print('✅ Unified cache performance verified')

import os
os.unlink(test_file)
"
```

---

## TASK I-4: Improve Exception Handling Specificity 🟢 **MEDIUM**

### Problem Description

The codebase uses broad `except Exception` blocks that silently catch and mask legitimate errors, making debugging difficult.

### Files to Modify

- `modelaudit/cache/scan_results_cache.py` (lines 100, 152, 214, 274, 327, 380, 444, 455)
- `modelaudit/cache/cache_manager.py` (lines 108)

### Specific Changes Required

#### Step 1: Create Custom Cache Exceptions

Create `modelaudit/cache/exceptions.py`:

```python
"""Custom exceptions for cache operations."""

class CacheError(Exception):
    """Base exception for cache-related errors."""
    pass

class CacheKeyGenerationError(CacheError):
    """Exception raised when cache key generation fails."""
    pass

class CacheStorageError(CacheError):
    """Exception raised when storing data to cache fails."""
    pass

class CacheRetrievalError(CacheError):
    """Exception raised when retrieving data from cache fails."""
    pass

class CacheValidationError(CacheError):
    """Exception raised when cache entry validation fails."""
    pass
```

#### Step 2: Update Cache Classes

In `modelaudit/cache/scan_results_cache.py`, replace broad exception handling with specific types:

```python
from .exceptions import CacheKeyGenerationError, CacheStorageError, CacheRetrievalError, CacheValidationError

# REPLACE broad "except Exception as e:" blocks with:
except (OSError, IOError) as e:
    logger.warning(f"File I/O error during cache lookup for {file_path}: {e}")
    self._record_cache_miss("io_error")
    return None
except (json.JSONDecodeError, KeyError, ValueError) as e:
    logger.warning(f"Cache data corruption for {file_path}: {e}")
    self._record_cache_miss("data_corruption")
    return None
except CacheValidationError as e:
    logger.debug(f"Cache validation failed for {file_path}: {e}")
    self._record_cache_miss("validation_failed")
    return None
except Exception as e:
    logger.error(f"Unexpected cache lookup error for {file_path}: {e}")
    self._record_cache_miss("unexpected_error")
    return None
```

### Success Criteria

1. ✅ All existing tests pass
2. ✅ New specific exception types are used appropriately
3. ✅ Error messages are more informative and actionable
4. ✅ Critical errors are not silently swallowed

### Validation Steps

```bash
# Check that broad exception handlers are reduced
grep -r "except Exception as e" modelaudit/cache/ | wc -l  # Should be lower than before

# Test error resilience
rye run python -c "
from modelaudit.cache.scan_results_cache import ScanResultsCache
import tempfile

cache = ScanResultsCache()

with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
    f.write(b'test data')
    test_file = f.name

# Should handle non-existent files gracefully
result = cache.get_cached_result('/non/existent/file.pkl')
assert result is None
print('✅ Handles non-existent files')

# Should handle valid operations normally
cache.store_result(test_file, {'test': 'data'})
result = cache.get_cached_result(test_file)
assert result is not None
print('✅ Normal operations work')

import os
os.unlink(test_file)
print('All error resilience tests passed!')
"
```

---

## TASK I-5: Performance Optimization - Reduce File System Calls 🔵 **LOW**

### Problem Description

Redundant file system calls in cache operations slow down performance, particularly `os.stat()` being called multiple times for the same file.

### Files to Modify

- `modelaudit/cache/scan_results_cache.py` (lines 120-130, 255-275)

### Specific Changes Required

Update methods to accept and reuse `os.stat_result`:

```python
def _generate_cache_key(self, file_path: str, file_stat: Optional[os.stat_result] = None) -> Optional[str]:
    """Generate cache key with optional stat reuse."""
    if file_stat is None:
        file_stat = os.stat(file_path)

    # Use file_stat.st_size and file_stat.st_mtime instead of calling os.stat() again
    # ... rest of method

def store_result(self, file_path: str, scan_result: dict[str, Any]) -> None:
    """Store scan result in cache with optimized file system calls."""
    try:
        # Get file stats ONCE and reuse
        file_stat = os.stat(file_path)

        # Pass file_stat to avoid redundant calls
        cache_key = self._generate_cache_key(file_path, file_stat=file_stat)
        # ... use file_stat throughout method
```

### Success Criteria

1. ✅ File system calls reduced by 30-50%
2. ✅ Cache operations are 10-20% faster
3. ✅ All existing functionality preserved

### Validation Steps

```bash
rye run python -c "
import tempfile
import pickle
import time
from modelaudit.cache.scan_results_cache import ScanResultsCache

cache = ScanResultsCache()

with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
    pickle.dump({'test': 'data'}, f)
    test_file = f.name

# Time cache operations
start = time.time()
for _ in range(100):
    cache.store_result(test_file, {'result': 'test'})
    result = cache.get_cached_result(test_file)
end = time.time()

avg_time = (end - start) / 100
print(f'Average cache operation time: {avg_time*1000:.2f}ms')

assert avg_time < 0.01, f'Cache operations too slow: {avg_time*1000:.2f}ms'
print('✅ Performance optimization verified')

import os
os.unlink(test_file)
"
```

---

## Infrastructure Tasks Final Validation

After completing infrastructure tasks I-1 through I-5:

```bash
# 1. Full test suite
rye run pytest -n auto

# 2. Static analysis
pydeps modelaudit --show-cycles  # Should show no cycles
rye run ruff check modelaudit/
rye run mypy modelaudit/

# 3. Functional validation
rye run modelaudit scan tests/assets/samples/pickles/safe_data.pkl --format json
rye run modelaudit cache stats

# 4. Performance validation
# Run timing tests to ensure no performance regressions
```

## Success Metrics

After completing infrastructure tasks:

- ✅ Circular import dependencies: 0
- ✅ Thread-safe cache operations
- ✅ 80+ lines of duplicate code eliminated
- ✅ Broad exception handlers reduced by 70%
- ✅ File system calls reduced by 30-50%
