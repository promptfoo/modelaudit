# ModelAudit Security Enhancement Tasks

Based on the comprehensive analysis of ModelScan, ModelAudit, and PickleScan, these tasks will significantly improve ModelAudit's exploit detection capabilities while maintaining its broader format support advantage.

## Task 1: Implement Advanced TensorFlow Operation Detection

**Priority**: P1 - Critical Security Gap
**Estimated Effort**: 3-5 days
**Dependencies**: None

### Objective

Add detection for dangerous TensorFlow operations (ReadFile, WriteFile, PyFunc, PyCall, ShellExecute) that ModelScan detects but ModelAudit currently misses.

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

## Task 2: Enhance Pickle Scanner with STACK_GLOBAL and Memo Tracking

**Priority**: P1 - Critical Security Gap
**Estimated Effort**: 4-6 days  
**Dependencies**: None

### Objective

Implement advanced pickle opcode analysis including STACK_GLOBAL parsing and memo object tracking to match ModelScan's sophisticated pickle analysis capabilities.

### Files to Modify

- `modelaudit/scanners/pickle_scanner.py` - Main pickle scanner
- `modelaudit/suspicious_symbols.py` - Add pickle opcode patterns
- `tests/test_pickle_scanner.py` - Enhanced pickle tests

### Implementation Details

1. **Enhance Pickle Scanner** (`modelaudit/scanners/pickle_scanner.py`):

   ```python
   import pickletools
   from typing import Dict, Set, Tuple, Union, List

   def _extract_globals_advanced(self, data: IO[bytes], multiple_pickles: bool = True) -> Set[Tuple[str, str]]:
       """Advanced pickle global extraction with STACK_GLOBAL and memo support"""
       globals_found: Set[Tuple[str, str]] = set()
       memo: Dict[Union[int, str], str] = {}

       # Scan for multiple pickle streams
       last_byte = b"dummy"
       while last_byte != b"":
           try:
               ops: List[Tuple[Any, Any, Union[int, None]]] = list(pickletools.genops(data))
           except Exception as e:
               # Return any globals found so far
               if len(globals_found) > 0:
                   logger.warning(f"Pickle parsing failed, but found {len(globals_found)} globals: {e}")
                   return globals_found
               raise

           last_byte = data.read(1)
           data.seek(-1, 1)

           # Process opcodes
           for n, (opcode, arg, pos) in enumerate(ops):
               op_name = opcode.name

               # Handle memo operations
               if op_name == "MEMOIZE" and n > 0:
                   memo[len(memo)] = ops[n - 1][1]
               elif op_name in ["PUT", "BINPUT", "LONG_BINPUT"] and n > 0:
                   memo[arg] = ops[n - 1][1]

               # Handle global imports
               elif op_name in ("GLOBAL", "INST"):
                   globals_found.add(tuple(arg.split(" ", 1)))

               # Handle STACK_GLOBAL - this is the sophisticated part ModelScan has
               elif op_name == "STACK_GLOBAL":
                   values = self._extract_stack_global_values(ops, n, memo)
                   if len(values) == 2:
                       globals_found.add((values[1], values[0]))  # module, name
                   else:
                       logger.debug(f"STACK_GLOBAL parsing failed at position {n}, found {len(values)} values")
                       globals_found.add(("unknown", "unknown"))  # Flag as suspicious

           if not multiple_pickles:
               break

       return globals_found

   def _extract_stack_global_values(self, ops: List, position: int, memo: Dict) -> List[str]:
       """Extract values for STACK_GLOBAL opcode by walking backwards through stack"""
       values = []

       for offset in range(1, min(position + 1, 10)):  # Look back max 10 operations
           prev_op = ops[position - offset]
           op_name = prev_op[0].name
           op_value = prev_op[1]

           # Skip memo operations
           if op_name in ["MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"]:
               continue

           # Handle memo references
           elif op_name in ["GET", "BINGET", "LONG_BINGET"]:
               if op_value in memo:
                   values.append(memo[op_value])
               else:
                   values.append("unknown")

           # Handle string values
           elif op_name in ["SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8"]:
               values.append(op_value)

           # Unknown opcode in stack - flag as suspicious
           else:
               logger.debug(f"Non-string opcode {op_name} in STACK_GLOBAL analysis")
               values.append("unknown")

           if len(values) == 2:
               break

       return values
   ```

2. **Update suspicious_symbols.py**:

   ```python
   # Add sophisticated pickle patterns
   ADVANCED_PICKLE_PATTERNS = {
       # OS aliases that ModelScan detects but ModelAudit might miss
       "nt": "*",           # Windows os module alias
       "posix": "*",        # Unix os module alias

       # Advanced exploitation patterns
       "operator": ["attrgetter"],  # Attribute access bypass
       "pty": "*",          # Pseudo-terminal spawning
       "bdb": "*",          # Python debugger access
       "asyncio": "*",      # Asynchronous execution
       "_pickle": "*",      # Low-level pickle module

       # Memo-based attacks
       "types": ["CodeType", "FunctionType"],  # Code object construction
   }
   ```

### Test Assets Required

Create sophisticated pickle test files in `tests/assets/pickles/`:

```python
# tests/assets/generators/generate_advanced_pickle_tests.py
import pickle
import pickletools

def generate_stack_global_attack():
    """Generate pickle that uses STACK_GLOBAL to obfuscate os.system"""
    class StackGlobalAttack:
        def __reduce__(self):
            # This will generate STACK_GLOBAL opcodes
            return (getattr, (__import__('os'), 'system')), ('echo pwned',)

    with open('tests/assets/pickles/stack_global_attack.pkl', 'wb') as f:
        pickle.dump(StackGlobalAttack(), f)

def generate_memo_based_attack():
    """Generate pickle that uses memo objects to hide malicious references"""
    class MemoAttack:
        def __reduce__(self):
            dangerous_module = __import__('subprocess')
            # Force memo storage
            return (dangerous_module.call, (['echo', 'memo_attack'],))

    with open('tests/assets/pickles/memo_attack.pkl', 'wb') as f:
        pickle.dump(MemoAttack(), f)

def generate_multiple_pickle_attack():
    """Generate file with multiple pickle streams"""
    import io

    buffer = io.BytesIO()

    # First pickle - appears safe
    safe_data = {'model': 'safe_weights'}
    pickle.dump(safe_data, buffer)

    # Second pickle - malicious
    class HiddenAttack:
        def __reduce__(self):
            return (eval, ("__import__('os').system('hidden_attack')",))

    pickle.dump(HiddenAttack(), buffer)

    with open('tests/assets/pickles/multiple_stream_attack.pkl', 'wb') as f:
        f.write(buffer.getvalue())
```

### Validation Steps

1. **Unit Tests** (`tests/test_pickle_advanced.py`):

   ```python
   def test_stack_global_detection():
       scanner = PickleScanner()
       result = scanner.scan("tests/assets/pickles/stack_global_attack.pkl")

       # Should detect the obfuscated os.system reference
       assert len(result.issues) > 0
       os_issues = [i for i in result.issues if "os" in i.message.lower()]
       assert len(os_issues) > 0

   def test_memo_object_tracking():
       scanner = PickleScanner()
       result = scanner.scan("tests/assets/pickles/memo_attack.pkl")

       # Should detect subprocess even when accessed via memo
       assert len(result.issues) > 0
       subprocess_issues = [i for i in result.issues if "subprocess" in i.message.lower()]
       assert len(subprocess_issues) > 0

   def test_multiple_pickle_streams():
       scanner = PickleScanner()
       result = scanner.scan("tests/assets/pickles/multiple_stream_attack.pkl")

       # Should find the malicious second pickle
       assert len(result.issues) > 0
       eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
       assert len(eval_issues) > 0
   ```

2. **Integration Tests**:

   ```bash
   # Test against ModelScan's test cases if available
   rye run pytest tests/test_pickle_advanced.py -v

   # Performance test - should handle large pickle files
   rye run modelaudit tests/assets/pickles/large_pickle_with_multiple_streams.pkl --timeout 30
   ```

### Acceptance Criteria

- [ ] Detects STACK_GLOBAL-based attacks that simple pattern matching misses
- [ ] Properly tracks memo objects across pickle operations
- [ ] Supports multiple pickle streams in single file
- [ ] Maintains performance on large pickle files
- [ ] Comprehensive test coverage including edge cases
- [ ] No regression in existing pickle detection capability

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

## Task 5: Implement Multiple Pickle Stream Support

**Priority**: P2 - Security Enhancement
**Estimated Effort**: 2-3 days
**Dependencies**: Task 2 (Enhanced Pickle Scanner)

### Objective

Enable scanning of files containing multiple pickle objects, which attackers use to hide malicious payloads after legitimate data.

### Files to Modify

- `modelaudit/scanners/pickle_scanner.py` - Extend pickle scanning logic
- `tests/test_pickle_multiple_streams.py` - New comprehensive tests

### Implementation Details

1. **Enhance Pickle Scanner** (extend Task 2 implementation):

   ```python
   def _scan_multiple_pickle_streams(self, file_path: str) -> List[ScanResult]:
       """Scan file for multiple pickle streams"""
       results = []

       with open(file_path, 'rb') as f:
           stream_number = 0

           while True:
               try:
                   # Record current position
                   start_pos = f.tell()

                   # Try to load next pickle object
                   data = pickle.load(f)
                   end_pos = f.tell()

                   # Create sub-result for this stream
                   stream_result = self._create_result()
                   stream_result.metadata['stream_number'] = stream_number
                   stream_result.metadata['stream_range'] = (start_pos, end_pos)

                   # Analyze this specific pickle stream
                   f.seek(start_pos)
                   stream_data = f.read(end_pos - start_pos)
                   stream_issues = self._analyze_pickle_stream(io.BytesIO(stream_data))

                   for issue in stream_issues:
                       issue.location = f"{file_path}:stream_{stream_number}"

                   stream_result.issues.extend(stream_issues)
                   results.append(stream_result)

                   stream_number += 1

               except EOFError:
                   # End of file reached
                   break
               except Exception as e:
                   logger.debug(f"Error reading pickle stream {stream_number}: {e}")
                   break

       return results
   ```

### Test Assets Required

Generate test files with multiple pickle streams:

```python
# tests/assets/generators/generate_multiple_stream_tests.py
def generate_hidden_malicious_stream():
    """Safe pickle followed by malicious pickle"""
    buffer = io.BytesIO()

    # Stream 1: Legitimate model data
    legitimate_data = {
        'model_weights': [1.0, 2.0, 3.0],
        'metadata': {'version': '1.0', 'author': 'legitimate_user'}
    }
    pickle.dump(legitimate_data, buffer)

    # Stream 2: Hidden malicious payload
    class HiddenMalware:
        def __reduce__(self):
            return (exec, ("import os; os.system('hidden_payload')",))

    pickle.dump(HiddenMalware(), buffer)

    # Stream 3: More legitimate-looking data
    more_data = {'config': {'batch_size': 32}}
    pickle.dump(more_data, buffer)

    with open('tests/assets/pickles/hidden_multiple_stream.pkl', 'wb') as f:
        f.write(buffer.getvalue())
```

### Validation Steps

```python
def test_multiple_stream_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/hidden_multiple_stream.pkl")

    # Should detect the malicious stream even when mixed with legitimate data
    assert len(result.issues) > 0
    exec_issues = [i for i in result.issues if "exec" in i.message.lower()]
    assert len(exec_issues) > 0

    # Should identify which stream contains the issue
    assert "stream_1" in exec_issues[0].location

def test_stream_isolation():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/mixed_streams.pkl")

    # Each stream should be analyzed independently
    stream_results = [i for i in result.issues if "stream_" in i.location]
    assert len(stream_results) > 0
```

### Acceptance Criteria

- [ ] Detects malicious content in any pickle stream within a file
- [ ] Provides clear location information (stream number)
- [ ] Handles files with dozens of pickle streams efficiently
- [ ] No false negatives when malicious content is in later streams
- [ ] Graceful handling of corrupted pickle streams

---

## Task 6: Add OS Alias Detection (Windows/Unix)

**Priority**: P2 - Security Enhancement  
**Estimated Effort**: 1-2 days
**Dependencies**: Task 3 (Severity System)

### Objective

Detect Windows (`nt`) and Unix (`posix`) OS module aliases that attackers use to evade basic `os` module detection.

### Files to Modify

- `modelaudit/suspicious_symbols.py` - Add OS alias patterns
- `tests/test_os_alias_detection.py` - Comprehensive tests

### Implementation Details

1. **Update Suspicious Symbols**:

   ```python
   # Add to SUSPICIOUS_GLOBALS
   OS_MODULE_ALIASES = {
       # Windows OS module aliases
       "nt": {
           "severity": "CRITICAL",
           "description": "Windows OS module alias - provides system access including os.system()",
           "functions": "*"  # All functions are dangerous
       },

       # Unix/Linux OS module aliases
       "posix": {
           "severity": "CRITICAL",
           "description": "Unix/Linux OS module alias - provides system access including os.system()",
           "functions": "*"
       },

       # Platform-specific dangerous functions
       "ntpath": {
           "severity": "HIGH",
           "description": "Windows path manipulation - can access restricted paths",
           "functions": "*"
       },

       "posixpath": {
           "severity": "HIGH",
           "description": "Unix path manipulation - can access restricted paths",
           "functions": "*"
       }
   }
   ```

### Test Assets Required

```python
# tests/assets/generators/generate_os_alias_tests.py
def generate_nt_alias_attack():
    """Generate pickle using nt module (Windows os alias)"""
    class NTAttack:
        def __reduce__(self):
            # Use nt instead of os to evade detection
            return (__import__('nt').system, ('calc.exe',))

    with open('tests/assets/pickles/nt_alias_attack.pkl', 'wb') as f:
        pickle.dump(NTAttack(), f)

def generate_posix_alias_attack():
    """Generate pickle using posix module (Unix os alias)"""
    class PosixAttack:
        def __reduce__(self):
            # Use posix instead of os to evade detection
            return (__import__('posix').system, ('/bin/sh -c "echo pwned"',))

    with open('tests/assets/pickles/posix_alias_attack.pkl', 'wb') as f:
        pickle.dump(PosixAttack(), f)
```

### Validation Steps

```python
def test_nt_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/nt_alias_attack.pkl")

    assert len(result.issues) > 0
    nt_issues = [i for i in result.issues if "nt" in i.message.lower()]
    assert len(nt_issues) > 0
    assert nt_issues[0].severity == IssueSeverity.CRITICAL

def test_posix_alias_detection():
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/pickles/posix_alias_attack.pkl")

    assert len(result.issues) > 0
    posix_issues = [i for i in result.issues if "posix" in i.message.lower()]
    assert len(posix_issues) > 0
    assert posix_issues[0].severity == IssueSeverity.CRITICAL
```

### Acceptance Criteria

- [ ] Detects `nt` module usage with CRITICAL severity
- [ ] Detects `posix` module usage with CRITICAL severity
- [ ] Provides clear explanation of why these aliases are dangerous
- [ ] Works across all pickle formats and opcode types
- [ ] No performance impact on legitimate pickle scanning

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

## Task 9: Add Direct URL and HuggingFace Scanning Support

**Priority**: P2 - Feature Enhancement  
**Estimated Effort**: 3-4 days
**Dependencies**: None

### Objective

Implement PickleScan's direct URL scanning and HuggingFace model scanning capabilities to enhance ModelAudit's accessibility for scanning remote models.

### Files to Modify

- `modelaudit/utils/` - Add remote scanning utilities
- `modelaudit/utils/remote_scanner.py` - New remote scanning logic
- `modelaudit/cli.py` - Add --url and enhanced --hf flags
- `tests/test_remote_scanning.py` - Remote scanning tests

### Implementation Details

1. **Remote Scanning Utilities** (`modelaudit/utils/remote_scanner.py`):

   ```python
   import http.client
   import urllib.parse
   import json
   from typing import Dict, List, Optional

   class RemoteScanner:
       def __init__(self, timeout: int = 30):
           self.timeout = timeout

       def http_get(self, url: str) -> bytes:
           """HTTP GET with redirect following"""
           parsed_url = urllib.parse.urlparse(url)
           path_and_query = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")

           conn = http.client.HTTPSConnection(parsed_url.netloc, timeout=self.timeout)
           try:
               conn.request("GET", path_and_query)
               response = conn.getresponse()

               if response.status == 302:  # Follow redirects
                   return self.http_get(response.headers["Location"])
               elif response.status >= 400:
                   raise RuntimeError(f"HTTP {response.status} ({response.reason}) calling GET {url}")

               return response.read()
           finally:
               conn.close()

       def scan_huggingface_model(self, repo_id: str) -> List[str]:
           """Get scannable files from HuggingFace model"""
           api_url = f"https://huggingface.co/api/models/{repo_id}"
           model_data = json.loads(self.http_get(api_url).decode('utf-8'))

           scannable_extensions = {
               '.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt',
               '.h5', '.keras', '.pb', '.onnx', '.zip', '.npz'
           }

           file_urls = []
           for sibling in model_data.get("siblings", []):
               filename = sibling.get("rfilename")
               if filename and any(filename.endswith(ext) for ext in scannable_extensions):
                   url = f"https://huggingface.co/{repo_id}/resolve/main/{filename}"
                   file_urls.append(url)

           return file_urls
   ```

2. **Enhanced CLI Support** (`modelaudit/cli.py`):

   ```python
   @click.option(
       "--url",
       type=str,
       help="URL to scan directly (supports HTTP/HTTPS)"
   )
   @click.option(
       "--hf-scan-all",
       is_flag=True,
       help="Scan all compatible files in HuggingFace model (not just pytorch_model.bin)"
   )
   def scan(paths, url, huggingface, hf_scan_all, **kwargs):
       if url:
           # Scan direct URL
           return scan_remote_url(url, **kwargs)
       elif huggingface and hf_scan_all:
           # Scan all files in HuggingFace model
           return scan_huggingface_comprehensive(huggingface, **kwargs)

   def scan_remote_url(url: str, **kwargs):
       """Scan a model from a direct URL"""
       remote_scanner = RemoteScanner()

       with yaspin(text=f"Downloading {url}...") as spinner:
           try:
               data = remote_scanner.http_get(url)
               spinner.text = f"Scanning downloaded content ({len(data)} bytes)..."

               # Create temporary file for scanning
               import tempfile
               with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                   tmp_file.write(data)
                   tmp_file.flush()

                   result = scan_model_directory_or_file(tmp_file.name, **kwargs)

               os.unlink(tmp_file.name)
               return result

           except Exception as e:
               spinner.fail(f"Failed to scan URL: {e}")
               return create_error_result(str(e))

   def scan_huggingface_comprehensive(repo_id: str, **kwargs):
       """Scan all compatible files in a HuggingFace model"""
       remote_scanner = RemoteScanner()

       with yaspin(text=f"Discovering files in {repo_id}...") as spinner:
           try:
               file_urls = remote_scanner.scan_huggingface_model(repo_id)
               spinner.text = f"Found {len(file_urls)} scannable files"

               combined_result = create_initial_audit_result()

               for i, file_url in enumerate(file_urls):
                   spinner.text = f"Scanning {os.path.basename(file_url)} ({i+1}/{len(file_urls)})"
                   file_result = scan_remote_url(file_url, **kwargs)
                   # Merge results
                   combined_result.issues.extend(file_result.issues)
                   combined_result.files_scanned += file_result.files_scanned

               return combined_result

           except Exception as e:
               spinner.fail(f"Failed to scan HuggingFace model: {e}")
               return create_error_result(str(e))
   ```

### Test Implementation

```python
def test_direct_url_scanning():
    """Test scanning model from direct URL"""
    # Mock HTTP response with malicious pickle
    with patch('http.client.HTTPSConnection') as mock_conn:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = create_malicious_pickle_bytes()
        mock_conn.return_value.__enter__.return_value.getresponse.return_value = mock_response

        result = runner.invoke(cli, ['--url', 'https://example.com/model.pkl'])
        assert result.exit_code == 1  # Should detect malicious content
        assert "eval" in result.output.lower()

def test_huggingface_comprehensive_scan():
    """Test comprehensive HuggingFace model scanning"""
    with patch('modelaudit.utils.remote_scanner.RemoteScanner.scan_huggingface_model') as mock_hf:
        mock_hf.return_value = ['https://hf.co/model/pytorch_model.bin', 'https://hf.co/model/config.json']

        result = runner.invoke(cli, ['--hf', 'test/model', '--hf-scan-all'])
        assert result.exit_code == 0
        assert "Found 2 scannable files" in result.output
```

### Acceptance Criteria

- [ ] Direct URL scanning with HTTP/HTTPS support
- [ ] Comprehensive HuggingFace model scanning (all compatible files)
- [ ] Progress indicators for remote downloads
- [ ] Proper error handling for network failures
- [ ] Timeout configuration for remote requests
- [ ] Support for redirects and common HTTP status codes

---

## Task 10: Implement Magic Byte and File Format Detection

**Priority**: P3 - Robustness Enhancement
**Estimated Effort**: 2-3 days
**Dependencies**: None

### Objective

Add PickleScan's magic byte detection for more reliable file format identification, reducing reliance on file extensions and improving detection of disguised malicious files.

### Files to Modify

- `modelaudit/utils/filetype.py` - Enhanced magic byte detection
- `modelaudit/scanners/pickle_scanner.py` - Use magic byte detection
- `tests/test_magic_byte_detection.py` - Magic byte tests

### Implementation Details

1. **Enhanced Magic Byte Detection** (`modelaudit/utils/filetype.py`):

   ```python
   # From PickleScan analysis - comprehensive magic byte patterns
   PICKLE_MAGIC_BYTES = {
       b"\x80\x00",  # Pickle protocol 0
       b"\x80\x01",  # Pickle protocol 1
       b"\x80\x02",  # Pickle protocol 2
       b"\x80\x03",  # Pickle protocol 3
       b"\x80\x04",  # Pickle protocol 4
       b"\x80\x05",  # Pickle protocol 5
   }

   NUMPY_MAGIC_BYTES = b"\x93NUMPY"
   PYTORCH_MAGIC_NUMBER = 0x1950a86a20f9469cfc6c
   ZIP_MAGIC_BYTES = {b"PK\x03\x04", b"PK\x05\x06"}  # ZIP file signatures

   def detect_file_format_by_magic(file_path: str) -> Optional[str]:
       """Detect file format using magic bytes, not just extension"""
       try:
           with open(file_path, 'rb') as f:
               # Read enough bytes for magic number detection
               header = f.read(32)

               # Check pickle magic bytes (protocol 2+)
               if any(header.startswith(magic) for magic in PICKLE_MAGIC_BYTES):
                   return "pickle"

               # Check NumPy magic
               if header.startswith(NUMPY_MAGIC_BYTES):
                   return "numpy"

               # Check ZIP magic (for PyTorch ZIP format)
               if any(header.startswith(magic) for magic in ZIP_MAGIC_BYTES):
                   return "zip"

               # Check PyTorch magic number (old format)
               if len(header) >= 8:
                   try:
                       import struct
                       magic_num = struct.unpack('<Q', header[:8])[0]
                       if magic_num == PYTORCH_MAGIC_NUMBER:
                           return "pytorch_legacy"
                   except struct.error:
                       pass

               return None

       except (IOError, OSError):
           return None

   def should_scan_file(file_path: str) -> Tuple[bool, Optional[str]]:
       """Determine if file should be scanned and what format it is"""
       # First try magic byte detection
       magic_format = detect_file_format_by_magic(file_path)
       if magic_format:
           return True, magic_format

       # Fallback to extension-based detection
       ext = os.path.splitext(file_path)[1].lower()
       extension_formats = {
           '.pkl': 'pickle', '.pickle': 'pickle', '.dill': 'pickle',
           '.pt': 'pytorch', '.pth': 'pytorch', '.bin': 'pytorch',
           '.npy': 'numpy', '.npz': 'numpy',
           '.h5': 'keras', '.keras': 'keras',
           '.pb': 'tensorflow',
           '.zip': 'zip', '.tar': 'tar'
       }

       if ext in extension_formats:
           return True, extension_formats[ext]

       return False, None
   ```

2. **Integration with Pickle Scanner**:

   ```python
   def can_handle(cls, path: str) -> bool:
       """Enhanced file detection using magic bytes"""
       should_scan, file_format = should_scan_file(path)
       return should_scan and file_format in ['pickle', 'pytorch', 'numpy']

   def scan(self, path: str) -> ScanResult:
       """Scan with format-aware detection"""
       should_scan, detected_format = should_scan_file(path)

       if not should_scan:
           result = self._create_result()
           result.add_check(
               name="File Format Detection",
               passed=False,
               message=f"File format not recognized for scanning: {path}",
               severity=IssueSeverity.INFO
           )
           return result

       # Use detected format to guide scanning approach
       if detected_format == 'pickle':
           return self._scan_pickle_format(path)
       elif detected_format == 'pytorch':
           return self._scan_pytorch_format(path)
       # ... etc
   ```

### Test Assets Required

```python
# tests/assets/generators/generate_disguised_files.py
def generate_disguised_pickle():
    """Create malicious pickle with wrong extension"""
    class MaliciousPayload:
        def __reduce__(self):
            return (eval, ("__import__('os').system('echo disguised')",))

    # Save as .txt file but it's actually a pickle
    with open('tests/assets/disguised/malicious.txt', 'wb') as f:
        pickle.dump(MaliciousPayload(), f, protocol=4)

def generate_pickle_without_magic():
    """Create pickle using protocol 0 (no magic bytes)"""
    class OldProtocolAttack:
        def __reduce__(self):
            return (eval, ("print('old_protocol_attack')",))

    with open('tests/assets/pickles/old_protocol.pkl', 'wb') as f:
        pickle.dump(OldProtocolAttack(), f, protocol=0)
```

### Validation Steps

```python
def test_magic_byte_detection():
    """Test magic byte detection overrides extension"""
    # Pickle file with wrong extension should still be detected
    should_scan, format_type = should_scan_file("tests/assets/disguised/malicious.txt")
    assert should_scan == True
    assert format_type == "pickle"

def test_disguised_file_scanning():
    """Test scanning of disguised malicious files"""
    scanner = PickleScanner()
    result = scanner.scan("tests/assets/disguised/malicious.txt")

    # Should detect malicious content despite .txt extension
    assert len(result.issues) > 0
    eval_issues = [i for i in result.issues if "eval" in i.message.lower()]
    assert len(eval_issues) > 0
```

### Acceptance Criteria

- [ ] Magic byte detection for all supported formats
- [ ] Accurate detection regardless of file extension
- [ ] Fallback to extension-based detection when magic bytes unavailable
- [ ] Detection of disguised malicious files (wrong extensions)
- [ ] Support for both old and new pickle protocols
- [ ] Performance optimization - magic byte reading should be fast

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
