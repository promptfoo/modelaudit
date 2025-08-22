# Jinja2 Template Injection Scanner Implementation Plan

## Executive Summary

This plan outlines the implementation of a comprehensive Jinja2 template injection scanner for ModelAudit to detect Server-Side Template Injection (SSTI) vulnerabilities in ML model files. The scanner will target multiple file formats and attack vectors discovered in recent security research.

## Background and Motivation

### Known Vulnerabilities

- **CVE-2024-34359 ("Llama Drama")**: Critical SSTI vulnerability in llama-cpp-python < 0.2.72 affecting GGUF models
- **HuggingFace Platform Risks**: 100+ malicious models discovered with code execution capabilities
- **Template Injection Scope**: 6,000+ GGUF models with chat templates, 40% of 116,000 analyzed models contain templates

### Security Impact

- **Remote Code Execution**: Direct system command execution via template injection
- **Data Exfiltration**: Access to file system and environment variables
- **Supply Chain Attacks**: Compromised models in public repositories
- **Silent Failures**: Template injection often executes without obvious indicators

## Scope and Target Files

### Primary Targets

1. **GGUF Models**: `.gguf` files with `tokenizer.chat_template` metadata
2. **HuggingFace Tokenizers**: `tokenizer_config.json` files with `chat_template` field
3. **Standalone Templates**: `.jinja`, `.j2`, `.template` files in ML contexts
4. **Configuration Files**: JSON/YAML files containing Jinja2 template strings

### File Extensions to Scan

- `.gguf` (GGUF model format)
- `.json` (tokenizer_config.json, config.json with chat_template)
- `.yaml/.yml` (configuration files with templates)
- `.jinja/.j2/.template` (standalone template files)

## Attack Vector Analysis

### 1. Object Traversal Attacks

**Technique**: Accessing Python object hierarchy to reach dangerous functions

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ config.__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].exit() }}
```

**Detection Patterns**:

- `__class__`, `__mro__`, `__base__`, `__bases__`
- `__subclasses__()`, `__globals__`, `__builtins__`
- Index access patterns: `[0]`, `[1]`, `[104]`, etc.

### 2. Direct Function Access

**Technique**: Accessing dangerous functions through global scope

```jinja2
{{ self.__init__.__globals__['__builtins__']['eval']('__import__("os").system("rm -rf /")') }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

**Detection Patterns**:

- `__init__.__globals__`
- `__builtins__['eval']`, `__builtins__['exec']`
- `os.system`, `os.popen`, `subprocess`

### 3. Request/Config Object Exploitation

**Technique**: Leveraging framework-specific objects

```jinja2
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.items() }}
```

**Detection Patterns**:

- `request.application`, `config.items()`
- Framework-specific object names

### 4. Loop-Based Exploitation

**Technique**: Using Jinja2 control structures to iterate and find exploitable classes

```jinja2
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen("ls").read() }}
  {% endif %}
{% endfor %}
```

**Detection Patterns**:

- `{% for ... in ... %}` with object traversal
- Conditional checks on class names
- Nested template execution

### 5. WAF Bypass Techniques

**Technique**: Obfuscation to evade basic filters

```jinja2
{{ request['application']['__globals__']['__builtins__']['__import__']('os') }}
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f') }}
```

**Detection Patterns**:

- Hex-encoded strings: `\x5f`, `\x2F`
- Bracket notation: `['__class__']`
- Filter-based access: `|attr()`

### 6. Environment Variable Access

**Technique**: Extracting sensitive configuration data

```jinja2
{{ self.environment.globals['__builtins__']['__import__']('os').environ }}
```

**Detection Patterns**:

- `environment.globals`
- `os.environ`, `sys.modules`

## Detection Pattern Categories

### Critical Risk Patterns (Auto-flag)

```python
CRITICAL_PATTERNS = {
    # Direct code execution
    "code_execution": [
        r"__import__\s*\(",
        r"eval\s*\(",
        r"exec\s*\(",
        r"os\.system",
        r"os\.popen",
        r"subprocess\.",
        r"compile\s*\(",
    ],

    # Object traversal chains
    "object_traversal": [
        r"__class__\.__mro__",
        r"__class__\.__base__",
        r"__class__\.__bases__",
        r"__subclasses__\(\)",
        r"__globals__\[",
        r"__builtins__\[",
    ],

    # Global access patterns
    "global_access": [
        r"__init__\.__globals__",
        r"self\.__init__\.__globals__",
        r"\.environment\.globals",
        r"request\.application\.__globals__",
    ],
}
```

### High Risk Patterns (Flag with context)

```python
HIGH_RISK_PATTERNS = {
    # Framework objects
    "framework_objects": [
        r"\brequest\b",
        r"\bconfig\b",
        r"\bcycler\b",
        r"\bjoiner\b",
        r"\bnamespace\b",
    ],

    # File operations
    "file_operations": [
        r"\.read\(\)",
        r"\.write\(",
        r"open\s*\(",
        r"file\s*\(",
    ],

    # System access
    "system_access": [
        r"sys\.",
        r"os\.",
        r"platform\.",
        r"socket\.",
    ],
}
```

### WAF Bypass Patterns

```python
BYPASS_PATTERNS = {
    "obfuscation": [
        r"\\x[0-9a-fA-F]{2}",  # Hex encoding
        r"\[['\"]\w+['\"]\]",   # Bracket notation
        r"\|attr\(",            # Filter-based access
        r"chr\(\d+\)",          # Character construction
        r"['\"]\.join\(",       # String joining
    ],

    "control_flow": [
        r"{% for .+ in .+__subclasses__",
        r"{% if .+ in .+__name__",
        r"{% set .+ = ",
    ],
}
```

## Implementation Architecture

### 1. Scanner Class Structure

```python
class Jinja2TemplateScanner(BaseScanner):
    name = "jinja2_template"
    description = "Scans for Jinja2 template injection vulnerabilities in ML models"
    supported_extensions = [".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"]
    priority = 15  # High priority for security scanner
```

### 2. File Type Handlers

#### GGUF Handler

```python
def _scan_gguf_file(self, path: str) -> List[Issue]:
    """Extract and analyze chat_template from GGUF metadata"""
    # Use gguf library to extract metadata
    # Check tokenizer.chat_template field
    # Analyze template content for SSTI patterns
```

#### JSON Handler

```python
def _scan_json_file(self, path: str) -> List[Issue]:
    """Analyze tokenizer_config.json and similar files"""
    # Parse JSON safely
    # Check chat_template, custom_chat_template fields
    # Analyze any string values that look like templates
```

#### Template Handler

```python
def _scan_template_file(self, path: str) -> List[Issue]:
    """Analyze standalone template files"""
    # Read raw template content
    # Apply all SSTI detection patterns
    # Check for ML-specific context indicators
```

### 3. Pattern Analysis Engine

```python
class TemplateAnalyzer:
    def __init__(self):
        self.critical_patterns = self._compile_patterns(CRITICAL_PATTERNS)
        self.high_risk_patterns = self._compile_patterns(HIGH_RISK_PATTERNS)
        self.bypass_patterns = self._compile_patterns(BYPASS_PATTERNS)

    def analyze_template(self, template_str: str, context: dict) -> List[DetectionResult]:
        """Main analysis method combining all detection techniques"""
        results = []

        # 1. Critical pattern detection (immediate flag)
        results.extend(self._check_critical_patterns(template_str))

        # 2. High-risk pattern detection (context-aware)
        results.extend(self._check_high_risk_patterns(template_str, context))

        # 3. Obfuscation detection
        results.extend(self._check_bypass_patterns(template_str))

        # 4. Jinja2 syntax validation with sandboxing test
        results.extend(self._validate_template_safety(template_str))

        return results
```

### 4. Context-Aware Analysis

```python
def _determine_ml_context(self, file_path: str, content: dict) -> MLContext:
    """Determine ML framework and model type for context-aware analysis"""
    context = MLContext()

    # Check file location and name patterns
    if "tokenizer" in file_path.lower():
        context.is_tokenizer = True

    # Check content for ML indicators
    if "model_type" in content:
        context.model_type = content["model_type"]

    if "transformers_version" in content:
        context.framework = "huggingface"

    return context
```

### 5. Sandboxing Test

```python
def _test_template_safety(self, template_str: str) -> bool:
    """Test template execution in sandboxed environment"""
    try:
        from jinja2.sandbox import SandboxedEnvironment
        env = SandboxedEnvironment()
        template = env.from_string(template_str)
        template.render()
        return True
    except jinja2.exceptions.SecurityError:
        return False  # Template contains dangerous operations
    except Exception:
        return True  # Other errors are not security-related
```

## Test Case Development

### 1. Known Vulnerable Templates

```python
# CVE-2024-34359 reproduction
KNOWN_VULNERABLE_TEMPLATES = [
    # Basic RCE payload
    "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c()._module.__builtins__['__import__']('os').system('touch /tmp/retr0reg') }}{% endif %}{% endfor %}",

    # File read payload
    "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",

    # Environment variable access
    "{{ self.__init__.__globals__['__builtins__']['__import__']('os').environ }}",

    # Subprocess execution
    "{{ config.__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['subprocess'].call(['whoami']) }}",
]
```

### 2. Benign Template Examples

```python
# Legitimate HuggingFace chat templates
BENIGN_TEMPLATES = [
    # Standard chat template
    "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}",

    # Conditional formatting
    "{% if messages[0]['role'] == 'system' %}{{ messages[0]['content'] }}\n{% endif %}",

    # Loop with safe operations
    "{% for message in messages %}{% if message['role'] == 'user' %}Human: {{ message['content'] }}{% endif %}{% endfor %}",
]
```

### 3. Edge Cases and Bypasses

```python
# Obfuscated payloads for bypass testing
BYPASS_TEST_CASES = [
    # Hex encoding
    "{{ '\\x5f\\x5fimport\\x5f\\x5f'|attr('__call__')('os').system('id') }}",

    # Bracket notation
    "{{ request['application']['__globals__']['__builtins__']['eval']('1+1') }}",

    # Filter-based access
    "{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}",
]
```

### 4. Test File Generation

```python
def generate_test_files():
    """Generate test files in various formats with known payloads"""

    # Generate GGUF test files (using mock GGUF structure)
    create_test_gguf_files()

    # Generate tokenizer_config.json files
    create_test_tokenizer_configs()

    # Generate standalone template files
    create_test_template_files()
```

## Integration Points

### 1. Scanner Registry Integration

```python
# Add to modelaudit/scanners/__init__.py
"jinja2_template": {
    "module": "modelaudit.scanners.jinja2_template_scanner",
    "class": "Jinja2TemplateScanner",
    "description": "Scans for Jinja2 template injection vulnerabilities",
    "extensions": [".gguf", ".json", ".yaml", ".yml", ".jinja", ".j2", ".template"],
    "priority": 15,
    "dependencies": ["jinja2", "gguf"],  # gguf library for GGUF parsing
    "numpy_sensitive": False,
}
```

### 2. Suspicious Symbols Extension

```python
# Add to modelaudit/suspicious_symbols.py
JINJA2_SSTI_PATTERNS = {
    "critical_injection": [
        "__import__",
        "__class__.__mro__",
        "__subclasses__()",
        "__globals__",
        "__builtins__",
        "os.system",
        "subprocess",
        "eval(",
        "exec(",
    ],
    "object_traversal": [
        "__class__",
        "__base__",
        "__bases__",
        "__init__.__globals__",
        "self.__init__.__globals__",
    ],
    "framework_exploitation": [
        "request.application",
        "config.items()",
        "cycler.__init__",
        "joiner.__init__",
        "namespace.__init__",
    ],
    "obfuscation": [
        "\\x5f",  # Hex-encoded underscore
        "|attr(",  # Filter-based access
        "chr(",    # Character construction
        "['__",   # Bracket notation
    ],
}
```

### 3. CLI Integration

```python
# Update CLI help text and options
@click.option(
    '--check-jinja2-templates',
    is_flag=True,
    default=True,
    help='Enable Jinja2 template injection scanning (default: enabled)'
)
```

## Validation and Testing Strategy

### 1. Unit Tests

- Pattern detection accuracy tests
- False positive reduction tests
- File format parsing tests
- Context-aware analysis tests

### 2. Integration Tests

- End-to-end scanning of test files
- CLI integration tests
- Error handling tests
- Performance tests with large files

### 3. Security Validation

- Test against known CVE-2024-34359 payloads
- Verify detection of obfuscated payloads
- Confirm benign template handling
- Test bypass technique detection

### 4. Performance Benchmarks

- Scanning speed for large GGUF files
- Memory usage with template analysis
- Pattern matching efficiency
- Comparison with existing scanners

## Success Metrics

### Detection Effectiveness

- **100% detection** of known CVE-2024-34359 payloads
- **95%+ detection** of SSTI payload variations
- **<5% false positive rate** on benign ML templates
- **Coverage of 15+ distinct attack vectors**

### Performance Targets

- **<10 seconds** to scan typical GGUF model files
- **<1 second** for tokenizer_config.json files
- **<100MB memory usage** for large model scanning
- **Minimal impact** on existing scan performance

### Integration Success

- **Zero breaking changes** to existing ModelAudit functionality
- **Seamless CLI integration** with existing options
- **Clear, actionable output** for detected vulnerabilities
- **Comprehensive documentation** and examples

## Risk Assessment and Mitigation

### False Positive Risks

- **Risk**: Flagging legitimate ML template patterns as malicious
- **Mitigation**: Context-aware analysis, ML framework detection, extensive benign template testing

### Performance Risks

- **Risk**: Slow scanning of large GGUF files with complex templates
- **Mitigation**: Streaming analysis, pattern optimization, configurable timeout limits

### Dependency Risks

- **Risk**: New dependencies (jinja2, gguf) causing installation issues
- **Mitigation**: Optional dependencies with graceful fallback, clear installation instructions

### Security Risks

- **Risk**: Scanner itself vulnerable to malicious templates during analysis
- **Mitigation**: Sandboxed template testing, safe parsing, no template execution

## Timeline and Milestones

### Phase 1: Core Implementation (Week 1)

- [ ] Implement base scanner class and file handlers
- [ ] Develop pattern detection engine
- [ ] Create context-aware analysis system
- [ ] Build test framework foundation

### Phase 2: Pattern Development (Week 2)

- [ ] Research and implement all SSTI attack vectors
- [ ] Develop comprehensive detection patterns
- [ ] Implement bypass detection techniques
- [ ] Create sandboxing test framework

### Phase 3: Integration and Testing (Week 3)

- [ ] Integrate with ModelAudit scanner registry
- [ ] Implement CLI options and help text
- [ ] Develop comprehensive test suites
- [ ] Performance optimization and benchmarking

### Phase 4: Validation and Documentation (Week 4)

- [ ] Security validation against known vulnerabilities
- [ ] False positive reduction and tuning
- [ ] Documentation and usage examples
- [ ] Final integration testing

## Conclusion

This implementation plan provides a comprehensive approach to detecting Jinja2 template injection vulnerabilities in ML models. The scanner will address a critical security gap in the ML ecosystem, providing both security researchers and practitioners with tools to identify and mitigate template injection risks.

The combination of pattern-based detection, context-aware analysis, and comprehensive test coverage will ensure high detection rates while minimizing false positives, making this scanner both effective and practical for real-world use.
