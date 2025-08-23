# TorchScript Security Considerations

Security guidelines for working with PyTorch TorchScript models and JIT compilation.

## TorchScript Security Risks

### 1. Dynamic Code Generation

- JIT compilation can execute arbitrary Python code
- Script modules can contain embedded system calls
- User input can influence code generation

### 2. Hook Injection

- Forward and backward hooks can execute arbitrary code
- Hooks persist with saved models
- Malicious hooks can access global state

### 3. Module Manipulation

- Dynamic attribute injection
- Compilation unit tampering
- Graph manipulation attacks

## Safe TorchScript Practices

### 1. Avoid Dynamic Code Generation

```python
# ✅ SAFE: Static script compilation
class SafeModel(torch.nn.Module):
    def forward(self, x):
        return torch.relu(x)

scripted_model = torch.jit.script(SafeModel())

# ❌ DANGEROUS: Dynamic compilation with user input
def create_dynamic_model(user_code):
    # Never do this - can execute arbitrary code
    return torch.jit.CompilationUnit(user_code)
```

### 2. Validate Script Modules

```python
def validate_script_module(module):
    """Validate TorchScript module for security"""

    # Check for dangerous operations
    dangerous_ops = ['aten::system', 'aten::exec', 'aten::eval']

    graph = module.graph
    for node in graph.nodes():
        if any(op in str(node) for op in dangerous_ops):
            raise ValueError(f"Dangerous operation found: {node}")

    return True
```

### 3. Hook Security

```python
# ❌ DANGEROUS: Arbitrary hook functions
def dangerous_hook(module, input, output):
    exec("malicious code here")  # Never do this

model.register_forward_hook(dangerous_hook)

# ✅ SAFE: Validated hook functions
def safe_logging_hook(module, input, output):
    # Only safe operations
    print(f"Module {type(module)} called with input shape {input[0].shape}")

model.register_forward_hook(safe_logging_hook)
```

## Advanced TorchScript Security

### Graph Analysis

```python
import torch.jit

def analyze_torchscript_graph(scripted_model):
    """Analyze TorchScript graph for security issues"""

    security_issues = []
    graph = scripted_model.graph

    # Check for dangerous operations
    dangerous_patterns = [
        'prim::PythonOp',  # Python operations
        'aten::system',    # System calls
        'aten::exec',      # Code execution
        'prim::CallFunction'  # Dynamic function calls
    ]

    for node in graph.nodes():
        node_str = str(node)
        for pattern in dangerous_patterns:
            if pattern in node_str:
                security_issues.append({
                    'node': node_str,
                    'risk': pattern,
                    'severity': 'HIGH'
                })

    return security_issues
```

### Compilation Unit Validation

```python
def validate_compilation_unit(cu):
    """Validate TorchScript compilation unit"""

    # Get all functions
    functions = [cu.find_function(name) for name in cu.get_functions()]

    for func in functions:
        if func is None:
            continue

        # Check function graph
        graph = func.graph

        # Look for suspicious patterns
        for node in graph.nodes():
            if 'PythonOp' in str(node.kind()):
                raise ValueError(f"Suspicious PythonOp found in function: {func.name}")

    return True
```

### Safe Model Serialization

```python
def safe_torchscript_save(model, path):
    """Safely save TorchScript model with validation"""

    # Script the model
    scripted_model = torch.jit.script(model)

    # Validate before saving
    security_issues = analyze_torchscript_graph(scripted_model)
    if security_issues:
        raise ValueError(f"Security issues found: {security_issues}")

    # Save with metadata
    torch.jit.save(scripted_model, path)

    # Log the operation
    import hashlib
    with open(path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"Saved TorchScript model: {path} (SHA256: {file_hash})")
```

### Safe Model Loading

```python
def safe_torchscript_load(path, validate=True):
    """Safely load TorchScript model with validation"""

    # Load the model
    try:
        model = torch.jit.load(path, map_location='cpu')
    except Exception as e:
        raise ValueError(f"Failed to load TorchScript model: {e}")

    if validate:
        # Validate after loading
        security_issues = analyze_torchscript_graph(model)
        if security_issues:
            raise ValueError(f"Security validation failed: {security_issues}")

    return model
```

## Hook Management

### Hook Registry

```python
class SafeHookRegistry:
    def __init__(self):
        self.approved_hooks = set()
        self.active_hooks = {}

    def register_safe_hook(self, hook_func, hook_name):
        """Register a pre-approved safe hook"""
        # Validate hook is safe (implementation specific)
        if self._validate_hook_safety(hook_func):
            self.approved_hooks.add(hook_name)

    def apply_hook(self, module, hook_name):
        """Apply only approved hooks"""
        if hook_name not in self.approved_hooks:
            raise ValueError(f"Hook {hook_name} not approved for use")

        # Apply the hook
        hook_func = self._get_hook_by_name(hook_name)
        handle = module.register_forward_hook(hook_func)
        self.active_hooks[module] = handle

        return handle

    def _validate_hook_safety(self, hook_func):
        """Validate hook function is safe"""
        # Check source code for dangerous patterns
        import inspect
        source = inspect.getsource(hook_func)

        dangerous_patterns = ['exec(', 'eval(', 'import os', 'subprocess']
        return not any(pattern in source for pattern in dangerous_patterns)
```

### Model Inference Security

```python
def secure_torchscript_inference(model, input_data):
    """Perform secure inference with TorchScript model"""

    # Pre-inference validation
    if hasattr(model, 'graph'):
        security_issues = analyze_torchscript_graph(model)
        if security_issues:
            raise ValueError("Model contains security issues")

    # Input validation
    if not isinstance(input_data, torch.Tensor):
        raise ValueError("Input must be a tensor")

    # Perform inference in try-catch
    try:
        with torch.no_grad():
            output = model(input_data)
        return output
    except Exception as e:
        # Log security-relevant errors
        if any(keyword in str(e).lower() for keyword in ['system', 'exec', 'eval']):
            raise ValueError(f"Security violation during inference: {e}")
        raise e
```

## Best Practices

### Development

1. **Use static compilation** whenever possible
2. **Avoid dynamic code generation** from user input
3. **Validate all hooks** before registration
4. **Analyze graphs** for suspicious operations
5. **Test models** in sandboxed environments

### Production

1. **Pre-validate all TorchScript models** before deployment
2. **Monitor inference** for security violations
3. **Log all model operations** for audit trails
4. **Implement circuit breakers** for suspicious behavior
5. **Regular security scans** of deployed models

### Security Controls

1. **Input validation** for all model inputs
2. **Output sanitization** for model outputs
3. **Resource limits** to prevent DoS attacks
4. **Network isolation** for model serving
5. **Regular updates** of PyTorch framework

## Detection Patterns

### Dangerous Operation Detection

```python
TORCHSCRIPT_SECURITY_PATTERNS = {
    'code_execution': [
        'prim::PythonOp',
        'aten::system',
        'aten::exec',
        'prim::CallFunction'
    ],
    'file_operations': [
        'aten::open',
        'aten::read',
        'aten::write'
    ],
    'network_operations': [
        'aten::socket',
        'aten::connect',
        'aten::send'
    ]
}

def scan_torchscript_security(model):
    """Scan TorchScript model for security issues"""
    issues = []
    graph = model.graph

    for category, patterns in TORCHSCRIPT_SECURITY_PATTERNS.items():
        for node in graph.nodes():
            node_str = str(node.kind())
            for pattern in patterns:
                if pattern in node_str:
                    issues.append({
                        'category': category,
                        'pattern': pattern,
                        'node': str(node),
                        'severity': 'CRITICAL'
                    })

    return issues
```

## Related Guides

- [PyTorch Security Overview](pytorch-overview.md) - Understanding threat vectors
- [Safe Loading Practices](pytorch-safe-loading.md) - Secure loading techniques
- [Security Checklist](pytorch-checklist.md) - Complete security checklist
