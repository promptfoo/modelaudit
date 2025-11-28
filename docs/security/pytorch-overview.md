# PyTorch Security Overview

A comprehensive overview of PyTorch security risks and threat vectors affecting ML model deployment.

## Primary Threat Vectors

### 1. **Pickle Deserialization (Critical)**

- PyTorch models use Python's pickle for serialization
- Pickle can execute arbitrary code during loading
- Affects: `.pt`, `.pth`, `.pkl` model files

### 2. **TorchScript Injection (High)**

- JIT-compiled code can contain malicious operations
- Script modules can execute system commands
- Affects: `torch.jit` compiled models

### 3. **Supply Chain Compromise (High)**

- Models from untrusted sources
- Compromised model repositories
- Man-in-the-middle attacks during download

### 4. **Version-Specific Vulnerabilities (Variable)**

- CVE-2025-32434: `weights_only=True` bypass
- Framework bugs and security patches
- Dependency vulnerabilities

## Model Format Security Comparison

| Format                          | Security Level     | Pros                                             | Cons                                      |
| ------------------------------- | ------------------ | ------------------------------------------------ | ----------------------------------------- |
| **SafeTensors**                 | 🟢 **Highest**     | No code execution, fast loading, cross-framework | Newer format, limited ecosystem           |
| **ONNX**                        | 🟡 **Medium-High** | Standardized, some protections                   | Custom operators can be risky             |
| **PyTorch (weights_only=True)** | 🟡 **Medium**      | Built-in, widely supported                       | Still vulnerable to sophisticated attacks |
| **PyTorch (full)**              | 🔴 **Lowest**      | Complete model serialization                     | Arbitrary code execution                  |
| **Pickle Files**                | 🔴 **Lowest**      | Python native                                    | Inherently unsafe                         |

## Migration Priority

1. **Immediate**: Stop using `torch.load()` without `weights_only=True`
2. **Short-term**: Update to PyTorch 2.6.0+
3. **Long-term**: Migrate to SafeTensors format

## Related Security Guides

- [Safe Loading Practices](pytorch-safe-loading.md) - Secure model loading techniques
- [Supply Chain Security](pytorch-supply-chain.md) - Model source validation
- [TorchScript Security](pytorch-torchscript.md) - JIT compilation security
- [ModelAudit Integration](pytorch-integration.md) - Automated security scanning
- [Security Checklist](pytorch-checklist.md) - Complete security checklist

---

For detailed information on specific security aspects, see the individual guides linked above.
