"""Security threat detection modules.

This package contains specialized detectors for identifying security threats in model files:
- CVE patterns (known vulnerabilities)
- Secrets (API keys, tokens, credentials)
- JIT/script code (TorchScript, executable code)
- Network communication (URLs, IPs, sockets)
- Suspicious symbols (dangerous function calls)
"""

from modelaudit.detectors import cve_patterns, jit_script, network_comm, secrets, suspicious_symbols

__all__ = [
    "cve_patterns",
    "jit_script",
    "network_comm",
    "secrets",
    "suspicious_symbols",
]
