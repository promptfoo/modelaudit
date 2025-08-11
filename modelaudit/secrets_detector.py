"""
Embedded Secrets Detection for ML Models
=========================================

Detects API keys, passwords, tokens, and other sensitive data embedded in model weights.
Part of ModelAudit's critical security validation suite.
"""

import math
import re
from typing import Any, Dict, List, Optional, Tuple

# High-priority secret patterns with descriptions
SECRET_PATTERNS: List[Tuple[str, str]] = [
    # API Keys
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"sk-proj-[a-zA-Z0-9]{48}", "OpenAI Project Key"),
    (r"aws_access_key_id\s*=\s*['\"]?([A-Z0-9]{20})['\"]?", "AWS Access Key ID"),
    (r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "AWS Secret Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Token"),
    (r"ghs_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-grained PAT"),
    (r"glpat-[a-zA-Z0-9\-_]{20}", "GitLab Personal Token"),
    (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square Access Token"),
    (r"sq0csp-[0-9A-Za-z\-_]{43}", "Square Secret"),
    (r"stripe_live_[a-zA-Z0-9]{24}", "Stripe Live Key"),
    (r"sk_live_[a-zA-Z0-9]{24}", "Stripe Secret Key"),
    (r"rk_live_[a-zA-Z0-9]{24}", "Stripe Restricted Key"),
    
    # Cloud Provider Keys
    (r"AZURE_[A-Z_]+_KEY\s*=\s*['\"]?([a-zA-Z0-9+/]{40,}={0,2})['\"]?", "Azure Key"),
    (r"AZ[a-zA-Z0-9]{34}", "Azure Client Secret"),
    (r"gcp_api_key\s*=\s*['\"]?([a-zA-Z0-9\-_]{39})['\"]?", "GCP API Key"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "SSH Private Key"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
    (r"-----BEGIN DSA PRIVATE KEY-----", "DSA Private Key"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key"),
    
    # Database Connection Strings
    (r"mongodb\+srv://[^:]+:[^@]+@[^/\s]+", "MongoDB Connection String"),
    (r"postgres://[^:]+:[^@]+@[^/\s]+", "PostgreSQL Connection String"),
    (r"mysql://[^:]+:[^@]+@[^/\s]+", "MySQL Connection String"),
    (r"redis://[^:]+:[^@]+@[^/\s]+", "Redis Connection String"),
    (r"amqp://[^:]+:[^@]+@[^/\s]+", "RabbitMQ Connection String"),
    
    # Tokens and Secrets
    (r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "JWT Token"),
    (r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer Token"),
    (r"Basic\s+[a-zA-Z0-9]+=*", "Basic Auth Credentials"),
    (r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", "UUID (potential secret)"),
    
    # Passwords and Auth  
    (r"password\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", "Hardcoded Password"),
    (r"passwd\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", "Hardcoded Password"),
    (r"pwd\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", "Hardcoded Password"),
    (r"secret\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", "Hardcoded Secret"),
    (r"api[_-]?key\s*[:=]\s*['\"]?([^'\"\s]{16,})['\"]?", "API Key"),
    (r"auth[_-]?token\s*[:=]\s*['\"]?([^'\"\s]{16,})['\"]?", "Auth Token"),
    (r"client[_-]?secret\s*[:=]\s*['\"]?([^'\"\s]{16,})['\"]?", "Client Secret"),
    (r"OPENAI_API_KEY\s*=\s*['\"]?(sk-[a-zA-Z0-9]{48})['\"]?", "OpenAI API Key"),
    
    # Slack/Discord/Telegram
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}", "Slack Token"),
    (r"slack://[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{8,}/[a-zA-Z0-9]{24}", "Slack Webhook"),
    (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", "Slack Webhook URL"),
    (r"[0-9]{17,19}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}", "Discord Bot Token"),
    (r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}", "Telegram Bot Token"),
    
    # Cryptocurrency
    (r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", "Bitcoin Address"),
    (r"0x[a-fA-F0-9]{40}", "Ethereum Address"),
    (r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}", "Litecoin Address"),
    (r"seed\s+phrase[:=]\s*['\"]([a-z\s]{20,})['\"]", "Crypto Seed Phrase"),
    
    # Other Services
    (r"twilio_[a-zA-Z_]+\s*=\s*['\"]?([a-zA-Z0-9]{32})['\"]?", "Twilio Key"),
    (r"sendgrid_api_key\s*=\s*['\"]?(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})['\"]?", "SendGrid API Key"),
    (r"mailgun_api_key\s*=\s*['\"]?(key-[a-f0-9]{32})['\"]?", "Mailgun API Key"),
    (r"npm_[a-zA-Z0-9]{36}", "NPM Token"),
    (r"rg_[a-zA-Z0-9]{32}", "Rollbar Token"),
    (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square OAuth Token"),
]


class SecretsDetector:
    """Detects embedded secrets, API keys, and credentials in model data."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the secrets detector with optional configuration.
        
        Args:
            config: Optional configuration dictionary with settings like:
                - min_entropy: Minimum entropy threshold for high-entropy detection (default: 4.5)
                - max_entropy: Maximum entropy threshold for flagging (default: 7.5)
                - patterns: Additional regex patterns to check
                - whitelist: Patterns to exclude from detection
        """
        self.config = config or {}
        self.min_entropy = self.config.get("min_entropy", 4.5)
        self.max_entropy = self.config.get("max_entropy", 7.5)
        
        # Combine default patterns with any custom patterns
        self.patterns = SECRET_PATTERNS.copy()
        if "patterns" in self.config:
            self.patterns.extend(self.config["patterns"])
        
        # Whitelist patterns that should be ignored
        self.whitelist = self.config.get("whitelist", [])
        
        # Compiled regex patterns for efficiency
        self._compiled_patterns = [(re.compile(pattern, re.IGNORECASE), desc) for pattern, desc in self.patterns]
        self._compiled_whitelist = [re.compile(pattern, re.IGNORECASE) for pattern in self.whitelist]
    
    @staticmethod
    def calculate_shannon_entropy(data: bytes, window_size: int = 64) -> float:
        """Calculate Shannon entropy for a byte sequence.
        
        Shannon entropy measures the randomness in data. High entropy often indicates
        encrypted or encoded secrets.
        
        Args:
            data: Byte sequence to analyze
            window_size: Size of the sliding window for entropy calculation
            
        Returns:
            Float between 0 and 8 representing the entropy in bits
        """
        if len(data) < window_size:
            return 0.0
        
        # Count byte frequencies
        freq = {}
        for byte in data[:window_size]:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / window_size
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _is_whitelisted(self, text: str) -> bool:
        """Check if a detected secret should be whitelisted."""
        for whitelist_pattern in self._compiled_whitelist:
            if whitelist_pattern.search(text):
                return True
        return False
    
    def scan_bytes(self, data: bytes, context: str = "") -> List[Dict[str, Any]]:
        """Scan binary data for embedded secrets.
        
        Args:
            data: Binary data to scan
            context: Context string for better error reporting
            
        Returns:
            List of detected secrets with details
        """
        findings = []
        
        # First, try to detect secrets in decoded text
        try:
            # Try UTF-8 decoding with error handling
            text = data.decode("utf-8", errors="ignore")
            text_findings = self.scan_text(text, context)
            findings.extend(text_findings)
        except Exception:
            pass
        
        # Check for high-entropy regions that might be encrypted/encoded secrets
        window_size = 64
        stride = 32  # Sliding window stride
        
        for i in range(0, len(data) - window_size, stride):
            window = data[i:i + window_size]
            entropy = self.calculate_shannon_entropy(window, window_size)
            
            if entropy > self.max_entropy:
                # Very high entropy - likely encrypted/compressed data
                findings.append({
                    "type": "high_entropy_region",
                    "severity": "WARNING",
                    "position": i,
                    "entropy": round(entropy, 2),
                    "message": f"High entropy region detected (entropy: {entropy:.2f}) - possible encoded secret",
                    "context": f"{context} offset:{i}" if context else f"offset:{i}",
                    "recommendation": "Review this region for base64/hex encoded secrets"
                })
            elif entropy > self.min_entropy:
                # Moderate entropy - might be a secret or just compressed data
                # Try to decode as base64 or hex to check for secrets
                try:
                    # Check if it might be base64
                    import base64
                    decoded = base64.b64decode(window, validate=True)
                    decoded_text = decoded.decode("utf-8", errors="ignore")
                    if len(decoded_text) > 10:
                        # Check decoded content for secrets
                        decoded_findings = self.scan_text(decoded_text, f"{context} (base64 decoded)")
                        if decoded_findings:
                            findings.extend(decoded_findings)
                except Exception:
                    pass
        
        return findings
    
    def scan_text(self, text: str, context: str = "") -> List[Dict[str, Any]]:
        """Scan text content for embedded secrets using regex patterns.
        
        Args:
            text: Text content to scan
            context: Context string for better error reporting
            
        Returns:
            List of detected secrets with details
        """
        findings = []
        
        # Limit text size to prevent DoS
        max_text_size = 10 * 1024 * 1024  # 10MB
        if len(text) > max_text_size:
            text = text[:max_text_size]
        
        for pattern, description in self._compiled_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                secret_text = match.group(0)
                
                # Skip if whitelisted
                if self._is_whitelisted(secret_text):
                    continue
                
                # Redact the secret for safe reporting
                if len(secret_text) > 10:
                    redacted = secret_text[:4] + "***" + secret_text[-4:]
                else:
                    redacted = "***REDACTED***"
                
                findings.append({
                    "type": "embedded_secret",
                    "severity": "CRITICAL",
                    "secret_type": description,
                    "position": match.start(),
                    "length": len(secret_text),
                    "pattern": pattern.pattern[:50] + "..." if len(pattern.pattern) > 50 else pattern.pattern,
                    "redacted_value": redacted,
                    "message": f"{description} detected",
                    "context": f"{context} pos:{match.start()}" if context else f"pos:{match.start()}",
                    "recommendation": f"Remove {description} from model data immediately"
                })
        
        return findings
    
    def scan_dict(self, data: Dict[str, Any], context: str = "") -> List[Dict[str, Any]]:
        """Recursively scan dictionary structures for secrets.
        
        Args:
            data: Dictionary to scan
            context: Context path for error reporting
            
        Returns:
            List of detected secrets
        """
        findings = []
        
        for key, value in data.items():
            key_context = f"{context}/{key}" if context else key
            
            # Check the key itself for secrets
            key_findings = self.scan_text(str(key), f"{key_context}[key]")
            findings.extend(key_findings)
            
            # Check the value
            if isinstance(value, str):
                findings.extend(self.scan_text(value, key_context))
            elif isinstance(value, bytes):
                findings.extend(self.scan_bytes(value, key_context))
            elif isinstance(value, dict):
                findings.extend(self.scan_dict(value, key_context))
            elif isinstance(value, (list, tuple)):
                for i, item in enumerate(value):
                    item_context = f"{key_context}[{i}]"
                    if isinstance(item, str):
                        findings.extend(self.scan_text(item, item_context))
                    elif isinstance(item, bytes):
                        findings.extend(self.scan_bytes(item, item_context))
                    elif isinstance(item, dict):
                        findings.extend(self.scan_dict(item, item_context))
        
        return findings
    
    def scan_model_weights(self, weights: Any, context: str = "weights") -> List[Dict[str, Any]]:
        """Scan model weights for embedded secrets.
        
        This is the main entry point for scanning model weight data.
        
        Args:
            weights: Model weights in various formats (dict, bytes, arrays, etc.)
            context: Context string for reporting
            
        Returns:
            List of detected secrets with full details
        """
        findings = []
        
        if isinstance(weights, dict):
            findings.extend(self.scan_dict(weights, context))
        elif isinstance(weights, bytes):
            findings.extend(self.scan_bytes(weights, context))
        elif isinstance(weights, str):
            findings.extend(self.scan_text(weights, context))
        elif hasattr(weights, "tobytes"):
            # NumPy arrays and similar
            try:
                byte_data = weights.tobytes()
                findings.extend(self.scan_bytes(byte_data, f"{context}[array]"))
            except Exception:
                pass
        elif isinstance(weights, (list, tuple)):
            for i, item in enumerate(weights):
                findings.extend(self.scan_model_weights(item, f"{context}[{i}]"))
        
        return findings


def detect_secrets_in_file(file_path: str, max_size: int = 500 * 1024 * 1024) -> List[Dict[str, Any]]:
    """Convenience function to scan a file for embedded secrets.
    
    Args:
        file_path: Path to the file to scan
        max_size: Maximum file size to scan (default 500MB)
        
    Returns:
        List of detected secrets
    """
    import os
    
    if not os.path.exists(file_path):
        return [{"type": "error", "message": f"File not found: {file_path}"}]
    
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        return [{"type": "error", "message": f"File too large: {file_size} bytes (max: {max_size})"}]
    
    detector = SecretsDetector()
    
    with open(file_path, "rb") as f:
        data = f.read()
    
    return detector.scan_bytes(data, file_path)