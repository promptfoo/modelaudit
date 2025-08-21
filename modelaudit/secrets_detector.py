"""
Embedded Secrets Detection for ML Models
=========================================

Detects API keys, passwords, tokens, and other sensitive data embedded in model weights.
Part of ModelAudit's critical security validation suite.
"""

import math
import re
from typing import Any, Optional

# High-priority secret patterns with descriptions
SECRET_PATTERNS: list[tuple[str, str]] = [
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
    # Cryptocurrency - with word boundaries to avoid false matches
    (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", "Bitcoin Address"),
    (r"\b0x[a-fA-F0-9]{40}\b", "Ethereum Address"),
    (r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b", "Litecoin Address"),
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

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize the secrets detector with optional configuration.

        Args:
            config: Optional configuration dictionary with settings like:
                - min_entropy: Minimum entropy threshold for high-entropy detection (default: 4.5)
                - max_entropy: Maximum entropy threshold for flagging (default: 7.5)
                - patterns: Additional regex patterns to check
                - whitelist: Patterns to exclude from detection
                - min_secret_length: Minimum length for a string to be considered a secret (default: 8)
                - require_high_confidence: Only report high-confidence matches (default: True)
        """
        self.config = config or {}
        self.min_entropy = self.config.get("min_entropy", 4.5)
        self.max_entropy = self.config.get("max_entropy", 7.5)
        self.min_secret_length = self.config.get("min_secret_length", 8)
        self.require_high_confidence = self.config.get("require_high_confidence", True)

        # Combine default patterns with any custom patterns
        self.patterns = SECRET_PATTERNS.copy()
        if "patterns" in self.config:
            self.patterns.extend(self.config["patterns"])

        # Whitelist patterns that should be ignored
        self.whitelist = self.config.get("whitelist", [])

        # Common false positive patterns in ML models
        self.ml_false_positives = [
            r"^[a-f0-9]{32}$",  # MD5 hashes (common in model checksums)
            r"^[a-f0-9]{40}$",  # SHA1 hashes
            r"^[a-f0-9]{64}$",  # SHA256 hashes
            r"^model_[a-z0-9_]+$",  # Model layer names
            r"^layer_[0-9]+$",  # Layer identifiers
            r"^weight_[a-z0-9_]+$",  # Weight names
            r"^bias_[a-z0-9_]+$",  # Bias names
            r"^embedding_[0-9]+$",  # Embedding identifiers
            r"^checkpoint_[0-9]+$",  # Checkpoint names
            r"^[0-9]+\.[0-9]+\.[0-9]+$",  # Version numbers
            r"^v[0-9]+\.[0-9]+\.[0-9]+$",  # Version tags
        ]

        # Compiled regex patterns for efficiency
        self._compiled_patterns = [(re.compile(pattern, re.IGNORECASE), desc) for pattern, desc in self.patterns]
        self._compiled_whitelist = [re.compile(pattern, re.IGNORECASE) for pattern in self.whitelist]
        self._compiled_ml_fps = [re.compile(pattern, re.IGNORECASE) for pattern in self.ml_false_positives]

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
        freq: dict[int, int] = {}
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
        return any(whitelist_pattern.search(text) for whitelist_pattern in self._compiled_whitelist)

    def _is_likely_false_positive(self, text: str, context: str = "") -> bool:
        """Check if a detected secret is likely a false positive in ML context.

        This significantly reduces false positives by checking for common patterns
        in ML models that might match secret patterns but aren't actually secrets.
        """
        # Check against ML-specific false positive patterns
        for fp_pattern in self._compiled_ml_fps:
            if fp_pattern.match(text):
                return True

        # Check if it's in a known ML context (layer names, weights, etc.)
        ml_contexts = [
            "weight",
            "bias",
            "layer",
            "embedding",
            "attention",
            "conv",
            "batch_norm",
            "dropout",
            "activation",
            "pooling",
            "dense",
            "lstm",
            "gru",
            "transformer",
            "encoder",
            "decoder",
        ]
        context_lower = context.lower()
        if any(ml_ctx in context_lower for ml_ctx in ml_contexts):
            # In ML context, be more strict about what we consider a secret
            # Must have high entropy or match very specific patterns
            if len(text) < 20:  # Short strings in ML context are likely parameters
                return True

            # Check if it looks like a parameter value (all numbers, decimals, scientific notation)
            if re.match(r"^[\d\.\-e]+$", text):
                return True

        # Check if it's a common word or phrase (not a secret)
        common_words = [
            "training",
            "validation",
            "testing",
            "model",
            "checkpoint",
            "optimizer",
            "learning_rate",
            "batch_size",
            "epochs",
            "steps",
            "accuracy",
            "loss",
            "metric",
            "score",
            "performance",
        ]
        text_lower = text.lower()
        if text_lower in common_words:
            return True

        # If it's all lowercase or all uppercase letters (likely a constant/config)
        if text.isalpha() and (text.islower() or text.isupper()) and len(text) < 20:
            return True

        # Check for sequences that look like UUIDs but aren't secrets
        # (common in model versioning)
        # This is a UUID - only flag if it's not in a secret-like context
        uuid_pattern = r"^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$"
        secret_contexts = ["key", "token", "secret", "password", "auth"]
        match = re.match(uuid_pattern, text.lower())
        return bool(match and not any(word in context_lower for word in secret_contexts))

    def _calculate_confidence(self, text: str, pattern_desc: str, context: str = "") -> float:
        """Calculate confidence score for a detected secret (0.0 to 1.0).

        Higher confidence means more likely to be a real secret.
        """
        confidence = 0.5  # Base confidence

        # Increase confidence for specific high-value patterns
        high_confidence_patterns = [
            "AWS Access Key",
            "OpenAI API Key",
            "GitHub Personal Token",
            "Private Key",
            "JWT Token",
            "Connection String",
            "Password",
            "Secret",
        ]
        if any(pattern in pattern_desc for pattern in high_confidence_patterns):
            confidence += 0.3

        # Increase confidence if in a secret-like context
        secret_contexts = ["key", "token", "secret", "password", "auth", "credential", "api"]
        if any(ctx in context.lower() for ctx in secret_contexts):
            confidence += 0.2

        # Smart handling of test/example indicators
        test_indicators = ["test", "example", "sample", "demo", "fake", "dummy", "placeholder"]
        text_lower = text.lower()

        # Special case: Well-known example/test secrets
        # These are commonly used in documentation and testing
        example_secrets = [
            "AKIAIOSFODNN7EXAMPLE",  # AWS example access key
            "bPxRfiCYEXAMPLEKEY",  # AWS example secret key
            # JWT.io example token (without signature part)
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # JWT.io example signature
        ]
        if any(example in text for example in example_secrets):
            # These are well-known example secrets - still report but lower severity
            # Set confidence to exactly 0.6 so it passes threshold but gets WARNING severity
            confidence = 0.6  # Exactly at threshold - will be WARNING level, not CRITICAL
        elif any(indicator in text_lower for indicator in test_indicators):
            # Check if it's JUST a test indicator or part of real data
            # If the entire string is "test" or "example", it's definitely fake
            if text_lower in test_indicators:
                confidence = 0.0  # Definitely not a secret
            else:
                # Partial match - might be real key with unfortunate naming
                confidence -= 0.2  # Reduce but don't eliminate

        # Increase confidence based on entropy (randomness)
        if len(text) >= 16:
            # Simple entropy check - high randomness increases confidence
            unique_chars = len(set(text))
            entropy_ratio = unique_chars / len(text)
            if entropy_ratio > 0.7:  # High entropy
                confidence += 0.1
            elif entropy_ratio < 0.3:  # Low entropy (like "aaaaaaaa")
                confidence -= 0.2

        # Decrease confidence for very short secrets
        if len(text) < self.min_secret_length:
            confidence -= 0.3

        return max(0.0, min(1.0, confidence))  # Clamp to [0, 1]

    def scan_bytes(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
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
            # Pass a flag indicating this is from binary data
            # This helps filter out false positives from model weights
            text_findings = self.scan_text(text, context, is_binary_source=True)
            findings.extend(text_findings)
        except Exception:
            pass

        # Check for high-entropy regions that might be encrypted/encoded secrets
        # Only check if data is not too large (to avoid flagging compressed model weights)
        if len(data) < 1024 * 1024:  # Only for files < 1MB
            window_size = 64
            stride = 32  # Sliding window stride

            for i in range(0, min(len(data) - window_size, 10000), stride):  # Check first 10KB max
                window = data[i : i + window_size]
                entropy = self.calculate_shannon_entropy(window, window_size)

                if entropy > self.max_entropy:
                    # Very high entropy - check if it's actually suspicious
                    # Try to decode as text to see if it contains patterns
                    try:
                        decoded_text = window.decode("utf-8", errors="ignore")
                        # If it decodes to mostly printable ASCII, it might be base64/hex
                        if (
                            len(decoded_text) > 0
                            and sum(c.isprintable() for c in decoded_text) / len(decoded_text) > 0.9
                            and (
                                re.match(r"^[A-Za-z0-9+/=]+$", decoded_text)
                                or re.match(r"^[0-9a-fA-F]+$", decoded_text)
                            )
                        ):
                            findings.append(
                                {
                                    "type": "high_entropy_region",
                                    "severity": "INFO",  # Lower severity as it's just suspicious
                                    "position": i,
                                    "entropy": round(entropy, 2),
                                    "confidence": 0.4,  # Low confidence for entropy-only detection
                                    "message": f"High entropy region detected (entropy: {entropy:.2f}) - "
                                    "possible encoded secret",
                                    "context": f"{context} offset:{i}" if context else f"offset:{i}",
                                    "recommendation": "Review this region for base64/hex encoded secrets",
                                }
                            )
                            break  # Only report first high-entropy region to avoid spam
                    except Exception:
                        pass
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

    def _is_likely_binary_context(self, text: str, position: int, window: int = 100) -> bool:
        """Check if the text around a position looks like binary data rather than text.

        Args:
            text: Full text being scanned
            position: Position of the potential secret
            window: Size of context window to check

        Returns:
            True if context appears to be binary data
        """
        # Get surrounding context
        start = max(0, position - window)
        end = min(len(text), position + window)
        context = text[start:end]

        # Count various character types
        printable_count = sum(1 for c in context if c.isprintable() or c.isspace())
        null_count = context.count("\x00")
        control_chars = sum(1 for c in context if ord(c) < 32 and c not in "\n\r\t")

        # Calculate ratios
        total_chars = len(context)
        if total_chars == 0:
            return False

        printable_ratio = printable_count / total_chars
        null_ratio = null_count / total_chars
        control_ratio = control_chars / total_chars

        # Binary data indicators:
        # - Low printable ratio (< 70%)
        # - High null byte ratio (> 10%)
        # - High control character ratio (> 20%)
        is_binary = printable_ratio < 0.7 or null_ratio > 0.1 or control_ratio > 0.2

        # Additional check: if we're looking at password patterns in what appears to be
        # weight data (lots of numbers, scientific notation), it's likely a false positive
        if "pwd" in text[position : position + 10].lower() or "password" in text[position : position + 20].lower():
            # Check if surrounded by float-like patterns (common in weights)
            float_pattern = r"[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?"
            float_matches = len(re.findall(float_pattern, context))
            if float_matches > 5:  # Many float-like values nearby
                return True

        return is_binary

    def scan_text(self, text: str, context: str = "", is_binary_source: bool = False) -> list[dict[str, Any]]:
        """Scan text content for embedded secrets using regex patterns.

        Args:
            text: Text content to scan
            context: Context string for better error reporting

        Returns:
            List of detected secrets with details
        """
        findings = []

        # Limit text size to prevent DoS
        max_text_size = 100 * 1024 * 1024  # 100MB text analysis limit
        if len(text) > max_text_size:
            text = text[:max_text_size]

        for pattern, description in self._compiled_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                # Use capture group if available (for patterns like key=VALUE)
                # This extracts just the secret value, not the key name
                if match.groups():
                    secret_text = match.group(1)  # Get first capture group
                    position = match.start(1)  # Position of the capture group
                else:
                    secret_text = match.group(0)  # Get full match
                    position = match.start()  # Position of the full match

                # Skip if too short
                if len(secret_text) < self.min_secret_length:
                    continue

                # Skip if whitelisted
                if self._is_whitelisted(secret_text):
                    continue

                # Skip if likely false positive
                if self._is_likely_false_positive(secret_text, context):
                    continue

                # NEW: Skip password patterns in binary context (model weights)
                # Check both the text context and if it's from a binary source
                if description == "Hardcoded Password" and (
                    is_binary_source or self._is_likely_binary_context(text, position)
                ):
                    continue

                # Calculate confidence
                confidence = self._calculate_confidence(secret_text, description, context)

                # Skip low confidence matches if high confidence is required
                if self.require_high_confidence and confidence < 0.6:
                    continue

                # Determine severity based on confidence and pattern type
                if confidence >= 0.8:
                    severity = "CRITICAL"
                elif confidence >= 0.6:
                    severity = "WARNING"
                else:
                    severity = "INFO"

                # Redact the secret for safe reporting
                redacted = secret_text[:4] + "***" + secret_text[-4:] if len(secret_text) > 10 else "***REDACTED***"

                findings.append(
                    {
                        "type": "embedded_secret",
                        "severity": severity,
                        "secret_type": description,
                        "position": position,
                        "length": len(secret_text),
                        "confidence": round(confidence, 2),
                        "pattern": pattern.pattern[:50] + "..." if len(pattern.pattern) > 50 else pattern.pattern,
                        "redacted_value": redacted,
                        "message": f"{description} detected (confidence: {confidence:.0%})",
                        "context": f"{context} pos:{position}" if context else f"pos:{position}",
                        "recommendation": f"Remove {description} from model data immediately"
                        if confidence >= 0.8
                        else f"Review and remove {description} if not intentional",
                    }
                )

        return findings

    def scan_dict(self, data: dict[str, Any], context: str = "") -> list[dict[str, Any]]:
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
                findings.extend(self.scan_text(value, key_context, is_binary_source=False))
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

    def scan_model_weights(self, weights: Any, context: str = "weights") -> list[dict[str, Any]]:
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


def detect_secrets_in_file(file_path: str, max_size: int = 500 * 1024 * 1024) -> list[dict[str, Any]]:
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
