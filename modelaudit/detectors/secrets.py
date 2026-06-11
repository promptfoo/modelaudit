"""
Embedded Secrets Detection for ML Models
=========================================

Detects API keys, passwords, tokens, and other sensitive data embedded in model weights.
Part of ModelAudit's critical security validation suite.
"""

import base64
import binascii
import logging
import math
import re
from typing import Any

logger: logging.Logger = logging.getLogger(__name__)

BASIC_AUTH_SECRET_TYPE = "Basic Auth Credentials"
BASIC_AUTH_TOKEN_MAX_LENGTH = 8192
BASIC_AUTH_CONFIDENCE = 0.8
BASIC_AUTH_TOKEN_TERMINATOR = r"(?=$|[\s\"'`,.;<\]\)}]|\\(?:[\"']|r|n))"
BASIC_AUTH_PATTERN = (
    rf"\bBasic[ \t]+([A-Za-z0-9+/]{{2,{BASIC_AUTH_TOKEN_MAX_LENGTH}}}={{0,2}}){BASIC_AUTH_TOKEN_TERMINATOR}"
)
BASIC_AUTH_HEADER_VALUE_CONTEXT_MAX_BYTES = BASIC_AUTH_TOKEN_MAX_LENGTH + 64

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
    (BASIC_AUTH_PATTERN, BASIC_AUTH_SECRET_TYPE),
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
ML_FALSE_POSITIVE_PATTERNS = (
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
)
_COMPILED_DEFAULT_PATTERNS = tuple((re.compile(pattern, re.IGNORECASE), desc) for pattern, desc in SECRET_PATTERNS)
_COMPILED_ML_FALSE_POSITIVES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in ML_FALSE_POSITIVE_PATTERNS)

ML_CONTEXT_HINTS = (
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
)
COMMON_ML_WORDS = frozenset(
    {
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
    }
)
FALSE_POSITIVE_SECRET_CONTEXTS = ("key", "token", "secret", "password", "auth")
UUID_LIKE_PATTERN = re.compile(r"^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$")
ML_PARAMETER_VALUE_PATTERN = re.compile(r"^[\d\.\-e]+$")
PLACEHOLDER_SECRET_TERM_PATTERN = re.compile(
    r"(?:(?:^|[_-])(?:api|auth|client|credential|key|password|secret|token)(?=$|[_-])"
    r"|^(?:apikey|clientsecret|credentialkey|passwordvalue|secrettoken)$)",
    re.IGNORECASE,
)
PLACEHOLDER_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
PLACEHOLDER_SECRET_TERMS = frozenset({"credential", "key", "password", "secret", "token"})
PLACEHOLDER_MARKER_TERMS = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "fake",
        "here",
        "insert",
        "placeholder",
        "redacted",
        "replace",
        "sample",
        "value",
        "your",
    }
)
PLACEHOLDER_COMPOUND_TERMS: dict[str, tuple[str, ...]] = {
    "apikey": ("api", "key"),
    "clientsecret": ("client", "secret"),
    "credentialkey": ("credential", "key"),
    "passwordvalue": ("password", "value"),
    "secrettoken": ("secret", "token"),
}
PLACEHOLDER_IDENTIFIER_TERMS = frozenset(
    {
        "access",
        "account",
        "anthropic",
        "api",
        "auth",
        "aws",
        "azure",
        "bearer",
        "bot",
        "changeme",
        "client",
        "cohere",
        "credential",
        "db",
        "discord",
        "dummy",
        "example",
        "fake",
        "gcp",
        "github",
        "gitlab",
        "google",
        "here",
        "hf",
        "huggingface",
        "id",
        "insert",
        "key",
        "mailgun",
        "me",
        "mongodb",
        "mysql",
        "name",
        "npm",
        "oauth",
        "openai",
        "password",
        "placeholder",
        "postgres",
        "private",
        "public",
        "rabbitmq",
        "redacted",
        "redis",
        "replace",
        "rollbar",
        "sample",
        "secret",
        "sendgrid",
        "service",
        "signing",
        "slack",
        "square",
        "stripe",
        "telegram",
        "token",
        "twilio",
        "value",
        "var",
        "variable",
        "webhook",
        "with",
        "your",
    }
)
PLACEHOLDER_IDENTIFIER_TERMS_BY_LENGTH = tuple(sorted(PLACEHOLDER_IDENTIFIER_TERMS, key=len, reverse=True))


def _split_lowercase_placeholder_compound(segment: str) -> tuple[str, ...]:
    if not segment.islower() or len(segment) > 128:
        return ()

    matches: dict[int, tuple[str, ...]] = {0: ()}
    for start in range(len(segment)):
        prefix = matches.get(start)
        if prefix is None:
            continue
        for term in PLACEHOLDER_IDENTIFIER_TERMS_BY_LENGTH:
            if segment.startswith(term, start):
                matches.setdefault(start + len(term), (*prefix, term))
    parts = matches.get(len(segment), ())
    return parts if len(parts) > 1 else ()


PLACEHOLDER_MARKER_PATTERN = re.compile(
    r"(?:^|[_-])(?:your|example|sample|placeholder|dummy|fake|changeme|replace(?:_me|_with)?|insert|redacted|here)"
    r"(?=$|[_-])",
    re.IGNORECASE,
)


def _is_obvious_placeholder_secret(text: str) -> bool:
    candidate = text.strip()
    if re.fullmatch(r"[x*]{8,}", candidate, re.IGNORECASE):
        return True

    wrappers = (("{{", "}}"), ("${", "}"), ("<", ">"), ("[", "]"), ("%", "%"))
    was_wrapped = False
    was_environment_reference = False
    for opening, closing in wrappers:
        if candidate.startswith(opening) and candidate.endswith(closing):
            candidate = candidate[len(opening) : -len(closing)]
            was_wrapped = True
            break

    for prefix in ("process.env.", "$env:", "$"):
        if candidate.casefold().startswith(prefix):
            candidate = candidate[len(prefix) :]
            was_environment_reference = True
            break

    if PLACEHOLDER_IDENTIFIER_PATTERN.fullmatch(candidate) is None:
        return False

    identifier_terms: set[str] = set()
    for segment in re.split(r"[_-]+", candidate):
        segment_terms = re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+", segment)
        compound_terms = PLACEHOLDER_COMPOUND_TERMS.get(segment.casefold()) or _split_lowercase_placeholder_compound(
            segment
        )
        if len(segment_terms) == 1 and compound_terms:
            identifier_terms.update(compound_terms)
        else:
            identifier_terms.update(term.casefold() for term in segment_terms)
    if not identifier_terms or not (
        PLACEHOLDER_SECRET_TERM_PATTERN.search(candidate) is not None or identifier_terms & PLACEHOLDER_SECRET_TERMS
    ):
        return False

    has_placeholder_grammar = identifier_terms <= PLACEHOLDER_IDENTIFIER_TERMS
    return has_placeholder_grammar and (
        PLACEHOLDER_MARKER_PATTERN.search(candidate) is not None
        or bool(identifier_terms & PLACEHOLDER_MARKER_TERMS)
        or was_wrapped
        or was_environment_reference
        or candidate.isupper()
    )


HIGH_CONFIDENCE_PATTERN_HINTS = (
    "AWS Access Key",
    "OpenAI API Key",
    "GitHub Personal Token",
    "Private Key",
    "JWT Token",
    "Connection String",
    "Password",
    "Secret",
)
SECRET_CONTEXT_HINTS = ("key", "token", "secret", "password", "auth", "credential", "api")
TEST_INDICATORS = frozenset({"test", "example", "sample", "demo", "fake", "dummy", "placeholder"})
EXAMPLE_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",  # AWS example access key
    "bPxRfiCYEXAMPLEKEY",  # AWS example secret key
    # JWT.io example token (without signature part)
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"),
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # JWT.io example signature
)

BINARY_FALSE_POSITIVE_TYPES = frozenset(
    {
        "Hardcoded Password",
        "Bitcoin Address",
        "Ethereum Address",
        "Litecoin Address",
        "Azure Client Secret",
        "AWS Access Key",  # AKIA + 16 uppercase alphanums matches random bytes
        "Basic Auth Credentials",  # "Basic " + base64 matches binary data
        "Bearer Token",  # "Bearer " + alphanums matches binary data
        "UUID (potential secret)",  # Random bytes form valid UUID patterns
    }
)
FLOAT_LIKE_PATTERN = re.compile(r"[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?")
REDACTED_CONTEXT_SECRET = "<redacted-secret>"
BASIC_AUTH_HEADER_PREFIX_PATTERN = re.compile(
    r"(?:^|[^\w-])(?:"
    r"(?:http[-_]?)?(?:"
    r"proxy[-_]?authorization|proxyauthorization|authorization"
    r"|basic[-_]?auth|auth[-_]?header|authorization[-_]?header|proxy[-_]?auth[-_]?header"
    r")"
    r")"
    r"\s*(?:\\?[\"'])?\s*(?:\\?\])?\s*[:=]\s*"
    r"(?:\\?[\"']|\[\s*(?:\\?[\"'])?|\(\s*(?:\\?[\"'])?)?\s*(?:[>|][+-]?\s*)?$",
    re.IGNORECASE,
)
BASIC_AUTH_SPLIT_HEADER_PREFIX_PATTERN = re.compile(
    r"(?:^|[^\w$])(?:"
    r"(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)*setRequestHeader"
    r"|(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)+(?:set|append)"
    r")\s*\(\s*\\?[\"']\s*(?:proxy-authorization|authorization)\s*\\?[\"']\s*,\s*\\?[\"']?\s*$",
    re.IGNORECASE,
)
BASIC_AUTH_HEADERS_CONSTRUCTOR_START_PATTERN = re.compile(
    r"(?:^|[^\w$])(?:new\s+)?Headers\s*\(\s*\[",
    re.IGNORECASE,
)
BASIC_AUTH_HEADERS_CONSTRUCTOR_TUPLE_PREFIX_PATTERN = re.compile(
    r"\[\s*\\?[\"']\s*"
    r"(?:proxy-authorization|authorization)\s*\\?[\"']\s*,\s*\\?[\"']?\s*$",
    re.IGNORECASE,
)
BASIC_AUTH_HEADERS_INIT_START_PATTERN = re.compile(
    r"(?:^|[^\w$])(?:\\?[\"']\s*)?headers\s*(?:\\?[\"'])?\s*:\s*\[",
    re.IGNORECASE,
)
BASIC_AUTH_HEADER_CONTEXT_MAX_CHARS = 256
BASIC_AUTH_HEADER_COLLECTION_CONTEXT_MAX_CHARS = 4096
BASIC_AUTH_HEADER_NAMES = {
    "authorization": "Authorization",
    "proxyauthorization": "Proxy-Authorization",
    "basicauth": "Authorization",
    "authheader": "Authorization",
    "authorizationheader": "Authorization",
    "proxyauthheader": "Proxy-Authorization",
}
BASIC_AUTH_CONTINUATION_PREFIX_PATTERN = re.compile(r"^\s*(?:-\s*)?[\"']?$")
BASIC_AUTH_HEADER_VALUE_PATTERN = re.compile(rf"^\s*{BASIC_AUTH_PATTERN}", re.IGNORECASE)
BASIC_AUTH_VALUE_PREFIX_PATTERN = re.compile(r"^\s*Basic\s+", re.IGNORECASE)
BASIC_AUTH_VALUE_PREFIX_BYTES_PATTERN = re.compile(rb"^\s*Basic\s+", re.IGNORECASE)


def _normalize_basic_auth_header_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _canonical_basic_auth_header_name(value: str) -> str | None:
    normalized = _normalize_basic_auth_header_name(value)
    if normalized.startswith("http"):
        without_http_prefix = normalized[4:]
        if without_http_prefix in BASIC_AUTH_HEADER_NAMES:
            normalized = without_http_prefix
    return BASIC_AUTH_HEADER_NAMES.get(normalized)


def _is_basic_auth_header_name(value: str) -> bool:
    return _canonical_basic_auth_header_name(value) is not None


def _canonical_basic_auth_header_key(value: object) -> str | None:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    return _canonical_basic_auth_header_name(str(value))


def _is_basic_auth_headers_container_key(value: object) -> bool:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return False
    return _normalize_basic_auth_header_name(str(value)) == "headers"


class SecretsDetector:
    """Detects embedded secrets, API keys, and credentials in model data."""

    def __init__(self, config: dict[str, Any] | None = None):
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
        configured_max_findings = self.config.get("max_findings")
        self.max_findings = (
            configured_max_findings
            if isinstance(configured_max_findings, int)
            and not isinstance(configured_max_findings, bool)
            and configured_max_findings > 0
            else None
        )
        self._active_findings_count = 0
        self._findings_truncated = False
        self._scan_depth = 0

        # Combine default patterns with any custom patterns
        self.patterns = SECRET_PATTERNS.copy()
        if "patterns" in self.config:
            self.patterns.extend(self.config["patterns"])

        # Whitelist patterns that should be ignored
        self.whitelist = self.config.get("whitelist", [])

        # Common false positive patterns in ML models
        self.ml_false_positives = list(ML_FALSE_POSITIVE_PATTERNS)

        # Compiled regex patterns for efficiency
        self._compiled_patterns = (
            [(re.compile(pattern, re.IGNORECASE), desc) for pattern, desc in self.patterns]
            if "patterns" in self.config
            else _COMPILED_DEFAULT_PATTERNS
        )
        self._compiled_whitelist = [re.compile(pattern, re.IGNORECASE) for pattern in self.whitelist]
        self._compiled_ml_fps = _COMPILED_ML_FALSE_POSITIVES

    def _record_finding(self, findings: list[dict[str, Any]], finding: dict[str, Any]) -> bool:
        if self.max_findings is not None and self._active_findings_count >= self.max_findings:
            self._findings_truncated = True
            return False
        self._active_findings_count += 1
        findings.append(finding)
        return True

    def _finding_limit_marker(self, context: str) -> dict[str, Any]:
        return {
            "type": "detector_finding_limit",
            "detector": "secrets",
            "severity": "INFO",
            "message": "Embedded secret findings exceeded the configured reporting limit",
            "max_findings": self.max_findings,
            "analysis_incomplete": True,
            "context": context,
        }

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

        context_lower = context.lower()
        if any(ml_ctx in context_lower for ml_ctx in ML_CONTEXT_HINTS):
            # In ML context, be more strict about what we consider a secret
            # Must have high entropy or match very specific patterns
            if len(text) < 20:  # Short strings in ML context are likely parameters
                return True

            # Check if it looks like a parameter value (all numbers, decimals, scientific notation)
            if ML_PARAMETER_VALUE_PATTERN.match(text):
                return True

        # Check if it's a common word or phrase (not a secret)
        text_lower = text.lower()
        if _is_obvious_placeholder_secret(text):
            return True
        if text_lower in COMMON_ML_WORDS:
            return True

        # If it's all lowercase or all uppercase letters (likely a constant/config)
        if text.isalpha() and (text.islower() or text.isupper()) and len(text) < 20:
            return True

        # Check for sequences that look like UUIDs but aren't secrets
        # (common in model versioning)
        # This is a UUID - only flag if it's not in a secret-like context
        match = UUID_LIKE_PATTERN.match(text_lower)
        return bool(match and not any(word in context_lower for word in FALSE_POSITIVE_SECRET_CONTEXTS))

    def _calculate_confidence(self, text: str, pattern_desc: str, context: str = "") -> float:
        """Calculate confidence score for a detected secret (0.0 to 1.0).

        Higher confidence means more likely to be a real secret.
        """
        confidence = 0.5  # Base confidence

        # Increase confidence for specific high-value patterns
        if any(pattern in pattern_desc for pattern in HIGH_CONFIDENCE_PATTERN_HINTS):
            confidence += 0.3

        # Increase confidence if in a secret-like context
        context_lower = context.lower()
        if any(ctx in context_lower for ctx in SECRET_CONTEXT_HINTS):
            confidence += 0.2

        # Heuristic handling of test/example indicators
        text_lower = text.lower()

        # Special case: Well-known example/test secrets
        # These are commonly used in documentation and testing
        if any(example in text for example in EXAMPLE_SECRETS):
            # The JWT.io sample appears in benign fixtures and documentation, so
            # suppress that one by default. Keep other canned examples at the
            # minimum warning threshold because they are useful test signals.
            confidence = 0.4 if pattern_desc == "JWT Token" else 0.6
        elif any(indicator in text_lower for indicator in TEST_INDICATORS):
            # Check if it's JUST a test indicator or part of real data
            # If the entire string is "test" or "example", it's definitely fake
            if text_lower in TEST_INDICATORS:
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

    def _redact_context(self, context: str) -> str:
        """Redact secret-shaped material before storing context strings."""
        redacted = context
        for pattern, _description in self._compiled_patterns:
            redacted = pattern.sub(REDACTED_CONTEXT_SECRET, redacted)
        return redacted

    @staticmethod
    def _basic_auth_match_has_header_context(text: str, position: int) -> bool:
        search_start = max(0, position - BASIC_AUTH_HEADER_CONTEXT_MAX_CHARS)
        last_newline = max(text.rfind("\n", search_start, position), text.rfind("\r", search_start, position))
        line_start = search_start if last_newline == -1 else last_newline + 1

        line_prefix = text[line_start:position]
        if len(line_prefix) > BASIC_AUTH_HEADER_CONTEXT_MAX_CHARS:
            return False
        if BASIC_AUTH_HEADER_PREFIX_PATTERN.search(line_prefix) is not None:
            return True
        if BASIC_AUTH_SPLIT_HEADER_PREFIX_PATTERN.search(line_prefix) is not None:
            return True
        bounded_prefix = text[search_start:position]
        if BASIC_AUTH_SPLIT_HEADER_PREFIX_PATTERN.search(bounded_prefix) is not None:
            return True
        if SecretsDetector._basic_auth_prefix_has_headers_constructor_context(bounded_prefix):
            return True
        if SecretsDetector._basic_auth_prefix_has_headers_init_context(bounded_prefix):
            return True
        if BASIC_AUTH_HEADERS_CONSTRUCTOR_TUPLE_PREFIX_PATTERN.search(bounded_prefix) is not None:
            collection_search_start = max(0, position - BASIC_AUTH_HEADER_COLLECTION_CONTEXT_MAX_CHARS)
            if collection_search_start < search_start:
                collection_prefix = text[collection_search_start:position]
                if SecretsDetector._basic_auth_prefix_has_headers_constructor_context(collection_prefix):
                    return True
                if SecretsDetector._basic_auth_prefix_has_headers_init_context(collection_prefix):
                    return True
        if BASIC_AUTH_CONTINUATION_PREFIX_PATTERN.fullmatch(line_prefix) is None:
            return False

        previous_end = line_start - 1
        if previous_end < 0:
            return False
        if text[previous_end] == "\n" and previous_end > 0 and text[previous_end - 1] == "\r":
            previous_end -= 1

        previous_search_start = max(0, previous_end - BASIC_AUTH_HEADER_CONTEXT_MAX_CHARS)
        previous_break = max(
            text.rfind("\n", previous_search_start, previous_end),
            text.rfind("\r", previous_search_start, previous_end),
        )
        previous_start = previous_search_start if previous_break == -1 else previous_break + 1

        previous_line = text[previous_start:previous_end]
        if len(previous_line) > BASIC_AUTH_HEADER_CONTEXT_MAX_CHARS:
            return False
        return (
            BASIC_AUTH_HEADER_PREFIX_PATTERN.search(previous_line) is not None
            or BASIC_AUTH_SPLIT_HEADER_PREFIX_PATTERN.search(previous_line) is not None
        )

    @staticmethod
    def _basic_auth_prefix_has_headers_constructor_context(prefix: str) -> bool:
        tuple_match = BASIC_AUTH_HEADERS_CONSTRUCTOR_TUPLE_PREFIX_PATTERN.search(prefix)
        if tuple_match is None:
            return False

        for constructor_match in BASIC_AUTH_HEADERS_CONSTRUCTOR_START_PATTERN.finditer(prefix[: tuple_match.start()]):
            if SecretsDetector._basic_auth_headers_constructor_remains_open(
                prefix[constructor_match.end() : tuple_match.start()]
            ):
                return True
        return False

    @staticmethod
    def _basic_auth_prefix_has_headers_init_context(prefix: str) -> bool:
        tuple_match = BASIC_AUTH_HEADERS_CONSTRUCTOR_TUPLE_PREFIX_PATTERN.search(prefix)
        if tuple_match is None:
            return False

        for headers_match in BASIC_AUTH_HEADERS_INIT_START_PATTERN.finditer(prefix[: tuple_match.start()]):
            if SecretsDetector._basic_auth_headers_init_array_remains_open(
                prefix[headers_match.end() : tuple_match.start()]
            ):
                return True
        return False

    @staticmethod
    def _basic_auth_headers_constructor_remains_open(value: str) -> bool:
        paren_depth = 1
        bracket_depth = 1
        quote: str | None = None
        escaped = False

        for character in value:
            if escaped:
                escaped = False
                continue
            if quote is not None:
                if character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
            elif character == "(":
                paren_depth += 1
            elif character == ")":
                paren_depth -= 1
                if paren_depth <= 0:
                    return False
            elif character == "[":
                bracket_depth += 1
            elif character == "]":
                bracket_depth -= 1
                if bracket_depth <= 0:
                    return False

        return paren_depth > 0 and bracket_depth > 0

    @staticmethod
    def _basic_auth_headers_init_array_remains_open(value: str) -> bool:
        bracket_depth = 1
        quote: str | None = None
        escaped = False

        for character in value:
            if escaped:
                escaped = False
                continue
            if quote is not None:
                if character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
            elif character == "[":
                bracket_depth += 1
            elif character == "]":
                bracket_depth -= 1
                if bracket_depth <= 0:
                    return False

        return bracket_depth > 0

    @staticmethod
    def _basic_auth_token_decodes_to_credentials(token: str) -> bool:
        if not token or len(token) > BASIC_AUTH_TOKEN_MAX_LENGTH or len(token) % 4 == 1:
            return False
        padding_start = token.find("=")
        if padding_start != -1 and any(character != "=" for character in token[padding_start:]):
            return False

        padded_token = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            decoded = base64.b64decode(padded_token.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            return False

        username, separator, password = decoded.partition(b":")
        return bool(separator and (username or password))

    def _basic_auth_match_is_valid(self, text: str, match: re.Match[str], token: str) -> bool:
        return self._basic_auth_match_has_header_context(
            text,
            match.start(),
        ) and self._basic_auth_token_decodes_to_credentials(token)

    def _record_basic_auth_finding(
        self,
        findings: list[dict[str, Any]],
        token: str,
        matched_text: str,
        pattern: re.Pattern[str],
        position: int,
        context: str,
        safe_context: str,
    ) -> bool:
        if len(matched_text) < self.min_secret_length:
            return True
        if self._is_whitelisted(token) or self._is_whitelisted(matched_text):
            return True

        confidence = max(
            self._calculate_confidence(token, BASIC_AUTH_SECRET_TYPE, context),
            BASIC_AUTH_CONFIDENCE,
        )
        severity = "CRITICAL" if confidence >= 0.8 else "WARNING"

        return self._record_finding(
            findings,
            {
                "type": "embedded_secret",
                "severity": severity,
                "secret_type": BASIC_AUTH_SECRET_TYPE,
                "position": position,
                "length": len(token),
                "confidence": round(confidence, 2),
                "pattern": pattern.pattern[:50] + "..." if len(pattern.pattern) > 50 else pattern.pattern,
                "redacted_value": "Basic <redacted>",
                "message": f"{BASIC_AUTH_SECRET_TYPE} detected (confidence: {confidence:.0%})",
                "context": f"{safe_context} pos:{position}" if safe_context else f"pos:{position}",
                "recommendation": f"Remove {BASIC_AUTH_SECRET_TYPE} from model data immediately",
            },
        )

    def _scan_basic_auth_header_text_value(
        self,
        value: str,
        header_name: str | None,
        context: str,
    ) -> list[dict[str, Any]]:
        if header_name is not None and BASIC_AUTH_VALUE_PREFIX_PATTERN.match(value):
            return self.scan_text(f"{header_name}: {value}", context, is_binary_source=False)
        return self.scan_text(value, context, is_binary_source=False)

    def _scan_basic_auth_header_bytes_value(
        self,
        value: bytes,
        header_name: str | None,
        context: str,
    ) -> list[dict[str, Any]]:
        if header_name is not None and BASIC_AUTH_VALUE_PREFIX_BYTES_PATTERN.match(value):
            value_text = value[:BASIC_AUTH_HEADER_VALUE_CONTEXT_MAX_BYTES].decode("ascii", errors="ignore")
            header_value_match = BASIC_AUTH_HEADER_VALUE_PATTERN.match(value_text)
            findings: list[dict[str, Any]] = []
            if header_value_match is not None:
                findings = self.scan_text(
                    f"{header_name}: {value_text[: header_value_match.end()]}",
                    context,
                    is_binary_source=False,
                )
                if self._findings_truncated:
                    return findings
            findings.extend(self.scan_bytes(value, context))
            return findings
        return self.scan_bytes(value, context)

    def _scan_basic_auth_structured_header_value(
        self,
        value: Any,
        header_name: str | None,
        context: str,
    ) -> list[dict[str, Any]]:
        if isinstance(value, str):
            return self._scan_basic_auth_header_text_value(value, header_name, context)
        if isinstance(value, bytes):
            return self._scan_basic_auth_header_bytes_value(value, header_name, context)
        if isinstance(value, dict):
            return self.scan_dict(value, context, header_name)
        return []

    def scan_bytes(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan binary data for embedded secrets.

        Args:
            data: Binary data to scan
            context: Context string for better error reporting

        Returns:
            List of detected secrets with details
        """
        findings: list[dict[str, Any]] = []
        safe_context = self._redact_context(context)

        # First, try to detect secrets in decoded text
        try:
            # Try UTF-8 decoding with error handling
            text = data.decode("utf-8", errors="ignore")
            # Pass a flag indicating this is from binary data
            # This helps filter out false positives from model weights
            text_findings = self.scan_text(text, context, is_binary_source=True)
            findings.extend(text_findings)
            if self._findings_truncated:
                return findings
        except Exception as e:
            logger.debug("Failed to decode binary data as UTF-8 for secrets scanning: %s", e)

        # Check for high-entropy regions that might be encrypted/encoded secrets
        # Only check if data is not too large (to avoid flagging compressed model weights)
        if len(data) < 1024 * 1024:  # Only for files < 1MB
            window_size = 64
            stride = 32  # Sliding window stride
            high_entropy_threshold = min(self.max_entropy, math.log2(window_size) - 0.25)

            for i in range(0, min(len(data) - window_size, 10000) + 1, stride):  # Check first 10KB max
                window = data[i : i + window_size]
                entropy = self.calculate_shannon_entropy(window, window_size)

                if entropy > high_entropy_threshold:
                    # Very high entropy - check if it's actually suspicious
                    # Try to decode as text to see if it contains patterns
                    try:
                        decoded_text = window.decode("ascii")
                        # If it decodes to mostly printable ASCII, it might be base64/hex
                        if (
                            len(decoded_text) > 0
                            and sum(c.isprintable() for c in decoded_text) / len(decoded_text) > 0.9
                            and (
                                re.match(r"^[A-Za-z0-9+/=]+$", decoded_text)
                                or re.match(r"^[0-9a-fA-F]+$", decoded_text)
                            )
                        ):
                            if not self._record_finding(
                                findings,
                                {
                                    "type": "high_entropy_region",
                                    "severity": "INFO",  # Lower severity as it's just suspicious
                                    "position": i,
                                    "entropy": round(entropy, 2),
                                    "confidence": 0.4,  # Low confidence for entropy-only detection
                                    "message": f"High entropy region detected (entropy: {entropy:.2f}) - "
                                    "possible encoded secret",
                                    "context": f"{safe_context} offset:{i}" if safe_context else f"offset:{i}",
                                    "recommendation": "Review this region for base64/hex encoded secrets",
                                },
                            ):
                                return findings
                            break  # Only report first high-entropy region to avoid spam
                    except Exception as e:
                        logger.debug("Error analyzing high-entropy region at offset %d: %s", i, e)
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
                    except Exception as e:
                        logger.debug("Failed to decode/analyze base64 content: %s", e)

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
            float_matches = len(FLOAT_LIKE_PATTERN.findall(context))
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
        findings: list[dict[str, Any]] = []
        safe_context = self._redact_context(context)

        # Limit text size to prevent DoS
        max_text_size = 100 * 1024 * 1024  # 100MB text analysis limit
        if len(text) > max_text_size:
            text = text[:max_text_size]

        for pattern, description in self._compiled_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                if description == BASIC_AUTH_SECRET_TYPE and pattern.pattern == BASIC_AUTH_PATTERN and match.lastindex:
                    token = match.group(1)
                    if not self._basic_auth_match_is_valid(text, match, token):
                        continue
                    if not self._record_basic_auth_finding(
                        findings,
                        token,
                        match.group(0),
                        pattern,
                        match.start(1),
                        context,
                        safe_context,
                    ):
                        return findings
                    continue

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

                if self._is_likely_false_positive(secret_text, context):
                    continue

                # Skip patterns that commonly match random binary model weight data.
                # Tensor weights are arbitrary byte sequences that frequently trigger
                # regex patterns designed for structured text.
                # NOTE: Use exact matching to avoid "AWS Access Key" also suppressing
                # "AWS Access Key ID" (which is a structured key=value pattern).
                if (description in BINARY_FALSE_POSITIVE_TYPES) and self._is_likely_binary_context(text, position):
                    continue

                confidence = self._calculate_confidence(secret_text, description, context)

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

                if not self._record_finding(
                    findings,
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
                        "context": f"{safe_context} pos:{position}" if safe_context else f"pos:{position}",
                        "recommendation": f"Remove {description} from model data immediately"
                        if confidence >= 0.8
                        else f"Review and remove {description} if not intentional",
                    },
                ):
                    return findings

        return findings

    def scan_dict(
        self,
        data: dict[str, Any],
        context: str = "",
        basic_auth_header_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Recursively scan dictionary structures for secrets.

        Args:
            data: Dictionary to scan
            context: Context path for error reporting

        Returns:
            List of detected secrets
        """
        findings = []

        for key, value in data.items():
            if self._findings_truncated:
                break
            key_context = f"{context}/{key}" if context else str(key)

            # Check the key itself for secrets
            key_findings = self.scan_text(str(key), f"{key_context}[key]")
            findings.extend(key_findings)

            # Check the value
            header_name = _canonical_basic_auth_header_key(key) or basic_auth_header_name
            if isinstance(value, list | tuple):
                headers_container = _is_basic_auth_headers_container_key(key)
                for i, item in enumerate(value):
                    item_context = f"{key_context}[{i}]"
                    if headers_container and isinstance(item, list | tuple) and len(item) == 2:
                        pair_header_name = _canonical_basic_auth_header_key(item[0])
                        if pair_header_name is not None:
                            findings.extend(
                                self._scan_basic_auth_structured_header_value(
                                    item[1],
                                    pair_header_name,
                                    f"{item_context}[1]",
                                )
                            )
                            continue
                    findings.extend(self._scan_basic_auth_structured_header_value(item, header_name, item_context))
            else:
                findings.extend(self._scan_basic_auth_structured_header_value(value, header_name, key_context))

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
        root_scan = self._scan_depth == 0
        if root_scan:
            self._active_findings_count = 0
            self._findings_truncated = False
        self._scan_depth += 1
        findings: list[dict[str, Any]] = []
        try:
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
                except Exception as e:
                    logger.debug("Failed to convert model weights to bytes for scanning: %s", e)
            elif isinstance(weights, list | tuple):
                for i, item in enumerate(weights):
                    if self._findings_truncated:
                        break
                    findings.extend(self.scan_model_weights(item, f"{context}[{i}]"))
        finally:
            self._scan_depth -= 1

        if root_scan and self._findings_truncated:
            findings.append(self._finding_limit_marker(context))
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
        return [{"type": "info", "severity": "INFO", "message": f"File too large: {file_size} bytes (max: {max_size})"}]

    detector = SecretsDetector()

    with open(file_path, "rb") as f:
        data = f.read()

    return detector.scan_bytes(data, file_path)
