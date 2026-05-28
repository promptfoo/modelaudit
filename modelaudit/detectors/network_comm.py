"""Network Communication Detection for ML models.

This module detects potential network communication capabilities in model files
that could be used for data exfiltration or command & control operations.
"""

import ipaddress
import re
from collections.abc import Iterator
from contextlib import suppress
from typing import Any, ClassVar
from urllib.parse import unquote, urlsplit, urlunsplit

_REDACTED_PATH_TOKEN = "<redacted>"
_SENSITIVE_PATH_TOKEN_PATTERN = re.compile(
    r"(?i)^(?:"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[ps]_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]*|"
    r"sk-(?:proj-)?[A-Za-z0-9]{24,}|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}"
    r")$"
)
_PATH_TOKEN_CHARACTER_CLASS_PATTERNS = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"\d"),
    re.compile(r"[._~+/=-]"),
)
_ARTIFACT_FILENAME_PATTERN = re.compile(r"(?i)^.+\.[a-z0-9]{1,10}$")
_TRAILING_PATH_DELIMITERS = ".,;:)]}"


def _split_trailing_path_delimiters(segment: str) -> tuple[str, str]:
    stripped = segment.rstrip(_TRAILING_PATH_DELIMITERS)
    return stripped, segment[len(stripped) :]


def _looks_like_capability_path_token(segment: str) -> bool:
    token_candidate, _trailing_delimiters = _split_trailing_path_delimiters(segment)
    decoded = unquote(token_candidate)
    if _SENSITIVE_PATH_TOKEN_PATTERN.fullmatch(decoded):
        return True

    if _ARTIFACT_FILENAME_PATTERN.fullmatch(decoded):
        return False
    if len(decoded) < 20:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", decoded):
        return False

    character_classes = sum(bool(pattern.search(decoded)) for pattern in _PATH_TOKEN_CHARACTER_CLASS_PATTERNS)
    unique_ratio = len(set(decoded)) / len(decoded)
    return character_classes >= 3 and unique_ratio >= 0.45


def _redact_url_path_tokens(hostname: str, path: str) -> str:
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if not segment:
            continue
        is_slack_webhook_secret = (
            hostname == "hooks.slack.com" and len(segments) > 2 and segments[1].lower() == "services" and index > 1
        )
        if is_slack_webhook_secret or _looks_like_capability_path_token(segment):
            _token_candidate, trailing_delimiters = _split_trailing_path_delimiters(segment)
            segments[index] = f"{_REDACTED_PATH_TOKEN}{trailing_delimiters}"
    return "/".join(segments)


def _redact_url_for_finding(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.netloc:
        return "[invalid-url]"

    hostname = parsed.hostname
    if not hostname:
        return "[invalid-url]"
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc = f"{hostname}:{port}" if port is not None else hostname
    safe_path = _redact_url_path_tokens(hostname.lower(), parsed.path)
    return urlunsplit((parsed.scheme, netloc, safe_path, "", ""))


_DOC_CONTEXT_EXTENSIONS: tuple[str, ...] = (
    ".md",
    ".rst",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
)
_DOC_CONTEXT_NAMES: frozenset[str] = frozenset(
    {
        "readme",
        "metadata",
        "description",
        "model_card",
        "manifest",
    }
)
_DOC_CONTEXT_SEGMENTS: frozenset[str] = frozenset(
    {
        "metadata",
        "description",
        "model_card",
        "manifest",
    }
)
_DOC_CONTEXT_NAME_PREFIXES: tuple[str, ...] = (
    "readme",
    "model_card",
)
_PROSE_MARKERS: tuple[str, ...] = (
    " example",
    " examples",
    " documentation",
    " readme",
    " description",
    " metadata",
    " says",
    " mentions",
    " includes",
)
_MAX_PROSE_LINE_CONTEXT_BYTES = 512
_WORD_PATTERN = re.compile(rb"[A-Za-z]{2,}")
_CODE_LINE_PREFIXES: tuple[bytes, ...] = (
    b"import ",
    b"from ",
    b"def ",
    b"class ",
    b"if ",
)
_CODE_LINE_MARKERS: tuple[bytes, ...] = (
    b"=",
    b";",
    b"lambda ",
)
_INLINE_COMPOUND_STATEMENT_PATTERN = re.compile(
    rb"^\s*(?:if|elif|else|for|while|with|try|except|finally|match|case)\b[^#\n]*:\s*\S"
)
_STRUCTURED_METADATA_PREFIXES: tuple[bytes, ...] = (b"{", b"[", b'"', b"'")
_EXPLICIT_VERSION_LITERAL_CONTEXT_PATTERN = re.compile(
    rb"\b(?:version|ver|release|build)\s*[:=]\s*[\"']?"
    rb"(?P<value>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[\"']?",
    re.IGNORECASE,
)
_PLAIN_VERSION_LITERAL_CONTEXT_PATTERN = re.compile(
    rb"(?:(?:^|[\r\n])\s*version|model\s+version|release|build)\s+[\"']?"
    rb"(?P<value>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[\"']?",
    re.IGNORECASE,
)
_ML_LAYER_DOMAIN_PATTERN = re.compile(
    r"^(?:layer\d+|conv\d*d?|bn\d+|norm\d+|fc\d+|dense\d+)\.(?:weight|bias)$",
    re.IGNORECASE,
)


def _is_metadata_context(context: str) -> bool:
    """Return whether the scan context appears to be documentation or metadata."""
    context_lower = context.lower()
    context_segments = [segment for segment in context_lower.replace("\\", "/").split("/") if segment]
    filename = context_segments[-1] if context_segments else context_lower
    stem = filename.rsplit(".", 1)[0]

    if filename.endswith(_DOC_CONTEXT_EXTENSIONS):
        return True
    if stem in _DOC_CONTEXT_NAMES or stem.startswith(_DOC_CONTEXT_NAME_PREFIXES):
        return True
    return any(segment in _DOC_CONTEXT_SEGMENTS for segment in context_segments[:-1])


def _extract_line(data: bytes, match_index: int) -> bytes:
    """Extract the line containing a matched network token."""
    line_start = max(data.rfind(b"\n", 0, match_index) + 1, match_index - _MAX_PROSE_LINE_CONTEXT_BYTES)
    line_end = data.find(b"\n", match_index)
    if line_end == -1:
        line_end = len(data)
    line_end = min(line_end, match_index + _MAX_PROSE_LINE_CONTEXT_BYTES)
    return data[line_start:line_end]


def _iter_pattern_matches(data: bytes, pattern: bytes) -> Iterator[int]:
    """Yield non-overlapping match positions for a byte pattern."""
    start = 0
    while True:
        match_index = data.find(pattern, start)
        if match_index < 0:
            break
        yield match_index
        start = match_index + max(1, len(pattern))


def _has_call_syntax(data: bytes, match_index: int, token_len: int) -> bool:
    """Return whether a token is followed by call syntax after optional whitespace."""
    cursor = match_index + token_len
    while cursor < len(data) and data[cursor : cursor + 1] in {b" ", b"\t", b"\r", b"\n"}:
        cursor += 1
    return cursor < len(data) and data[cursor : cursor + 1] == b"("


def _is_version_literal_context(surrounding_bytes: bytes, token: bytes) -> bool:
    """Return whether the matched token is explicitly presented as a version literal."""
    return any(
        match.group("value") == token
        for pattern in (_EXPLICIT_VERSION_LITERAL_CONTEXT_PATTERN, _PLAIN_VERSION_LITERAL_CONTEXT_PATTERN)
        for match in pattern.finditer(surrounding_bytes)
    )


def _is_doc_only_network_reference(
    data: bytes,
    *,
    match_index: int,
    token_len: int,
    context: str,
    requires_call: bool,
) -> bool:
    """Return whether a raw network token appears in prose instead of executable code."""
    if requires_call and _has_call_syntax(data, match_index, token_len):
        return False

    line = _extract_line(data, match_index)
    line_lower = line.lower()
    stripped = line_lower.lstrip()
    word_count = len(_WORD_PATTERN.findall(line))
    metadata_context = _is_metadata_context(context)

    if any(stripped.startswith(prefix) for prefix in _CODE_LINE_PREFIXES):
        return False
    if _INLINE_COMPOUND_STATEMENT_PATTERN.match(line_lower):
        return False
    if any(marker in line_lower for marker in _CODE_LINE_MARKERS):
        return False
    if metadata_context and stripped.startswith(_STRUCTURED_METADATA_PREFIXES):
        return False

    text = line.decode("utf-8", errors="ignore").lower()
    has_prose_marker = any(marker in text for marker in _PROSE_MARKERS)
    if not has_prose_marker:
        return False
    return (metadata_context and word_count >= 4) or word_count >= 6


class NetworkCommDetector:
    """Detector for network communication patterns in model files."""

    # URL patterns - also match ftp, ftps, ssh, etc.
    URL_PATTERN = re.compile(
        rb"(?:https?|ftp|ftps|ssh|telnet|ws|wss)://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+", re.IGNORECASE
    )

    # Cloud storage URL patterns for detecting external resource references
    # These patterns detect references to cloud storage that could indicate
    # external dependencies or potential data exfiltration vectors
    CLOUD_STORAGE_PATTERNS: ClassVar[list[tuple[re.Pattern[bytes], str, str]]] = [
        # AWS S3
        (re.compile(rb"s3://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "AWS S3 URI", "s3"),
        (
            re.compile(rb"https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 URL",
            "s3",
        ),
        (
            re.compile(rb"https?://s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 URL",
            "s3",
        ),
        (
            re.compile(rb"https?://s3\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "AWS S3 Regional URL",
            "s3",
        ),
        # Google Cloud Storage
        (re.compile(rb"gs://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Google Cloud Storage URI", "gcs"),
        (
            re.compile(rb"https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Google Cloud Storage URL",
            "gcs",
        ),
        (
            re.compile(rb"https?://storage\.cloud\.google\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Google Cloud Storage URL",
            "gcs",
        ),
        # Azure Blob Storage
        (
            re.compile(rb"https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "Azure Blob Storage URL",
            "azure",
        ),
        (re.compile(rb"az://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Azure Storage URI", "azure"),
        (
            re.compile(
                rb"wasbs?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE
            ),
            "Azure WASB URI",
            "azure",
        ),
        (
            re.compile(
                rb"abfss?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.dfs\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE
            ),
            "Azure ADLS Gen2 URI",
            "azure",
        ),
        # Hugging Face Hub (external model references)
        (
            re.compile(rb"https?://huggingface\.co/[a-zA-Z0-9.\-_]+/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
            "HuggingFace Hub URL",
            "huggingface",
        ),
    ]

    # IP address patterns (v4 and v6)
    IPV4_PATTERN = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    IPV6_PATTERN = re.compile(rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")

    # Domain patterns
    DOMAIN_PATTERN = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

    # Network library imports
    NETWORK_LIBRARIES: ClassVar[list[bytes]] = [
        b"socket",
        b"urllib",
        b"requests",
        b"httplib",
        b"http.client",
        b"ftplib",
        b"telnetlib",
        b"smtplib",
        b"poplib",
        b"imaplib",
        b"paramiko",
        b"pycurl",
        b"aiohttp",
        b"tornado",
        b"twisted",
        b"httpx",
        b"websocket",
        b"websockets",
        b"grpc",
        b"zeromq",
        b"paho.mqtt",
        b"redis",
        b"pymongo",
        b"psycopg2",
        b"mysql.connector",
    ]
    NETWORK_LIBRARY_PATTERNS: ClassVar[dict[bytes, tuple[bytes, ...]]] = {
        lib: (b"import " + lib, b"from " + lib, lib + b".connect", lib + b".request", lib + b".__init__")
        for lib in NETWORK_LIBRARIES
    }

    # Network functions
    NETWORK_FUNCTIONS: ClassVar[list[bytes]] = [
        b"urlopen",
        b"urlretrieve",
        b"socket.connect",
        b"socket.create_connection",
        b"requests.get",
        b"requests.post",
        b"requests.put",
        b"requests.delete",
        b"http.request",
        b"ftp.connect",
        b"ssh.connect",
        b"telnet.open",
        b"smtp.connect",
        b"imap.login",
        b"redis.connect",
        b"mongo.connect",
        b"getaddrinfo",
        b"gethostbyname",
        b"gethostbyaddr",
        b"dns.resolver",
    ]

    # Known C&C patterns. Keep this list to high-signal indicators; ordinary
    # metadata keys like download_url or heartbeat are common in model cards.
    CC_PATTERNS: ClassVar[list[bytes]] = [
        b"beacon_url",
        b"callback_url",
        b"c2_server",
        b"command_server",
        b"exfil_endpoint",
        b"malware",
        b"backdoor",
        b"trojan",
        b"botnet",
        b"zombie",
        b"phone_home",
        b"check_in",
    ]

    # Suspicious ports
    SUSPICIOUS_PORTS: ClassVar[list[int]] = [
        22,  # SSH
        23,  # Telnet
        135,  # RPC
        139,  # NetBIOS
        445,  # SMB
        1337,  # Common backdoor
        1433,  # MSSQL
        1434,  # MSSQL Browser
        3128,  # Proxy
        3306,  # MySQL
        3389,  # RDP
        4444,  # Metasploit
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Proxy
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017,  # MongoDB
        31337,  # Back Orifice
    ]

    # Precompile port patterns to avoid repeated compilation during scanning
    PORT_PATTERNS: ClassVar[dict[int, list[bytes]]] = {
        port: [
            f":{port}".encode(),
            f"port={port}".encode(),
            f"port {port}".encode(),
            f"PORT={port}".encode(),
        ]
        for port in SUSPICIOUS_PORTS
    }
    PORT_NAMES: ClassVar[dict[int, str]] = {
        22: "SSH",
        23: "Telnet",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        1337: "Common Backdoor",
        1433: "MSSQL",
        3128: "Proxy",
        3306: "MySQL",
        3389: "RDP",
        4444: "Metasploit",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
        31337: "Back Orifice",
    }

    EXPLICIT_PORT_PATTERNS: ClassVar[dict[int, list[re.Pattern]]] = {
        port: [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in [
                f"connect.*:{port}".encode(),
                f"socket.*port={port}".encode(),
                f"http://.*:{port}".encode(),
                f"https://.*:{port}".encode(),
                f"ssh.*:{port}".encode(),
                f"telnet.*:{port}".encode(),
            ]
        ]
        for port in SUSPICIOUS_PORTS
    }

    # Blacklisted domains - empty by default, should be configured by user
    # via config parameter if they have specific domains to block
    BLACKLISTED_DOMAINS: ClassVar[list[bytes]] = []

    INFORMATIONAL_DOMAIN_SUFFIXES: ClassVar[tuple[str, ...]] = (
        "huggingface.co",
        "amazonaws.com",
        "storage.googleapis.com",
        "storage.cloud.google.com",
        "blob.core.windows.net",
        "dfs.core.windows.net",
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the detector with optional configuration."""
        self.config = config or {}
        self.findings: list[dict[str, Any]] = []

        # Clone class-level patterns to avoid cross-instance leakage
        self.cc_patterns: list[bytes] = self.CC_PATTERNS.copy()
        self.blacklisted_domains: list[bytes] = self.BLACKLISTED_DOMAINS.copy()

        def _to_lower_bytes(value: bytes | str) -> bytes:
            return value.lower() if isinstance(value, bytes) else value.encode().lower()

        # Add custom patterns from config, normalizing to lowercase bytes
        if "custom_cc_patterns" in self.config:
            self.cc_patterns.extend(_to_lower_bytes(p) for p in self.config["custom_cc_patterns"])
        if "custom_blacklist" in self.config:
            self.blacklisted_domains.extend(_to_lower_bytes(d) for d in self.config["custom_blacklist"])

    def scan(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan data for network communication patterns.

        Args:
            data: Binary data to scan
            context: Context information (e.g., filename)

        Returns:
            List of findings with details about detected patterns
        """
        self.findings = []

        # Scan for URLs
        self._scan_urls(data, context)

        # Scan for cloud storage URLs (external resource references)
        self._scan_cloud_storage_urls(data, context)

        # Scan for IP addresses
        self._scan_ip_addresses(data, context)

        # Scan for domains
        self._scan_domains(data, context)

        # Scan for network libraries
        self._scan_network_libraries(data, context)

        # Scan for network functions
        self._scan_network_functions(data, context)

        # Scan for C&C patterns
        self._scan_cc_patterns(data, context)

        # Scan for suspicious ports
        self._scan_suspicious_ports(data, context)

        # Check against blacklist
        self._check_blacklist(data, context)

        return self.findings

    def _scan_urls(self, data: bytes, context: str) -> None:
        """Scan for URL patterns."""
        for match in self.URL_PATTERN.finditer(data):
            url = match.group().decode("utf-8", errors="ignore")
            safe_url = _redact_url_for_finding(url)

            # Calculate confidence based on URL characteristics
            confidence = 0.5
            severity = "MEDIUM"
            if any(pattern in url.lower() for pattern in ["eval", "exec", "cmd", "shell"]):
                confidence = 0.9
                severity = "HIGH"
            elif any(port in url for port in [":1337", ":4444", ":31337"]):
                confidence = 0.8
                severity = "HIGH"
            elif "://" in url and not url.startswith(("http://", "https://")):
                confidence = 0.7
            elif self._is_cloud_storage_url(url):
                severity = "INFO"

            self.findings.append(
                {
                    "type": "url_detected",
                    "severity": severity,
                    "confidence": confidence,
                    "message": f"URL detected in model: {safe_url[:100]}",
                    "url": safe_url,
                    "position": match.start(),
                    "context": context,
                }
            )

    def _scan_cloud_storage_urls(self, data: bytes, context: str) -> None:
        """Scan for cloud storage URL patterns (S3, GCS, Azure, etc.).

        These patterns detect references to external cloud storage that could indicate:
        - External model dependencies
        - Potential data exfiltration vectors
        - Supply chain risks from external resources
        """
        seen_urls: set[str] = set()

        for pattern, description, provider in self.CLOUD_STORAGE_PATTERNS:
            for match in pattern.finditer(data):
                url = match.group().decode("utf-8", errors="ignore")
                safe_url = _redact_url_for_finding(url)

                # Skip duplicates
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Determine severity based on context
                # INFO for HuggingFace (common and usually legitimate)
                # INFO for other cloud URLs (informational - may be legitimate)
                severity = "INFO"
                confidence = 0.9  # High confidence - pattern is specific

                # Check for suspicious indicators that might elevate severity
                url_lower = url.lower()
                suspicious_indicators = ["malware", "exploit", "hack", "evil", "backdoor", "exfil"]
                if any(indicator in url_lower for indicator in suspicious_indicators):
                    severity = "WARNING"
                    confidence = 0.95

                self.findings.append(
                    {
                        "type": "cloud_storage_url",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"{description} detected: {safe_url[:150]}",
                        "url": safe_url,
                        "provider": provider,
                        "description": description,
                        "position": match.start(),
                        "context": context,
                    }
                )

    def _scan_ip_addresses(self, data: bytes, context: str) -> None:
        """Scan for IP address patterns."""
        # IPv4
        for match in self.IPV4_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")

            # Check for common false positives (version numbers) only when the
            # matched token itself is the version literal.
            start = max(0, match.start() - 20)
            end = min(len(data), match.end() + 20)
            surrounding_bytes = data[start:end]
            surrounding = surrounding_bytes.decode("utf-8", errors="ignore").lower()

            if _is_version_literal_context(surrounding_bytes, match.group()):
                continue

            # Skip if surrounded by quotes and has typical version patterns
            if '"' + ip + '"' in surrounding or "'" + ip + "'" in surrounding:
                parts = ip.split(".")
                # Version numbers typically have small numbers
                if all(int(p) < 100 for p in parts):
                    continue

            # Skip patterns that look like array indices or numeric data
            # e.g., [1.0, 2.0, 3.0, 4.0] or similar
            if (("[" in surrounding and "]" in surrounding) or ("{" in surrounding and "}" in surrounding)) and (
                ".0" in surrounding or "float" in surrounding or "weight" in surrounding or "bias" in surrounding
            ):
                continue

            # Validate it's a real IP
            with suppress(ipaddress.AddressValueError):
                ip_obj = ipaddress.IPv4Address(ip)

                # Check if it's private/reserved
                confidence = 0.4
                if ip_obj.is_private:
                    confidence = 0.3  # Lower confidence for private IPs
                elif ip_obj.is_global:
                    confidence = 0.7  # Higher for public IPs

                self.findings.append(
                    {
                        "type": "ipv4_address",
                        "severity": "MEDIUM",
                        "confidence": confidence,
                        "message": f"IPv4 address detected: {ip}",
                        "ip": ip,
                        "is_private": ip_obj.is_private,
                        "is_global": ip_obj.is_global,
                        "position": match.start(),
                        "context": context,
                    }
                )

        # IPv6
        for match in self.IPV6_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")
            with suppress(ipaddress.AddressValueError):
                ip6_obj = ipaddress.IPv6Address(ip)

                self.findings.append(
                    {
                        "type": "ipv6_address",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "message": f"IPv6 address detected: {ip}",
                        "ip": ip,
                        "is_private": ip6_obj.is_private,
                        "is_global": ip6_obj.is_global,
                        "position": match.start(),
                        "context": context,
                    }
                )

    def _scan_domains(self, data: bytes, context: str) -> None:
        """Scan for domain name patterns."""
        seen_domains = set()

        # Skip domain detection in binary ML model files to avoid false positives
        # Binary weights can randomly match domain patterns
        if context and any(ext in context.lower() for ext in [".bin", ".pt", ".pth", ".ckpt", ".h5", ".pb", ".onnx"]):
            # For ML model files, only look for very explicit domain references
            # that are unlikely to occur randomly
            explicit_domain_patterns = [
                rb"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}",  # Full URLs only
                # Config-like patterns
                rb'["\'](?:api|webhook|callback|endpoint)["\']:\s*["\'][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}',
            ]

            for pattern in explicit_domain_patterns:
                for match in re.finditer(pattern, data, re.IGNORECASE):
                    domain_match = match.group()
                    if b"://" in domain_match:
                        # Extract domain from URL
                        parts = domain_match.split(b"://", 1)[1].split(b"/")[0]
                        domain = parts.decode("utf-8", errors="ignore").lower()
                    else:
                        domain = match.group().decode("utf-8", errors="ignore").lower()

                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        severity = "INFO" if self._is_informational_domain(domain) else "MEDIUM"
                        confidence = 0.3 if severity == "INFO" else 0.8
                        self.findings.append(
                            {
                                "type": "domain",
                                "severity": severity,
                                "confidence": confidence,
                                "message": f"Domain name detected: {domain}",
                                "domain": domain,
                                "position": match.start(),
                                "context": context,
                            }
                        )
            return

        for match in self.DOMAIN_PATTERN.finditer(data):
            domain = match.group().decode("utf-8", errors="ignore").lower()

            # Skip common false positives
            if domain in seen_domains:
                continue
            if domain.endswith((".pkl", ".pt", ".h5", ".pb", ".onnx", ".json")):
                continue  # File extensions
            if domain in ["numpy.org", "pytorch.org", "tensorflow.org"]:
                continue  # ML framework domains

            # Skip actual layer-name grammar (e.g., layer1.weight), not any
            # attacker-controlled DNS name that happens to contain ML words.
            if _ML_LAYER_DOMAIN_PATTERN.fullmatch(domain):
                continue
            # Bare method calls such as weight.to(device) are code tokens, not DNS names.
            if _has_call_syntax(data, match.start(), len(match.group())):
                continue

            # Skip very short domain names in binary files (likely false positives)
            # e.g., "8.to", "9.cc" are probably random bytes, not real domains
            domain_parts = domain.split(".")
            if len(domain_parts) < 2:
                continue

            # Skip single character subdomains with short TLDs (common false positive in binary data)
            if len(domain_parts) == 2 and len(domain_parts[0]) <= 2 and len(domain_parts[1]) <= 2:
                continue  # Skip patterns like "8.to", "h8.cc", etc.
            tld = domain_parts[-1]
            # Common TLDs (not exhaustive, but covers most)
            valid_tlds = [
                "com",
                "org",
                "net",
                "edu",
                "gov",
                "mil",
                "int",
                "io",
                "co",
                "uk",
                "de",
                "fr",
                "jp",
                "cn",
                "au",
                "us",
                "ru",
                "ch",
                "it",
                "nl",
                "se",
                "no",
                "es",
                "ca",
                "tk",
                "ml",
                "ga",
                "cf",
                "cc",
                "to",
                "pw",
                "ai",
                "app",
                "dev",
                "xyz",
            ]
            if tld not in valid_tlds:
                continue

            seen_domains.add(domain)

            # Check TLD for suspicious domains
            suspicious_tlds = ["tk", "ml", "ga", "cf", "cc", "to", "pw"]

            confidence = 0.3
            if tld in suspicious_tlds:
                confidence = 0.7
            if any(sus in domain for sus in ["malware", "evil", "hack", "exploit"]):
                confidence = 0.9

            if confidence > 0.2:  # Only report domains with reasonable confidence
                severity = "INFO" if self._is_informational_domain(domain) else "MEDIUM"
                if confidence >= 0.7:
                    severity = "HIGH"
                self.findings.append(
                    {
                        "type": "domain_name",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"Domain name detected: {domain}",
                        "domain": domain,
                        "tld": tld,
                        "position": match.start(),
                        "context": context,
                    }
                )

    @classmethod
    def _is_cloud_storage_url(cls, url: str) -> bool:
        """Return whether a URL is already covered by specific informational cloud URL detection."""
        url_bytes = url.encode()
        return any(pattern.fullmatch(url_bytes) for pattern, _, _ in cls.CLOUD_STORAGE_PATTERNS)

    @classmethod
    def _is_informational_domain(cls, domain: str) -> bool:
        """Return whether a generic domain hit is covered by informational model/cloud URL handling."""
        return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in cls.INFORMATIONAL_DOMAIN_SUFFIXES)

    def _scan_network_libraries(self, data: bytes, context: str) -> None:
        """Scan for network library imports."""
        for lib in self.NETWORK_LIBRARIES:
            for pattern in self.NETWORK_LIBRARY_PATTERNS[lib]:
                for match_index in _iter_pattern_matches(data, pattern):
                    if _is_doc_only_network_reference(
                        data,
                        match_index=match_index,
                        token_len=len(pattern),
                        context=context,
                        requires_call=False,
                    ):
                        continue

                    confidence = 0.7
                    severity = "HIGH"

                    # Some libraries are more suspicious than others
                    if lib in [b"socket", b"paramiko", b"pycurl"]:
                        confidence = 0.8
                        severity = "CRITICAL"

                    self.findings.append(
                        {
                            "type": "network_library",
                            "severity": severity,
                            "confidence": confidence,
                            "message": f"Network library detected: {lib.decode()}",
                            "library": lib.decode(),
                            "pattern": pattern.decode("utf-8", errors="ignore"),
                            "context": context,
                        }
                    )
                    break  # One finding per library
                else:
                    continue
                break

    def _scan_network_functions(self, data: bytes, context: str) -> None:
        """Scan for network function calls."""
        for func in self.NETWORK_FUNCTIONS:
            for idx in _iter_pattern_matches(data, func):
                if _is_doc_only_network_reference(
                    data,
                    match_index=idx,
                    token_len=len(func),
                    context=context,
                    requires_call=True,
                ):
                    continue

                # Try to get some context around the function call
                start = max(0, idx - 50)
                end = min(len(data), idx + 100)
                snippet = data[start:end].decode("utf-8", errors="ignore")

                confidence = 0.6
                severity = "HIGH"

                # Higher confidence for certain functions
                if b"socket.connect" in func or b"requests." in func:
                    confidence = 0.8
                    severity = "CRITICAL"

                self.findings.append(
                    {
                        "type": "network_function",
                        "severity": severity,
                        "confidence": confidence,
                        "message": f"Network function call detected: {func.decode()}",
                        "function": func.decode(),
                        "snippet": snippet,
                        "context": context,
                    }
                )
                break

    def _scan_cc_patterns(self, data: bytes, context: str) -> None:
        """Scan for command & control patterns."""
        lowered_data = data.lower()
        for pattern in self.cc_patterns:
            idx = lowered_data.find(pattern)
            if idx < 0:
                continue

            # Get context
            start = max(0, idx - 30)
            end = min(len(data), idx + len(pattern) + 30)
            snippet = data[start:end].decode("utf-8", errors="ignore")

            confidence = 0.8
            severity = "CRITICAL"

            # Very suspicious patterns
            if pattern in [b"malware", b"backdoor", b"trojan", b"botnet"]:
                confidence = 0.95

            self.findings.append(
                {
                    "type": "cc_pattern",
                    "severity": severity,
                    "confidence": confidence,
                    "message": f"C&C pattern detected: {pattern.decode()}",
                    "pattern": pattern.decode(),
                    "snippet": snippet,
                    "context": context,
                }
            )

    def _scan_suspicious_ports(self, data: bytes, context: str) -> None:
        """Scan for references to suspicious ports."""
        ml_extensions = [
            ".bin",
            ".pt",
            ".pth",
            ".ckpt",
            ".h5",
            ".pb",
            ".onnx",
            ".safetensors",
            ".pkl",
            ".pickle",
            ".joblib",
        ]
        is_ml_model = context and any(ext in context.lower() for ext in ml_extensions)

        # For ML models, we need to be much more conservative to avoid false positives
        # Binary model weights can contain random byte sequences that match port patterns
        if is_ml_model:
            # Only scan for very explicit network patterns in ML models
            # Skip port scanning for pure binary model files to avoid false positives
            self._scan_explicit_network_patterns_in_ml_models(data, context)
            return

        # For non-ML files, use the original port detection logic
        for port in self.SUSPICIOUS_PORTS:
            for pattern_bytes in self.PORT_PATTERNS[port]:
                if pattern_bytes in data:
                    port_name = self._get_port_name(port)

                    self.findings.append(
                        {
                            "type": "suspicious_port",
                            "severity": "MEDIUM",
                            "confidence": 0.6,
                            "message": f"Suspicious port detected: {port} ({port_name})",
                            "port": port,
                            "service": port_name,
                            "context": context,
                        }
                    )
                    break

    def _scan_explicit_network_patterns_in_ml_models(self, data: bytes, context: str) -> None:
        """Scan for very explicit network patterns in ML models with high confidence."""
        # Only look for very explicit network communication patterns that are unlikely
        # to occur in legitimate model weights. These patterns require clear context.

        explicit_network_patterns = [
            # Very explicit URL patterns that are unlikely in model weights
            (rb"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s]*", "url"),
            # Explicit socket connection patterns with clear text context
            (rb'socket\.connect\s*\(\s*["\']?[a-zA-Z0-9.-]+["\']?\s*,\s*\d+', "socket_connection"),
            # Clear HTTP request patterns
            (rb"(GET|POST|PUT|DELETE)\s+\/[^\s]*\s+HTTP\/1\.[01]", "http_request"),
            # Explicit network library imports in clear text
            (rb"import\s+(socket|urllib|requests|httplib)", "network_import"),
        ]

        for pattern, pattern_type in explicit_network_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.finditer(data)

            for match in matches:
                if pattern_type == "network_import" and _is_doc_only_network_reference(
                    data,
                    match_index=match.start(),
                    token_len=len(match.group()),
                    context=context,
                    requires_call=False,
                ):
                    continue

                # Get context around the match to validate it's not in binary weights
                start_pos = max(0, match.start() - 100)
                end_pos = min(len(data), match.end() + 100)
                context_data = data[start_pos:end_pos]

                # Check if this looks like legitimate text (not binary weights)
                try:
                    context_str = context_data.decode("utf-8", errors="strict")
                    # If we can decode it as UTF-8, it's likely text-based and suspicious
                    printable_ratio = sum(c.isprintable() for c in context_str) / len(context_str)

                    if printable_ratio > 0.7:  # High ratio of printable characters
                        matched_text = match.group().decode("utf-8", errors="ignore")
                        self.findings.append(
                            {
                                "type": "explicit_network_pattern",
                                "severity": "CRITICAL",
                                "confidence": 0.95,
                                "message": f"Explicit network pattern in ML model: {matched_text[:100]}",
                                "pattern_type": pattern_type,
                                "matched_text": matched_text[:200],
                                "context": context,
                            }
                        )
                except UnicodeDecodeError:
                    # If it can't be decoded as UTF-8, it's likely binary data
                    # Skip to avoid false positives in model weights
                    continue

    def _check_blacklist(self, data: bytes, context: str) -> None:
        """Check against blacklisted domains/IPs."""
        if not self.blacklisted_domains:
            return

        lowered_data = data.lower()
        for blacklisted in self.blacklisted_domains:
            if blacklisted in lowered_data:
                self.findings.append(
                    {
                        "type": "blacklisted_domain",
                        "severity": "CRITICAL",
                        "confidence": 1.0,
                        "message": f"Blacklisted domain detected: {blacklisted.decode()}",
                        "domain": blacklisted.decode(),
                        "context": context,
                    }
                )

    def _get_port_name(self, port: int) -> str:
        """Get common service name for a port."""
        return self.PORT_NAMES.get(port, "Unknown")


def detect_network_communication(file_path: str, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Convenience function to scan a file for network communication patterns.

    Args:
        file_path: Path to the file to scan
        config: Optional configuration dictionary

    Returns:
        List of findings
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        detector = NetworkCommDetector(config)
        return detector.scan(data, context=file_path)

    except FileNotFoundError:
        return [{"type": "error", "severity": "ERROR", "message": f"File not found: {file_path}"}]
    except Exception as e:
        return [{"type": "error", "severity": "ERROR", "message": f"Error scanning file: {e!s}"}]
