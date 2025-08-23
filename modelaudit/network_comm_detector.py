"""Network Communication Detection for ML models.

This module detects potential network communication capabilities in model files
that could be used for data exfiltration or command & control operations.
"""

import ipaddress
import re
from typing import Any, ClassVar, Optional, Union


class NetworkCommDetector:
    """Detector for network communication patterns in model files."""

    # URL patterns - also match ftp, ftps, ssh, etc.
    URL_PATTERN = re.compile(
        rb"(?:https?|ftp|ftps|ssh|telnet|ws|wss)://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+", re.IGNORECASE
    )

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

    # Known C&C patterns
    CC_PATTERNS: ClassVar[list[bytes]] = [
        b"beacon_url",
        b"callback_url",
        b"c2_server",
        b"command_server",
        b"exfil_endpoint",
        b"report_url",
        b"telemetry_endpoint",
        b"update_server",
        b"download_url",
        b"upload_endpoint",
        b"malware",
        b"backdoor",
        b"trojan",
        b"botnet",
        b"zombie",
        b"phone_home",
        b"check_in",
        b"heartbeat",
        b"keepalive",
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

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize the detector with optional configuration."""
        self.config = config or {}
        self.findings: list[dict[str, Any]] = []

        # Clone class-level patterns to avoid cross-instance leakage
        self.cc_patterns: list[bytes] = self.CC_PATTERNS.copy()
        self.blacklisted_domains: list[bytes] = self.BLACKLISTED_DOMAINS.copy()

        def _to_lower_bytes(value: Union[bytes, str]) -> bytes:
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

            # Calculate confidence based on URL characteristics
            confidence = 0.5
            if any(pattern in url.lower() for pattern in ["eval", "exec", "cmd", "shell"]):
                confidence = 0.9
            elif any(port in url for port in [":1337", ":4444", ":31337"]):
                confidence = 0.8
            elif "://" in url and not url.startswith(("http://", "https://")):
                confidence = 0.7

            self.findings.append(
                {
                    "type": "url_detected",
                    "severity": "HIGH" if confidence > 0.7 else "MEDIUM",
                    "confidence": confidence,
                    "message": f"URL detected in model: {url[:100]}",
                    "url": url,
                    "position": match.start(),
                    "context": context,
                }
            )

    def _scan_ip_addresses(self, data: bytes, context: str) -> None:
        """Scan for IP address patterns."""
        # IPv4
        for match in self.IPV4_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")

            # Check for common false positives (version numbers)
            # Look at surrounding context
            start = max(0, match.start() - 20)
            end = min(len(data), match.end() + 20)
            surrounding = data[start:end].decode("utf-8", errors="ignore").lower()

            # Skip if it looks like a version number
            if any(word in surrounding for word in ["version", "ver", "v.", "release", "build"]):
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
            try:
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
            except ipaddress.AddressValueError:
                pass  # Not a valid IP

        # IPv6
        for match in self.IPV6_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")
            try:
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
            except ipaddress.AddressValueError:
                pass

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
                        self.findings.append(
                            {
                                "type": "domain",
                                "severity": "MEDIUM",
                                "confidence": 0.8,
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

            # Skip ML model layer names (e.g., layer1.weight, conv2d.bias)
            if any(pattern in domain for pattern in ["layer", "weight", "bias", "conv", "bn", "norm", "fc", "dense"]):
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
                self.findings.append(
                    {
                        "type": "domain_name",
                        "severity": "MEDIUM" if confidence < 0.7 else "HIGH",
                        "confidence": confidence,
                        "message": f"Domain name detected: {domain}",
                        "domain": domain,
                        "tld": tld,
                        "position": match.start(),
                        "context": context,
                    }
                )

    def _scan_network_libraries(self, data: bytes, context: str) -> None:
        """Scan for network library imports."""
        for lib in self.NETWORK_LIBRARIES:
            # Look for import statements
            patterns = [b"import " + lib, b"from " + lib, lib + b".connect", lib + b".request", lib + b".__init__"]

            for pattern in patterns:
                if pattern in data:
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

    def _scan_network_functions(self, data: bytes, context: str) -> None:
        """Scan for network function calls."""
        for func in self.NETWORK_FUNCTIONS:
            if func in data:
                # Try to get some context around the function call
                idx = data.find(func)
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

    def _scan_cc_patterns(self, data: bytes, context: str) -> None:
        """Scan for command & control patterns."""
        for pattern in self.cc_patterns:
            if pattern in data.lower():
                # Get context
                idx = data.lower().find(pattern)
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
        is_ml_model = context and any(
            ext in context.lower() for ext in [".bin", ".pt", ".pth", ".ckpt", ".h5", ".pb", ".onnx", ".safetensors"]
        )

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
            import re

            regex = re.compile(pattern, re.IGNORECASE)
            matches = regex.finditer(data)

            for match in matches:
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
        for blacklisted in self.blacklisted_domains:
            if blacklisted in data.lower():
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
        port_names = {
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
        return port_names.get(port, "Unknown")


def detect_network_communication(file_path: str, config: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
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
