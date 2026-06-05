"""Scanner for text-based ML files like README.md and vocab.txt."""

import os
import re
from typing import Any, ClassVar
from urllib.parse import urlsplit

from modelaudit.core_results import mark_operational_scan_error
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from modelaudit.scanners.base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

TEXT_CONTENT_SECURITY_SCAN_INCOMPLETE_REASON = "text_content_security_scan_incomplete"
TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON = "text_content_security_detector_failed"
TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON = "text_content_security_finding_limit"
DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES = 100 * 1024 * 1024
DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS = 1024
DETECTOR_FINDING_LIMIT_TYPE = "detector_finding_limit"
DOCUMENTATION_TEXT_FILENAMES = frozenset(
    {
        "license.md",
        "license.rst",
        "license.txt",
        "model_card.md",
        "model_card.rst",
        "readme.md",
        "readme.markdown",
        "readme.rst",
        "readme.txt",
    }
)
PASSIVE_NETWORK_FINDING_TYPES = frozenset(
    {
        "cloud_storage_url",
        "domain",
        "domain_name",
        "ipv4_address",
        "ipv6_address",
        "url_detected",
    }
)
PASSIVE_DATA_TEXT_FILENAMES = frozenset({"classes.txt"})
PASSIVE_DATA_TEXT_PREFIXES = ("label", "token", "vocab")
BARE_NETWORK_URL_TOKEN_PATTERN = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://\S+")
BARE_NETWORK_IPV4_TOKEN_PATTERN = re.compile(
    rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
BARE_NETWORK_IPV6_TOKEN_PATTERN = re.compile(rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
BARE_NETWORK_DOMAIN_TOKEN_PATTERN = re.compile(rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
BARE_NETWORK_TOKEN_PATTERNS = (
    BARE_NETWORK_URL_TOKEN_PATTERN,
    BARE_NETWORK_IPV4_TOKEN_PATTERN,
    BARE_NETWORK_IPV6_TOKEN_PATTERN,
    BARE_NETWORK_DOMAIN_TOKEN_PATTERN,
)
MAX_TEXT_FINDING_CONTEXT_BYTES = 4096
DOCUMENTATION_CODE_ASSIGNMENT_PATTERN = re.compile(rb"(?:^|[\s{[(,;])[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*[rubfRUBF]*[\"']?$")
DOCUMENTATION_CODE_CALL_PATTERN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()]{0,4096}[rubfRUBF]*[\"']$")
DOCUMENTATION_ENCLOSING_CALL_PATTERN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()\n]{0,4096}$")
DOCUMENTATION_CONFIG_MAPPING_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])(?:url|uri|endpoint|host|server|callback|webhook)(?:[_-][A-Za-z0-9_.-]+)*\s*:\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_CONFIG_TAG_PATTERN = re.compile(
    rb"<(?:url|uri|endpoint|host|server|callback|webhook)(?:[-_:][A-Za-z0-9_.-]+)*>\s*$",
    re.IGNORECASE,
)
DOCUMENTATION_LAMBDA_PATTERN = re.compile(rb"\blambda\b[^:\n]{0,256}:\s*[^\n]*$", re.IGNORECASE)
DOCUMENTATION_SHELL_COMMAND_PATTERN = re.compile(
    rb"^\s*(?:[-*+]\s+)?(?:(?:[$>#]|[A-Za-z0-9._-]+[$#])\s*)?"
    rb"(?:(?:bash|sh|zsh)\s+-c\s+[\"']?\s*)?"
    rb"(?:(?:curl|fetch|invoke-webrequest|iwr|wget)\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'])"
    rb"|(?:powershell(?:\.exe)?|pwsh)\b\s+-[A-Za-z])",
    re.IGNORECASE,
)
DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN = re.compile(
    rb"(?:^|[;&|]\s*)(?:(?:curl|fetch|invoke-webrequest|iwr|wget)\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'])"
    rb"|(?:powershell(?:\.exe)?|pwsh)\b\s+-[A-Za-z])",
    re.IGNORECASE,
)
DOCUMENTATION_SUSPICIOUS_NETWORK_LABEL_PATTERN = re.compile(
    rb"\b(?:beacon|callback|c2|command(?:[_ -]+and[_ -]+control)?|exfil(?:tration)?|phone[_ -]+home|webhook)\b"
    rb"[^\n]{0,32}:\s*$",
    re.IGNORECASE,
)
BENIGN_DOCUMENTATION_CC_PATTERN = re.compile(
    rb"(?:"
    rb"\b(?:not|no|without)\s+(?:a\s+)?(?:known\s+)?(?:malware|backdoor|trojan|botnet|zombie)\b"
    rb"|\b(?:malware|backdoor|trojan|botnet|zombie)[ -]free\b"
    rb"|\b(?:malware|backdoor|trojan|botnet|zombie)\s+"
    rb"(?:analysis|benchmark|classification|classifier|dataset|defen[cs]e|detection|mitigation|research|resistance|robustness|testing)\b"
    rb"|\b(?:detect(?:ing|ion|s)?|mitigat(?:e|ing|ion)|resistan(?:ce|t)|robust(?:ness)?)\s+"
    rb"(?:malware|backdoor|trojan|botnet|zombie)\b"
    rb")",
    re.IGNORECASE,
)
GENERIC_CC_PROSE_PATTERNS = frozenset({"backdoor", "botnet", "malware", "trojan", "zombie"})
REQUIREMENTS_URL_DIRECTIVE_PATTERN = re.compile(
    rb"^(?:(?:--index-url|--extra-index-url|--find-links)(?:\s+|=)"
    rb"|(?:-i|-f)(?:\s+|(?=[A-Za-z][A-Za-z0-9+.-]*://)))",
    re.IGNORECASE,
)
REQUIREMENTS_DIRECT_REFERENCE_PATTERN = re.compile(
    rb"^[A-Za-z0-9_.-]+(?:\[[^\]\r\n]+\])?\s*@\s*[A-Za-z][A-Za-z0-9+.-]*://",
    re.IGNORECASE,
)
TRUSTED_REQUIREMENTS_HOSTS = frozenset(
    {
        "download.pytorch.org",
        "files.pythonhosted.org",
        "pypi.org",
        "pypi.python.org",
    }
)


class TextScanner(BaseScanner):
    """Scanner for text-based ML-related files."""

    name = "text"
    supported_extensions: ClassVar[list[str]] = [".txt", ".md", ".markdown", ".rst"]
    default_max_file_read_size = DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the scanner with optional configuration."""
        super().__init__(config)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check for ML-related text files
        filename = os.path.basename(path).lower()
        ml_text_files = {
            "readme.md",
            "readme.rst",
            "readme.txt",
            "readme.markdown",
            "vocab.txt",
            "vocabulary.txt",
            "tokens.txt",
            "tokenizer.txt",
            "labels.txt",
            "classes.txt",
            "model_card.md",
            "model_card.rst",
            "license.txt",
            "license.md",
            "license.rst",
            "requirements.txt",
        }

        return filename in ml_text_files or any(filename.startswith(prefix) for prefix in ["vocab", "token", "label"])

    @staticmethod
    def _get_file_size(path: str) -> int:
        """Return file size for bounded text classification."""
        return os.path.getsize(path)

    def _get_content_security_scan_bytes(self) -> int:
        return self._normalize_positive_int_config(
            self.config.get("text_content_scan_bytes", self.max_file_read_size),
            DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES,
        )

    def _get_content_security_max_findings(self) -> int:
        return self._normalize_positive_int_config(
            self.config.get("text_content_max_findings", DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS),
            DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS,
        )

    @staticmethod
    def _is_documentation_sidecar(path: str) -> bool:
        filename = os.path.basename(path).lower()
        return filename in DOCUMENTATION_TEXT_FILENAMES

    @staticmethod
    def _is_passive_data_sidecar(path: str) -> bool:
        filename = os.path.basename(path).lower()
        return filename in PASSIVE_DATA_TEXT_FILENAMES or filename.startswith(PASSIVE_DATA_TEXT_PREFIXES)

    @staticmethod
    def _finding_line_parts(payload: bytes, finding: dict[str, Any]) -> tuple[bytes, int] | None:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return None
        line_start = max(payload.rfind(b"\n", 0, position) + 1, position - MAX_TEXT_FINDING_CONTEXT_BYTES)
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            line_end = len(payload)
        line_end = min(line_end, position + MAX_TEXT_FINDING_CONTEXT_BYTES)
        return payload[line_start:line_end], position - line_start

    @classmethod
    def _finding_line(cls, payload: bytes, finding: dict[str, Any]) -> bytes | None:
        line_parts = cls._finding_line_parts(payload, finding)
        return line_parts[0].strip() if line_parts is not None else None

    @staticmethod
    def _finding_line_prefix_is_truncated(payload: bytes, finding: dict[str, Any]) -> bool:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return False
        return position - (payload.rfind(b"\n", 0, position) + 1) > MAX_TEXT_FINDING_CONTEXT_BYTES

    @staticmethod
    def _documentation_line_is_code_shaped(line: bytes, position: int) -> bool:
        prefix = line[:position]
        stripped = line.lstrip()
        return (
            DOCUMENTATION_SHELL_COMMAND_PATTERN.match(stripped) is not None
            or DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN.search(prefix) is not None
            or DOCUMENTATION_SUSPICIOUS_NETWORK_LABEL_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CODE_ASSIGNMENT_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
            or DOCUMENTATION_LAMBDA_PATTERN.search(prefix) is not None
            or stripped.startswith((b"import ", b"from ", b"def ", b"class "))
        )

    @classmethod
    def _documentation_finding_is_actionable(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        if cls._finding_line_prefix_is_truncated(payload, finding):
            return True
        line_parts = cls._finding_line_parts(payload, finding)
        if line_parts is not None and cls._documentation_line_is_code_shaped(*line_parts):
            return True
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return False
        prefix = payload[max(0, position - MAX_TEXT_FINDING_CONTEXT_BYTES) : position]
        return (
            DOCUMENTATION_CODE_ASSIGNMENT_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
        )

    @classmethod
    def _retarget_documentation_finding(
        cls,
        payload: bytes,
        lowered_payload: bytes,
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        finding_type = finding.get("type")
        token = finding.get("function") if finding_type == "network_function" else finding.get("pattern")
        if finding_type not in {"network_function", "cc_pattern"} or not isinstance(token, str) or not token:
            return finding

        token_bytes = token.encode().lower()
        search_start = 0
        while True:
            position = lowered_payload.find(token_bytes, search_start)
            if position < 0:
                return finding
            candidate = {**finding, "position": position}
            if finding_type == "network_function":
                actionable = not cls._documentation_network_function_is_prose(payload, candidate)
            else:
                actionable = not cls._documentation_cc_finding_is_benign_prose(payload, candidate)
            if actionable:
                candidate.pop("snippet", None)
                return candidate
            search_start = position + len(token_bytes)

    @classmethod
    def _documentation_network_function_is_prose(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        line_parts = cls._finding_line_parts(payload, finding)
        function = finding.get("function")
        if (
            line_parts is None
            or not isinstance(function, str)
            or cls._finding_line_prefix_is_truncated(payload, finding)
        ):
            return False
        line, position = line_parts
        cursor = position + len(function.encode())
        while cursor < len(line) and line[cursor : cursor + 1] in {b" ", b"\t"}:
            cursor += 1
        return (
            (cursor >= len(line) or line[cursor : cursor + 1] != b"(")
            and not cls._documentation_line_is_code_shaped(
                line,
                position,
            )
            and DOCUMENTATION_ENCLOSING_CALL_PATTERN.search(line[:position]) is None
        )

    @classmethod
    def _documentation_cc_finding_is_benign_prose(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        pattern = finding.get("pattern")
        line_parts = cls._finding_line_parts(payload, finding)
        if (
            pattern not in GENERIC_CC_PROSE_PATTERNS
            or line_parts is None
            or cls._finding_line_prefix_is_truncated(payload, finding)
        ):
            return False
        line, position = line_parts
        return not cls._documentation_line_is_code_shaped(line, position) and any(
            match.start() <= position < match.end() for match in BENIGN_DOCUMENTATION_CC_PATTERN.finditer(line)
        )

    @classmethod
    def _standard_requirements_network_finding(cls, path: str, payload: bytes, finding: dict[str, Any]) -> bool:
        if os.path.basename(path).lower() != "requirements.txt":
            return False
        line = cls._finding_line(payload, finding)
        if line is None:
            return False
        url = finding.get("url")
        domain = finding.get("domain")
        try:
            parsed_url = urlsplit(url) if isinstance(url, str) else None
            hostname = parsed_url.hostname if parsed_url is not None else domain if isinstance(domain, str) else None
            url_port = parsed_url.port if parsed_url is not None else None
        except ValueError:
            return False
        if hostname is None or hostname.casefold() not in TRUSTED_REQUIREMENTS_HOSTS:
            return False
        if parsed_url is not None and (parsed_url.scheme.casefold() != "https" or url_port not in {None, 443}):
            return False
        stripped = line.strip()
        return (
            REQUIREMENTS_URL_DIRECTIVE_PATTERN.match(stripped) is not None
            or REQUIREMENTS_DIRECT_REFERENCE_PATTERN.match(stripped) is not None
            or BARE_NETWORK_URL_TOKEN_PATTERN.fullmatch(stripped) is not None
        )

    @classmethod
    def _is_bare_data_network_token(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        line = cls._finding_line(payload, finding)
        if not line or b"@" in line:
            return False
        if BARE_NETWORK_URL_TOKEN_PATTERN.fullmatch(line):
            return True
        line_text = line.decode("utf-8", errors="ignore").casefold()
        return any(
            isinstance(value, str) and line_text == value.casefold()
            for value in (finding.get("domain"), finding.get("ip"))
        )

    @staticmethod
    def _all_network_candidate_lines_are_bare(payload: bytes) -> bool:
        for line in payload.splitlines():
            stripped = line.strip()
            if not stripped or not any(pattern.search(stripped) for pattern in BARE_NETWORK_TOKEN_PATTERNS):
                continue
            if b"@" in stripped or not any(pattern.fullmatch(stripped) for pattern in BARE_NETWORK_TOKEN_PATTERNS):
                return False
        return True

    @staticmethod
    def _split_detector_finding_limit(
        findings: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        limit_finding = next(
            (finding for finding in findings if finding.get("type") == DETECTOR_FINDING_LIMIT_TYPE),
            None,
        )
        return (
            [finding for finding in findings if finding.get("type") != DETECTOR_FINDING_LIMIT_TYPE],
            limit_finding,
        )

    @classmethod
    def _passive_network_reporting_limit(
        cls,
        path: str,
        payload: bytes,
        findings: list[dict[str, Any]],
        finding_limit: dict[str, Any],
    ) -> bool:
        if finding_limit.get("truncated_finding_type") not in PASSIVE_NETWORK_FINDING_TYPES:
            return False
        truncated_finding = finding_limit.get("truncated_finding")
        return (
            cls._is_passive_data_sidecar(path)
            and all(finding.get("severity") == "INFO" for finding in findings)
            and isinstance(truncated_finding, dict)
            and cls._is_bare_data_network_token(payload, truncated_finding)
            and cls._all_network_candidate_lines_are_bare(payload)
        )

    @classmethod
    def _sidecar_network_finding_is_informational(
        cls,
        path: str,
        payload: bytes,
        finding: dict[str, Any],
    ) -> bool:
        if cls._is_documentation_sidecar(path):
            finding_type = finding.get("type")
            return (
                (
                    finding_type in PASSIVE_NETWORK_FINDING_TYPES
                    and not cls._documentation_finding_is_actionable(payload, finding)
                )
                or (
                    finding_type == "network_function"
                    and cls._documentation_network_function_is_prose(payload, finding)
                )
                or (finding_type == "cc_pattern" and cls._documentation_cc_finding_is_benign_prose(payload, finding))
            )
        if cls._is_passive_data_sidecar(path):
            return finding.get("type") in PASSIVE_NETWORK_FINDING_TYPES and cls._is_bare_data_network_token(
                payload,
                finding,
            )
        return finding.get("type") in PASSIVE_NETWORK_FINDING_TYPES and cls._standard_requirements_network_finding(
            path,
            payload,
            finding,
        )

    @classmethod
    def _downgrade_sidecar_network_findings(
        cls,
        path: str,
        payload: bytes,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        classified_findings: list[dict[str, Any]] = []
        documentation_sidecar = cls._is_documentation_sidecar(path)
        lowered_payload = payload.lower() if documentation_sidecar else b""
        for finding in findings:
            if documentation_sidecar:
                finding = cls._retarget_documentation_finding(payload, lowered_payload, finding)
            if cls._sidecar_network_finding_is_informational(path, payload, finding):
                finding = {**finding, "severity": "INFO"}
            classified_findings.append(finding)
        return classified_findings

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_metadata_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "text_metadata_read_failed")
        mark_operational_scan_error(result, "text_metadata_read_failed")
        result.add_check(
            name="Text File Metadata Read",
            passed=False,
            message=f"Unable to inspect text file metadata: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "text_metadata_read_failed",
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _mark_content_security_scan_incomplete(
        result: ScanResult,
        path: str,
        *,
        reason: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name="Text Content Security Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            details={
                **details,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    def _run_content_security_checks(self, path: str, result: ScanResult, file_size: int) -> int:
        check_secrets = self._get_bool_config("check_secrets", True)
        check_network = self._get_bool_config("check_network_comm", True)
        if not check_secrets:
            result.metadata.setdefault("disabled_checks", []).append("Embedded Secrets Detection")
        if not check_network:
            result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")
        if not check_secrets and not check_network:
            return 0

        read_limit = self._get_content_security_scan_bytes()
        max_findings = self._get_content_security_max_findings()
        try:
            with open(path, "rb") as file_obj:
                payload = file_obj.read(read_limit + 1)
        except OSError as error:
            self._mark_content_security_scan_incomplete(
                result,
                path,
                reason="text_content_read_failed",
                message=f"Unable to read text content for security detectors: {error!s}",
                details={
                    "exception": str(error),
                    "exception_type": type(error).__name__,
                    "file_size": file_size,
                    "read_limit": read_limit,
                },
            )
            return 0

        truncated = len(payload) > read_limit
        inspected_payload = payload[:read_limit]
        inspected_bytes = len(inspected_payload)

        detector_incomplete = False
        if check_secrets:
            try:
                secret_findings = self.collect_embedded_secret_findings(
                    inspected_payload,
                    path,
                    raise_on_error=True,
                    max_findings=max_findings,
                )
                secret_findings, finding_limit = self._split_detector_finding_limit(secret_findings)
                if secret_findings or not truncated:
                    self.add_embedded_secret_findings(secret_findings, result, context=path)
                if finding_limit is not None:
                    detector_incomplete = True
                    self._mark_content_security_scan_incomplete(
                        result,
                        path,
                        reason=TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON,
                        message="Embedded secret findings exceeded the configured reporting limit",
                        details=finding_limit,
                    )
            except Exception as error:
                detector_incomplete = True
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Embedded secret detector failed for text content: {error!s}",
                    details={
                        "detector": "secrets",
                        "exception": str(error),
                        "exception_type": type(error).__name__,
                    },
                )

        if check_network:
            try:
                network_findings = self.collect_network_communication_findings(
                    inspected_payload,
                    path,
                    raise_on_error=True,
                    max_findings=max_findings,
                )
                network_findings, finding_limit = self._split_detector_finding_limit(network_findings)
                network_findings = self._downgrade_sidecar_network_findings(path, inspected_payload, network_findings)
                if network_findings or not truncated:
                    self.add_network_communication_findings(network_findings, result, context=path)
                if finding_limit is not None:
                    if self._passive_network_reporting_limit(
                        path,
                        inspected_payload,
                        network_findings,
                        finding_limit,
                    ):
                        result.add_check(
                            name="Network Communication Reporting Limit",
                            passed=False,
                            message="Passive network references exceeded the reporting limit",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                **finding_limit,
                                "analysis_incomplete": False,
                                "reporting_incomplete": True,
                            },
                        )
                    else:
                        detector_incomplete = True
                        self._mark_content_security_scan_incomplete(
                            result,
                            path,
                            reason=TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON,
                            message="Network communication findings exceeded the configured reporting limit",
                            details=finding_limit,
                        )
            except Exception as error:
                detector_incomplete = True
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Network communication detector failed for text content: {error!s}",
                    details={
                        "detector": "network_communication",
                        "exception": str(error),
                        "exception_type": type(error).__name__,
                    },
                )

        if truncated:
            self._mark_content_security_scan_incomplete(
                result,
                path,
                reason=TEXT_CONTENT_SECURITY_SCAN_INCOMPLETE_REASON,
                message=f"Text content security scan truncated at configured limit ({read_limit} bytes)",
                details={
                    "file_size": file_size,
                    "read_limit": read_limit,
                    "inspected_bytes": inspected_bytes,
                    "enabled_detectors": [
                        detector
                        for detector, enabled in (("secrets", check_secrets), ("network_communication", check_network))
                        if enabled
                    ],
                },
            )
        elif not detector_incomplete:
            result.add_check(
                name="Text Content Security Coverage",
                passed=True,
                message="Text content security detectors completed",
                location=path,
                details={
                    "file_size": file_size,
                    "read_limit": read_limit,
                    "inspected_bytes": inspected_bytes,
                },
            )

        return inspected_bytes

    def scan(self, path: str) -> ScanResult:
        """Scan a text file for security issues."""
        result = self._create_scan_result_after_preflight(path, check_size_limit=False)
        if not result.success:
            if self._is_unreadable_path_result(result):
                return self._finish_metadata_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return result

        try:
            # Get file size
            file_size = self._get_file_size(path)
            result.metadata["file_size"] = file_size

            # Check if file exceeds expected size for text files
            if file_size > 100 * 1024 * 1024:  # 100MB
                result.add_check(
                    name="File Size Check",
                    passed=False,
                    message=f"Unusually large text file: {file_size / (1024 * 1024):.1f}MB",
                    rule_code="S902",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"file_size": file_size},
                )
            else:
                result.add_check(
                    name="File Size Check",
                    passed=True,
                    message="Text file size is reasonable",
                    location=path,
                    details={"file_size": file_size},
                    rule_code=None,  # Passing check
                )

            filename = os.path.basename(path).lower()

            # Identify file type - these are informational checks, not security issues
            if filename in ["readme.md", "readme.txt", "readme.markdown", "model_card.md"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Model documentation file",
                    location=path,
                    details={"file_type": "documentation"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["vocab.txt", "vocabulary.txt", "tokens.txt", "tokenizer.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Tokenizer vocabulary file",
                    location=path,
                    details={"file_type": "vocabulary"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["labels.txt", "classes.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Classification labels file",
                    location=path,
                    details={"file_type": "labels"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["license.txt", "license.md"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="License file",
                    location=path,
                    details={"file_type": "license"},
                    rule_code=None,  # Passing check
                )
            elif filename == "requirements.txt":
                # Could scan for suspicious dependencies in the future
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Python requirements file",
                    location=path,
                    details={"file_type": "requirements"},
                    rule_code=None,  # Passing check
                )
            else:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="ML-related text file",
                    location=path,
                    details={"file_type": "text"},
                    rule_code=None,  # Passing check
                )

            result.bytes_scanned = self._run_content_security_checks(path, result, file_size)
            result.finish(
                success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
            )

        except OSError as e:
            self._finish_metadata_read_failure(result, path, e)
        except Exception as e:
            result.add_check(
                name="Text File Scan",
                passed=False,
                message=f"Error scanning text file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e)},
                rule_code="S902",
            )
            result.finish(success=False)

        return result
