"""Scanner for text-based ML files like README.md and vocab.txt."""

import os
import re
from typing import Any, ClassVar

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
        "license.txt",
        "model_card.md",
        "readme.md",
        "readme.markdown",
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
            "readme.txt",
            "readme.markdown",
            "vocab.txt",
            "vocabulary.txt",
            "tokens.txt",
            "tokenizer.txt",
            "labels.txt",
            "classes.txt",
            "model_card.md",
            "license.txt",
            "license.md",
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
        return filename in DOCUMENTATION_TEXT_FILENAMES or os.path.splitext(filename)[1] in {
            ".markdown",
            ".md",
            ".rst",
        }

    @staticmethod
    def _is_passive_data_sidecar(path: str) -> bool:
        filename = os.path.basename(path).lower()
        return filename in PASSIVE_DATA_TEXT_FILENAMES or filename.startswith(PASSIVE_DATA_TEXT_PREFIXES)

    @staticmethod
    def _finding_line(payload: bytes, finding: dict[str, Any]) -> bytes | None:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return None
        line_start = payload.rfind(b"\n", 0, position) + 1
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            line_end = len(payload)
        return payload[line_start:line_end].strip()

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
    def _passive_documentation_network_limit(cls, path: str, finding_limit: dict[str, Any]) -> bool:
        return (
            cls._is_documentation_sidecar(path)
            and finding_limit.get("truncated_finding_type") in PASSIVE_NETWORK_FINDING_TYPES
        )

    @classmethod
    def _downgrade_passive_network_findings(
        cls,
        path: str,
        payload: bytes,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        documentation_sidecar = cls._is_documentation_sidecar(path)
        passive_data_sidecar = cls._is_passive_data_sidecar(path)
        if not documentation_sidecar and not passive_data_sidecar:
            return findings
        return [
            {**finding, "severity": "INFO"}
            if finding.get("type") in PASSIVE_NETWORK_FINDING_TYPES
            and (documentation_sidecar or (passive_data_sidecar and cls._is_bare_data_network_token(payload, finding)))
            else finding
            for finding in findings
        ]

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
                network_findings = self._downgrade_passive_network_findings(path, inspected_payload, network_findings)
                self.add_network_communication_findings(network_findings, result, context=path)
                if finding_limit is not None:
                    if self._passive_documentation_network_limit(path, finding_limit):
                        result.add_check(
                            name="Network Communication Reporting Limit",
                            passed=False,
                            message="Passive documentation network references exceeded the reporting limit",
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
