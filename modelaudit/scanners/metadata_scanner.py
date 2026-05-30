"""Scanner for model metadata files (README, model cards, documentation)."""

import logging
from pathlib import Path
from typing import ClassVar
from urllib.parse import unquote, urlparse, urlunparse

from ..core_results import mark_operational_scan_error
from ..scanner_results import mark_inconclusive_scan_result, scan_result_has_inconclusive_outcome
from .base import BaseScanner, CheckStatus, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)

SUSPICIOUS_URL_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rb.gy",
    "tiny.one",
    "ngrok.io",
    "localtunnel.me",
)
_METADATA_READ_FAILED_REASON = "metadata_read_failed"
_METADATA_TIMEOUT_REASON = "scan_timeout"
_REDACTED_SECRET_PREVIEW = "<redacted>"


def _redact_url_for_display(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return "[invalid-url]"

    if not parsed.scheme or not parsed.netloc:
        return "[invalid-url]"

    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    try:
        port = parsed.port
    except ValueError:
        port = None

    netloc = f"{hostname}:{port}" if port else hostname
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


class MetadataScanner(BaseScanner):
    """Scanner for model documentation files looking for security issues."""

    name = "metadata"
    description = "Scans model documentation files for security issues"
    supported_extensions: ClassVar[list[str]] = [".md", ".markdown", ".rst", ".txt", ".yml", ".yaml"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the file."""
        p = Path(path)

        # MetadataScanner focuses on documentation files only
        # JSON config files are handled by ManifestScanner

        # Handle README/model card files (including extensionless README files)
        filename_lower = p.name.lower()
        return filename_lower in [
            "readme",
            "readme.md",
            "readme.rst",
            "readme.txt",
            "model_card.md",
            "modelcard.md",
            "model_card",
            "model_card.txt",
            "model-index.yml",
            "model-index.yaml",
        ] or filename_lower.startswith("readme.")

    def scan(self, path: str) -> ScanResult:
        """Scan metadata file for security issues."""
        path_check_result = self._check_path(path)
        if path_check_result:
            if any(
                check.name == "Path Readable" and check.status == CheckStatus.FAILED
                for check in path_check_result.checks
            ):
                result = self._create_result()
                self._mark_metadata_read_failure(result, path, PermissionError(f"Path is not readable: {path}"))
                result.finish(success=False)
                return result
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        self._start_scan_timer()
        result = self._create_result()
        p = Path(path)
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            self.current_file_path = path
            self._check_timeout()

            # MetadataScanner only handles text/documentation files
            self._scan_text_metadata(path, result)
            self._check_timeout()

        except TimeoutError as e:
            mark_inconclusive_scan_result(result, _METADATA_TIMEOUT_REASON)
            mark_operational_scan_error(result, _METADATA_TIMEOUT_REASON)
            result.add_check(
                name="Metadata Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "timeout_seconds": self.timeout,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": _METADATA_TIMEOUT_REASON,
                },
                why="Metadata scanning exceeded the configured timeout before all checks completed",
            )
        except Exception as e:
            logger.warning(f"Error scanning metadata file {path}: {e}")
            result.add_check(
                name="Metadata Scan Error",
                passed=False,
                message=f"Failed to scan metadata file: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e)},
                why="Failed to process metadata file during scanning",
            )

        result.bytes_scanned = file_size if p.exists() else 0
        result.finish(success=not scan_result_has_inconclusive_outcome(result))
        return result

    def _add_issue_check(self, result: ScanResult, issue: Issue) -> None:
        """Persist an issue as a failed check on the scan result."""
        result.add_check(
            name=issue.type or "Metadata Security Check",
            passed=False,
            message=issue.message,
            severity=issue.severity,
            location=issue.location,
            details=issue.details,
            why=issue.why,
        )

    def _scan_text_metadata(self, file_path: str, result: ScanResult) -> None:
        """Scan text metadata files (README, model cards) for security issues."""
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            self._check_timeout()

            # Check for suspicious URLs
            self._check_suspicious_urls_in_text(content, file_path, result)
            self._check_timeout()

            # Check for exposed credentials in text
            self._check_exposed_secrets_in_text(content, file_path, result)

        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            self._mark_metadata_read_failure(result, file_path, e)
        except Exception as e:
            self._add_issue_check(
                result,
                Issue(
                    message=f"Error reading text metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="File access errors may indicate permission issues or tampering",
                    type="file_error",
                ),
            )

    @staticmethod
    def _mark_metadata_read_failure(result: ScanResult, file_path: str, error: OSError | UnicodeError) -> None:
        """Record unavailable document coverage without fabricating a security finding."""
        mark_inconclusive_scan_result(result, _METADATA_READ_FAILED_REASON)
        mark_operational_scan_error(result, _METADATA_READ_FAILED_REASON)
        result.add_check(
            name="Metadata File Read",
            passed=False,
            message=f"Unable to load metadata document for analysis: {error!s}",
            severity=IssueSeverity.INFO,
            location=file_path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": _METADATA_READ_FAILED_REASON,
            },
        )

    def _check_suspicious_urls_in_text(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for suspicious URLs in text content."""
        import re

        # Find URLs in text
        url_pattern = r'https?://[^\s<>"\']+[^\s<>"\',.]'
        urls = re.findall(url_pattern, content)

        seen = set()
        for url in urls:
            self._check_timeout()
            if url in seen:
                continue
            seen.add(url)
            parsed = urlparse(url)
            matched_domain = None
            matched_component = None

            for userinfo_part in (parsed.username, parsed.password):
                matched_domain = self._match_suspicious_domain(userinfo_part or "")
                if matched_domain is not None:
                    matched_component = "userinfo"
                    break

            # Treat deceptive userinfo consistently with manifest semantics while
            # avoiding noise from ordinary authenticated URLs.
            if matched_domain is None:
                matched_domain = self._match_suspicious_domain(parsed.hostname or "")
                if matched_domain is not None:
                    matched_component = "hostname"

            if matched_domain is None:
                continue

            safe_url = _redact_url_for_display(url)
            self._add_issue_check(
                result,
                Issue(
                    message=f"Suspicious URL found in text metadata: {safe_url}",
                    severity=IssueSeverity.INFO,
                    location=file_path,
                    details={
                        "url": safe_url,
                        "suspicious_domain": matched_domain,
                        "url_component": matched_component,
                    },
                    why="URL shorteners and tunnel services can hide malicious endpoints",
                    type="suspicious_url",
                ),
            )

    @staticmethod
    def _match_suspicious_domain(candidate: str) -> str | None:
        """Return the matching suspicious domain for a URL component, if any."""
        normalized = unquote(candidate).lower().rstrip(".")
        if not normalized:
            return None

        for domain in SUSPICIOUS_URL_DOMAINS:
            if normalized == domain or normalized.endswith(f".{domain}"):
                return domain
        return None

    def _calculate_entropy(self, text: str) -> float:
        """Calculate the Shannon entropy of a text string."""
        import math
        from collections import Counter

        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _check_exposed_secrets_in_text(self, content: str, file_path: str, result: ScanResult) -> None:
        """Check for exposed secrets in text content."""
        import re

        # Specific secret patterns (removed overly broad generic pattern)
        # Only include patterns with known prefixes/formats to avoid false positives
        secret_patterns = [
            # GitHub tokens have specific prefixes
            (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
            (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth token"),
            (r"ghu_[A-Za-z0-9]{36}", "GitHub user token"),
            (r"ghs_[A-Za-z0-9]{36}", "GitHub server token"),
            (r"ghr_[A-Za-z0-9]{36}", "GitHub refresh token"),
            # OpenAI API keys have specific prefix
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API key"),
            # AWS keys have specific format
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            # Slack tokens
            (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack token"),
            # Bearer tokens (but with context - needs Bearer keyword)
            (r"Bearer\s+[A-Za-z0-9._-]{20,}", "Bearer token"),
            # API key assignments with explicit key/token keywords
            (
                r'(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9._-]{16,})["\']',
                "API key assignment",
            ),
        ]

        for pattern, description in secret_patterns:
            self._check_timeout()
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._check_timeout()
                # Skip obvious examples or placeholders
                matched_text = match.group(0)

                # Extract the actual secret part for entropy analysis
                # If pattern has capture group, use that; otherwise use full match
                secret_part = match.group(1) if match.lastindex and match.lastindex >= 1 else matched_text

                # For Bearer tokens, extract just the token part
                if "Bearer" in matched_text and " " in matched_text:
                    secret_part = matched_text.split(" ", 1)[1].strip()

                # Check for obvious placeholders
                is_placeholder = any(
                    placeholder in matched_text.lower()
                    for placeholder in [
                        "example",
                        "placeholder",
                        "your_",
                        "xxx",
                        "****",
                        "token_here",
                        "sample",
                        "test",
                    ]
                )

                # For well-known token formats (GitHub, OpenAI, AWS), we trust the pattern
                # and don't need entropy checks - these have specific prefixes/formats
                is_known_format = self._is_known_secret_format(description)

                if is_known_format:
                    # Known format - report if not a placeholder
                    if not is_placeholder:
                        self._add_issue_check(
                            result,
                            Issue(
                                message=f"Potential exposed secret in text metadata: {description}",
                                severity=IssueSeverity.INFO,
                                location=file_path,
                                details={
                                    "pattern_description": description,
                                    "match_preview": _REDACTED_SECRET_PREVIEW,
                                    "length": len(secret_part),
                                },
                                why="Exposed secrets in documentation can lead to unauthorized access",
                                type="exposed_secret",
                            ),
                        )

                else:
                    # Generic pattern - use entropy check to reduce false positives
                    entropy = self._calculate_entropy(secret_part)
                    min_entropy = 4.0

                    if not is_placeholder and entropy >= min_entropy and len(secret_part) >= 16:
                        self._add_issue_check(
                            result,
                            Issue(
                                message=f"Potential exposed secret in text metadata: {description}",
                                severity=IssueSeverity.INFO,
                                location=file_path,
                                details={
                                    "pattern_description": description,
                                    "match_preview": _REDACTED_SECRET_PREVIEW,
                                    "entropy": round(entropy, 2),
                                    "length": len(secret_part),
                                },
                                why="Exposed secrets in documentation can lead to unauthorized access",
                                type="exposed_secret",
                            ),
                        )

    @staticmethod
    def _is_known_secret_format(description: str) -> bool:
        lowered_description = description.lower()
        return any(prefix in lowered_description for prefix in ["github", "openai", "aws", "slack"])
