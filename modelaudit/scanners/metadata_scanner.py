"""Scanner for model metadata files (README, model cards, documentation)."""

import logging
from pathlib import Path

from .base import BaseScanner, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


class MetadataScanner(BaseScanner):
    """Scanner for model documentation files looking for security issues."""

    @staticmethod
    def can_handle(file_path: str) -> bool:
        """Check if this scanner can handle the file."""
        path = Path(file_path)

        # MetadataScanner focuses on documentation files only
        # JSON config files are handled by ManifestScanner

        # Handle README/model card files (including extensionless README files)
        filename_lower = path.name.lower()
        return filename_lower in [
            "readme",
            "readme.md",
            "readme.txt",
            "model_card.md",
            "model_card.txt",
            "model-index.yml",
            "model-index.yaml",
        ] or filename_lower.startswith("readme.")

    def scan(self, file_path: str, timeout: int = 300) -> ScanResult:
        """Scan metadata file for security issues."""
        issues: list[Issue] = []
        path = Path(file_path)

        try:
            # MetadataScanner only handles text/documentation files
            issues.extend(self._scan_text_metadata(file_path))

        except Exception as e:
            logger.warning(f"Error scanning metadata file {file_path}: {e}")
            issues.append(
                Issue(
                    message=f"Failed to scan metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="Failed to process metadata file during scanning",
                    type="scan_error",
                )
            )

        result = ScanResult("metadata")
        result.issues = issues
        result.bytes_scanned = path.stat().st_size if path.exists() else 0
        return result

    def _scan_text_metadata(self, file_path: str) -> list[Issue]:
        """Scan text metadata files (README, model cards) for security issues."""
        issues: list[Issue] = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Check for suspicious URLs
            issues.extend(self._check_suspicious_urls_in_text(content, file_path))

            # Check for exposed credentials in text
            issues.extend(self._check_exposed_secrets_in_text(content, file_path))

        except Exception as e:
            issues.append(
                Issue(
                    message=f"Error reading text metadata file: {e}",
                    severity=IssueSeverity.WARNING,
                    location=file_path,
                    details={"error": str(e)},
                    why="File access errors may indicate permission issues or tampering",
                    type="file_error",
                )
            )

        return issues

    def _check_suspicious_urls_in_text(self, content: str, file_path: str) -> list[Issue]:
        """Check for suspicious URLs in text content."""
        issues: list[Issue] = []
        import re

        # Find URLs in text
        url_pattern = r'https?://[^\s<>"\']+[^\s<>"\',.]'
        urls = re.findall(url_pattern, content)

        suspicious_domains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "github.io",
            "gitlab.io",
            "ngrok.io",
            "localtunnel.me",
        ]

        for url in urls:
            for domain in suspicious_domains:
                if domain in url.lower():
                    issues.append(
                        Issue(
                            message=f"Suspicious URL found in text metadata: {url}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={"url": url, "suspicious_domain": domain},
                            why="URL shorteners and tunnel services can hide malicious endpoints",
                            type="suspicious_url",
                        )
                    )

        return issues

    def _check_exposed_secrets_in_text(self, content: str, file_path: str) -> list[Issue]:
        """Check for exposed secrets in text content."""
        issues: list[Issue] = []
        import re

        # Common secret patterns
        secret_patterns = [
            (r"[A-Za-z0-9]{20,}", "Potential API key or token"),
            (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API key"),
            (r"Bearer\s+[A-Za-z0-9._-]+", "Bearer token"),
            (r'[A-Za-z0-9._-]*[Tt]oken[A-Za-z0-9._-]*\s*[:=]\s*["\']?([A-Za-z0-9._-]{10,})', "Token assignment"),
        ]

        for pattern, description in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Skip obvious examples or placeholders
                matched_text = match.group(0)
                if not any(
                    placeholder in matched_text.lower()
                    for placeholder in ["example", "placeholder", "your_", "xxx", "****", "token_here"]
                ):
                    issues.append(
                        Issue(
                            message=f"Potential exposed secret in text metadata: {description}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={
                                "pattern_description": description,
                                "match_preview": matched_text[:20] + "..." if len(matched_text) > 20 else matched_text,
                            },
                            why="Exposed secrets in documentation can lead to unauthorized access",
                            type="exposed_secret",
                        )
                    )

        return issues
