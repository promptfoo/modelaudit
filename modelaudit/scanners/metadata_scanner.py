"""Scanner for model metadata files (README, model cards, documentation)."""

import logging
from pathlib import Path

from .base import BaseScanner, Issue, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


class MetadataScanner(BaseScanner):
    """Scanner for model documentation files looking for security issues."""

    name = "metadata"
    description = "Scans model documentation files for security issues"

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
            return path_check_result

        result = self._create_result()
        p = Path(path)

        try:
            # MetadataScanner only handles text/documentation files
            issues = self._scan_text_metadata(path)
            for issue in issues:
                result.add_check(
                    name=issue.type or "Metadata Security Check",
                    passed=False,
                    message=issue.message,
                    severity=issue.severity,
                    location=issue.location,
                    details=issue.details,
                    why=issue.why,
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

        result.bytes_scanned = p.stat().st_size if p.exists() else 0
        result.finish(success=True)
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
            "is.gd",
            "rb.gy",
            "tiny.one",
            "ngrok.io",
            "localtunnel.me",
        ]

        seen = set()
        for url in urls:
            if url in seen:
                continue
            for domain in suspicious_domains:
                if domain in url.lower():
                    seen.add(url)
                    issues.append(
                        Issue(
                            message=f"Suspicious URL found in text metadata: {url}",
                            severity=IssueSeverity.INFO,
                            location=file_path,
                            details={"url": url, "suspicious_domain": domain},
                            why="URL shorteners and tunnel services can hide malicious endpoints",
                            type="suspicious_url",
                        )
                    )
                    break  # Avoid duplicate issues for the same URL

        return issues

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

    def _check_exposed_secrets_in_text(self, content: str, file_path: str) -> list[Issue]:
        """Check for exposed secrets in text content."""
        issues: list[Issue] = []
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
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
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
                is_known_format = any(prefix in description.lower() for prefix in ["github", "openai", "aws", "slack"])

                if is_known_format:
                    # Known format - report if not a placeholder
                    if not is_placeholder:
                        issues.append(
                            Issue(
                                message=f"Potential exposed secret in text metadata: {description}",
                                severity=IssueSeverity.INFO,
                                location=file_path,
                                details={
                                    "pattern_description": description,
                                    "match_preview": matched_text[:20] + "..."
                                    if len(matched_text) > 20
                                    else matched_text,
                                    "length": len(secret_part),
                                },
                                why="Exposed secrets in documentation can lead to unauthorized access",
                                type="exposed_secret",
                            )
                        )
                else:
                    # Generic pattern - use entropy check to reduce false positives
                    entropy = self._calculate_entropy(secret_part)
                    min_entropy = 4.0

                    if not is_placeholder and entropy >= min_entropy and len(secret_part) >= 16:
                        issues.append(
                            Issue(
                                message=f"Potential exposed secret in text metadata: {description}",
                                severity=IssueSeverity.INFO,
                                location=file_path,
                                details={
                                    "pattern_description": description,
                                    "match_preview": matched_text[:20] + "..."
                                    if len(matched_text) > 20
                                    else matched_text,
                                    "entropy": round(entropy, 2),
                                    "length": len(secret_part),
                                },
                                why="Exposed secrets in documentation can lead to unauthorized access",
                                type="exposed_secret",
                            )
                        )

        return issues
