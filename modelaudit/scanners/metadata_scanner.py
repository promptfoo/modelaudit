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

        # High-risk domains that are almost always suspicious
        high_risk_domains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "ngrok.io",
            "localtunnel.me",
        ]

        # Medium-risk domains that could be legitimate but worth flagging
        medium_risk_domains = [
            "github.io",
            "gitlab.io",
        ]

        for url in urls:
            url_lower = url.lower()
            for domain in high_risk_domains:
                if domain in url_lower:
                    issues.append(
                        Issue(
                            message=f"Suspicious URL found in text metadata: {url}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={"url": url, "suspicious_domain": domain, "risk_level": "high"},
                            why="URL shorteners and tunnel services can hide malicious endpoints",
                            type="suspicious_url",
                        )
                    )
                    break  # Avoid duplicate issues for the same URL

            # For medium-risk domains, be more selective
            for domain in medium_risk_domains:
                if domain in url_lower:
                    # Check if this looks like a legitimate project page
                    if not self._looks_like_legitimate_project_url(url):
                        issues.append(
                            Issue(
                                message=f"Potentially suspicious hosting service in text metadata: {url}",
                                severity=IssueSeverity.INFO,  # Lower severity for medium risk
                                location=file_path,
                                details={"url": url, "suspicious_domain": domain, "risk_level": "medium"},
                                why="Third-party hosting services should be verified for legitimacy",
                                type="suspicious_url",
                            )
                        )
                    break  # Avoid duplicate issues for the same URL

        return issues

    def _looks_like_legitimate_project_url(self, url: str) -> bool:
        """Check if a URL looks like a legitimate project page rather than suspicious content."""
        url_lower = url.lower()

        # Look for patterns that suggest legitimate project pages
        legitimate_patterns = [
            # Common project/documentation patterns
            r"github\.io/[\w\-]+/?$",  # Simple username.github.io
            r"[\w\-]+\.github\.io/?$",  # Project pages
            r"gitlab\.io/[\w\-]+/?$",   # Simple username.gitlab.io
            r"[\w\-]+\.gitlab\.io/?$",  # Project pages
            # Documentation and common project files
            r"/docs?/?$",
            r"/readme\.md$",
            r"/index\.html?$",
        ]

        import re
        return any(re.search(pattern, url_lower) for pattern in legitimate_patterns)

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

                # Extract the actual secret part for entropy analysis
                secret_part = matched_text
                if "=" in matched_text:
                    # For token assignments like "api_key=abc123", extract just the value
                    secret_part = matched_text.split("=", 1)[1].strip(' "\'')
                elif " " in matched_text and "Bearer" in matched_text:
                    # For Bearer tokens, extract just the token part
                    secret_part = matched_text.split(" ", 1)[1].strip()

                # Check for obvious placeholders
                is_placeholder = any(
                    placeholder in matched_text.lower()
                    for placeholder in ["example", "placeholder", "your_", "xxx", "****", "token_here", "sample"]
                )

                # Calculate entropy to reduce false positives
                entropy = self._calculate_entropy(secret_part)

                # Only flag as suspicious if it has sufficient entropy (randomness)
                # Typical thresholds: low entropy (~2.0) for structured text, high entropy (~4.5+) for random tokens
                min_entropy = 3.5  # Balanced threshold to catch real secrets but avoid common words

                if not is_placeholder and entropy >= min_entropy and len(secret_part) >= 10:
                    issues.append(
                        Issue(
                            message=f"Potential exposed secret in text metadata: {description}",
                            severity=IssueSeverity.WARNING,
                            location=file_path,
                            details={
                                "pattern_description": description,
                                "match_preview": matched_text[:20] + "..." if len(matched_text) > 20 else matched_text,
                                "entropy": round(entropy, 2),
                                "length": len(secret_part),
                            },
                            why="Exposed secrets in documentation can lead to unauthorized access",
                            type="exposed_secret",
                        )
                    )

        return issues
