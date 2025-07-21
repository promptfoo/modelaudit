"""Scanner for text-based ML files like README.md and vocab.txt."""

import os
from typing import Any, ClassVar, Optional

from modelaudit.scanners.base import BaseScanner, IssueSeverity, ScanResult


class TextScanner(BaseScanner):
    """Scanner for text-based ML-related files."""

    name = "text"
    supported_extensions: ClassVar[list[str]] = [".txt", ".md", ".markdown", ".rst"]

    def __init__(self, config: Optional[dict[str, Any]] = None):
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

        return filename in ml_text_files or any(
            filename.startswith(prefix) for prefix in ["vocab", "token", "label"]
        )

    def scan(self, path: str, timeout: Optional[int] = None) -> ScanResult:
        """Scan a text file for security issues."""
        result = ScanResult(scanner_name=self.name)

        try:
            # Get file size
            file_size = os.path.getsize(path)
            result.metadata["file_size"] = file_size

            # Check if file is too large (text files shouldn't be huge)
            if file_size > 100 * 1024 * 1024:  # 100MB
                result.add_issue(
                    f"Unusually large text file: {file_size / (1024 * 1024):.1f}MB",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"file_size": file_size},
                )

            filename = os.path.basename(path).lower()

            # Identify file type
            if filename in [
                "readme.md",
                "readme.txt",
                "readme.markdown",
                "model_card.md",
            ]:
                result.add_issue(
                    "Model documentation file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "documentation"},
                )
            elif filename in [
                "vocab.txt",
                "vocabulary.txt",
                "tokens.txt",
                "tokenizer.txt",
            ]:
                result.add_issue(
                    "Tokenizer vocabulary file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "vocabulary"},
                )
            elif filename in ["labels.txt", "classes.txt"]:
                result.add_issue(
                    "Classification labels file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "labels"},
                )
            elif filename in ["license.txt", "license.md"]:
                result.add_issue(
                    "License file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "license"},
                )
            elif filename == "requirements.txt":
                # Could scan for suspicious dependencies in the future
                result.add_issue(
                    "Python requirements file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "requirements"},
                )
            else:
                result.add_issue(
                    "ML-related text file",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"file_type": "text"},
                )

            result.bytes_scanned = file_size
            result.finish(success=True)

        except Exception as e:
            result.add_issue(
                f"Error scanning text file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e)},
            )
            result.finish(success=False)

        return result
