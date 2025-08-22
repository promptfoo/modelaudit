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

        return filename in ml_text_files or any(filename.startswith(prefix) for prefix in ["vocab", "token", "label"])

    def scan(self, path: str, timeout: Optional[int] = None) -> ScanResult:
        """Scan a text file for security issues."""
        result = ScanResult(scanner_name=self.name)

        try:
            # Get file size
            file_size = os.path.getsize(path)
            result.metadata["file_size"] = file_size

            # Check if file exceeds expected size for text files
            if file_size > 100 * 1024 * 1024:  # 100MB
                result.add_check(
                    name="File Size Check",
                    passed=False,
                    message=f"Unusually large text file: {file_size / (1024 * 1024):.1f}MB",
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
                )
            elif filename in ["vocab.txt", "vocabulary.txt", "tokens.txt", "tokenizer.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Tokenizer vocabulary file",
                    location=path,
                    details={"file_type": "vocabulary"},
                )
            elif filename in ["labels.txt", "classes.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Classification labels file",
                    location=path,
                    details={"file_type": "labels"},
                )
            elif filename in ["license.txt", "license.md"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="License file",
                    location=path,
                    details={"file_type": "license"},
                )
            elif filename == "requirements.txt":
                # Could scan for suspicious dependencies in the future
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Python requirements file",
                    location=path,
                    details={"file_type": "requirements"},
                )
            else:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="ML-related text file",
                    location=path,
                    details={"file_type": "text"},
                )

            result.bytes_scanned = file_size
            result.finish(success=True)

        except Exception as e:
            result.add_check(
                name="Text File Scan",
                passed=False,
                message=f"Error scanning text file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e)},
            )
            result.finish(success=False)

        return result
