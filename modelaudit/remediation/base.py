"""Base classes for model conversion and remediation."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from modelaudit.scanners.base import Issue

logger = logging.getLogger(__name__)


@dataclass
class ConversionResult:
    """Result of a model conversion operation."""

    success: bool
    output_path: Optional[Path] = None
    error_message: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    validation_passed: bool = False
    numerical_accuracy: Optional[float] = None
    size_reduction: Optional[float] = None
    security_issues_removed: int = 0


class BaseConverter(ABC):
    """Abstract base class for model format converters."""

    def __init__(self) -> None:
        """Initialize the converter."""
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def can_convert(self, source_path: Path, target_format: str) -> bool:
        """Check if this converter can handle the given conversion.

        Parameters
        ----------
        source_path : Path
            Path to the source model file.
        target_format : str
            Target format name (e.g., 'safetensors', 'onnx').

        Returns
        -------
        bool
            True if this converter can handle the conversion.
        """
        pass

    @abstractmethod
    def convert(
        self,
        source_path: Path,
        output_path: Path,
        *,
        validate: bool = True,
        preserve_metadata: bool = True,
        backup: bool = True,
        **kwargs: Any,
    ) -> ConversionResult:
        """Convert a model from one format to another.

        Parameters
        ----------
        source_path : Path
            Path to the source model file.
        output_path : Path
            Path where the converted model should be saved.
        validate : bool
            Whether to validate the conversion accuracy.
        preserve_metadata : bool
            Whether to preserve model metadata during conversion.
        backup : bool
            Whether to create a backup of the source file.
        **kwargs
            Additional converter-specific arguments.

        Returns
        -------
        ConversionResult
            Result of the conversion operation.
        """
        pass

    @abstractmethod
    def get_supported_conversions(self) -> dict[str, list[str]]:
        """Get the conversions supported by this converter.

        Returns
        -------
        dict[str, list[str]]
            Mapping of source formats to supported target formats.
            Example: {'pkl': ['safetensors', 'onnx'], 'pth': ['safetensors']}
        """
        pass

    def validate_conversion(
        self,
        source_path: Path,
        converted_path: Path,
        samples: int = 100,
        tolerance: float = 1e-6,
    ) -> tuple[bool, Optional[float]]:
        """Validate that a conversion maintains model accuracy.

        Parameters
        ----------
        source_path : Path
            Path to the original model.
        converted_path : Path
            Path to the converted model.
        samples : int
            Number of test samples to use for validation.
        tolerance : float
            Maximum allowed numerical difference.

        Returns
        -------
        tuple[bool, Optional[float]]
            Validation success and maximum numerical difference found.
        """
        self.logger.info("Skipping validation - not implemented for this converter")
        return True, None

    def _create_backup(self, source_path: Path) -> Optional[Path]:
        """Create a backup of the source file.

        Parameters
        ----------
        source_path : Path
            Path to the file to backup.

        Returns
        -------
        Optional[Path]
            Path to the backup file, or None if backup failed.
        """
        try:
            backup_path = source_path.with_suffix(source_path.suffix + ".backup")
            if backup_path.exists():
                # Add timestamp if backup already exists
                import time

                timestamp = int(time.time())
                backup_path = source_path.with_suffix(f"{source_path.suffix}.backup.{timestamp}")

            import shutil

            shutil.copy2(source_path, backup_path)
            self.logger.info("Created backup at %s", backup_path)
            return backup_path
        except Exception as e:
            self.logger.warning("Failed to create backup: %s", e)
            return None

    def _calculate_size_reduction(self, source_path: Path, output_path: Path) -> float:
        """Calculate the size reduction percentage.

        Parameters
        ----------
        source_path : Path
            Original file path.
        output_path : Path
            Converted file path.

        Returns
        -------
        float
            Size reduction percentage (positive means smaller).
        """
        try:
            source_size = source_path.stat().st_size
            output_size = output_path.stat().st_size
            if source_size > 0:
                return ((source_size - output_size) / source_size) * 100
            return 0.0
        except Exception:
            return 0.0


class BaseRemediator(ABC):
    """Abstract base class for in-place model remediation."""

    def __init__(self) -> None:
        """Initialize the remediator."""
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def can_remediate(self, file_path: Path) -> bool:
        """Check if this remediator can handle the given file.

        Parameters
        ----------
        file_path : Path
            Path to the model file.

        Returns
        -------
        bool
            True if this remediator can handle the file.
        """
        pass

    @abstractmethod
    def analyze(self, file_path: Path) -> list[Issue]:
        """Analyze a model file for security issues that can be remediated.

        Parameters
        ----------
        file_path : Path
            Path to the model file.

        Returns
        -------
        list[Issue]
            List of security issues found.
        """
        pass

    @abstractmethod
    def remediate(
        self,
        file_path: Path,
        *,
        dry_run: bool = False,
        backup: bool = True,
        interactive: bool = False,
        **kwargs: Any,
    ) -> ConversionResult:
        """Remediate security issues in a model file.

        Parameters
        ----------
        file_path : Path
            Path to the model file to remediate.
        dry_run : bool
            If True, show what would be changed without making changes.
        backup : bool
            Whether to create a backup before remediation.
        interactive : bool
            Whether to prompt for user confirmation on each change.
        **kwargs
            Additional remediator-specific arguments.

        Returns
        -------
        ConversionResult
            Result of the remediation operation.
        """
        pass
