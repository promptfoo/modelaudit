"""Converter for Pickle/PyTorch to SafeTensors format."""

import logging
import pickle
import sys
from pathlib import Path
from typing import Any, ClassVar, Optional

from modelaudit.remediation.base import BaseConverter, ConversionResult
from modelaudit.remediation.converters import register_converter

logger = logging.getLogger(__name__)


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe types for weight extraction."""

    SAFE_MODULES: ClassVar[set[str]] = {
        "torch",
        "torch._utils",
        "torch.nn",
        "torch.nn.modules",
        "torch.nn.parameter",
        "torch.storage",
        "numpy",
        "numpy.core",
        "numpy.core.multiarray",
        "collections",
        "typing",
    }

    def find_class(self, module: str, name: str) -> Any:
        """Override find_class to restrict imports."""
        # Allow torch and numpy modules for tensor loading
        if any(module.startswith(safe) for safe in self.SAFE_MODULES):
            return super().find_class(module, name)

        # Allow basic Python types
        if module == "builtins" and name in {
            "dict",
            "list",
            "tuple",
            "set",
            "frozenset",
            "int",
            "float",
            "str",
            "bytes",
            "bool",
            "type",
            "object",
        }:
            return super().find_class(module, name)

        # Block everything else
        raise pickle.UnpicklingError(f"Blocked unsafe import: {module}.{name}")


@register_converter("pickle_to_safetensors")
class PickleToSafeTensorsConverter(BaseConverter):
    """Convert Pickle/PyTorch files to SafeTensors format."""

    def can_convert(self, source_path: Path, target_format: str) -> bool:
        """Check if this converter can handle the conversion."""
        source_ext = source_path.suffix.lower()
        return source_ext in {".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin"} and target_format == "safetensors"

    def get_supported_conversions(self) -> dict[str, list[str]]:
        """Get supported conversions."""
        return {
            "pkl": ["safetensors"],
            "pickle": ["safetensors"],
            "pt": ["safetensors"],
            "pth": ["safetensors"],
            "ckpt": ["safetensors"],
            "bin": ["safetensors"],
        }

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
        """Convert a Pickle/PyTorch file to SafeTensors format."""
        try:
            # Check if safetensors is available
            try:
                import safetensors
                import safetensors.torch
            except ImportError:
                return ConversionResult(
                    success=False,
                    error_message="safetensors package not installed. Install with: pip install safetensors",
                )

            # Create backup if requested
            if backup:
                self._create_backup(source_path)

            # Load the pickle file safely
            self.logger.info("Loading pickle file: %s", source_path)
            state_dict, metadata = self._load_pickle_safely(source_path)

            if not state_dict:
                return ConversionResult(
                    success=False,
                    error_message="No tensor data found in pickle file",
                )

            # Convert to SafeTensors
            self.logger.info("Converting to SafeTensors format")
            save_kwargs = {"tensors": state_dict}

            if preserve_metadata and metadata:
                # SafeTensors metadata must be string -> string
                string_metadata = {}
                for key, value in metadata.items():
                    if isinstance(value, (str, int, float, bool)):
                        string_metadata[str(key)] = str(value)
                    elif isinstance(value, (list, dict)):
                        import json

                        string_metadata[str(key)] = json.dumps(value)
                if string_metadata:
                    save_kwargs["metadata"] = string_metadata

            # Save as SafeTensors
            safetensors.torch.save_file(**save_kwargs, filename=str(output_path))

            # Calculate size reduction
            size_reduction = self._calculate_size_reduction(source_path, output_path)

            # Validate if requested
            numerical_accuracy = None
            validation_passed = True
            if validate:
                validation_passed, numerical_accuracy = self.validate_conversion(source_path, output_path)

            result = ConversionResult(
                success=True,
                output_path=output_path,
                validation_passed=validation_passed,
                numerical_accuracy=numerical_accuracy,
                size_reduction=size_reduction,
                metadata={
                    "source_format": source_path.suffix,
                    "target_format": "safetensors",
                    "tensors_converted": len(state_dict),
                    "metadata_preserved": len(save_kwargs.get("metadata", {})),
                },
            )

            # Count security issues removed (pickle format inherently has security risks)
            result.security_issues_removed = 1  # Removed pickle deserialization risk

            return result

        except Exception as e:
            self.logger.error("Conversion failed: %s", e, exc_info=True)
            return ConversionResult(
                success=False,
                error_message=f"Conversion failed: {e!s}",
            )

    def _load_pickle_safely(self, file_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        """Load a pickle file with restricted unpickling.

        Returns
        -------
        tuple[dict[str, Any], dict[str, Any]]
            Tuple of (state_dict, metadata)
        """
        try:
            # First try with restricted unpickler
            with open(file_path, "rb") as f:
                unpickler = RestrictedUnpickler(f)
                data = unpickler.load()

            return self._extract_state_dict(data)

        except pickle.UnpicklingError as e:
            self.logger.warning("Restricted unpickling failed: %s", e)

            # Try torch.load if available (it has some built-in safety)
            try:
                import torch

                data = torch.load(file_path, map_location="cpu", weights_only=True)
                return self._extract_state_dict(data)
            except Exception as torch_error:
                self.logger.warning("Torch load failed: %s", torch_error)

            # As a last resort, try regular pickle with warnings
            self.logger.warning("Falling back to regular pickle.load - this is less safe!")
            with open(file_path, "rb") as f:
                data = pickle.load(f)
            return self._extract_state_dict(data)

    def _extract_state_dict(self, data: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        """Extract state dict and metadata from loaded data.

        Parameters
        ----------
        data : Any
            Loaded pickle data.

        Returns
        -------
        tuple[dict[str, Any], dict[str, Any]]
            Tuple of (state_dict, metadata)
        """
        state_dict = {}
        metadata = {}

        # Handle different data structures
        if isinstance(data, dict):
            # Check if it's already a state dict
            if all(self._is_tensor(v) for v in data.values()):
                state_dict = data
            else:
                # Look for common keys
                for key in ["state_dict", "model_state_dict", "model", "net"]:
                    if key in data and isinstance(data[key], dict):
                        state_dict = data[key]
                        break

                # Extract metadata
                for key in ["metadata", "meta", "config", "hparams", "epoch", "iteration"]:
                    if key in data:
                        metadata[key] = data[key]

                # If no state dict found, try to extract tensors
                if not state_dict:
                    state_dict = {k: v for k, v in data.items() if self._is_tensor(v)}

        elif hasattr(data, "state_dict"):
            # Handle nn.Module objects
            try:
                state_dict = data.state_dict()
            except Exception as e:
                self.logger.warning("Failed to call state_dict(): %s", e)

        return state_dict, metadata

    def _is_tensor(self, obj: Any) -> bool:
        """Check if an object is a tensor."""
        # Check for PyTorch tensors
        if "torch" in sys.modules:
            import torch

            if isinstance(obj, torch.Tensor):
                return True

        # Check for NumPy arrays
        if "numpy" in sys.modules:
            import numpy as np

            if isinstance(obj, np.ndarray):
                return True

        return False

    def validate_conversion(
        self,
        source_path: Path,
        converted_path: Path,
        samples: int = 100,
        tolerance: float = 1e-6,
    ) -> tuple[bool, Optional[float]]:
        """Validate conversion accuracy."""
        try:
            import safetensors
            import torch

            # Load original weights (using torch.load for comparison)
            original_data = torch.load(source_path, map_location="cpu", weights_only=True)
            if isinstance(original_data, dict) and "state_dict" in original_data:
                original_data = original_data["state_dict"]

            # Load converted weights
            converted_data = safetensors.torch.load_file(str(converted_path))

            # Compare keys
            orig_keys = set(original_data.keys()) if isinstance(original_data, dict) else set()
            conv_keys = set(converted_data.keys())

            if orig_keys != conv_keys:
                missing = orig_keys - conv_keys
                extra = conv_keys - orig_keys
                self.logger.warning("Key mismatch - Missing: %s, Extra: %s", missing, extra)
                return False, None

            # Compare tensor values
            max_diff = 0.0
            for key in orig_keys:
                if key in converted_data:
                    orig_tensor = original_data[key]
                    conv_tensor = converted_data[key]

                    if isinstance(orig_tensor, torch.Tensor) and isinstance(conv_tensor, torch.Tensor):
                        diff = torch.abs(orig_tensor.float() - conv_tensor.float()).max().item()
                        max_diff = max(max_diff, diff)

            validation_passed = max_diff <= tolerance
            if not validation_passed:
                self.logger.warning("Numerical difference exceeds tolerance: %e > %e", max_diff, tolerance)

            return validation_passed, max_diff

        except Exception as e:
            self.logger.error("Validation failed: %s", e)
            return False, None
