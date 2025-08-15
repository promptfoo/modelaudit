import os
from typing import ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

try:  # pragma: no cover - optional dependency
    from coremltools.proto import Model_pb2

    HAS_COREML = True
except Exception:  # pragma: no cover - optional dependency
    HAS_COREML = False


class CoreMLScanner(BaseScanner):
    """Scanner for Apple Core ML model files (.mlmodel)."""

    name = "coreml"
    description = "Scans Core ML model files for custom layers and other risks"
    supported_extensions: ClassVar[list[str]] = [".mlmodel"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not HAS_COREML:
            return False
        return os.path.isfile(path) and os.path.splitext(path)[1].lower() in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        result.metadata["file_size"] = self.get_file_size(path)

        if not HAS_COREML:
            result.add_check(
                name="CoreML Library Check",
                passed=False,
                message="coremltools package not installed. Install with 'pip install modelaudit[coreml]'",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"required_package": "coremltools"},
            )
            result.finish(success=False)
            return result

        try:
            with open(path, "rb") as f:
                data = f.read()
                result.bytes_scanned = len(data)
            spec = Model_pb2.Model()
            spec.ParseFromString(data)
        except Exception as e:  # pragma: no cover - parse errors
            result.add_check(
                name="CoreML File Parse",
                passed=False,
                message=f"Invalid Core ML file or parse error: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        model_type = spec.WhichOneof("Type")
        result.metadata["model_type"] = model_type

        if model_type == "customModel":
            result.add_check(
                name="Custom Model Detection",
                passed=False,
                message="Core ML model uses customModel which may execute arbitrary code",
                severity=IssueSeverity.CRITICAL,
                location=path,
            )
        else:
            result.add_check(
                name="Custom Model Detection",
                passed=True,
                message="Core ML model does not use customModel",
                location=path,
                details={"model_type": model_type},
            )
        if model_type in {"neuralNetwork", "neuralNetworkClassifier", "neuralNetworkRegressor"}:
            nn = getattr(spec, model_type)
            custom_layers_found = False
            for layer in nn.layers:
                if layer.WhichOneof("layer") == "custom":
                    class_name = layer.custom.className
                    result.add_check(
                        name="Custom Layer Detection",
                        passed=False,
                        message=f"Custom layer '{class_name}' detected in Core ML model",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={"layer": layer.name, "class_name": class_name},
                    )
                    custom_layers_found = True

            if not custom_layers_found and nn.layers:
                result.add_check(
                    name="Custom Layer Detection",
                    passed=True,
                    message="No custom layers detected in Core ML model",
                    location=path,
                    details={"layer_count": len(nn.layers)},
                )

        if spec.HasField("linkedModel"):
            result.add_check(
                name="External Model Link Check",
                passed=False,
                message="Core ML model links to external model",
                severity=IssueSeverity.WARNING,
                location=path,
            )
        else:
            result.add_check(
                name="External Model Link Check",
                passed=True,
                message="Core ML model does not link to external models",
                location=path,
            )

        if spec.HasField("serializedModel"):
            result.add_check(
                name="Serialized Sub-Model Check",
                passed=False,
                message="Core ML model contains serialized sub-model",
                severity=IssueSeverity.WARNING,
                location=path,
            )
        else:
            result.add_check(
                name="Serialized Sub-Model Check",
                passed=True,
                message="Core ML model does not contain serialized sub-models",
                location=path,
            )

        result.finish(success=not result.has_errors)
        return result
