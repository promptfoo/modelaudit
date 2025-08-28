import os
from pathlib import Path
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

try:
    import numpy as np
    import onnx
    from onnx import mapping

    HAS_ONNX = True
except Exception:
    HAS_ONNX = False


class OnnxScanner(BaseScanner):
    """Scanner for ONNX model files."""

    name = "onnx"
    description = "Scans ONNX models for custom operators and integrity issues"
    supported_extensions: ClassVar[list[str]] = [".onnx"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not HAS_ONNX:
            return False
        if not os.path.isfile(path):
            return False
        return os.path.splitext(path)[1].lower() in cls.supported_extensions

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)
        self.current_file_path = path

        if not HAS_ONNX:
            result.add_check(
                name="ONNX Library Check",
                passed=False,
                message="onnx package not installed, cannot scan ONNX files.",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"required_package": "onnx"},
            )
            result.finish(success=False)
            return result

        try:
            # Check for interrupts before starting the potentially long-running load
            self.check_interrupted()
            model = onnx.load(path, load_external_data=False)
            # Check for interrupts after loading completes
            self.check_interrupted()
            result.bytes_scanned = file_size
        except KeyboardInterrupt:
            # Re-raise keyboard interrupt for graceful shutdown
            raise
        except Exception as e:  # pragma: no cover - unexpected parse errors
            result.add_check(
                name="ONNX Model Parsing",
                passed=False,
                message=f"Error parsing ONNX model: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.metadata.update(
            {
                "ir_version": model.ir_version,
                "producer_name": model.producer_name,
                "node_count": len(model.graph.node),
            },
        )

        # Check for JIT/Script code execution risks in the ONNX model
        # Read the file as binary to scan for patterns
        try:
            # Check for interrupts before file reading
            self.check_interrupted()
            with open(path, "rb") as f:
                model_data = f.read()
            # Check for interrupts after file reading
            self.check_interrupted()
            # Collect findings without creating individual checks
            jit_findings = self.collect_jit_script_findings(
                model_data,
                model_type="onnx",
                context=path,
            )
            network_findings = self.collect_network_communication_findings(
                model_data,
                context=path,
            )

            # Create single aggregated checks for the file
            self.summarize_jit_script_findings(jit_findings, result, context=path)
            self.summarize_network_communication_findings(network_findings, result, context=path)

        except Exception as e:
            # Log but don't fail the scan
            result.add_check(
                name="JIT/Script Code Execution Detection",
                passed=False,
                message=f"Failed to check for JIT/Script code: {e}",
                severity=IssueSeverity.DEBUG,
                location=path,
                details={"exception": str(e)},
            )

        self._check_custom_ops(model, path, result)
        self._check_external_data(model, path, result)
        self._check_tensor_sizes(model, path, result)

        result.finish(success=True)
        return result

    def _check_custom_ops(self, model: Any, path: str, result: ScanResult) -> None:
        custom_domains = set()
        python_ops_found = False
        safe_nodes = 0

        for node in model.graph.node:
            # Check for interrupts periodically during node processing
            self.check_interrupted()
            if node.domain and node.domain not in ("", "ai.onnx"):
                custom_domains.add(node.domain)
                result.add_check(
                    name="Custom Operator Domain Check",
                    passed=False,
                    message=f"Model uses custom operator domain '{node.domain}'",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} (node: {node.name})",
                    details={"op_type": node.op_type, "domain": node.domain},
                )
            elif "python" in node.op_type.lower():
                python_ops_found = True
                result.add_check(
                    name="Python Operator Detection",
                    passed=False,
                    message=f"Model uses Python operator '{node.op_type}'",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path} (node: {node.name})",
                    details={"op_type": node.op_type, "domain": node.domain},
                )
            else:
                safe_nodes += 1

        # Record successful checks for safe operators
        if safe_nodes > 0 and not custom_domains:
            result.add_check(
                name="Custom Operator Domain Check",
                passed=True,
                message="All operators use standard ONNX domains",
                location=path,
                details={"safe_nodes": safe_nodes},
            )

        if not python_ops_found:
            result.add_check(
                name="Python Operator Detection",
                passed=True,
                message="No Python operators detected",
                location=path,
                details={"nodes_checked": len(model.graph.node)},
            )

        if custom_domains:
            result.metadata["custom_domains"] = sorted(custom_domains)

    def _check_external_data(self, model: Any, path: str, result: ScanResult) -> None:
        model_dir = Path(path).resolve().parent
        for tensor in model.graph.initializer:
            # Check for interrupts during external data processing
            self.check_interrupted()
            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                info = {entry.key: entry.value for entry in tensor.external_data}
                location = info.get("location")
                if location is None:
                    result.add_check(
                        name="External Data Location Check",
                        passed=False,
                        message=f"Tensor '{tensor.name}' uses external data without location",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={"tensor": tensor.name},
                    )
                    continue
                external_path = (model_dir / location).resolve()
                if not external_path.exists():
                    result.add_check(
                        name="External Data File Existence",
                        passed=False,
                        message=f"External data file not found for tensor '{tensor.name}'",
                        severity=IssueSeverity.CRITICAL,
                        location=str(external_path),
                        details={"tensor": tensor.name, "file": location},
                    )
                elif not str(external_path).startswith(str(model_dir)):
                    result.add_check(
                        name="External Data Path Traversal Check",
                        passed=False,
                        message=f"External data file outside model directory for tensor '{tensor.name}'",
                        severity=IssueSeverity.CRITICAL,
                        location=str(external_path),
                        details={"tensor": tensor.name, "file": location},
                    )
                else:
                    result.add_check(
                        name="External Data Path Traversal Check",
                        passed=True,
                        message=f"External data file path is safe for tensor '{tensor.name}'",
                        location=str(external_path),
                        details={"tensor": tensor.name, "file": location},
                    )
                    self._validate_external_size(tensor, external_path, result)

    def _validate_external_size(
        self,
        tensor: Any,
        external_path: Path,
        result: ScanResult,
    ) -> None:
        try:
            dtype = np.dtype(mapping.TENSOR_TYPE_TO_NP_TYPE[tensor.data_type])
            num_elem = 1
            for d in tensor.dims:
                num_elem *= d
            expected_size = int(num_elem) * int(dtype.itemsize)
            actual_size = external_path.stat().st_size
            if actual_size < expected_size:
                result.add_check(
                    name="External Data Size Validation",
                    passed=False,
                    message="External data file size mismatch",
                    severity=IssueSeverity.CRITICAL,
                    location=str(external_path),
                    details={
                        "tensor": tensor.name,
                        "expected_size": expected_size,
                        "actual_size": actual_size,
                    },
                )
            else:
                result.add_check(
                    name="External Data Size Validation",
                    passed=True,
                    message="External data file size matches expected",
                    location=str(external_path),
                    details={
                        "tensor": tensor.name,
                        "size": actual_size,
                    },
                )
        except Exception as e:
            result.add_check(
                name="External Data Size Validation",
                passed=False,
                message=f"Failed to validate external data size: {e}",
                severity=IssueSeverity.DEBUG,
                location=str(external_path),
            )

    def _check_tensor_sizes(self, model: Any, path: str, result: ScanResult) -> None:
        for tensor in model.graph.initializer:
            # Check for interrupts during tensor size validation
            self.check_interrupted()
            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                continue
            if tensor.raw_data:
                try:
                    dtype = np.dtype(mapping.TENSOR_TYPE_TO_NP_TYPE[tensor.data_type])
                    num_elem = 1
                    for d in tensor.dims:
                        num_elem *= d
                    expected_size = int(num_elem) * int(dtype.itemsize)
                    actual_size = len(tensor.raw_data)
                    if actual_size < expected_size:
                        result.add_check(
                            name="Tensor Size Validation",
                            passed=False,
                            message=f"Tensor '{tensor.name}' data appears truncated",
                            severity=IssueSeverity.CRITICAL,
                            location=f"{path} (tensor: {tensor.name})",
                            details={
                                "expected_size": expected_size,
                                "actual_size": actual_size,
                            },
                        )
                    else:
                        result.add_check(
                            name="Tensor Size Validation",
                            passed=True,
                            message=f"Tensor '{tensor.name}' size is valid",
                            location=f"{path} (tensor: {tensor.name})",
                            details={
                                "size": actual_size,
                            },
                        )
                except Exception as e:
                    result.add_check(
                        name="Tensor Validation",
                        passed=False,
                        message=f"Failed to validate tensor '{tensor.name}': {e}",
                        severity=IssueSeverity.DEBUG,
                        location=path,
                    )
