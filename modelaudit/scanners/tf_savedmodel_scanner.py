import os
from typing import Any, Dict, Optional

from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import TensorFlow, but handle the case where it's not installed
try:
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

    # Create a placeholder for type hints when TensorFlow is not available
    class SavedModelPlaceholder:
        """Placeholder for SavedModel when TensorFlow is not installed"""

        meta_graphs: list = []

    SavedModel = SavedModelPlaceholder


# List of suspicious TensorFlow operations that could be security risks
SUSPICIOUS_OPS = {
    # File I/O operations
    "ReadFile",
    "WriteFile",
    "MergeV2Checkpoints",
    "Save",
    "SaveV2",
    # Python execution
    "PyFunc",
    "PyCall",
    # System operations
    "ShellExecute",
    "ExecuteOp",
    "SystemConfig",
    # Other potentially risky operations
    "DecodeRaw",
    "DecodeJpeg",
    "DecodePng",
}


class TensorFlowSavedModelScanner(BaseScanner):
    """Scanner for TensorFlow SavedModel format"""

    name = "tensorflow_savedmodel"
    description = "Scans TensorFlow SavedModel for suspicious operations"
    supported_extensions = []  # Directory-based format

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Additional TensorFlow-specific configuration
        self.check_ops = self.config.get("check_ops", True)
        self.check_pickle_files = self.config.get("check_pickle_files", True)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if the path is a TensorFlow SavedModel directory"""
        if not os.path.isdir(path):
            return False

        # Check for required SavedModel files
        saved_model_pb = os.path.join(path, "saved_model.pb")
        variables_dir = os.path.join(path, "variables")

        return os.path.isfile(saved_model_pb) and os.path.isdir(variables_dir)

    def scan(self, path: str) -> ScanResult:
        """Scan a TensorFlow SavedModel directory for suspicious content"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()

        if not HAS_TENSORFLOW:
            result.add_issue(
                "TensorFlow not available - cannot analyze SavedModel operations",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"missing_dependency": "tensorflow"},
            )
        else:
            # Scan the SavedModel protobuf for suspicious operations
            if self.check_ops:
                self._scan_saved_model_ops(path, result)

        # Check for suspicious pickle files
        if self.check_pickle_files:
            self._scan_pickle_files(path, result)

        result.finish(success=True)
        return result

    def _scan_saved_model_ops(self, path: str, result: ScanResult) -> None:
        """Scan SavedModel protobuf for suspicious operations"""
        saved_model_path = os.path.join(path, "saved_model.pb")

        try:
            with open(saved_model_path, "rb") as f:
                saved_model = SavedModel()
                saved_model.ParseFromString(f.read())

            # Analyze the graph for suspicious operations
            for meta_graph in saved_model.meta_graphs:
                graph_def = meta_graph.graph_def
                for node in graph_def.node:
                    if node.op in SUSPICIOUS_OPS:
                        result.add_issue(
                            f"Suspicious TensorFlow operation: {node.op}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}/saved_model.pb",
                            details={
                                "operation": node.op,
                                "node_name": node.name,
                                "node_input": list(node.input),
                            },
                        )

                    # Check for PyFunc operations specifically
                    if node.op == "PyFunc":
                        # PyFunc can execute arbitrary Python code
                        result.add_issue(
                            "PyFunc operation found - can execute arbitrary Python code",
                            severity=IssueSeverity.ERROR,
                            location=f"{path}/saved_model.pb",
                            details={
                                "operation": node.op,
                                "node_name": node.name,
                                "attributes": dict(node.attr),
                            },
                        )

                    # Check for file I/O operations
                    if node.op in ["ReadFile", "WriteFile"]:
                        result.add_issue(
                            f"File I/O operation found: {node.op}",
                            severity=IssueSeverity.WARNING,
                            location=f"{path}/saved_model.pb",
                            details={
                                "operation": node.op,
                                "node_name": node.name,
                                "node_input": list(node.input),
                            },
                        )

        except Exception as e:
            result.add_issue(
                f"Error reading SavedModel protobuf: {str(e)}",
                severity=IssueSeverity.ERROR,
                location=saved_model_path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _scan_pickle_files(self, path: str, result: ScanResult) -> None:
        """Scan for pickle files that might contain malicious code"""
        from .pickle_scanner import PickleScanner

        pickle_scanner = PickleScanner(self.config)

        # Recursively search for pickle files
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith((".pkl", ".pickle")):
                    pickle_path = os.path.join(root, file)
                    try:
                        # Scan the pickle file
                        pickle_result = pickle_scanner.scan(pickle_path)

                        # Add context that this was found in a SavedModel
                        for issue in pickle_result.issues:
                            if issue.details:
                                issue.details["found_in_savedmodel"] = path
                            else:
                                issue.details = {"found_in_savedmodel": path}

                        # Merge the results
                        result.merge(pickle_result)

                    except Exception as e:
                        result.add_issue(
                            f"Error scanning pickle file {file}: {str(e)}",
                            severity=IssueSeverity.ERROR,
                            location=pickle_path,
                            details={
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                                "found_in_savedmodel": path,
                            },
                        )
