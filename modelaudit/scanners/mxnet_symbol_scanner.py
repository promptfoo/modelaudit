"""
MXNet Symbol Scanner

Security scanner for MXNet model symbol/architecture files (JSON format).
Detects vulnerabilities in MXNet network architecture definitions including
CVE-2022-24294 ReDoS attacks and custom operator security risks.

Supported Formats:
- JSON symbol files (*-symbol.json): Network architecture definitions
- JSON files with MXNet graph structure (nodes, arg_nodes, etc.)

Security Focus:
- CVE-2022-24294: ReDoS via malicious operator names
- Custom operator detection (potential external code requirements)
- Malformed graph structures leading to DoS
- Suspicious patterns in JSON content
- Graph complexity and resource exhaustion attacks
"""

import json
import os
import re
from typing import Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult


class MXNetSymbolScanner(BaseScanner):
    """Scanner for MXNet symbol/architecture JSON files."""

    name: ClassVar[str] = "mxnet_symbol"
    description: ClassVar[str] = "Scans MXNet symbol files for security vulnerabilities"
    supported_extensions: ClassVar[list[str]] = [".json"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.max_json_size = self.config.get("max_json_size", 50 * 1024 * 1024)  # 50MB
        self.max_nodes = self.config.get("max_nodes", 100000)  # Max nodes in graph
        self.max_op_name_length = self.config.get("max_op_name_length", 200)
        self.max_graph_depth = self.config.get("max_graph_depth", 1000)

        # Known MXNet built-in operators (subset for validation)
        self.known_ops = {
            "Convolution",
            "FullyConnected",
            "Activation",
            "Pooling",
            "BatchNorm",
            "Dropout",
            "SoftmaxOutput",
            "LinearRegressionOutput",
            "Concat",
            "Flatten",
            "Reshape",
            "Transpose",
            "SliceChannel",
            "ElementWiseSum",
            "broadcast_add",
            "broadcast_mul",
            "Embedding",
            "LSTM",
            "RNN",
            "GRU",
            "LeakyReLU",
            "Crop",
            "UpSampling",
            "ROIPooling",
            "Deconvolution",
            "_copy",
            "_zeros",
            "_ones",
            "null",
            "Variable",  # Special MXNet operators
        }

        # CVE-2022-24294: ReDoS patterns that trigger catastrophic backtracking
        self.redos_patterns = [
            # Complex repetition patterns that can cause regex DoS
            r".*(\(+.*\)+.*){10,}",  # Many nested parentheses
            r".*(\[+.*\]+.*){10,}",  # Many nested brackets
            r".*(a+a+a+a+){5,}",  # Repetitive character patterns causing backtracking
            r".*([a-z]+_){30,}",  # Many underscored components (raised threshold)
            r".*(([a-zA-Z])\2{10,}){5,}",  # Repeated character sequences (e.g., aaaaaaaaaa)
            r".*((.)\\1{20,}){3,}",  # Backreference patterns causing exponential time
        ]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        if not os.path.isfile(path):
            return False

        # Check for JSON extension
        if not path.lower().endswith(".json"):
            return False

        # Check if it's likely an MXNet symbol file
        try:
            with open(path, encoding="utf-8") as f:
                # Read first few KB to check for MXNet-specific structure
                content = f.read(8192)

            # Parse as JSON to check structure
            try:
                data = json.loads(content)

                # Must have 'nodes' array as primary indicator
                if not isinstance(data.get("nodes"), list):
                    return False

                # Additional MXNet-specific indicators (at least 2 required)
                mxnet_indicators = [
                    '"arg_nodes":' in content,
                    '"node_row_ptr":' in content,
                    '"heads":' in content,
                    '"attrs":' in content,
                    '"mxnet_version":' in content,
                    any('"op":' in str(node) for node in data.get("nodes", [])[:5] if isinstance(node, dict)),
                ]

                # Exclude XGBoost files explicitly
                if '"learner":' in content or ('"version":' in content and '"gradient_booster"' in content):
                    return False

                # Exclude Keras/TensorFlow configs
                if '"class_name":' in content or '"config":' in content:
                    return False

                return sum(mxnet_indicators) >= 2

            except json.JSONDecodeError:
                # If we can't parse as JSON, fall back to text search
                mxnet_patterns = [
                    '"nodes":',
                    '"arg_nodes":',
                    '"node_row_ptr":',
                    '"heads":',
                    '"attrs":',
                    '"mxnet_version":',
                    '"op":',
                    '"name":',
                    '"inputs":',
                ]

                # Exclude XGBoost/Keras patterns
                exclude_patterns = ['"learner":', '"gradient_booster":', '"class_name":', '"config":']
                if any(pattern in content for pattern in exclude_patterns):
                    return False

                return sum(1 for pattern in mxnet_patterns if pattern in content) >= 3
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False

    def scan(self, path: str) -> ScanResult:
        """Scan MXNet symbol JSON file for security vulnerabilities."""
        # Standard path checks
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path

        # Add file integrity check
        self.add_file_integrity_check(path, result)

        # Check file size limits
        file_size = os.path.getsize(path)
        if file_size > self.max_json_size:
            result.add_check(
                name="JSON File Size Check",
                passed=False,
                message=f"MXNet symbol JSON file too large: {file_size} bytes (max: {self.max_json_size})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"file_size": file_size, "max_size": self.max_json_size},
                why="Extremely large JSON files may cause memory exhaustion during parsing",
            )
            result.finish(success=False)
            return result

        try:
            # Parse JSON
            with open(path, encoding="utf-8") as f:
                symbol_data = json.load(f)

            result.add_check(
                name="JSON Parsing",
                passed=True,
                message="MXNet symbol JSON parsed successfully",
                location=path,
                details={"file_size": file_size},
            )

            # Validate MXNet symbol structure
            self._validate_mxnet_symbol_structure(symbol_data, result, path)

            # Check for CVE-2022-24294 (ReDoS via operator names)
            self._check_redos_vulnerability(symbol_data, result, path)

            # Detect custom operators and unknown ops
            self._check_custom_operators(symbol_data, result, path)

            # Check for suspicious content patterns
            self._check_suspicious_content(symbol_data, result, path)

            # Validate graph complexity
            self._validate_graph_complexity(symbol_data, result, path)

        except json.JSONDecodeError as e:
            result.add_check(
                name="JSON Parsing",
                passed=False,
                message=f"Invalid JSON format in MXNet symbol: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"json_error": str(e)},
                why="Malformed JSON may indicate file corruption or attack",
            )
        except Exception as e:
            result.add_check(
                name="MXNet Symbol Analysis",
                passed=False,
                message=f"Error analyzing MXNet symbol file: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e)},
            )

        result.finish(success=True)
        return result

    def _validate_mxnet_symbol_structure(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate basic MXNet symbol JSON structure."""
        # Check for required top-level keys
        required_keys = ["nodes"]
        missing_keys = [key for key in required_keys if key not in data]

        if missing_keys:
            result.add_check(
                name="MXNet Symbol Structure Validation",
                passed=False,
                message=f"Missing required MXNet symbol keys: {missing_keys}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"missing_keys": missing_keys, "available_keys": list(data.keys())},
                why="Invalid structure may indicate corruption or non-MXNet JSON file",
            )
            return

        # Validate nodes structure
        nodes = data.get("nodes", [])
        if not isinstance(nodes, list):
            result.add_check(
                name="MXNet Nodes Structure Validation",
                passed=False,
                message="MXNet 'nodes' field is not a list",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"nodes_type": type(nodes).__name__},
                why="Invalid nodes structure may indicate malformed or malicious content",
            )
            return

        result.add_check(
            name="MXNet Symbol Structure Validation",
            passed=True,
            message="MXNet symbol structure validation passed",
            location=path,
            details={"num_nodes": len(nodes)},
        )

        # Check MXNet version if available
        attrs = data.get("attrs", {})
        if isinstance(attrs, dict):
            mxnet_version = attrs.get("mxnet_version")
            if mxnet_version:
                result.add_check(
                    name="MXNet Version Detection",
                    passed=True,
                    message=f"MXNet version detected: {mxnet_version}",
                    location=path,
                    details={"mxnet_version": mxnet_version},
                )

    def _check_redos_vulnerability(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for CVE-2022-24294 ReDoS vulnerability patterns."""
        nodes = data.get("nodes", [])

        for i, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue

            # Check operator name for ReDoS patterns
            op_name = node.get("op", "")
            node_name = node.get("name", "")

            # Check both operator name and node name
            for name_type, name_value in [("operator", op_name), ("node", node_name)]:
                if not isinstance(name_value, str):
                    continue

                # Length check - CVE-2022-24294 often involves very long names
                if len(name_value) > self.max_op_name_length:
                    result.add_check(
                        name="CVE-2022-24294 Length Check",
                        passed=False,
                        message=f"Extremely long {name_type} name ({len(name_value)} chars) may exploit CVE-2022-24294",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "node_index": i,
                            "name_type": name_type,
                            "name_length": len(name_value),
                            "max_length": self.max_op_name_length,
                            "cve": "CVE-2022-24294",
                        },
                        why="CVE-2022-24294: Extremely long operator names can trigger ReDoS in MXNet < 1.9.1",
                    )

                # Pattern-based ReDoS detection
                for pattern in self.redos_patterns:
                    if re.search(pattern, name_value, re.IGNORECASE):
                        result.add_check(
                            name="CVE-2022-24294 Pattern Check",
                            passed=False,
                            message=f"Suspicious {name_type} name pattern may exploit CVE-2022-24294 ReDoS",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "node_index": i,
                                "name_type": name_type,
                                "pattern_matched": pattern,
                                "cve": "CVE-2022-24294",
                            },
                            why="CVE-2022-24294: Complex patterns in operator names cause regex DoS in MXNet < 1.9.1",
                        )
                        break

    def _check_custom_operators(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Detect custom operators that may require external code."""
        nodes = data.get("nodes", [])
        custom_ops = []
        unknown_ops = []

        for i, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue

            op_name = node.get("op", "")
            if not isinstance(op_name, str):
                continue

            # Check for explicit custom operators
            if op_name.lower() == "custom":
                custom_ops.append({"index": i, "node_name": node.get("name", "unknown")})

            # Check for unknown operators not in built-in set
            elif op_name and op_name not in self.known_ops:
                unknown_ops.append({"index": i, "op": op_name, "node_name": node.get("name", "")})

        # Report custom operators
        if custom_ops:
            result.add_check(
                name="Custom Operator Detection",
                passed=False,
                message=f"Found {len(custom_ops)} custom operators requiring external code",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "custom_operators": custom_ops[:10],  # Limit to first 10
                    "total_count": len(custom_ops),
                },
                why="Custom operators require external implementations that could contain malicious code",
            )

        # Report unknown operators (could be custom or typos)
        if unknown_ops:
            result.add_check(
                name="Unknown Operator Detection",
                passed=False,
                message=f"Found {len(unknown_ops)} unknown/unrecognized operators",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "unknown_operators": unknown_ops[:10],  # Limit to first 10
                    "total_count": len(unknown_ops),
                },
                why="Unknown operators may indicate custom implementations, typos, or newer MXNet versions",
            )

    def _check_suspicious_content(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Check for suspicious patterns in JSON content."""
        # Convert to string for pattern matching
        json_str = json.dumps(data, separators=(",", ":"))

        # Suspicious patterns that shouldn't appear in model architecture
        suspicious_patterns = [
            (r"eval\s*\(", "Eval function call in JSON"),
            (r"exec\s*\(", "Exec function call in JSON"),
            (r"import\s+os", "OS module import in JSON"),
            (r"subprocess\.", "Subprocess usage in JSON"),
            (r"system\s*\(", "System call in JSON"),
            (r"__import__", "Dynamic import in JSON"),
            (r"\\x[0-9a-fA-F]{2}", "Hex-encoded data (potential shellcode)"),
            (r"\.popen\s*\(", "Process spawning in JSON"),
            (r'open\s*\([\'"][^\'"]*(\/etc\/|\/bin\/)', "File system access patterns"),
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, json_str, re.IGNORECASE):
                result.add_check(
                    name="Suspicious Content Detection",
                    passed=False,
                    message=f"Suspicious pattern detected: {description}",
                    severity=IssueSeverity.CRITICAL,
                    location=path,
                    details={"pattern": pattern, "description": description},
                    why="Suspicious patterns in model JSON may indicate embedded malicious code",
                )

    def _validate_graph_complexity(self, data: dict[str, Any], result: ScanResult, path: str) -> None:
        """Validate graph complexity to detect potential DoS attacks."""
        nodes = data.get("nodes", [])
        num_nodes = len(nodes)

        # Check total number of nodes
        if num_nodes > self.max_nodes:
            result.add_check(
                name="Graph Complexity Check",
                passed=False,
                message=f"Extremely large graph with {num_nodes} nodes (max: {self.max_nodes})",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"num_nodes": num_nodes, "max_nodes": self.max_nodes},
                why="Extremely large graphs may cause memory exhaustion or parsing delays",
            )

        # Check graph depth and connectivity
        if isinstance(nodes, list):
            max_depth = self._calculate_graph_depth(nodes)
            if max_depth > self.max_graph_depth:
                result.add_check(
                    name="Graph Depth Check",
                    passed=False,
                    message=f"Extremely deep graph (depth: {max_depth}, max: {self.max_graph_depth})",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"graph_depth": max_depth, "max_depth": self.max_graph_depth},
                    why="Extremely deep graphs may cause stack overflow during processing",
                )

        # Check for reasonable graph structure
        if num_nodes > 0:
            result.add_check(
                name="Graph Complexity Check",
                passed=True,
                message=f"Graph complexity within reasonable limits ({num_nodes} nodes)",
                location=path,
                details={"num_nodes": num_nodes},
            )

    def _calculate_graph_depth(self, nodes: list[dict[str, Any]]) -> int:
        """Calculate maximum depth of the computation graph."""
        try:
            # Build adjacency list
            graph = {}
            for i, node in enumerate(nodes):
                inputs = node.get("inputs", [])
                if isinstance(inputs, list):
                    graph[i] = [inp[0] if isinstance(inp, list) and inp else inp for inp in inputs if inp is not None]
                else:
                    graph[i] = []

            # DFS to find maximum depth
            visited = set()

            def dfs(node_id: int, depth: int = 0) -> int:
                if node_id in visited or node_id not in graph:
                    return depth
                visited.add(node_id)
                max_child_depth = depth
                for child in graph[node_id]:
                    if isinstance(child, int):
                        max_child_depth = max(max_child_depth, dfs(child, depth + 1))
                return max_child_depth

            max_depth = 0
            for node_id in graph:
                visited.clear()
                max_depth = max(max_depth, dfs(node_id))

            return max_depth

        except Exception:
            # If depth calculation fails, return a safe default
            return len(nodes) // 10  # Conservative estimate
