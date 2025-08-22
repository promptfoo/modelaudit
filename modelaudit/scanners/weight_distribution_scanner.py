import os
import zipfile
from typing import Any, ClassVar, Optional

import numpy as np
from scipy import stats

from .base import BaseScanner, IssueSeverity, ScanResult, logger

# Try to import format-specific libraries
try:
    import h5py

    HAS_H5PY = True
except ImportError:
    HAS_H5PY = False

try:
    import torch

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import tensorflow as tf

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False


class WeightDistributionScanner(BaseScanner):
    """Scanner that detects anomalous weight distributions potentially indicating trojaned models"""

    name = "weight_distribution"
    description = "Analyzes weight distributions to detect potential backdoors or trojans"
    supported_extensions: ClassVar[list[str]] = [
        ".pt",
        ".pth",
        ".h5",
        ".keras",
        ".hdf5",
        ".pb",
        ".onnx",
        # Note: .safetensors removed - handled exclusively by SafeTensorsScanner
    ]

    def __init__(self, config: Optional[dict[str, Any]] = None):
        super().__init__(config)
        # Configuration parameters
        self.z_score_threshold = self.config.get("z_score_threshold", 3.0)
        self.cosine_similarity_threshold = self.config.get(
            "cosine_similarity_threshold",
            0.7,
        )
        self.weight_magnitude_threshold = self.config.get(
            "weight_magnitude_threshold",
            3.0,
        )
        self.llm_vocab_threshold = self.config.get("llm_vocab_threshold", 10000)
        self.enable_llm_checks = self.config.get("enable_llm_checks", False)
        # Use max_array_size for in-memory array size limits (default 100MB)
        self.max_array_size = self.config.get("max_array_size", 100 * 1024 * 1024)
        # Flag set when weight extraction would be unsafe
        self.extraction_unsafe = False

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if os.path.isdir(path):
            return HAS_TENSORFLOW and os.path.exists(os.path.join(path, "saved_model.pb"))

        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Skip weight distribution analysis for SafeTensors files
        # SafeTensors are inherently safe and can only contain tensor data
        # The SafeTensorsScanner already validates structure and metadata
        if ext == ".safetensors":
            return False

        # Check if we have the necessary libraries for the format
        if ext in [".pt", ".pth"] and not HAS_TORCH:
            return False
        if ext in [".h5", ".keras", ".hdf5"] and not HAS_H5PY:
            return False
        return not (ext == ".pb" and not HAS_TENSORFLOW)

    def scan(self, path: str) -> ScanResult:
        """Scan a model file for weight distribution anomalies"""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        # Reset flag before extraction
        self.extraction_unsafe = False

        try:
            # Extract weights based on file format
            if os.path.isdir(path):
                weights_info = self._extract_tensorflow_weights(path)
            else:
                ext = os.path.splitext(path)[1].lower()

                if ext in [".pt", ".pth"]:
                    weights_info = self._extract_pytorch_weights(path)
                elif ext in [".h5", ".keras", ".hdf5"]:
                    weights_info = self._extract_keras_weights(path)
                elif ext == ".pb":
                    weights_info = self._extract_tensorflow_weights(path)
                elif ext == ".onnx":
                    weights_info = self._extract_onnx_weights(path)
                elif ext == ".safetensors":
                    weights_info = self._extract_safetensors_weights(path)
                else:
                    result.add_check(
                        name="Model Format Support Check",
                        passed=False,
                        message=f"Unsupported model format for weight distribution scanner: {ext}",
                        severity=IssueSeverity.DEBUG,
                        location=path,
                        details={"extension": ext},
                    )
                    result.finish(success=False)
                    return result

            if not weights_info:
                message = "Failed to extract weights from model"
                severity = IssueSeverity.DEBUG
                if self.extraction_unsafe:
                    message = "Unsafe to extract weights from data.pkl in PyTorch archive"
                    severity = IssueSeverity.WARNING
                result.add_check(
                    name="Weight Extraction",
                    passed=False,
                    message=message,
                    severity=severity,
                    location=path,
                )
                result.finish(success=True)
                return result

            # Analyze the weights
            anomalies = self._analyze_weight_distributions(weights_info)

            # Add issues for any anomalies found
            for anomaly in anomalies:
                result.add_check(
                    name="Weight Distribution Anomaly Detection",
                    passed=False,
                    message=anomaly["description"],
                    severity=anomaly["severity"],
                    location=path,
                    details=anomaly["details"],
                    why=anomaly.get("why"),
                )

            # Add metadata
            result.metadata["layers_analyzed"] = len(weights_info)
            result.metadata["anomalies_found"] = len(anomalies)

            result.bytes_scanned = file_size

        except Exception as e:
            result.add_check(
                name="Weight Distribution Analysis",
                passed=False,
                message=f"Error analyzing weight distributions: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _extract_pytorch_weights(self, path: str) -> dict[str, np.ndarray]:
        """Extract weights from PyTorch model files"""
        if not HAS_TORCH:
            return {}

        # Reset safety flag for each extraction
        self.extraction_unsafe = False

        weights_info: dict[str, np.ndarray] = {}

        try:
            # Load model with map_location to CPU to avoid GPU requirements
            model_data = torch.load(path, map_location=torch.device("cpu"))

            # Handle different PyTorch save formats
            if isinstance(model_data, dict):
                # State dict format
                state_dict = model_data.get("state_dict", model_data)

                # Find final layer weights (classification head)
                for key, value in state_dict.items():
                    if isinstance(value, torch.Tensor) and (
                        (
                            any(
                                pattern in key.lower()
                                for pattern in [
                                    "fc",
                                    "classifier",
                                    "head",
                                    "output",
                                    "final",
                                ]
                            )
                            and "weight" in key.lower()
                        )
                        or ("weight" in key.lower() and len(value.shape) >= 2)
                    ):
                        # PyTorch uses (out_features, in_features) but we expect (in_features, out_features)
                        weights_info[key] = value.detach().cpu().numpy().T

            elif hasattr(model_data, "state_dict"):
                # Full model format
                state_dict = model_data.state_dict()
                for key, value in state_dict.items():
                    if "weight" in key.lower() and isinstance(value, torch.Tensor):
                        # PyTorch uses (out_features, in_features) but we expect (in_features, out_features)
                        weights_info[key] = value.detach().cpu().numpy().T

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")
            # Try loading as a zip file (newer PyTorch format)
            try:
                with zipfile.ZipFile(path, "r") as z:
                    data_pkl_path = next(
                        (n for n in z.namelist() if n.endswith("/data.pkl") or n == "data.pkl"),
                        None,
                    )
                    if data_pkl_path:
                        import io
                        import pickle
                        import pickletools

                        data = z.read(data_pkl_path)

                        # Look for disallowed opcodes that could trigger code execution
                        disallowed = {
                            "GLOBAL",
                            "STACK_GLOBAL",
                            "REDUCE",
                            "BUILD",
                            "INST",
                            "OBJ",
                            "NEWOBJ",
                            "NEWOBJ_EX",
                        }
                        unsafe = False
                        for opcode, _arg, _pos in pickletools.genops(data):
                            if opcode.name in disallowed:
                                unsafe = True
                                break

                        if unsafe:
                            self.extraction_unsafe = True
                        else:
                            try:

                                class RestrictedUnpickler(pickle.Unpickler):
                                    def find_class(self, module: str, name: str) -> Any:
                                        raise pickle.UnpicklingError("global lookup not allowed")

                                obj = RestrictedUnpickler(io.BytesIO(data)).load()
                                if isinstance(obj, dict):
                                    for key, value in obj.items():
                                        array = np.array(value)
                                        if len(array.shape) >= 2 and (
                                            "weight" in key.lower() or "kernel" in key.lower()
                                        ):
                                            weights_info[key] = array
                                else:
                                    self.extraction_unsafe = True
                            except Exception as e2:  # pragma: no cover - defensive
                                logger.debug(
                                    f"Failed restricted unpickle for {path}: {e2}",
                                )
                                self.extraction_unsafe = True
            except Exception as e2:  # pragma: no cover - defensive
                logger.debug(f"Failed to extract weights from {path}: {e2}")

        return weights_info

    def _extract_keras_weights(self, path: str) -> dict[str, np.ndarray]:
        """Extract weights from Keras/TensorFlow H5 model files"""
        if not HAS_H5PY:
            return {}

        weights_info: dict[str, np.ndarray] = {}

        try:
            with h5py.File(path, "r") as f:
                # Navigate through the HDF5 structure to find weights
                def extract_weights(name, obj):
                    if isinstance(obj, h5py.Dataset) and ("kernel" in name or "weight" in name):
                        weights_info[name] = np.array(obj)

                f.visititems(extract_weights)

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_tensorflow_weights(self, path: str) -> dict[str, np.ndarray]:
        """Extract weights from TensorFlow SavedModel files"""
        if not HAS_TENSORFLOW:
            return {}

        weights_info: dict[str, np.ndarray] = {}

        try:
            if os.path.isdir(path):
                ckpt_prefix = os.path.join(path, "variables", "variables")
                if os.path.exists(ckpt_prefix + ".index"):
                    for name, _shape in tf.train.list_variables(ckpt_prefix):
                        if "weight" not in name.lower() and "kernel" not in name.lower():
                            continue
                        tensor = tf.train.load_variable(ckpt_prefix, name)
                        array = np.array(tensor)
                        if self.max_array_size and self.max_array_size > 0 and array.nbytes > self.max_array_size:
                            continue
                        # Only include 2D+ tensors for consistency with .pb file handling
                        if len(array.shape) >= 2:
                            weights_info[name] = array
            else:
                data = self._read_file_safely(path)
                from tensorflow.core.framework import graph_pb2
                from tensorflow.core.protobuf import saved_model_pb2

                nodes: list[Any] = []
                saved_model = saved_model_pb2.SavedModel()
                try:
                    saved_model.ParseFromString(data)
                    if saved_model.meta_graphs:
                        for meta_graph in saved_model.meta_graphs:
                            nodes.extend(meta_graph.graph_def.node)
                except Exception:
                    pass

                if not nodes:
                    graph_def = graph_pb2.GraphDef()
                    graph_def.ParseFromString(data)
                    nodes = list(graph_def.node)

                for node in nodes:
                    if node.op == "Const" and "value" in node.attr:
                        tensor_proto = node.attr["value"].tensor
                        array = tf.make_ndarray(tensor_proto)
                        if self.max_array_size and self.max_array_size > 0 and array.nbytes > self.max_array_size:
                            continue
                        if ("weight" in node.name.lower() or "kernel" in node.name.lower()) and len(array.shape) >= 2:
                            weights_info[node.name] = array
        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_onnx_weights(self, path: str) -> dict[str, np.ndarray]:
        """Extract weights from ONNX model files"""
        try:
            import onnx

            HAS_ONNX = True
        except ImportError:
            HAS_ONNX = False

        if not HAS_ONNX:
            return {}

        weights_info: dict[str, np.ndarray] = {}

        try:
            model = onnx.load(path)

            # Extract initializers (weights)
            for initializer in model.graph.initializer:
                if "weight" in initializer.name.lower():
                    weights_info[initializer.name] = onnx.numpy_helper.to_array(
                        initializer,
                    )

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_safetensors_weights(self, path: str) -> dict[str, np.ndarray]:
        """Extract weights from SafeTensors files"""
        try:
            from safetensors import safe_open

            HAS_SAFETENSORS = True
        except ImportError:
            HAS_SAFETENSORS = False

        if not HAS_SAFETENSORS:
            return {}

        weights_info: dict[str, np.ndarray] = {}

        try:
            with safe_open(path, framework="numpy") as f:
                for key in f:
                    if "weight" in key.lower():
                        weights_info[key] = f.get_tensor(key)

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _analyze_weight_distributions(
        self,
        weights_info: dict[str, np.ndarray],
    ) -> list[dict[str, Any]]:
        """Analyze weight distributions for anomalies"""
        anomalies = []

        # SECURITY FIX: Perform architecture analysis once with complete model information
        # This provides accurate architectural classification instead of per-layer analysis
        architecture_analysis = self._analyze_architecture_properties(weights_info)

        # Focus on final layer weights (classification heads)
        final_layer_candidates = {}
        for name, weights in weights_info.items():
            if (
                any(
                    pattern in name.lower()
                    for pattern in [
                        "fc",
                        "classifier",
                        "head",
                        "output",
                        "final",
                        "dense",
                    ]
                )
                and "weight" in name.lower()
            ) and len(weights.shape) == 2:  # Ensure it's a 2D weight matrix
                final_layer_candidates[name] = weights

        # If no clear final layer found, analyze all 2D weight matrices
        if not final_layer_candidates:
            final_layer_candidates = {
                name: weights for name, weights in weights_info.items() if len(weights.shape) == 2
            }

        # Analyze each candidate layer with complete architectural context
        for layer_name, weights in final_layer_candidates.items():
            layer_anomalies = self._analyze_layer_weights(layer_name, weights, architecture_analysis)
            anomalies.extend(layer_anomalies)

        return anomalies

    def _analyze_architecture_properties(self, weights_info: dict[str, np.ndarray]) -> dict[str, Any]:
        """
        Analyze the mathematical and architectural properties to determine model characteristics.
        Uses structural analysis rather than name-based detection to avoid security bypasses.
        """
        analysis: dict[str, Any] = {
            "is_likely_transformer": False,
            "is_likely_llm": False,
            "confidence": 0.0,
            "evidence": [],
            "architectural_features": {},
            "total_parameters": 0,
            "layer_count": 0,
        }

        if not weights_info:
            return analysis

        # Collect weight matrix information
        weight_matrices: list[dict[str, Any]] = []
        total_params = 0

        for layer_name, weights in weights_info.items():
            if len(weights.shape) == 2:  # 2D weight matrices
                weight_matrices.append(
                    {
                        "name": layer_name,
                        "shape": weights.shape,
                        "params": weights.size,
                        "input_dim": weights.shape[0],
                        "output_dim": weights.shape[1],
                    }
                )
                total_params += weights.size

        analysis["total_parameters"] = total_params
        analysis["layer_count"] = len(weight_matrices)

        if len(weight_matrices) == 0:
            analysis["evidence"].append("No 2D weight matrices found")
            return analysis

        # Analyze dimensional patterns typical of transformer architectures
        input_dims = [w["input_dim"] for w in weight_matrices]
        output_dims = [w["output_dim"] for w in weight_matrices]

        # Check for common transformer dimensions (powers of 2, multiples of 64)
        transformer_dims = [64, 128, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 8192]
        matching_dims = 0

        for dim in input_dims + output_dims:
            if dim in transformer_dims or any(dim % td == 0 and dim // td <= 16 for td in transformer_dims):
                matching_dims += 1

        if matching_dims > len(weight_matrices) * 0.6:  # 60% of dimensions match transformer patterns
            analysis["confidence"] += 0.3
            analysis["evidence"].append(f"Found {matching_dims} dimensions matching transformer patterns")
            analysis["is_likely_transformer"] = True

        # Check for large vocabulary/embedding patterns (characteristic of LLMs)
        large_vocab_evidence = 0
        common_vocab_sizes = [30522, 50257, 32000, 28996, 51200, 65536, 100000]  # Known vocab sizes

        for matrix in weight_matrices:
            # Check if either dimension could be a vocabulary size
            for vocab_size in common_vocab_sizes:
                if abs(matrix["output_dim"] - vocab_size) < vocab_size * 0.05:  # 5% tolerance
                    large_vocab_evidence += 1
                    analysis["evidence"].append(f"Found vocabulary-sized layer: {matrix['output_dim']} ≈ {vocab_size}")
                    break

        # Check for large hidden dimensions typical of modern LLMs
        large_hidden_dims = [dim for dim in input_dims + output_dims if dim >= 768]
        if large_hidden_dims:
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Found large hidden dimensions: {set(large_hidden_dims)}")

        # Check for architectural consistency (repeated dimension patterns)
        dim_frequency: dict[int, int] = {}
        for dim in input_dims + output_dims:
            dim_frequency[dim] = dim_frequency.get(dim, 0) + 1

        # Look for repeated dimensions (characteristic of structured architectures)
        repeated_dims = [dim for dim, freq in dim_frequency.items() if freq >= 3]
        if repeated_dims:
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Found repeated architectural dimensions: {repeated_dims}")

        # Check total parameter count (modern LLMs have millions/billions of parameters)
        if total_params > 100_000_000:  # > 100M parameters
            analysis["confidence"] += 0.3
            analysis["evidence"].append(f"Large parameter count: {total_params:,} parameters")
            analysis["is_likely_llm"] = True
        elif total_params > 10_000_000:  # > 10M parameters
            analysis["confidence"] += 0.2
            analysis["evidence"].append(f"Medium parameter count: {total_params:,} parameters")

        # Final classification based on structural evidence
        if analysis["confidence"] > 0.7 and (large_vocab_evidence > 0 or total_params > 50_000_000):
            analysis["is_likely_llm"] = True
            analysis["evidence"].append("High confidence: Large Language Model based on structural analysis")
        elif analysis["confidence"] > 0.5:
            analysis["is_likely_transformer"] = True
            analysis["evidence"].append("Moderate confidence: Transformer-based model")

        analysis["architectural_features"] = {
            "vocab_evidence": large_vocab_evidence,
            "transformer_dims": matching_dims,
            "repeated_dims": len(repeated_dims),
            "max_dimension": max(input_dims + output_dims) if input_dims + output_dims else 0,
            "dimension_diversity": len(set(input_dims + output_dims)),
        }

        return analysis

    def _analyze_layer_weights(
        self,
        layer_name: str,
        weights: np.ndarray,
        architecture_analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Analyze a single layer's weights for anomalies using pre-computed architectural analysis"""
        anomalies: list[dict[str, Any]] = []

        # Weights shape is typically (input_features, output_features) for dense layers
        if len(weights.shape) != 2:
            return anomalies

        n_inputs, n_outputs = weights.shape

        # SECURITY FIX: Use pre-computed architecture analysis from complete model
        # instead of incorrectly analyzing only a single layer

        # Determine appropriate thresholds based on structural properties, not names
        if architecture_analysis["is_likely_llm"] and not self.enable_llm_checks:
            # For confirmed LLMs based on structural analysis, use relaxed thresholds
            # but don't completely skip checks (that would be a security vulnerability)
            z_score_threshold = max(8.0, self.z_score_threshold * 2.5)
            outlier_percentage_threshold = 0.0001  # 0.01% for LLMs
        elif (
            # Large output dimensions (vocabulary layers)
            n_outputs > self.llm_vocab_threshold
            # Large input dimensions (hidden layers in large models)
            or n_inputs > 2048
            # Large weight matrices (characteristic of large models)
            or weights.size > 10_000_000
        ):
            # Moderate relaxation for large models based on size analysis
            z_score_threshold = max(6.0, self.z_score_threshold * 1.8)
            outlier_percentage_threshold = 0.001  # 0.1% for large models
        else:
            # Standard thresholds for smaller models
            z_score_threshold = self.z_score_threshold
            outlier_percentage_threshold = 0.01  # 1% for classification models

        # Always perform security checks regardless of model type
        # (The original code had a security flaw where it would skip all checks for "LLMs")

        # 1. Check for outlier output neurons using Z-score
        output_norms = np.linalg.norm(weights, axis=0)  # L2 norm of each output neuron
        if len(output_norms) > 1:
            z_scores = np.abs(stats.zscore(output_norms))
            outlier_indices = np.where(z_scores > z_score_threshold)[0]

            # Only flag if the number of outliers is reasonable
            outlier_percentage = len(outlier_indices) / n_outputs
            if len(outlier_indices) > 0 and outlier_percentage < outlier_percentage_threshold:
                anomalies.append(
                    {
                        "description": f"Layer '{layer_name}' has {len(outlier_indices)} output neurons with "
                        f"abnormal weight magnitudes",
                        "severity": IssueSeverity.INFO,
                        "details": {
                            "layer": layer_name,
                            "outlier_neurons": outlier_indices.tolist()[:10],  # Limit to first 10
                            "total_outliers": len(outlier_indices),
                            "outlier_percentage": float(outlier_percentage * 100),
                            "z_scores": z_scores[outlier_indices].tolist()[:10],
                            "weight_norms": output_norms[outlier_indices].tolist()[:10],
                            "mean_norm": float(np.mean(output_norms)),
                            "std_norm": float(np.std(output_norms)),
                            "analysis_method": "structural_analysis",
                            "architecture_confidence": architecture_analysis["confidence"],
                        },
                        "why": (
                            "Neurons with weight magnitudes significantly different from others in the same layer may "
                            "indicate tampering, backdoors, or training anomalies. These outliers are flagged when "
                            "their statistical z-score exceeds the threshold. Thresholds are adjusted based on "
                            "structural analysis of the model architecture."
                        ),
                    },
                )

        # 2. Check for dissimilar weight vectors using cosine similarity
        # Only perform this check for smaller output layers to avoid false positives in large vocab models
        if 2 < n_outputs <= 1000:  # Skip for large vocabulary models based on size, not name
            # Compute pairwise cosine similarities
            normalized_weights = weights / (np.linalg.norm(weights, axis=0) + 1e-8)
            similarities = np.dot(normalized_weights.T, normalized_weights)

            dissimilar_neurons = []
            # Find neurons that are dissimilar to all others
            for i in range(n_outputs):
                # Get similarities to other neurons
                other_similarities = np.concatenate(
                    [similarities[i, :i], similarities[i, i + 1 :]],
                )
                max_similarity = np.max(np.abs(other_similarities)) if len(other_similarities) > 0 else 0

                if max_similarity < self.cosine_similarity_threshold:
                    dissimilar_neurons.append((i, max_similarity))

            # Only flag if we have a small number of dissimilar neurons (< 5% or max 3)
            if 0 < len(dissimilar_neurons) <= max(3, int(0.05 * n_outputs)):
                for neuron_idx, max_sim in dissimilar_neurons:
                    anomalies.append(
                        {
                            "description": f"Layer '{layer_name}' output neuron {neuron_idx} has unusually "
                            f"dissimilar weights",
                            "severity": IssueSeverity.INFO,
                            "details": {
                                "layer": layer_name,
                                "neuron_index": neuron_idx,
                                "max_similarity_to_others": float(max_sim),
                                "weight_norm": float(output_norms[neuron_idx]),
                                "total_outputs": n_outputs,
                                "analysis_method": "structural_analysis",
                            },
                            "why": (
                                "Neurons with weight patterns completely unlike others in the same layer are "
                                "uncommon in standard training. This dissimilarity (measured by cosine similarity "
                                "below threshold) may indicate injected functionality or training irregularities."
                            ),
                        },
                    )

        # 3. Check for extreme weight values
        weight_magnitudes = np.abs(weights)
        mean_magnitude = np.mean(weight_magnitudes)
        std_magnitude = np.std(weight_magnitudes)
        threshold = mean_magnitude + self.weight_magnitude_threshold * std_magnitude

        extreme_weights = np.where(weight_magnitudes > threshold)
        if len(extreme_weights[0]) > 0:
            # Group by output neuron
            neurons_with_extreme_weights = np.unique(extreme_weights[1])
            # Only flag if very few neurons affected (< 0.1% or max 5)
            if len(neurons_with_extreme_weights) <= max(5, int(0.001 * n_outputs)):
                anomalies.append(
                    {
                        "description": f"Layer '{layer_name}' has neurons with extremely large weight values",
                        "severity": IssueSeverity.INFO,
                        "details": {
                            "layer": layer_name,
                            "affected_neurons": neurons_with_extreme_weights.tolist()[:10],  # Limit list
                            "total_affected": len(neurons_with_extreme_weights),
                            "num_extreme_weights": len(extreme_weights[0]),
                            "threshold": float(threshold),
                            "max_weight": float(np.max(weight_magnitudes)),
                            "total_outputs": n_outputs,
                            "analysis_method": "structural_analysis",
                        },
                        "why": (
                            "Weight values that are orders of magnitude larger than typical can cause numerical "
                            "instability, overflow attacks, or may encode hidden data. Detection uses statistical "
                            "analysis rather than name-based classification to avoid security bypasses."
                        ),
                    },
                )

        return anomalies
