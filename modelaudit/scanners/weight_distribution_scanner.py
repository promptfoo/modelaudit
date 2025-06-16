import os
import zipfile
from typing import Any, Dict, List, Optional

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
    import tensorflow as tf  # noqa: F401

    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False


class WeightDistributionScanner(BaseScanner):
    """Scanner that detects anomalous weight distributions potentially indicating trojaned models"""

    name = "weight_distribution"
    description = (
        "Analyzes weight distributions to detect potential backdoors or trojans"
    )
    supported_extensions = [
        ".pt",
        ".pth",
        ".h5",
        ".keras",
        ".hdf5",
        ".pb",
        ".onnx",
        ".safetensors",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Configuration parameters
        self.z_score_threshold = self.config.get("z_score_threshold", 3.0)
        self.cosine_similarity_threshold = self.config.get(
            "cosine_similarity_threshold", 0.7
        )
        self.weight_magnitude_threshold = self.config.get(
            "weight_magnitude_threshold", 3.0
        )
        self.llm_vocab_threshold = self.config.get("llm_vocab_threshold", 10000)
        self.enable_llm_checks = self.config.get("enable_llm_checks", False)

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check if we have the necessary libraries for the format
        if ext in [".pt", ".pth"] and not HAS_TORCH:
            return False
        if ext in [".h5", ".keras", ".hdf5"] and not HAS_H5PY:
            return False
        if ext == ".pb" and not HAS_TENSORFLOW:
            return False

        return True

    def scan(self, path: str) -> ScanResult:
        """Scan a model file for weight distribution anomalies"""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Extract weights based on file format
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
                result.add_issue(
                    f"Unsupported model format for weight distribution scanner: {ext}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )
                result.finish(success=False)
                return result

            if not weights_info:
                result.add_issue(
                    "Could not extract weights from model",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )
                result.finish(success=True)
                return result

            # Analyze the weights
            anomalies = self._analyze_weight_distributions(weights_info)

            # Add issues for any anomalies found
            for anomaly in anomalies:
                result.add_issue(
                    anomaly["description"],
                    severity=anomaly["severity"],
                    location=path,
                    details=anomaly["details"],
                )

            # Add metadata
            result.metadata["layers_analyzed"] = len(weights_info)
            result.metadata["anomalies_found"] = len(anomalies)

            result.bytes_scanned = file_size

        except Exception as e:
            result.add_issue(
                f"Error analyzing weight distributions: {str(e)}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _extract_pytorch_weights(self, path: str) -> Dict[str, np.ndarray]:
        """Extract weights from PyTorch model files"""
        if not HAS_TORCH:
            return {}

        weights_info: Dict[str, np.ndarray] = {}

        try:
            # Load model with map_location to CPU to avoid GPU requirements
            model_data = torch.load(path, map_location=torch.device("cpu"))

            # Handle different PyTorch save formats
            if isinstance(model_data, dict):
                # State dict format
                state_dict = model_data.get("state_dict", model_data)

                # Find final layer weights (classification head)
                for key, value in state_dict.items():
                    if isinstance(value, torch.Tensor):
                        # Look for final layer patterns
                        if (
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
                        ):
                            # PyTorch uses (out_features, in_features) but we expect (in_features, out_features)
                            weights_info[key] = value.detach().cpu().numpy().T
                        # Also include all weight tensors for comprehensive analysis
                        elif "weight" in key.lower() and len(value.shape) >= 2:
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
                    # Look for data.pkl which contains the weights
                    if "data.pkl" in z.namelist():
                        # We can't easily extract weights from pickle without executing it
                        # This is a limitation we should document
                        pass
            except Exception as e:
                logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_keras_weights(self, path: str) -> Dict[str, np.ndarray]:
        """Extract weights from Keras/TensorFlow H5 model files"""
        if not HAS_H5PY:
            return {}

        weights_info: Dict[str, np.ndarray] = {}

        try:
            with h5py.File(path, "r") as f:
                # Navigate through the HDF5 structure to find weights
                def extract_weights(name, obj):
                    if isinstance(obj, h5py.Dataset):
                        # Check if this is a weight array
                        if "kernel" in name or "weight" in name:
                            weights_info[name] = np.array(obj)

                f.visititems(extract_weights)

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_tensorflow_weights(self, path: str) -> Dict[str, np.ndarray]:
        """Extract weights from TensorFlow SavedModel files"""
        if not HAS_TENSORFLOW:
            return {}

        weights_info: Dict[str, np.ndarray] = {}

        # TensorFlow SavedModel weight extraction is complex and would require
        # loading the full graph. For now, we'll return empty.
        # This is a limitation that should be documented.

        return weights_info

    def _extract_onnx_weights(self, path: str) -> Dict[str, np.ndarray]:
        """Extract weights from ONNX model files"""
        try:
            import onnx

            HAS_ONNX = True
        except ImportError:
            HAS_ONNX = False

        if not HAS_ONNX:
            return {}

        weights_info: Dict[str, np.ndarray] = {}

        try:
            model = onnx.load(path)

            # Extract initializers (weights)
            for initializer in model.graph.initializer:
                if "weight" in initializer.name.lower():
                    weights_info[initializer.name] = onnx.numpy_helper.to_array(
                        initializer
                    )

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _extract_safetensors_weights(self, path: str) -> Dict[str, np.ndarray]:
        """Extract weights from SafeTensors files"""
        try:
            from safetensors import safe_open

            HAS_SAFETENSORS = True
        except ImportError:
            HAS_SAFETENSORS = False

        if not HAS_SAFETENSORS:
            return {}

        weights_info: Dict[str, np.ndarray] = {}

        try:
            with safe_open(path, framework="numpy") as f:
                for key in f.keys():
                    if "weight" in key.lower():
                        weights_info[key] = f.get_tensor(key)

        except Exception as e:
            logger.debug(f"Failed to extract weights from {path}: {e}")

        return weights_info

    def _analyze_weight_distributions(
        self, weights_info: Dict[str, np.ndarray]
    ) -> List[Dict[str, Any]]:
        """Analyze weight distributions for anomalies"""
        anomalies = []

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
            ):
                if len(weights.shape) == 2:  # Ensure it's a 2D weight matrix
                    final_layer_candidates[name] = weights

        # If no clear final layer found, analyze all 2D weight matrices
        if not final_layer_candidates:
            final_layer_candidates = {
                name: weights
                for name, weights in weights_info.items()
                if len(weights.shape) == 2
            }

        # Analyze each candidate layer
        for layer_name, weights in final_layer_candidates.items():
            layer_anomalies = self._analyze_layer_weights(layer_name, weights)
            anomalies.extend(layer_anomalies)

        return anomalies

    def _analyze_layer_weights(
        self, layer_name: str, weights: np.ndarray
    ) -> List[Dict[str, Any]]:
        """Analyze a single layer's weights for anomalies"""
        anomalies: List[Dict[str, Any]] = []

        # Weights shape is typically (input_features, output_features) for dense layers
        if len(weights.shape) != 2:
            return anomalies

        n_inputs, n_outputs = weights.shape

        # Detect if this is likely an LLM vocabulary layer
        is_likely_llm = n_outputs > self.llm_vocab_threshold

        # Skip checks for LLMs if disabled
        if is_likely_llm and not self.enable_llm_checks:
            return []

        # For LLMs, we need much stricter thresholds to avoid false positives
        if is_likely_llm:
            # For LLMs, only check for extreme outliers with much higher thresholds
            z_score_threshold = max(5.0, self.z_score_threshold * 1.5)
            outlier_percentage_threshold = 0.001  # 0.1% for LLMs
        else:
            z_score_threshold = self.z_score_threshold
            outlier_percentage_threshold = 0.01  # 1% for classification models

        # 1. Check for outlier output neurons using Z-score
        output_norms = np.linalg.norm(weights, axis=0)  # L2 norm of each output neuron
        if len(output_norms) > 1:
            z_scores = np.abs(stats.zscore(output_norms))
            outlier_indices = np.where(z_scores > z_score_threshold)[0]

            # Only flag if the number of outliers is reasonable
            outlier_percentage = len(outlier_indices) / n_outputs
            if (
                len(outlier_indices) > 0
                and outlier_percentage < outlier_percentage_threshold
            ):
                anomalies.append(
                    {
                        "description": f"Layer '{layer_name}' has {len(outlier_indices)} output neurons with abnormal weight magnitudes",
                        "severity": IssueSeverity.INFO,
                        "details": {
                            "layer": layer_name,
                            "outlier_neurons": outlier_indices.tolist()[
                                :10
                            ],  # Limit to first 10
                            "total_outliers": len(outlier_indices),
                            "outlier_percentage": float(outlier_percentage * 100),
                            "z_scores": z_scores[outlier_indices].tolist()[:10],
                            "weight_norms": output_norms[outlier_indices].tolist()[:10],
                            "mean_norm": float(np.mean(output_norms)),
                            "std_norm": float(np.std(output_norms)),
                        },
                    }
                )

        # 2. Check for dissimilar weight vectors using cosine similarity
        # Only perform this check for classification models (small number of outputs)
        if 2 < n_outputs <= 1000:  # Skip for large vocabulary models
            # Compute pairwise cosine similarities
            normalized_weights = weights / (np.linalg.norm(weights, axis=0) + 1e-8)
            similarities = np.dot(normalized_weights.T, normalized_weights)

            dissimilar_neurons = []
            # Find neurons that are dissimilar to all others
            for i in range(n_outputs):
                # Get similarities to other neurons
                other_similarities = np.concatenate(
                    [similarities[i, :i], similarities[i, i + 1 :]]
                )
                max_similarity = (
                    np.max(np.abs(other_similarities))
                    if len(other_similarities) > 0
                    else 0
                )

                if max_similarity < self.cosine_similarity_threshold:
                    dissimilar_neurons.append((i, max_similarity))

            # Only flag if we have a small number of dissimilar neurons (< 5% or max 3)
            if 0 < len(dissimilar_neurons) <= max(3, int(0.05 * n_outputs)):
                for neuron_idx, max_sim in dissimilar_neurons:
                    anomalies.append(
                        {
                            "description": f"Layer '{layer_name}' output neuron {neuron_idx} has unusually dissimilar weights",
                            "severity": IssueSeverity.INFO,
                            "details": {
                                "layer": layer_name,
                                "neuron_index": neuron_idx,
                                "max_similarity_to_others": float(max_sim),
                                "weight_norm": float(output_norms[neuron_idx]),
                                "total_outputs": n_outputs,
                            },
                        }
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
                            "affected_neurons": neurons_with_extreme_weights.tolist()[
                                :10
                            ],  # Limit list
                            "total_affected": len(neurons_with_extreme_weights),
                            "num_extreme_weights": len(extreme_weights[0]),
                            "threshold": float(threshold),
                            "max_weight": float(np.max(weight_magnitudes)),
                            "total_outputs": n_outputs,
                        },
                    }
                )

        return anomalies
