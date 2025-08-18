"""Statistical anomaly detection for model files."""

import math
from dataclasses import dataclass
from typing import Any

import numpy as np
from scipy import stats


@dataclass
class StatisticalProfile:
    """Statistical profile of a model component."""

    mean: float
    std: float
    min_val: float
    max_val: float
    percentiles: dict[int, float]  # 1, 5, 25, 50, 75, 95, 99
    skewness: float
    kurtosis: float
    entropy: float
    zero_ratio: float
    sparsity: float

    def is_anomalous(self, other: "StatisticalProfile", threshold: float = 3.0) -> tuple[bool, float]:
        """Check if another profile is anomalous compared to this one."""
        # Calculate z-scores for each metric
        z_scores = []

        # Mean difference
        if self.std > 0:
            z_scores.append(abs(other.mean - self.mean) / self.std)

        # Standard deviation ratio
        if self.std > 0:
            std_ratio = other.std / self.std
            z_scores.append(abs(math.log(std_ratio)) if std_ratio > 0 else threshold)

        # Range difference
        range_self = self.max_val - self.min_val
        range_other = other.max_val - other.min_val
        if range_self > 0:
            z_scores.append(abs(range_other - range_self) / range_self)

        # Distribution shape differences
        z_scores.append(abs(other.skewness - self.skewness))
        z_scores.append(abs(other.kurtosis - self.kurtosis) / 10.0)  # Kurtosis can be large

        # Sparsity difference
        z_scores.append(abs(other.sparsity - self.sparsity) * 10.0)

        # Calculate composite anomaly score
        anomaly_score = np.mean(z_scores) if z_scores else 0.0

        return bool(anomaly_score > threshold), float(anomaly_score)


class AnomalyDetector:
    """Detects anomalies in model files using statistical analysis."""

    def __init__(self):
        # Known good profiles for different layer types
        self.layer_profiles = {
            "conv2d_weights": StatisticalProfile(
                mean=0.0,
                std=0.05,
                min_val=-0.3,
                max_val=0.3,
                percentiles={1: -0.15, 5: -0.1, 25: -0.05, 50: 0.0, 75: 0.05, 95: 0.1, 99: 0.15},
                skewness=0.0,
                kurtosis=3.0,
                entropy=7.5,
                zero_ratio=0.01,
                sparsity=0.05,
            ),
            "dense_weights": StatisticalProfile(
                mean=0.0,
                std=0.1,
                min_val=-0.5,
                max_val=0.5,
                percentiles={1: -0.25, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.25},
                skewness=0.0,
                kurtosis=3.0,
                entropy=7.6,
                zero_ratio=0.02,
                sparsity=0.1,
            ),
            "attention_weights": StatisticalProfile(
                mean=0.0,
                std=0.02,
                min_val=-0.1,
                max_val=0.1,
                percentiles={1: -0.05, 5: -0.04, 25: -0.02, 50: 0.0, 75: 0.02, 95: 0.04, 99: 0.05},
                skewness=0.0,
                kurtosis=3.0,
                entropy=7.3,
                zero_ratio=0.001,
                sparsity=0.01,
            ),
            "embedding_weights": StatisticalProfile(
                mean=0.0,
                std=0.1,
                min_val=-0.5,
                max_val=0.5,
                percentiles={1: -0.3, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.3},
                skewness=0.0,
                kurtosis=3.0,
                entropy=7.7,
                zero_ratio=0.001,
                sparsity=0.02,
            ),
            "batch_norm_weights": StatisticalProfile(
                mean=1.0,
                std=0.1,
                min_val=0.5,
                max_val=1.5,
                percentiles={1: 0.8, 5: 0.85, 25: 0.95, 50: 1.0, 75: 1.05, 95: 1.15, 99: 1.2},
                skewness=0.0,
                kurtosis=3.0,
                entropy=6.5,
                zero_ratio=0.0,
                sparsity=0.0,
            ),
        }

        # Pattern anomaly thresholds
        self.anomaly_thresholds = {
            "weight_distribution": 3.0,  # Z-score threshold
            "activation_pattern": 2.5,
            "gradient_flow": 4.0,
            "layer_connectivity": 2.0,
        }

    def compute_statistical_profile(self, data: np.ndarray) -> StatisticalProfile:
        """Compute statistical profile of data."""
        if data.size == 0:
            return StatisticalProfile(
                mean=0,
                std=0,
                min_val=0,
                max_val=0,
                percentiles=dict.fromkeys([1, 5, 25, 50, 75, 95, 99], 0),
                skewness=0,
                kurtosis=0,
                entropy=0,
                zero_ratio=1,
                sparsity=1,
            )

        # Flatten if multidimensional
        flat_data = data.flatten()

        # Basic statistics
        mean = np.mean(flat_data)
        std = np.std(flat_data)
        min_val = float(np.min(flat_data))
        max_val = float(np.max(flat_data))

        # Percentiles
        percentiles = {p: np.percentile(flat_data, p) for p in [1, 5, 25, 50, 75, 95, 99]}

        # Distribution shape
        skewness = stats.skew(flat_data)
        kurtosis = stats.kurtosis(flat_data)

        # Entropy (discretized)
        hist, _ = np.histogram(flat_data, bins=50)
        hist = hist / hist.sum()  # Normalize
        # Filter out zero values to avoid log of zero
        nonzero_hist = hist[hist > 0]
        entropy = -float(np.sum(nonzero_hist * np.log2(nonzero_hist))) if len(nonzero_hist) > 0 else 0.0

        # Sparsity measures
        zero_ratio = np.sum(np.abs(flat_data) < 1e-8) / flat_data.size
        sparsity = 1.0 - np.count_nonzero(flat_data) / flat_data.size

        return StatisticalProfile(
            mean=float(mean),
            std=float(std),
            min_val=float(min_val),
            max_val=float(max_val),
            percentiles={k: float(v) for k, v in percentiles.items()},
            skewness=float(skewness),
            kurtosis=float(kurtosis),
            entropy=float(entropy),
            zero_ratio=float(zero_ratio),
            sparsity=float(sparsity),
        )

    def detect_weight_anomalies(self, weights: dict[str, np.ndarray]) -> dict[str, dict[str, Any]]:
        """Detect anomalies in model weights."""
        anomalies = {}

        for layer_name, weight_data in weights.items():
            # Determine expected layer type
            layer_type = self._infer_layer_type(layer_name, weight_data.shape)

            # Compute actual profile
            actual_profile = self.compute_statistical_profile(weight_data)

            # Compare with expected profile
            if layer_type in self.layer_profiles:
                expected_profile = self.layer_profiles[layer_type]
                is_anomalous, score = expected_profile.is_anomalous(actual_profile)

                if is_anomalous:
                    anomalies[layer_name] = {
                        "type": "weight_distribution",
                        "severity": self._score_to_severity(score),
                        "score": score,
                        "expected_stats": expected_profile,
                        "actual_stats": actual_profile,
                        "details": self._analyze_anomaly(expected_profile, actual_profile),
                    }

            # Check for specific suspicious patterns
            suspicious_patterns = self._check_suspicious_patterns(weight_data)
            if suspicious_patterns:
                if layer_name not in anomalies:
                    anomalies[layer_name] = {}
                anomalies[layer_name]["suspicious_patterns"] = suspicious_patterns

        return anomalies

    def _infer_layer_type(self, layer_name: str, shape: tuple[int, ...]) -> str:
        """Infer layer type from name and shape."""
        layer_name_lower = layer_name.lower()

        # Check layer name patterns
        if any(conv in layer_name_lower for conv in ["conv", "convolution"]):
            return "conv2d_weights"
        elif any(dense in layer_name_lower for dense in ["dense", "linear", "fc"]):
            return "dense_weights"
        elif any(attn in layer_name_lower for attn in ["attention", "attn", "query", "key", "value"]):
            return "attention_weights"
        elif any(emb in layer_name_lower for emb in ["embedding", "embed"]):
            return "embedding_weights"
        elif any(bn in layer_name_lower for bn in ["batch_norm", "bn", "batchnorm"]):
            return "batch_norm_weights"

        # Infer from shape
        if len(shape) == 4:  # Likely conv2d
            return "conv2d_weights"
        elif len(shape) == 2:  # Likely dense
            return "dense_weights"

        return "dense_weights"  # Default

    def _check_suspicious_patterns(self, data: np.ndarray) -> list[dict[str, Any]]:
        """Check for specific suspicious patterns in data."""
        suspicious = []
        flat_data = data.flatten()

        # Check for hidden executable signatures
        if self._contains_executable_signature(flat_data):
            suspicious.append(
                {
                    "pattern": "executable_signature",
                    "severity": "critical",
                    "details": "Data contains executable file signatures",
                }
            )

        # Check for encoded strings
        if self._contains_encoded_strings(flat_data):
            suspicious.append(
                {
                    "pattern": "encoded_strings",
                    "severity": "high",
                    "details": "Data contains patterns resembling encoded strings",
                }
            )

        # Check for repeating patterns (possible backdoor)
        if self._has_repeating_patterns(flat_data):
            suspicious.append(
                {"pattern": "repeating_pattern", "severity": "medium", "details": "Unusual repeating patterns detected"}
            )

        # Check for data that doesn't follow expected distribution
        if self._violates_distribution_laws(flat_data):
            suspicious.append(
                {
                    "pattern": "distribution_violation",
                    "severity": "medium",
                    "details": "Data distribution violates expected statistical laws",
                }
            )

        return suspicious

    def _contains_executable_signature(self, data: np.ndarray) -> bool:
        """Check if data contains executable signatures."""
        # Convert to bytes for pattern matching
        if data.dtype == np.float32:
            bytes_data = data.tobytes()

            # Check for common executable signatures
            signatures = [b"MZ", b"\x7fELF", b"#!/", b"PK\x03\x04"]
            for sig in signatures:
                if sig in bytes_data:
                    # Verify it's not a coincidence by checking surrounding bytes
                    idx = bytes_data.find(sig)
                    if idx >= 0 and idx % 4 == 0:  # Aligned to float boundary
                        return True

        return False

    def _contains_encoded_strings(self, data: np.ndarray) -> bool:
        """Check for patterns that might be encoded strings."""
        # Look for ASCII-like patterns in float data
        if data.dtype == np.float32:
            # Check if values cluster around ASCII ranges when interpreted as bytes
            byte_interpretation: np.ndarray = (data * 255).astype(np.int32)
            ascii_printable = np.logical_and(byte_interpretation >= 32, byte_interpretation <= 126)
            ascii_ratio = np.mean(ascii_printable)

            # High ASCII ratio in float data is suspicious
            if ascii_ratio > 0.7:
                return True

        return False

    def _has_repeating_patterns(self, data: np.ndarray) -> bool:
        """Detect suspicious repeating patterns."""
        if len(data) < 1000:
            return False

        # Check for periodic patterns using autocorrelation
        autocorr = np.correlate(data[:1000], data[:1000], mode="full")
        autocorr = autocorr[len(autocorr) // 2 :]  # Keep positive lags

        # Normalize
        autocorr = autocorr / autocorr[0]

        # Look for strong periodic peaks
        peaks = []
        for i in range(10, min(100, len(autocorr))):
            if autocorr[i] > 0.8:  # Strong correlation
                peaks.append(i)

        # Multiple strong periodic peaks are suspicious
        return len(peaks) > 3

    def _violates_distribution_laws(self, data: np.ndarray) -> bool:
        """Check if data violates expected distribution laws."""
        # Benford's Law check for first significant digit
        abs_data = np.abs(data[data != 0])
        if len(abs_data) > 1000:
            # Extract first significant digit
            first_digits = []
            for val in abs_data[:1000]:
                val_str = f"{val:.10e}"
                for char in val_str:
                    if char.isdigit() and char != "0":
                        first_digits.append(int(char))
                        break

            if first_digits:
                # Expected Benford distribution
                benford_expected = [np.log10(1 + 1 / d) for d in range(1, 10)]

                # Actual distribution
                digit_counts = np.bincount(first_digits, minlength=10)[1:10]
                digit_freq = digit_counts / digit_counts.sum()

                # Chi-square test
                chi2: float = float(np.sum((digit_freq - benford_expected) ** 2 / benford_expected))

                # Significant deviation from Benford's Law
                if chi2 > 20:  # Very high chi-square value
                    return True

        return False

    def _analyze_anomaly(self, expected: StatisticalProfile, actual: StatisticalProfile) -> dict[str, str]:
        """Analyze what makes the profile anomalous."""
        details = {}

        if abs(actual.mean - expected.mean) > 3 * expected.std:
            details["mean_shift"] = f"Mean shifted from {expected.mean:.3f} to {actual.mean:.3f}"

        if actual.std / expected.std > 2 or actual.std / expected.std < 0.5:
            details["variance_change"] = f"Std changed from {expected.std:.3f} to {actual.std:.3f}"

        if abs(actual.skewness) > 2:
            details["skewness"] = f"High skewness: {actual.skewness:.3f}"

        if actual.kurtosis > 10 or actual.kurtosis < -2:
            details["kurtosis"] = f"Abnormal kurtosis: {actual.kurtosis:.3f}"

        if actual.sparsity > 0.9:
            details["sparsity"] = f"Extremely sparse: {actual.sparsity:.3f}"

        return details

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level."""
        if score < 2:
            return "low"
        elif score < 3:
            return "medium"
        elif score < 5:
            return "high"
        else:
            return "critical"
