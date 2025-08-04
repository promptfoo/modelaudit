"""Entropy-based analysis to distinguish code from data."""

import math
import struct
from collections import Counter

import numpy as np


class EntropyAnalyzer:
    """Analyzes entropy patterns to distinguish code from data."""

    def __init__(self):
        # Entropy thresholds learned from analysis
        self.code_entropy_range = (5.0, 7.0)  # Typical for code
        self.random_data_entropy = (7.5, 8.0)  # Near maximum
        self.weight_data_entropy = (6.5, 7.8)  # ML weights
        self.text_entropy_range = (4.0, 6.0)  # Natural language

    def calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = Counter(data)
        total_bytes = len(data)

        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return entropy

    def calculate_sliding_window_entropy(self, data: bytes, window_size: int = 256) -> list[float]:
        """Calculate entropy using sliding window."""
        if len(data) < window_size:
            return [self.calculate_shannon_entropy(data)]

        entropies = []
        for i in range(0, len(data) - window_size + 1, window_size // 2):
            window = data[i : i + window_size]
            entropies.append(self.calculate_shannon_entropy(window))

        return entropies

    def analyze_float_patterns(self, data: bytes) -> dict[str, float]:
        """Analyze patterns specific to floating-point data."""
        if len(data) < 4:
            return {"float_ratio": 0.0, "float_entropy": 0.0}

        # Try to interpret as float32 array
        float_values = []
        valid_floats = 0

        for i in range(0, len(data) - 3, 4):
            try:
                value = struct.unpack("<f", data[i : i + 4])[0]
                # Check if it's a reasonable float (not NaN or Inf)
                if -1e10 < value < 1e10 and not math.isnan(value) and not math.isinf(value):
                    float_values.append(value)
                    valid_floats += 1
            except (struct.error, ValueError):
                pass

        float_ratio = valid_floats / (len(data) // 4) if len(data) >= 4 else 0

        # Calculate entropy of float values
        float_entropy = 0.0
        if float_values:
            # Discretize floats for entropy calculation
            bins = np.histogram(float_values, bins=50)[0]
            total = sum(bins)
            if total > 0:
                for count in bins:
                    if count > 0:
                        p = count / total
                        float_entropy -= p * math.log2(p)

        # Check for weight-like distributions
        weight_indicators = 0
        if float_values:
            values_array = np.array(float_values)
            mean = np.mean(values_array)
            std = np.std(values_array)

            # Weights often have specific characteristics
            if -0.1 < mean < 0.1:  # Centered around zero
                weight_indicators += 1
            if 0.01 < std < 2.0:  # Reasonable standard deviation
                weight_indicators += 1
            if np.percentile(values_array, 95) < 3.0:  # Most values within reasonable range
                weight_indicators += 1

        return {
            "float_ratio": float_ratio,
            "float_entropy": float_entropy,
            "weight_probability": weight_indicators / 3.0,
            "valid_float_count": valid_floats,
        }

    def detect_code_patterns(self, data: bytes) -> dict[str, float]:
        """Detect patterns indicative of code vs data."""
        if not data:
            return {"code_probability": 0.0}

        # Calculate base entropy
        entropy = self.calculate_shannon_entropy(data)

        # Check for code-like byte patterns
        code_indicators = 0
        total_checks = 0

        # ASCII printable characters (code tendency)
        printable_count = sum(1 for b in data if 32 <= b < 127)
        printable_ratio = printable_count / len(data)
        if 0.7 < printable_ratio < 0.95:  # Code has high but not perfect printability
            code_indicators += 1
        total_checks += 1

        # Newline patterns (code structure)
        newline_count = data.count(b"\n") + data.count(b"\r\n")
        newline_ratio = newline_count / len(data)
        if 0.01 < newline_ratio < 0.1:  # Code has regular line breaks
            code_indicators += 1
        total_checks += 1

        # Null byte ratio (binary vs text)
        null_ratio = data.count(b"\x00") / len(data)
        if null_ratio < 0.01:  # Code rarely has null bytes
            code_indicators += 1
        total_checks += 1

        # Specific code patterns
        code_patterns = [
            b"def ",
            b"class ",
            b"import ",
            b"from ",
            b"if ",
            b"else:",
            b"for ",
            b"while ",
            b"return ",
            b"print(",
            b"self.",
        ]
        pattern_matches = sum(1 for pattern in code_patterns if pattern in data)
        if pattern_matches >= 3:
            code_indicators += 1
        total_checks += 1

        # Entropy-based classification
        if self.code_entropy_range[0] <= entropy <= self.code_entropy_range[1]:
            code_indicators += 1
        total_checks += 1

        # Check for obvious binary data patterns
        binary_indicators = 0
        if entropy > 7.5:  # Very high entropy suggests compressed/encrypted
            binary_indicators += 1
        if null_ratio > 0.1:  # Many null bytes suggest binary
            binary_indicators += 1
        if printable_ratio < 0.3:  # Low printability suggests binary
            binary_indicators += 1

        code_probability = code_indicators / total_checks
        binary_probability = binary_indicators / 3.0

        # Adjust code probability based on binary indicators
        if binary_probability > 0.5:
            code_probability *= 1.0 - binary_probability

        return {
            "code_probability": code_probability,
            "binary_probability": binary_probability,
            "entropy": entropy,
            "printable_ratio": printable_ratio,
            "pattern_matches": pattern_matches,
        }

    def classify_data_type(self, data: bytes) -> tuple[str, float]:
        """Classify data type with confidence score."""
        if len(data) < 16:
            return "unknown", 0.0

        # Analyze different aspects
        entropy_info = self.detect_code_patterns(data)
        float_info = self.analyze_float_patterns(data)

        classifications = []

        # Check for ML weights
        if float_info["float_ratio"] > 0.8 and float_info["weight_probability"] > 0.6:
            classifications.append(("ml_weights", 0.9 * float_info["weight_probability"]))

        # Check for code
        if entropy_info["code_probability"] > 0.6:
            classifications.append(("code", entropy_info["code_probability"]))

        # Check for binary data
        if entropy_info["binary_probability"] > 0.7:
            classifications.append(("binary_data", entropy_info["binary_probability"]))

        # Check for random data
        if entropy_info["entropy"] > 7.5:
            classifications.append(("random_data", 0.8))

        # Return the highest confidence classification
        if classifications:
            return max(classifications, key=lambda x: x[1])

        return "unknown", 0.0

    def should_skip_pattern_search(self, data: bytes, pattern: bytes) -> bool:
        """Determine if pattern search should be skipped based on data type."""
        data_type, confidence = self.classify_data_type(data)

        # High confidence ML weights - skip most pattern searches
        if data_type == "ml_weights" and confidence > 0.8:
            # Only search for extremely suspicious patterns
            extremely_suspicious = [b"exec", b"eval", b"__import__"]
            return pattern not in extremely_suspicious

        # Random data - skip all pattern searches
        if data_type == "random_data" and confidence > 0.7:
            return True

        # Binary data - be selective about patterns
        if data_type == "binary_data" and confidence > 0.7:
            # Only search for code-like patterns if we have high ASCII content
            _, _, _, printable_ratio, _ = self.detect_code_patterns(data).values()
            return printable_ratio < 0.3

        return False
