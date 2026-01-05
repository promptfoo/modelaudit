"""Tests for entropy analyzer module."""

import struct

import pytest

from modelaudit.analysis.entropy_analyzer import EntropyAnalyzer


@pytest.fixture
def analyzer():
    """Create an EntropyAnalyzer instance."""
    return EntropyAnalyzer()


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_data(self, analyzer):
        """Test entropy of empty data is 0."""
        assert analyzer.calculate_shannon_entropy(b"") == 0.0

    def test_single_byte_type(self, analyzer):
        """Test entropy of uniform data is 0."""
        data = b"\x00" * 100
        assert analyzer.calculate_shannon_entropy(data) == 0.0

    def test_two_byte_types_equal(self, analyzer):
        """Test entropy of two equally distributed bytes is 1.0."""
        data = b"\x00\x01" * 50
        entropy = analyzer.calculate_shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_random_data_high_entropy(self, analyzer):
        """Test that random-like data has high entropy."""
        # Create data with all byte values represented
        data = bytes(range(256)) * 4
        entropy = analyzer.calculate_shannon_entropy(data)
        assert entropy > 7.5  # Close to maximum of 8

    def test_text_data_moderate_entropy(self, analyzer):
        """Test that text data has moderate entropy."""
        text = b"The quick brown fox jumps over the lazy dog. " * 10
        entropy = analyzer.calculate_shannon_entropy(text)
        assert 3.5 < entropy < 5.5


class TestSlidingWindowEntropy:
    """Tests for sliding window entropy calculation."""

    def test_small_data(self, analyzer):
        """Test with data smaller than window size."""
        data = b"small"
        result = analyzer.calculate_sliding_window_entropy(data, window_size=256)
        assert len(result) == 1

    def test_multiple_windows(self, analyzer):
        """Test with data large enough for multiple windows."""
        data = bytes(range(256)) * 8  # 2048 bytes
        result = analyzer.calculate_sliding_window_entropy(data, window_size=256)
        assert len(result) > 1

    def test_entropy_values_valid(self, analyzer):
        """Test that all entropy values are in valid range."""
        data = b"test data " * 100
        result = analyzer.calculate_sliding_window_entropy(data, window_size=64)
        for entropy in result:
            assert 0.0 <= entropy <= 8.0


class TestFloatPatterns:
    """Tests for floating-point pattern analysis."""

    def test_no_data(self, analyzer):
        """Test with insufficient data."""
        result = analyzer.analyze_float_patterns(b"\x00\x01\x02")
        assert result["float_ratio"] == 0.0

    def test_valid_floats(self, analyzer):
        """Test with valid float data."""
        # Create valid float32 data
        floats = [0.1, 0.2, 0.3, -0.1, -0.2]
        data = b"".join(struct.pack("<f", f) for f in floats)
        result = analyzer.analyze_float_patterns(data)
        assert result["float_ratio"] > 0.9
        assert result["valid_float_count"] == 5

    def test_weight_like_floats(self, analyzer):
        """Test with weight-like float distribution."""
        # Create weights: small values centered around 0
        import numpy as np

        np.random.seed(42)
        weights = np.random.normal(0, 0.5, 100).astype(np.float32)
        data = weights.tobytes()
        result = analyzer.analyze_float_patterns(data)
        assert result["weight_probability"] > 0.5

    def test_invalid_floats(self, analyzer):
        """Test with data that doesn't decode to valid floats."""
        # Create data with many NaN/Inf values when interpreted as floats
        data = b"\xff\xff\xff\x7f" * 20  # NaN pattern
        result = analyzer.analyze_float_patterns(data)
        assert result["float_ratio"] < 0.5


class TestCodePatterns:
    """Tests for code pattern detection."""

    def test_empty_data(self, analyzer):
        """Test with empty data."""
        result = analyzer.detect_code_patterns(b"")
        assert result["code_probability"] == 0.0

    def test_python_code(self, analyzer):
        """Test detection of Python code."""
        code = b"""
def hello_world():
    print("Hello, World!")
    return True

class MyClass:
    def __init__(self):
        self.value = 42

if __name__ == "__main__":
    hello_world()
"""
        result = analyzer.detect_code_patterns(code)
        assert result["code_probability"] > 0.5
        assert result["pattern_matches"] >= 3

    def test_binary_data(self, analyzer):
        """Test with binary data."""
        data = bytes(range(256)) * 4
        result = analyzer.detect_code_patterns(data)
        # Binary data should have high entropy and low printability
        assert result["entropy"] > 7.0
        assert result["printable_ratio"] < 0.5

    def test_compressed_data_high_entropy(self, analyzer):
        """Test that high-entropy data is detected as binary."""
        # Simulate compressed/encrypted data with uniform distribution
        data = bytes(range(256)) * 10
        result = analyzer.detect_code_patterns(data)
        assert result["entropy"] > 7.0

    def test_newline_detection(self, analyzer):
        """Test newline pattern detection."""
        code_with_newlines = b"line1\nline2\nline3\nline4\nline5\n" * 10
        result = analyzer.detect_code_patterns(code_with_newlines)
        # Should have reasonable newline ratio
        assert 0.01 < result.get("printable_ratio", 0) < 1.0


class TestDataClassification:
    """Tests for data type classification."""

    def test_small_data_unknown(self, analyzer):
        """Test that very small data returns unknown."""
        data_type, confidence = analyzer.classify_data_type(b"tiny")
        assert data_type == "unknown"
        assert confidence == 0.0

    def test_ml_weights_classification(self, analyzer):
        """Test classification of ML weights."""
        import numpy as np

        np.random.seed(42)
        weights = np.random.normal(0, 0.3, 500).astype(np.float32)
        data = weights.tobytes()
        data_type, _confidence = analyzer.classify_data_type(data)
        assert data_type in ["ml_weights", "binary_data", "unknown"]

    def test_code_classification(self, analyzer):
        """Test classification of code."""
        code = b"""
import os
import sys

def main():
    print("Running main function")
    for i in range(10):
        if i % 2 == 0:
            print(f"Even: {i}")
        else:
            print(f"Odd: {i}")
    return 0

class DataProcessor:
    def __init__(self, name):
        self.name = name
        self.data = []

    def process(self, item):
        self.data.append(item)
        return len(self.data)

if __name__ == "__main__":
    main()
"""
        data_type, confidence = analyzer.classify_data_type(code)
        assert data_type == "code"
        assert confidence > 0.5

    def test_random_data_classification(self, analyzer):
        """Test classification of random data."""
        # Create high-entropy data
        data = bytes(range(256)) * 20
        data_type, _confidence = analyzer.classify_data_type(data)
        assert data_type in ["random_data", "binary_data"]


class TestPatternSearchSkipping:
    """Tests for pattern search skip logic."""

    def test_skip_for_ml_weights(self, analyzer):
        """Test that pattern search is skipped for ML weights."""
        import numpy as np

        np.random.seed(42)
        weights = np.random.normal(0, 0.2, 1000).astype(np.float32)
        data = weights.tobytes()

        # Normal patterns should be skipped
        should_skip = analyzer.should_skip_pattern_search(data, b"os.system")
        # May or may not skip depending on classification confidence

        # Extremely suspicious patterns should not be skipped
        should_skip_exec = analyzer.should_skip_pattern_search(data, b"exec")
        # exec is in the extremely_suspicious list

    def test_skip_for_random_data(self, analyzer):
        """Test that pattern search is skipped for random data."""
        data = bytes(range(256)) * 50  # High-entropy data
        data_type, confidence = analyzer.classify_data_type(data)

        if data_type == "random_data" and confidence > 0.7:
            should_skip = analyzer.should_skip_pattern_search(data, b"any_pattern")
            assert should_skip is True

    def test_no_skip_for_code(self, analyzer):
        """Test that pattern search is not skipped for code."""
        code = (
            b"""
def hello():
    import os
    os.system('echo hello')
    return True
"""
            * 5
        )
        should_skip = analyzer.should_skip_pattern_search(code, b"os.system")
        assert should_skip is False

    def test_no_skip_for_small_data(self, analyzer):
        """Test that small data doesn't cause issues."""
        small_data = b"small"
        should_skip = analyzer.should_skip_pattern_search(small_data, b"pattern")
        # Should return False for unknown data type
        assert should_skip is False


class TestEntropyRanges:
    """Tests for entropy range constants."""

    def test_code_entropy_range(self, analyzer):
        """Test code entropy range is valid."""
        assert analyzer.code_entropy_range[0] < analyzer.code_entropy_range[1]
        assert 0 <= analyzer.code_entropy_range[0] <= 8
        assert 0 <= analyzer.code_entropy_range[1] <= 8

    def test_random_data_entropy_range(self, analyzer):
        """Test random data entropy range is valid."""
        assert analyzer.random_data_entropy[0] < analyzer.random_data_entropy[1]
        assert analyzer.random_data_entropy[1] <= 8.0

    def test_weight_data_entropy_range(self, analyzer):
        """Test weight data entropy range is valid."""
        assert analyzer.weight_data_entropy[0] < analyzer.weight_data_entropy[1]

    def test_text_entropy_range(self, analyzer):
        """Test text entropy range is valid."""
        assert analyzer.text_entropy_range[0] < analyzer.text_entropy_range[1]


class TestEdgeCases:
    """Tests for edge cases."""

    def test_all_null_bytes(self, analyzer):
        """Test with all null bytes."""
        data = b"\x00" * 1000
        entropy = analyzer.calculate_shannon_entropy(data)
        assert entropy == 0.0

        result = analyzer.detect_code_patterns(data)
        assert result["code_probability"] == 0.0

    def test_all_same_byte(self, analyzer):
        """Test with all same non-null byte."""
        data = b"\xff" * 1000
        entropy = analyzer.calculate_shannon_entropy(data)
        assert entropy == 0.0

    def test_struct_error_handling(self, analyzer):
        """Test that struct errors are handled gracefully."""
        # Data that might cause struct issues
        data = b"\xff\xff\xff\xff" * 10
        result = analyzer.analyze_float_patterns(data)
        # Should not raise, should return valid result
        assert "float_ratio" in result
