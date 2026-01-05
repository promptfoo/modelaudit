"""Tests for anomaly detector module."""

import pytest

from modelaudit.analysis.anomaly_detector import AnomalyDetector, StatisticalProfile


class TestStatisticalProfile:
    """Tests for StatisticalProfile dataclass."""

    @pytest.fixture
    def base_profile(self):
        """Create a base profile for testing."""
        return StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={1: -0.25, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.25},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )

    def test_create_profile(self, base_profile):
        """Test creating a statistical profile."""
        assert base_profile.mean == 0.0
        assert base_profile.std == 0.1
        assert base_profile.entropy == 7.5

    def test_is_anomalous_similar_profiles(self, base_profile):
        """Test similar profiles are not anomalous."""
        similar = StatisticalProfile(
            mean=0.01,
            std=0.11,
            min_val=-0.5,
            max_val=0.5,
            percentiles={1: -0.25, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.25},
            skewness=0.1,
            kurtosis=3.1,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.06,
        )
        is_anomalous, score = base_profile.is_anomalous(similar)
        assert is_anomalous is False
        assert score < 3.0

    def test_is_anomalous_different_mean(self, base_profile):
        """Test profile with very different mean is anomalous."""
        different = StatisticalProfile(
            mean=5.0,  # Very different mean
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={1: -0.25, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.25},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        is_anomalous, score = base_profile.is_anomalous(different)
        assert is_anomalous is True
        assert score > 3.0

    def test_is_anomalous_zero_std(self):
        """Test with zero standard deviation."""
        profile_zero_std = StatisticalProfile(
            mean=0.0,
            std=0.0,
            min_val=0.0,
            max_val=0.0,
            percentiles={1: 0.0, 5: 0.0, 25: 0.0, 50: 0.0, 75: 0.0, 95: 0.0, 99: 0.0},
            skewness=0.0,
            kurtosis=0.0,
            entropy=0.0,
            zero_ratio=1.0,
            sparsity=1.0,
        )
        other = StatisticalProfile(
            mean=1.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={1: 0.0, 5: 0.0, 25: 0.0, 50: 0.0, 75: 0.0, 95: 0.0, 99: 0.0},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        # Should not crash with zero std
        is_anomalous, score = profile_zero_std.is_anomalous(other)
        assert isinstance(is_anomalous, bool)
        assert isinstance(score, float)

    def test_is_anomalous_high_sparsity_difference(self, base_profile):
        """Test profile with very different sparsity."""
        sparse = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={1: -0.25, 5: -0.2, 25: -0.1, 50: 0.0, 75: 0.1, 95: 0.2, 99: 0.25},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.9,
            sparsity=0.95,  # Very high sparsity difference
        )
        _is_anomalous, score = base_profile.is_anomalous(sparse)
        assert score > 1.0  # Should have elevated score


class TestAnomalyDetector:
    """Tests for AnomalyDetector class."""

    @pytest.fixture
    def detector(self):
        """Create an anomaly detector instance."""
        return AnomalyDetector()

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert "conv2d_weights" in detector.layer_profiles
        assert "dense_weights" in detector.layer_profiles
        assert "attention_weights" in detector.layer_profiles
        assert "embedding_weights" in detector.layer_profiles
        assert "batch_norm_weights" in detector.layer_profiles

    def test_layer_profiles_have_expected_values(self, detector):
        """Test layer profiles have reasonable values."""
        conv_profile = detector.layer_profiles["conv2d_weights"]
        assert conv_profile.mean == 0.0
        assert conv_profile.std == 0.05

        bn_profile = detector.layer_profiles["batch_norm_weights"]
        assert bn_profile.mean == 1.0  # BatchNorm gamma typically initialized to 1

    def test_anomaly_thresholds_exist(self, detector):
        """Test anomaly thresholds are defined."""
        assert "weight_distribution" in detector.anomaly_thresholds
        assert "activation_pattern" in detector.anomaly_thresholds
        assert detector.anomaly_thresholds["weight_distribution"] == 3.0

    def test_compute_statistical_profile_no_numpy(self, detector, monkeypatch):
        """Test profile computation falls back gracefully without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy" or name == "scipy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        # Should return empty profile
        profile = detector.compute_statistical_profile([1, 2, 3])
        assert profile.mean == 0.0
        assert profile.sparsity == 1.0

    def test_infer_layer_type_conv(self, detector):
        """Test layer type inference for conv layers."""
        assert detector._infer_layer_type("conv2d.weight", (64, 3, 3, 3)) == "conv2d_weights"
        assert detector._infer_layer_type("convolution_layer", (64, 3, 3, 3)) == "conv2d_weights"

    def test_infer_layer_type_dense(self, detector):
        """Test layer type inference for dense layers."""
        assert detector._infer_layer_type("dense.weight", (100, 100)) == "dense_weights"
        assert detector._infer_layer_type("linear.weight", (100, 100)) == "dense_weights"
        assert detector._infer_layer_type("fc_layer", (100, 100)) == "dense_weights"

    def test_infer_layer_type_attention(self, detector):
        """Test layer type inference for attention layers."""
        assert detector._infer_layer_type("attention.weight", (100, 100)) == "attention_weights"
        assert detector._infer_layer_type("query_proj", (100, 100)) == "attention_weights"
        assert detector._infer_layer_type("key_weight", (100, 100)) == "attention_weights"
        assert detector._infer_layer_type("value.weight", (100, 100)) == "attention_weights"

    def test_infer_layer_type_embedding(self, detector):
        """Test layer type inference for embedding layers."""
        assert detector._infer_layer_type("embedding.weight", (30000, 768)) == "embedding_weights"
        assert detector._infer_layer_type("embed_tokens", (30000, 768)) == "embedding_weights"

    def test_infer_layer_type_batch_norm(self, detector):
        """Test layer type inference for batch norm layers."""
        assert detector._infer_layer_type("batch_norm.weight", (256,)) == "batch_norm_weights"
        assert detector._infer_layer_type("bn1.weight", (256,)) == "batch_norm_weights"
        assert detector._infer_layer_type("batchnorm.gamma", (256,)) == "batch_norm_weights"

    def test_infer_layer_type_from_shape(self, detector):
        """Test layer type inference from shape when name doesn't match."""
        # 4D tensor -> conv2d
        assert detector._infer_layer_type("unknown_layer", (64, 3, 3, 3)) == "conv2d_weights"
        # 2D tensor -> dense
        assert detector._infer_layer_type("unknown_layer", (100, 100)) == "dense_weights"

    def test_score_to_severity(self, detector):
        """Test score to severity conversion."""
        assert detector._score_to_severity(0.5) == "low"
        assert detector._score_to_severity(1.9) == "low"
        assert detector._score_to_severity(2.5) == "medium"
        assert detector._score_to_severity(3.5) == "high"
        assert detector._score_to_severity(6.0) == "critical"

    def test_analyze_anomaly_mean_shift(self, detector):
        """Test anomaly analysis detects mean shift."""
        expected = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        actual = StatisticalProfile(
            mean=1.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        details = detector._analyze_anomaly(expected, actual)
        assert "mean_shift" in details

    def test_analyze_anomaly_variance_change(self, detector):
        """Test anomaly analysis detects variance change."""
        expected = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        actual = StatisticalProfile(
            mean=0.0,
            std=0.5,
            min_val=-0.5,
            max_val=0.5,  # 5x std change
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        details = detector._analyze_anomaly(expected, actual)
        assert "variance_change" in details

    def test_analyze_anomaly_high_skewness(self, detector):
        """Test anomaly analysis detects high skewness."""
        expected = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        actual = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=5.0,
            kurtosis=3.0,  # High skewness
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        details = detector._analyze_anomaly(expected, actual)
        assert "skewness" in details

    def test_analyze_anomaly_abnormal_kurtosis(self, detector):
        """Test anomaly analysis detects abnormal kurtosis."""
        expected = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        actual = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=20.0,  # Very high kurtosis
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        details = detector._analyze_anomaly(expected, actual)
        assert "kurtosis" in details

    def test_analyze_anomaly_extreme_sparsity(self, detector):
        """Test anomaly analysis detects extreme sparsity."""
        expected = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.05,
        )
        actual = StatisticalProfile(
            mean=0.0,
            std=0.1,
            min_val=-0.5,
            max_val=0.5,
            percentiles={},
            skewness=0.0,
            kurtosis=3.0,
            entropy=7.5,
            zero_ratio=0.01,
            sparsity=0.95,  # Extremely sparse
        )
        details = detector._analyze_anomaly(expected, actual)
        assert "sparsity" in details


class TestSuspiciousPatternDetection:
    """Tests for suspicious pattern detection without numpy."""

    @pytest.fixture
    def detector(self):
        """Create an anomaly detector instance."""
        return AnomalyDetector()

    def test_check_suspicious_patterns_no_numpy(self, detector, monkeypatch):
        """Test suspicious pattern checking falls back without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = detector._check_suspicious_patterns([1, 2, 3])
        assert result == []

    def test_contains_executable_signature_no_numpy(self, detector, monkeypatch):
        """Test executable signature check without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = detector._contains_executable_signature([1, 2, 3])
        assert result is False

    def test_contains_encoded_strings_no_numpy(self, detector, monkeypatch):
        """Test encoded strings check without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = detector._contains_encoded_strings([1, 2, 3])
        assert result is False

    def test_has_repeating_patterns_no_numpy(self, detector, monkeypatch):
        """Test repeating patterns check without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = detector._has_repeating_patterns([1, 2, 3])
        assert result is False

    def test_has_repeating_patterns_short_data(self, detector):
        """Test repeating patterns with short data returns False."""
        pytest.importorskip("numpy")
        import numpy as np

        short_data = np.random.randn(100)
        result = detector._has_repeating_patterns(short_data)
        assert result is False

    def test_violates_distribution_laws_no_numpy(self, detector, monkeypatch):
        """Test distribution law check without numpy."""
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "numpy":
                raise ImportError("No module named 'numpy'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = detector._violates_distribution_laws([1, 2, 3])
        assert result is False


class TestWithNumpy:
    """Tests that require numpy."""

    @pytest.fixture
    def detector(self):
        """Create an anomaly detector instance."""
        return AnomalyDetector()

    @pytest.fixture
    def np(self):
        """Import numpy or skip."""
        return pytest.importorskip("numpy")

    def test_compute_statistical_profile_normal_data(self, detector, np):
        """Test profile computation with normal data."""
        pytest.importorskip("scipy")
        data = np.random.randn(1000).astype(np.float32)
        profile = detector.compute_statistical_profile(data)

        assert abs(profile.mean) < 0.2  # Should be close to 0
        assert 0.8 < profile.std < 1.2  # Should be close to 1
        assert profile.entropy > 0

    def test_compute_statistical_profile_empty_data(self, detector, np):
        """Test profile computation with empty data."""
        pytest.importorskip("scipy")
        data = np.array([]).astype(np.float32)
        profile = detector.compute_statistical_profile(data)

        assert profile.mean == 0.0
        assert profile.sparsity == 1.0

    def test_compute_statistical_profile_2d_data(self, detector, np):
        """Test profile computation with 2D data."""
        pytest.importorskip("scipy")
        data = np.random.randn(100, 100).astype(np.float32)
        profile = detector.compute_statistical_profile(data)

        assert isinstance(profile.mean, float)
        assert isinstance(profile.std, float)

    def test_detect_weight_anomalies_normal_weights(self, detector, np):
        """Test anomaly detection with normal weights."""
        pytest.importorskip("scipy")
        weights = {
            "conv1.weight": np.random.randn(64, 3, 3, 3).astype(np.float32) * 0.05,
            "dense1.weight": np.random.randn(100, 100).astype(np.float32) * 0.1,
        }
        anomalies = detector.detect_weight_anomalies(weights)
        # Normal weights shouldn't have many anomalies
        assert isinstance(anomalies, dict)

    def test_check_suspicious_patterns_with_array(self, detector, np):
        """Test suspicious pattern checking with numpy array."""
        normal_data = np.random.randn(1000).astype(np.float32)
        result = detector._check_suspicious_patterns(normal_data)
        assert isinstance(result, list)

    def test_contains_executable_signature_clean(self, detector, np):
        """Test executable signature detection with clean data."""
        clean_data = np.random.randn(1000).astype(np.float32)
        result = detector._contains_executable_signature(clean_data)
        assert result is False

    def test_contains_encoded_strings_clean(self, detector, np):
        """Test encoded string detection with clean data."""
        clean_data = np.random.randn(1000).astype(np.float32)
        result = detector._contains_encoded_strings(clean_data)
        assert result is False

    def test_has_repeating_patterns_random(self, detector, np):
        """Test repeating pattern detection with random data."""
        random_data = np.random.randn(2000).astype(np.float32)
        result = detector._has_repeating_patterns(random_data)
        assert result is False

    def test_violates_distribution_laws_normal(self, detector, np):
        """Test distribution law check with normal data."""
        normal_data = np.random.randn(2000).astype(np.float32) * 10 + 100
        result = detector._violates_distribution_laws(normal_data)
        # Random data should generally follow Benford's law approximately
        assert isinstance(result, bool)
