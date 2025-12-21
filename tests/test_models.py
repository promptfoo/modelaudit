"""Tests for modelaudit.models module."""

import time

import pytest
from pydantic import ValidationError

from modelaudit.models import (
    AssetModel,
    CopyrightNoticeModel,
    DetectorFinding,
    FileHashesModel,
    FileMetadataModel,
    JITScriptFinding,
    LicenseInfoModel,
    MLContextModel,
    MLFrameworkInfo,
    NetworkCommFinding,
    NetworkPatternModel,
    ScanConfigModel,
    ScannerCapabilities,
    ScannerPerformanceMetrics,
    SecretsFinding,
    WeightAnalysisModel,
    convert_assets_to_models,
    convert_checks_to_models,
    convert_issues_to_models,
    create_audit_result_model,
    create_initial_audit_result,
    rebuild_models,
)
from modelaudit.scanners.base import Issue, IssueSeverity


class TestDetectorFinding:
    """Tests for DetectorFinding model."""

    def test_create_minimal(self):
        """Test creating a DetectorFinding with minimal required fields."""
        finding = DetectorFinding(
            message="Test finding",
            severity="WARNING",
            context="test_context",
        )
        assert finding.message == "Test finding"
        assert finding.severity == "WARNING"
        assert finding.context == "test_context"
        assert finding.confidence == 1.0
        assert finding.details == {}

    def test_create_full(self):
        """Test creating a DetectorFinding with all fields."""
        finding = DetectorFinding(
            message="Test finding",
            severity="CRITICAL",
            context="test_context",
            pattern="test_pattern",
            recommendation="Fix this issue",
            confidence=0.85,
            details={"key": "value"},
        )
        assert finding.pattern == "test_pattern"
        assert finding.recommendation == "Fix this issue"
        assert finding.confidence == 0.85
        assert finding.details == {"key": "value"}

    def test_to_dict(self):
        """Test converting DetectorFinding to dictionary."""
        finding = DetectorFinding(
            message="Test",
            severity="INFO",
            context="ctx",
            pattern=None,
        )
        result = finding.to_dict()
        assert "message" in result
        assert "pattern" not in result  # None values excluded

    def test_confidence_validation(self):
        """Test confidence field validation."""
        with pytest.raises(ValidationError):
            DetectorFinding(
                message="Test",
                severity="WARNING",
                context="ctx",
                confidence=1.5,  # Out of range
            )


class TestJITScriptFinding:
    """Tests for JITScriptFinding model."""

    def test_create_with_all_fields(self):
        """Test creating JITScriptFinding with all fields."""
        finding = JITScriptFinding(
            message="JIT issue",
            severity="WARNING",
            context="pytorch",
            framework="pytorch",
            code_snippet="torch.jit.script",
            type="script",
            operation="compile",
            builtin="eval",
            **{"import": "torch"},  # Use alias
        )
        assert finding.framework == "pytorch"
        assert finding.code_snippet == "torch.jit.script"
        assert finding.import_ == "torch"


class TestNetworkCommFinding:
    """Tests for NetworkCommFinding model."""

    def test_create_with_network_details(self):
        """Test creating NetworkCommFinding with network details."""
        finding = NetworkCommFinding(
            message="Network communication detected",
            severity="WARNING",
            context="model_file",
            url="https://example.com",
            ip_address="192.168.1.1",
            domain="example.com",
            protocol="https",
        )
        assert finding.url == "https://example.com"
        assert finding.ip_address == "192.168.1.1"


class TestSecretsFinding:
    """Tests for SecretsFinding model."""

    def test_create_with_secret_details(self):
        """Test creating SecretsFinding with secret details."""
        finding = SecretsFinding(
            message="Secret detected",
            severity="CRITICAL",
            context="config_file",
            secret_type="api_key",
            location="line 42",
            masked_value="sk_***",
        )
        assert finding.secret_type == "api_key"
        assert finding.masked_value == "sk_***"


class TestDictCompatMixin:
    """Tests for DictCompatMixin functionality."""

    def test_get_method(self):
        """Test dict-style get() method."""
        asset = AssetModel(path="/test/file.pkl", type="pickle")
        assert asset.get("path") == "/test/file.pkl"
        assert asset.get("nonexistent", "default") == "default"

    def test_getitem(self):
        """Test dict-style bracket access."""
        asset = AssetModel(path="/test/file.pkl", type="pickle")
        assert asset["path"] == "/test/file.pkl"

    def test_getitem_keyerror(self):
        """Test KeyError for missing keys."""
        asset = AssetModel(path="/test/file.pkl", type="pickle")
        with pytest.raises(KeyError):
            _ = asset["nonexistent"]

    def test_contains(self):
        """Test 'in' operator."""
        asset = AssetModel(path="/test/file.pkl", type="pickle")
        assert "path" in asset
        assert "nonexistent" not in asset


class TestAssetModel:
    """Tests for AssetModel."""

    def test_create_minimal(self):
        """Test creating AssetModel with minimal fields."""
        asset = AssetModel(path="/test/model.pkl", type="pickle")
        assert asset.path == "/test/model.pkl"
        assert asset.type == "pickle"
        assert asset.size is None

    def test_create_full(self):
        """Test creating AssetModel with all fields."""
        asset = AssetModel(
            path="/test/model.safetensors",
            type="safetensors",
            size=1024,
            tensors=["weight", "bias"],
            keys=["key1"],
            contents=[{"name": "file.txt"}],
        )
        assert asset.tensors == ["weight", "bias"]
        assert asset.keys == ["key1"]


class TestMLFrameworkInfo:
    """Tests for MLFrameworkInfo model."""

    def test_create_framework_info(self):
        """Test creating MLFrameworkInfo."""
        info = MLFrameworkInfo(
            name="pytorch",
            version="2.0.0",
            confidence=0.95,
            indicators=["torch.nn.Module"],
            file_patterns=["*.pt"],
        )
        assert info.name == "pytorch"
        assert info.confidence == 0.95

    def test_default_values(self):
        """Test default values for MLFrameworkInfo."""
        info = MLFrameworkInfo()
        assert info.confidence == 0.0
        assert info.indicators == []


class TestWeightAnalysisModel:
    """Tests for WeightAnalysisModel."""

    def test_create_weight_analysis(self):
        """Test creating WeightAnalysisModel."""
        analysis = WeightAnalysisModel(
            appears_to_be_weights=True,
            weight_confidence=0.9,
            pattern_density=0.8,
            float_ratio=0.95,
        )
        assert analysis.appears_to_be_weights is True
        assert analysis.weight_confidence == 0.9


class TestMLContextModel:
    """Tests for MLContextModel."""

    def test_add_framework(self):
        """Test adding framework to MLContextModel."""
        context = MLContextModel()
        context.add_framework(
            name="pytorch",
            confidence=0.9,
            version="2.0",
            indicators=["torch"],
            file_patterns=["*.pt"],
        )
        assert "pytorch" in context.frameworks
        assert context.overall_confidence == 0.9
        assert context.is_ml_content is True

    def test_set_weight_analysis(self):
        """Test setting weight analysis."""
        context = MLContextModel()
        context.set_weight_analysis(
            {
                "appears_to_be_weights": True,
                "weight_confidence": 0.8,
            }
        )
        assert context.weight_analysis is not None
        assert context.weight_analysis.appears_to_be_weights is True


class TestLicenseInfoModel:
    """Tests for LicenseInfoModel."""

    def test_valid_spdx_id(self):
        """Test valid SPDX ID."""
        license_info = LicenseInfoModel(spdx_id="MIT", name="MIT License")
        assert license_info.spdx_id == "MIT"

    def test_valid_spdx_id_with_special_chars(self):
        """Test SPDX ID with allowed special characters."""
        license_info = LicenseInfoModel(spdx_id="Apache-2.0")
        assert license_info.spdx_id == "Apache-2.0"

    def test_invalid_spdx_id(self):
        """Test invalid SPDX ID raises error."""
        with pytest.raises(ValidationError):
            LicenseInfoModel(spdx_id="Invalid@License!")


class TestCopyrightNoticeModel:
    """Tests for CopyrightNoticeModel."""

    def test_valid_year(self):
        """Test valid year format."""
        notice = CopyrightNoticeModel(holder="Test Corp", year="2023")
        assert notice.year == "2023"

    def test_valid_year_range(self):
        """Test valid year range format."""
        notice = CopyrightNoticeModel(holder="Test Corp", year="2020-2023")
        assert notice.year == "2020-2023"

    def test_invalid_year(self):
        """Test invalid year format raises error."""
        with pytest.raises(ValidationError):
            CopyrightNoticeModel(holder="Test Corp", year="invalid")


class TestFileHashesModel:
    """Tests for FileHashesModel."""

    def test_valid_hashes(self):
        """Test valid hash formats."""
        hashes = FileHashesModel(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        assert hashes.md5 is not None
        assert hashes.sha256 is not None

    def test_has_any_hash(self):
        """Test has_any_hash method."""
        hashes = FileHashesModel(sha256="a" * 64)
        assert hashes.has_any_hash() is True

        empty_hashes = FileHashesModel()
        assert empty_hashes.has_any_hash() is False

    def test_get_strongest_hash(self):
        """Test get_strongest_hash method."""
        hashes = FileHashesModel(
            md5="d" * 32,
            sha256="a" * 64,
        )
        result = hashes.get_strongest_hash()
        assert result == ("sha256", "a" * 64)

    def test_get_strongest_hash_priority(self):
        """Test hash priority order."""
        # SHA512 is strongest
        hashes = FileHashesModel(sha512="b" * 128)
        assert hashes.get_strongest_hash()[0] == "sha512"

        # SHA256 next
        hashes = FileHashesModel(sha256="a" * 64, sha1="c" * 40)
        assert hashes.get_strongest_hash()[0] == "sha256"

    def test_get_strongest_hash_none(self):
        """Test get_strongest_hash returns None when empty."""
        hashes = FileHashesModel()
        assert hashes.get_strongest_hash() is None


class TestFileMetadataModel:
    """Tests for FileMetadataModel."""

    def test_add_license_info(self):
        """Test adding license info."""
        metadata = FileMetadataModel()
        metadata.add_license_info(
            spdx_id="MIT",
            name="MIT License",
            confidence=0.9,
        )
        assert len(metadata.license_info) == 1

    def test_add_license_info_with_url(self):
        """Test adding license info with URL."""
        metadata = FileMetadataModel()
        metadata.add_license_info(
            spdx_id="MIT",
            url="https://opensource.org/licenses/MIT",
        )
        assert metadata.license_info[0].url is not None

    def test_add_license_info_invalid_url(self):
        """Test adding license info with invalid URL."""
        metadata = FileMetadataModel()
        metadata.add_license_info(
            spdx_id="MIT",
            url="not-a-url",
        )
        assert metadata.license_info[0].url is None

    def test_add_copyright_notice(self):
        """Test adding copyright notice."""
        metadata = FileMetadataModel()
        metadata.add_copyright_notice(
            holder="Test Corp",
            years="2023",
            notice_text="Copyright 2023 Test Corp",
        )
        assert len(metadata.copyright_notices) == 1

    def test_set_file_hashes(self):
        """Test setting file hashes."""
        metadata = FileMetadataModel()
        metadata.set_file_hashes({"sha256": "a" * 64})
        assert metadata.file_hashes is not None

    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        metadata = FileMetadataModel(suspicious_count=5)
        score = metadata.calculate_risk_score()
        assert score > 0
        assert metadata.risk_score == score

    def test_calculate_risk_score_with_ml_context(self):
        """Test risk score with ML context."""
        ml_context = MLContextModel(overall_confidence=0.9, is_ml_content=True)
        metadata = FileMetadataModel(ml_context=ml_context)
        score = metadata.calculate_risk_score()
        assert score >= 0.1

    def test_calculate_risk_score_capped(self):
        """Test risk score is capped at 1.0."""
        metadata = FileMetadataModel(
            suspicious_count=100,
            max_stack_depth=100,
        )
        score = metadata.calculate_risk_score()
        assert score <= 1.0


class TestModelAuditResultModel:
    """Tests for ModelAuditResultModel."""

    def test_create_initial_result(self):
        """Test creating initial audit result."""
        result = create_initial_audit_result()
        assert result.bytes_scanned == 0
        assert result.files_scanned == 0
        assert result.has_errors is False

    def test_aggregate_scan_result(self):
        """Test aggregating scan results."""
        result = create_initial_audit_result()
        result.aggregate_scan_result(
            {
                "bytes_scanned": 1000,
                "files_scanned": 1,
                "issues": [],
                "checks": [],
                "assets": [],
            }
        )
        assert result.bytes_scanned == 1000
        assert result.files_scanned == 1

    def test_aggregate_scan_result_with_issues(self):
        """Test aggregating results with issues."""
        result = create_initial_audit_result()
        result.aggregate_scan_result(
            {
                "bytes_scanned": 500,
                "files_scanned": 1,
                "issues": [
                    {
                        "message": "Test issue",
                        "severity": "warning",  # lowercase for enum
                        "timestamp": time.time(),
                    }
                ],
                "checks": [],
                "assets": [],
            }
        )
        assert len(result.issues) == 1

    def test_aggregate_with_has_errors(self):
        """Test aggregating results with errors."""
        result = create_initial_audit_result()
        result.aggregate_scan_result(
            {
                "bytes_scanned": 100,
                "files_scanned": 1,
                "has_errors": True,
                "issues": [],
                "checks": [],
                "assets": [],
            }
        )
        assert result.has_errors is True

    def test_aggregate_scanner_names(self):
        """Test scanner names are tracked."""
        result = create_initial_audit_result()
        result.aggregate_scan_result(
            {
                "bytes_scanned": 100,
                "files_scanned": 1,
                "scanners": ["PickleScanner", "ZipScanner"],
                "issues": [],
                "checks": [],
                "assets": [],
            }
        )
        assert "PickleScanner" in result.scanner_names

    def test_finalize_statistics(self):
        """Test finalizing statistics."""
        result = create_initial_audit_result()
        time.sleep(0.01)  # Small delay to ensure duration > 0
        result.finalize_statistics()
        assert result.duration > 0

    def test_deduplicate_issues(self):
        """Test issue deduplication."""
        result = create_initial_audit_result()
        issue = Issue(
            message="Duplicate issue",
            severity=IssueSeverity.WARNING,
            timestamp=time.time(),
        )
        result.issues = [issue, issue, issue]
        result.deduplicate_issues()
        assert len(result.issues) == 1

    def test_dict_compat(self):
        """Test dictionary-like access."""
        result = create_initial_audit_result()
        assert result["bytes_scanned"] == 0
        assert result.get("nonexistent", "default") == "default"


class TestScanConfigModel:
    """Tests for ScanConfigModel."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScanConfigModel()
        assert config.timeout == 3600
        assert config.max_file_size == 0
        assert config.enable_progress is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ScanConfigModel(
            timeout=600,
            max_file_size=1024 * 1024,
            verbose=True,
        )
        assert config.timeout == 600
        assert config.verbose is True

    def test_to_dict(self):
        """Test converting to dictionary."""
        config = ScanConfigModel(timeout=300)
        result = config.to_dict()
        assert result["timeout"] == 300

    def test_from_dict(self):
        """Test creating from dictionary."""
        config = ScanConfigModel.from_dict({"timeout": 100, "verbose": True})
        assert config.timeout == 100
        assert config.verbose is True


class TestNetworkPatternModel:
    """Tests for NetworkPatternModel."""

    def test_create_pattern(self):
        """Test creating network pattern."""
        pattern = NetworkPatternModel(
            pattern=r"https?://.*",
            category="url",
            description="URL detection",
        )
        assert pattern.pattern == r"https?://.*"
        assert pattern.severity == "warning"

    def test_immutable(self):
        """Test pattern is immutable (frozen)."""
        pattern = NetworkPatternModel(
            pattern="test",
            category="url",
            description="test",
        )
        with pytest.raises(ValidationError):
            pattern.pattern = "new_pattern"


class TestScannerCapabilities:
    """Tests for ScannerCapabilities model."""

    def test_default_capabilities(self):
        """Test default capability values."""
        caps = ScannerCapabilities()
        assert caps.can_stream is False
        assert caps.parallel_safe is True
        assert caps.detects_malicious_code is True


class TestScannerPerformanceMetrics:
    """Tests for ScannerPerformanceMetrics model."""

    def test_initial_state(self):
        """Test initial metrics state."""
        metrics = ScannerPerformanceMetrics()
        assert metrics.total_scans == 0
        assert metrics.get_success_rate() == 0.0

    def test_record_scan_result(self):
        """Test recording scan results."""
        metrics = ScannerPerformanceMetrics()
        metrics.record_scan_result(success=True, scan_time=1.0, bytes_scanned=1000)
        assert metrics.total_scans == 1
        assert metrics.successful_scans == 1
        assert metrics.total_bytes_scanned == 1000

    def test_record_failed_scan(self):
        """Test recording failed scan."""
        metrics = ScannerPerformanceMetrics()
        metrics.record_scan_result(success=False, scan_time=0.5, bytes_scanned=500)
        assert metrics.failed_scans == 1

    def test_success_rate(self):
        """Test success rate calculation."""
        metrics = ScannerPerformanceMetrics()
        metrics.record_scan_result(success=True, scan_time=1.0, bytes_scanned=1000)
        metrics.record_scan_result(success=True, scan_time=1.0, bytes_scanned=1000)
        metrics.record_scan_result(success=False, scan_time=1.0, bytes_scanned=1000)
        assert abs(metrics.get_success_rate() - 66.67) < 1

    def test_throughput(self):
        """Test throughput calculation."""
        metrics = ScannerPerformanceMetrics()
        metrics.record_scan_result(
            success=True,
            scan_time=1.0,
            bytes_scanned=1024 * 1024,  # 1 MB
        )
        throughput = metrics.get_throughput_mbps()
        assert throughput > 0


class TestConversionFunctions:
    """Tests for conversion helper functions."""

    def test_convert_issues_to_models_from_dict(self):
        """Test converting issue dicts to models."""
        issues = [
            {"message": "Test", "severity": "warning", "timestamp": time.time()},
        ]
        result = convert_issues_to_models(issues)
        assert len(result) == 1
        assert isinstance(result[0], Issue)

    def test_convert_issues_to_models_from_issue(self):
        """Test converting Issue objects."""
        issue = Issue(message="Test", severity=IssueSeverity.WARNING, timestamp=time.time())
        result = convert_issues_to_models([issue])
        assert len(result) == 1

    def test_convert_issues_to_models_adds_timestamp(self):
        """Test that timestamp is added if missing."""
        issues = [{"message": "Test", "severity": "warning"}]
        result = convert_issues_to_models(issues)
        assert result[0].timestamp is not None

    def test_convert_checks_to_models(self):
        """Test converting check dicts to models."""
        checks = [
            {
                "name": "test_check",
                "status": "passed",
                "message": "OK",
                "timestamp": time.time(),
            },
        ]
        result = convert_checks_to_models(checks)
        assert len(result) == 1

    def test_convert_assets_to_models(self):
        """Test converting asset dicts to models."""
        assets = [
            {"path": "/test/file.pkl", "type": "pickle"},
        ]
        result = convert_assets_to_models(assets)
        assert len(result) == 1
        assert isinstance(result[0], AssetModel)

    def test_convert_assets_from_model(self):
        """Test converting AssetModel objects."""
        asset = AssetModel(path="/test", type="pickle")
        result = convert_assets_to_models([asset])
        assert len(result) == 1


class TestCreateAuditResultModel:
    """Tests for create_audit_result_model function."""

    def test_create_from_aggregated_results(self):
        """Test creating model from aggregated results."""
        aggregated = {
            "bytes_scanned": 1000,
            "files_scanned": 5,
            "issues": [],
            "checks": [],
            "assets": [],
            "has_errors": False,
            "scanner_names": ["PickleScanner"],
            "file_metadata": {},
            "start_time": time.time(),
            "duration": 1.5,
            "total_checks": 10,
            "passed_checks": 9,
            "failed_checks": 1,
        }
        result = create_audit_result_model(aggregated)
        assert result.bytes_scanned == 1000
        assert result.files_scanned == 5


class TestRebuildModels:
    """Tests for rebuild_models function."""

    def test_rebuild_models(self):
        """Test that rebuild_models doesn't raise errors."""
        # Should not raise
        rebuild_models()
