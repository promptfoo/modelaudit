"""Tests for cloud storage URL detection (Requirement 19: External Resource References)."""

import json

import pytest

from modelaudit.detectors.network_comm import NetworkCommDetector
from modelaudit.scanners.manifest_scanner import CLOUD_STORAGE_PATTERNS, ManifestScanner


class TestCloudStoragePatterns:
    """Test cloud storage URL pattern matching."""

    @pytest.fixture
    def detector(self):
        """Create a NetworkCommDetector instance."""
        return NetworkCommDetector()

    # AWS S3 URL tests
    @pytest.mark.parametrize(
        "url,expected_provider",
        [
            ("s3://my-bucket/path/to/model.bin", "s3"),
            ("s3://bucket-name/weights.safetensors", "s3"),
            ("s3://my-ml-models/v1/model.pt", "s3"),
            ("https://mybucket.s3.amazonaws.com/model.bin", "s3"),
            ("https://my-bucket.s3.amazonaws.com/path/file.pt", "s3"),
            ("https://s3.amazonaws.com/mybucket/model.bin", "s3"),
            ("https://s3.us-west-2.amazonaws.com/mybucket/model.bin", "s3"),
            ("https://s3.eu-central-1.amazonaws.com/bucket/weights.bin", "s3"),
        ],
    )
    def test_aws_s3_url_detection(self, detector, url, expected_provider):
        """Test detection of AWS S3 URLs."""
        data = url.encode("utf-8")
        findings = detector.scan(data, context="test.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) >= 1, f"Expected to detect S3 URL: {url}"
        assert cloud_findings[0]["provider"] == expected_provider

    # Google Cloud Storage URL tests
    @pytest.mark.parametrize(
        "url,expected_provider",
        [
            ("gs://my-bucket/model.bin", "gcs"),
            ("gs://gcp-ml-models/weights.safetensors", "gcs"),
            ("https://storage.googleapis.com/my-bucket/model.bin", "gcs"),
            ("https://storage.cloud.google.com/bucket/weights.pt", "gcs"),
        ],
    )
    def test_gcs_url_detection(self, detector, url, expected_provider):
        """Test detection of Google Cloud Storage URLs."""
        data = url.encode("utf-8")
        findings = detector.scan(data, context="test.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) >= 1, f"Expected to detect GCS URL: {url}"
        assert cloud_findings[0]["provider"] == expected_provider

    # Azure Blob Storage URL tests
    @pytest.mark.parametrize(
        "url,expected_provider",
        [
            ("https://myaccount.blob.core.windows.net/container/model.bin", "azure"),
            ("az://my-container/model.bin", "azure"),
            ("wasbs://container@account.blob.core.windows.net/path/model.bin", "azure"),
            ("wasb://container@account.blob.core.windows.net/model.bin", "azure"),
            ("abfss://container@account.dfs.core.windows.net/model.bin", "azure"),
            ("abfs://container@account.dfs.core.windows.net/weights.pt", "azure"),
        ],
    )
    def test_azure_url_detection(self, detector, url, expected_provider):
        """Test detection of Azure Blob Storage URLs."""
        data = url.encode("utf-8")
        findings = detector.scan(data, context="test.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) >= 1, f"Expected to detect Azure URL: {url}"
        assert cloud_findings[0]["provider"] == expected_provider

    # HuggingFace Hub URL tests
    @pytest.mark.parametrize(
        "url,expected_provider",
        [
            ("https://huggingface.co/meta-llama/Llama-2-7b", "huggingface"),
            ("https://huggingface.co/openai/whisper-large", "huggingface"),
            ("https://huggingface.co/bert-base/uncased/resolve/main/model.bin", "huggingface"),
        ],
    )
    def test_huggingface_url_detection(self, detector, url, expected_provider):
        """Test detection of HuggingFace Hub URLs."""
        data = url.encode("utf-8")
        findings = detector.scan(data, context="test.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) >= 1, f"Expected to detect HuggingFace URL: {url}"
        assert cloud_findings[0]["provider"] == expected_provider

    def test_no_false_positives_for_regular_urls(self, detector):
        """Test that regular URLs are not flagged as cloud storage URLs."""
        regular_urls = [
            b"https://example.com/page",
            b"http://localhost:8080/api",
            b"https://github.com/user/repo",
            b"https://pytorch.org/docs",
            b"https://tensorflow.org/guide",
        ]

        for url in regular_urls:
            findings = detector.scan(url, context="test.json")
            cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
            assert len(cloud_findings) == 0, f"Unexpected cloud URL detection for: {url.decode()}"

    def test_suspicious_url_elevated_severity(self, detector):
        """Test that suspicious URLs get elevated severity."""
        suspicious_url = b"s3://malware-bucket/evil-model.bin"
        findings = detector.scan(suspicious_url, context="test.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) >= 1
        assert cloud_findings[0]["severity"] == "WARNING"

    def test_multiple_urls_in_content(self, detector):
        """Test detection of multiple cloud URLs in single content."""
        content = b"""
        {
            "model_url": "s3://bucket1/model.bin",
            "weights_url": "gs://bucket2/weights.pt",
            "backup_url": "https://myaccount.blob.core.windows.net/backup/model.bin"
        }
        """
        findings = detector.scan(content, context="config.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) == 3

        providers = {f["provider"] for f in cloud_findings}
        assert providers == {"s3", "gcs", "azure"}

    def test_duplicate_urls_deduplicated(self, detector):
        """Test that duplicate URLs are only reported once."""
        content = b"""
        {
            "url1": "s3://bucket/model.bin",
            "url2": "s3://bucket/model.bin",
            "url3": "s3://bucket/model.bin"
        }
        """
        findings = detector.scan(content, context="config.json")

        cloud_findings = [f for f in findings if f["type"] == "cloud_storage_url"]
        assert len(cloud_findings) == 1


class TestManifestScannerCloudUrls:
    """Test cloud URL detection in ManifestScanner."""

    @pytest.fixture
    def scanner(self):
        """Create a ManifestScanner instance."""
        return ManifestScanner()

    def test_cloud_url_detection_in_config_json(self, scanner, tmp_path):
        """Test cloud URL detection in config.json files."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "weights_url": "s3://my-models/bert/weights.bin",
            "external_data": "gs://gcp-bucket/data.pt",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        # Check that cloud URLs were detected
        cloud_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
        assert len(cloud_checks) == 2

        # Verify providers detected
        providers = {c.details["provider"] for c in cloud_checks}
        assert providers == {"s3", "gcs"}

    def test_cloud_url_detection_severity_info(self, scanner, tmp_path):
        """Test that normal cloud URLs get INFO severity."""
        config_file = tmp_path / "config.json"
        config_content = {"weights_url": "s3://legitimate-bucket/model.bin"}
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        cloud_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
        assert len(cloud_checks) == 1
        assert cloud_checks[0].severity.name == "INFO"

    def test_suspicious_cloud_url_severity_warning(self, scanner, tmp_path):
        """Test that suspicious cloud URLs get WARNING severity."""
        config_file = tmp_path / "config.json"
        config_content = {"weights_url": "s3://malware-bucket/exploit.bin"}
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        cloud_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
        assert len(cloud_checks) == 1
        assert cloud_checks[0].severity.name == "WARNING"

    def test_no_cloud_urls_no_findings(self, scanner, tmp_path):
        """Test that configs without cloud URLs don't produce findings."""
        config_file = tmp_path / "config.json"
        config_content = {
            "model_type": "bert",
            "hidden_size": 768,
            "num_attention_heads": 12,
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        cloud_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
        assert len(cloud_checks) == 0

    def test_all_cloud_providers_detected(self, scanner, tmp_path):
        """Test detection of all supported cloud providers."""
        config_file = tmp_path / "config.json"
        config_content = {
            "aws": "s3://bucket/model.bin",
            "gcp": "gs://bucket/model.bin",
            "azure": "https://account.blob.core.windows.net/container/model.bin",
            "huggingface": "https://huggingface.co/meta/llama/model.bin",
        }
        config_file.write_text(json.dumps(config_content))

        result = scanner.scan(str(config_file))

        cloud_checks = [c for c in result.checks if c.name == "Cloud Storage URL Detection"]
        providers = {c.details["provider"] for c in cloud_checks}
        assert providers == {"s3", "gcs", "azure", "huggingface"}


class TestCloudStoragePatternsCompleteness:
    """Test that all expected cloud storage patterns are defined."""

    def test_all_major_providers_covered(self):
        """Verify all major cloud providers have patterns defined."""
        providers = {provider for _, _, provider in CLOUD_STORAGE_PATTERNS}
        expected_providers = {"s3", "gcs", "azure", "huggingface"}
        assert expected_providers.issubset(providers)

    def test_pattern_count(self):
        """Verify minimum number of patterns are defined."""
        # We should have at least 10 patterns for comprehensive coverage
        assert len(CLOUD_STORAGE_PATTERNS) >= 10

    def test_patterns_are_compiled_regex(self):
        """Verify all patterns are compiled regex objects."""
        import re

        for pattern, description, _provider in CLOUD_STORAGE_PATTERNS:
            assert isinstance(pattern, re.Pattern), f"Pattern for {description} is not compiled"
