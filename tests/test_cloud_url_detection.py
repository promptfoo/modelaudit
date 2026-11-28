"""Tests for cloud storage URL detection (Requirement 19: External Resource References)."""

import pytest

from modelaudit.detectors.network_comm import NetworkCommDetector


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
