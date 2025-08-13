"""Tests for training data leakage detection."""

import numpy as np

from modelaudit.data_leakage_detector import DataLeakageDetector, detect_data_leakage


class TestDataLeakageDetector:
    """Test the DataLeakageDetector class."""

    def test_detect_ssn(self):
        """Test detection of Social Security Numbers."""
        detector = DataLeakageDetector()

        # Test data with SSNs
        data = b"""
        Customer record: John Doe
        SSN: 123-45-6789
        Another SSN 987-65-4321
        Invalid: 000-12-3456
        """

        findings = detector.scan(data, "test_file.pkl")
        ssn_findings = [f for f in findings if f["type"] == "ssn_detected"]

        # Should detect valid SSNs but not invalid ones
        assert len(ssn_findings) >= 2
        # Check masked SSN in message
        assert any("12*" in f["message"] for f in ssn_findings)

    def test_detect_credit_cards(self):
        """Test detection of credit card numbers."""
        detector = DataLeakageDetector()

        # Test data with credit card numbers
        data = b"""
        Visa: 4532015112830366
        MasterCard: 5425233430109903
        Invalid: 1234567890123456
        """

        findings = detector.scan(data)
        cc_findings = [f for f in findings if f["type"] == "credit_card_detected"]

        # Should detect valid credit cards with Luhn check
        assert len(cc_findings) >= 2
        assert all(f["confidence"] > 0.9 for f in cc_findings)

    def test_detect_emails(self):
        """Test detection of email addresses."""
        detector = DataLeakageDetector()

        data = b"""
        Contact: john.doe@example.com
        Admin: admin@company.org
        Support: support@test.io
        User1@domain.co.uk
        test.email+tag@example.com
        another@email.net
        """

        findings = detector.scan(data)
        email_findings = [f for f in findings if "email" in f["type"]]

        # Should detect multiple emails
        assert len(email_findings) >= 5

        # Check for multiple emails summary
        multiple = [f for f in email_findings if f["type"] == "multiple_emails_detected"]
        assert len(multiple) > 0

    def test_detect_phone_numbers(self):
        """Test detection of phone numbers."""
        detector = DataLeakageDetector()

        data = b"""
        Call us: (555) 123-4567
        Mobile: 555-987-6543
        Office: +1 555 246 8135
        Fax: 555.369.2580
        """

        findings = detector.scan(data)
        phone_findings = [f for f in findings if f["type"] == "phone_numbers_detected"]

        assert len(phone_findings) == 1
        assert phone_findings[0]["message"].startswith("Phone numbers detected:")

    def test_detect_ip_addresses(self):
        """Test detection of IP addresses."""
        detector = DataLeakageDetector()

        data = b"""
        Server: 8.8.8.8
        Internal: 192.168.1.1
        Private: 10.0.0.1
        Public: 52.84.228.25
        """

        findings = detector.scan(data)
        ip_findings = [f for f in findings if f["type"] == "ip_address_detected"]

        # Should only report public IPs
        assert len(ip_findings) >= 2
        assert any("8.8.8.8" in f["message"] for f in ip_findings)
        assert any("52.84.228.25" in f["message"] for f in ip_findings)
        # Should not report private IPs
        assert not any("192.168" in f["message"] for f in ip_findings)

    def test_detect_id_numbers(self):
        """Test detection of ID numbers."""
        detector = DataLeakageDetector()

        data = b"""
        Patient MRN: 12345678
        Account #: 987654321
        Member ID: 456789012
        Policy Number: POL-123456
        """

        findings = detector.scan(data)
        id_findings = [f for f in findings if f["type"] == "id_numbers_detected"]

        assert len(id_findings) == 1
        assert "ID numbers detected" in id_findings[0]["message"]

    def test_entropy_analysis(self):
        """Test high entropy region detection."""
        detector = DataLeakageDetector()

        # Create data with high entropy region (random bytes)
        import random

        random_data = bytes([random.randint(0, 255) for _ in range(2048)])

        # Add some normal data
        data = b"Normal text data " * 100 + random_data + b" More normal text" * 100

        findings = detector.scan(data)
        entropy_findings = [f for f in findings if f["type"] == "high_entropy_region"]

        # Should detect high entropy region
        assert len(entropy_findings) > 0
        assert entropy_findings[0]["confidence"] >= 0.6

    def test_embedding_detection(self):
        """Test detection of embedding vectors."""
        detector = DataLeakageDetector()

        # Create embedding-like data (normalized floats)
        embeddings = np.random.uniform(-1, 1, 512).astype(np.float32)
        data = embeddings.tobytes()

        # Add some padding
        data = b"Header" + data + b"Footer"

        findings = detector.scan(data)
        embedding_findings = [f for f in findings if f["type"] == "embedding_vectors_detected"]

        # Should detect embedding-like patterns
        assert len(embedding_findings) > 0
        assert "embedding vectors" in embedding_findings[0]["message"].lower()

    def test_gradient_detection(self):
        """Test detection of gradient data."""
        detector = DataLeakageDetector()

        # Create gradient-like data (many small values, some spikes)
        gradients = np.random.normal(0, 0.01, 1000).astype(np.float32)
        # Add some spikes
        gradients[::50] = np.random.uniform(-1, 1, 20)

        data = gradients.tobytes()

        findings = detector.scan(data)
        gradient_findings = [f for f in findings if f["type"] == "gradient_data_detected"]

        # Should detect gradient-like patterns
        assert len(gradient_findings) > 0
        assert "gradient" in gradient_findings[0]["message"].lower()

    def test_repeated_patterns(self):
        """Test detection of repeated patterns."""
        detector = DataLeakageDetector()

        # Create data with repeated patterns
        pattern = b"SECRET_TOKEN_12345"
        data = b"Start " + (pattern + b" padding " * 5) * 10 + b" End"

        findings = detector.scan(data)
        repeat_findings = [f for f in findings if f["type"] == "repeated_text_pattern"]

        # Should detect repeated pattern
        assert len(repeat_findings) > 0
        # Check that it found the token pattern (may be partial due to chunking)
        assert "TOKEN" in repeat_findings[0]["message"] or "SECRET" in repeat_findings[0]["message"]

    def test_masking_functions(self):
        """Test that sensitive data is properly masked in reports."""
        detector = DataLeakageDetector()

        # Test SSN masking
        data = b"SSN: 123-45-6789"
        findings = detector.scan(data)
        ssn_findings = [f for f in findings if f["type"] == "ssn_detected"]

        if ssn_findings:
            # Should be masked
            assert "****" in ssn_findings[0]["message"] or "*" in ssn_findings[0]["message"]
            assert "123-45-6789" not in ssn_findings[0]["message"]

    def test_luhn_validation(self):
        """Test Luhn algorithm for credit card validation."""
        detector = DataLeakageDetector()

        # Valid credit card (test number)
        assert detector._validate_luhn("4532015112830366")

        # Invalid credit card
        assert not detector._validate_luhn("1234567890123456")

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        detector = DataLeakageDetector()

        # All same byte (zero entropy)
        data1 = b"a" * 100
        entropy1 = detector._calculate_entropy(data1)
        assert entropy1 == 0.0

        # Random data (high entropy)
        import random

        data2 = bytes([random.randint(0, 255) for _ in range(256)])
        entropy2 = detector._calculate_entropy(data2)
        assert entropy2 > 7.0  # Should be close to 8 bits

        # Mixed data (medium entropy)
        data3 = b"abcd" * 25
        entropy3 = detector._calculate_entropy(data3)
        assert 1.0 < entropy3 < 3.0

    def test_configuration(self):
        """Test configuration options."""
        config = {
            "entropy_threshold": 6.0  # Lower threshold
        }
        detector = DataLeakageDetector(config)

        # Should use config
        assert detector.config["entropy_threshold"] == 6.0

    def test_no_false_positives_clean_data(self):
        """Test that clean model data doesn't trigger false positives."""
        detector = DataLeakageDetector()

        # Clean model weights
        weights = np.random.normal(0, 0.1, (100, 100)).astype(np.float32)
        data = weights.tobytes()

        findings = detector.scan(data)

        # Should not detect PII in random weights
        pii_findings = [f for f in findings if "ssn" in f["type"] or "credit_card" in f["type"] or "email" in f["type"]]
        assert len(pii_findings) == 0


class TestDetectDataLeakage:
    """Test the convenience function."""

    def test_scan_file(self, tmp_path):
        """Test scanning a file for data leakage."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"SSN: 123-45-6789, Email: test@example.com")

        findings = detect_data_leakage(str(test_file))
        assert len(findings) > 0
        assert any("SSN" in f.get("message", "") for f in findings)

    def test_file_not_found(self):
        """Test handling of non-existent files."""
        findings = detect_data_leakage("/non/existent/file.pkl")
        assert len(findings) == 1
        assert findings[0]["type"] == "error"
        assert "not found" in findings[0]["message"]
