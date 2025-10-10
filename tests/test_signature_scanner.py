"""Tests for signature verification scanner."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from modelaudit.scanners.signature_scanner import SignatureScanner


class TestSignatureScanner:
    """Test cases for SignatureScanner."""

    def test_can_handle_signature_files(self):
        """Test that scanner can handle signature file extensions."""
        scanner = SignatureScanner()

        # Test signature file extensions
        assert SignatureScanner.can_handle("model.pkl.sig")
        assert SignatureScanner.can_handle("model.pt.asc")
        assert SignatureScanner.can_handle("model.onnx.gpg")
        assert SignatureScanner.can_handle("certificate.pem")
        assert SignatureScanner.can_handle("signature.p7s")

        # Test non-signature files
        assert not SignatureScanner.can_handle("model.pkl")
        assert not SignatureScanner.can_handle("data.txt")

    def test_can_handle_with_existing_signature_files(self):
        """Test can_handle when signature files exist alongside model files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create model file and signature
            model_file = temp_path / "model.pkl"
            signature_file = temp_path / "model.pkl.sig"

            model_file.write_text("fake model data")
            signature_file.write_text("fake signature")

            # Should handle the model file when signature exists
            assert SignatureScanner.can_handle(str(model_file))

    def test_scan_no_signature_found(self):
        """Test scanning when no signature files are found."""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_file = Path(temp_dir) / "model.pkl"
            model_file.write_text("fake model data")

            scanner = SignatureScanner()
            result = scanner.scan(str(model_file))

            assert result.scanner_name == "signature"
            assert len(result.issues) == 1
            assert result.issues[0].severity.value == "info"
            assert "No digital signature found" in result.issues[0].message

    def test_scan_signature_file_directly(self):
        """Test scanning a signature file directly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sig_file = Path(temp_dir) / "model.asc"
            # Use PGP signature format so it's recognized
            sig_file.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfake signature data\n-----END PGP SIGNATURE-----")

            scanner = SignatureScanner()
            result = scanner.scan(str(sig_file))

            assert result.scanner_name == "signature"
            assert len(result.issues) == 1
            assert "Digital signature file detected" in result.issues[0].message

    def test_detect_signature_types(self):
        """Test signature type detection."""
        scanner = SignatureScanner()

        # Test PGP signature
        pgp_content = b"-----BEGIN PGP SIGNATURE-----\nfake pgp data\n-----END PGP SIGNATURE-----"
        assert scanner._detect_signature_type(pgp_content) == "PGP"

        # Test X.509 certificate
        x509_content = b"-----BEGIN CERTIFICATE-----\nfake cert data\n-----END CERTIFICATE-----"
        assert scanner._detect_signature_type(x509_content) == "X.509"

        # Test PKCS#7
        pkcs7_content = b"-----BEGIN PKCS7-----\nfake pkcs7 data\n-----END PKCS7-----"
        assert scanner._detect_signature_type(pkcs7_content) == "PKCS#7"

        # Test unknown type
        unknown_content = b"unknown signature format"
        assert scanner._detect_signature_type(unknown_content) == "unknown"

    def test_find_signature_files(self):
        """Test finding signature files for a model file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create model file and various signature files
            model_file = temp_path / "model.pkl"
            model_file.write_text("fake model")

            sig_files = [
                temp_path / "model.pkl.sig",
                temp_path / "model.pkl.asc",
                temp_path / "model.pkl.gpg",
            ]

            for sig_file in sig_files:
                sig_file.write_text("fake signature")

            scanner = SignatureScanner()
            found_sigs = scanner._find_signature_files(model_file)

            assert len(found_sigs) == 3
            assert all(sig_file in found_sigs for sig_file in sig_files)

    def test_command_available(self):
        """Test command availability checking."""
        scanner = SignatureScanner()

        # Test with a command that should exist
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            assert scanner._command_available("echo")

        # Test with a command that doesn't exist
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert not scanner._command_available("nonexistent_command")

    @patch("subprocess.run")
    def test_verify_pgp_signature_success(self, mock_run):
        """Test successful PGP signature verification."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr='Good signature from "Test User <test@example.com>"'
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            model_file = temp_path / "model.pkl"
            sig_file = temp_path / "model.pkl.asc"

            model_file.write_text("fake model")
            sig_file.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----")

            scanner = SignatureScanner()

            # Mock gpg availability
            with patch.object(scanner, "_command_available", return_value=True):
                result = scanner._scan_signatures(str(model_file), Mock())
                # The method modifies the result object passed to it

    @patch("subprocess.run")
    def test_verify_pgp_signature_failure(self, mock_run):
        """Test failed PGP signature verification."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr='BAD signature from "Test User <test@example.com>"'
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            model_file = temp_path / "model.pkl"
            sig_file = temp_path / "model.pkl.asc"

            model_file.write_text("fake model")
            sig_file.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----")

            scanner = SignatureScanner()

            # Mock gpg availability
            with patch.object(scanner, "_command_available", return_value=True):
                result = scanner._scan_signatures(str(model_file), Mock())

    def test_extract_pgp_signer(self):
        """Test PGP signer extraction from gpg output."""
        scanner = SignatureScanner()

        # Test good signature
        output = 'gpg: Good signature from "John Doe <john@example.com>" [ultimate]'
        signer = scanner._extract_pgp_signer(output)
        assert signer == "John Doe <john@example.com>"

        # Test key ID format
        output = "gpg: Signature made Mon 01 Jan 2024 using RSA key ID ABCD1234"
        signer = scanner._extract_pgp_signer(output)
        assert signer == "Key ID: ABCD1234"

        # Test no match
        output = "gpg: some other output"
        signer = scanner._extract_pgp_signer(output)
        assert signer is None

    def test_parse_pgp_error(self):
        """Test PGP error parsing."""
        scanner = SignatureScanner()

        assert scanner._parse_pgp_error("BAD signature from someone") == "Invalid signature"
        assert scanner._parse_pgp_error("public key not found") == "Public key not found"
        assert scanner._parse_pgp_error("No public key available") == "Public key not found"
        assert scanner._parse_pgp_error("signature expired") == "Signature expired"
        assert scanner._parse_pgp_error("some other error") == "Unknown error"

    def test_extract_metadata_with_signatures(self):
        """Test metadata extraction when signature files exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create model and signature files
            model_file = temp_path / "model.pkl"
            sig_file = temp_path / "model.pkl.sig"
            asc_file = temp_path / "model.pkl.asc"

            model_file.write_text("fake model")
            sig_file.write_text("fake binary signature")
            asc_file.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfake pgp\n-----END PGP SIGNATURE-----")

            scanner = SignatureScanner()
            metadata = scanner.extract_metadata(str(model_file))

            assert metadata["has_signatures"] is True
            assert metadata["signature_count"] == 2
            assert len(metadata["signatures"]) == 2

            # Check signature info
            sig_info = next(s for s in metadata["signatures"] if s["file"].endswith(".sig"))
            assert sig_info["type"] == "unknown"

            asc_info = next(s for s in metadata["signatures"] if s["file"].endswith(".asc"))
            assert asc_info["type"] == "PGP"

    def test_extract_metadata_no_signatures(self):
        """Test metadata extraction when no signature files exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_file = Path(temp_dir) / "model.pkl"
            model_file.write_text("fake model")

            scanner = SignatureScanner()
            metadata = scanner.extract_metadata(str(model_file))

            assert metadata["has_signatures"] is False
            assert metadata["signature_count"] == 0

    def test_scan_with_gpg_unavailable(self):
        """Test scanning when gpg command is not available."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            model_file = temp_path / "model.pkl"
            sig_file = temp_path / "model.pkl.asc"

            model_file.write_text("fake model")
            sig_file.write_bytes(b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----")

            scanner = SignatureScanner()

            # Mock gpg not available
            with patch.object(scanner, "_command_available", return_value=False):
                result = scanner.scan(str(model_file))

                # Should have found signature file but couldn't verify
                assert len(result.issues) > 0
                # Check for the warning about gpg not being available
                gpg_warnings = [issue for issue in result.issues if "gpg not available" in issue.message]
                assert len(gpg_warnings) > 0

    def test_scan_with_openssl_unavailable(self):
        """Test scanning with X.509 signature when openssl is unavailable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            model_file = temp_path / "model.pkl"
            sig_file = temp_path / "model.pkl.p7s"

            model_file.write_text("fake model")
            sig_file.write_bytes(b"-----BEGIN PKCS7-----\nfake\n-----END PKCS7-----")

            scanner = SignatureScanner()

            # Mock openssl not available
            with patch.object(scanner, "_command_available", side_effect=lambda cmd: cmd != "openssl"):
                result = scanner.scan(str(model_file))

                # Should have found signature file but couldn't verify
                assert len(result.issues) > 0
                openssl_warnings = [issue for issue in result.issues if "openssl not available" in issue.message]
                assert len(openssl_warnings) > 0
