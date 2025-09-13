"""Model Signature Verification Scanner.

This scanner verifies digital signatures and certificates for model files to ensure:
1. Model authenticity (signed by trusted entity)
2. Model integrity (not tampered with)
3. Provenance tracking (chain of custody)
"""

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from ..models import SignatureFinding
from .base import BaseScanner, IssueSeverity, ScanResult

logger = logging.getLogger(__name__)


class SignatureScanner(BaseScanner):
    """Scanner for verifying digital signatures on model files."""

    name: ClassVar[str] = "signature"
    description: ClassVar[str] = "Verifies digital signatures and certificates for model authenticity"
    supported_extensions: ClassVar[list[str]] = [
        ".sig",      # Generic signature files
        ".asc",      # ASCII armored PGP signatures
        ".p7s",      # PKCS#7 signature files
        ".gpg",      # GPG signature files
        ".pem",      # PEM certificate files
        ".crt",      # Certificate files
        ".cer",      # Certificate files
        ".p12",      # PKCS#12 files
        ".pfx",      # PKCS#12 files (Windows)
    ]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path."""
        file_path = Path(path)

        # Check for signature files by extension
        if file_path.suffix.lower() in cls.supported_extensions:
            return True

        # Check for signature files alongside model files
        signature_files = [
            file_path.with_suffix(file_path.suffix + ".sig"),
            file_path.with_suffix(file_path.suffix + ".asc"),
            file_path.with_suffix(file_path.suffix + ".gpg"),
            file_path.parent / f"{file_path.name}.sig",
            file_path.parent / f"{file_path.name}.asc",
            file_path.parent / f"{file_path.name}.gpg",
        ]

        return any(sig_file.exists() for sig_file in signature_files)

    def scan(self, path: str) -> ScanResult:
        """Scan for signature verification issues."""
        result = ScanResult(scanner_name=self.name)

        try:
            self._scan_signatures(path, result)
        except Exception as e:
            logger.error(f"Error scanning signatures for {path}: {e}")
            result.add_issue(
                f"Failed to scan signatures: {e!s}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e)},
            )

        result.finish()
        return result

    def _scan_signatures(self, path: str, result: ScanResult) -> None:
        """Main signature scanning logic."""
        file_path = Path(path)

        # If path is a signature file itself, analyze it
        if file_path.suffix.lower() in self.supported_extensions:
            self._analyze_signature_file(file_path, result)
            return

        # Look for signature files alongside the model file
        signature_files = self._find_signature_files(file_path)

        if not signature_files:
            result.add_issue(
                "No digital signature found for model file",
                severity=IssueSeverity.INFO,
                details={
                    "recommendation": "Consider signing model files to ensure authenticity and integrity",
                    "impact": "Cannot verify model provenance or detect tampering",
                },
            )
            return

        for sig_file in signature_files:
            self._verify_signature(file_path, sig_file, result)

    def _find_signature_files(self, model_file: Path) -> list[Path]:
        """Find signature files associated with a model file."""

        # Common signature file patterns
        patterns = [
            model_file.with_suffix(model_file.suffix + ".sig"),
            model_file.with_suffix(model_file.suffix + ".asc"),
            model_file.with_suffix(model_file.suffix + ".gpg"),
            model_file.with_suffix(model_file.suffix + ".p7s"),
            model_file.parent / f"{model_file.name}.sig",
            model_file.parent / f"{model_file.name}.asc",
            model_file.parent / f"{model_file.name}.gpg",
            model_file.parent / f"{model_file.name}.p7s",
        ]

        # Use set to avoid duplicates, then convert back to list
        found_files = set()
        for pattern in patterns:
            if pattern.exists():
                found_files.add(pattern)

        return list(found_files)

    def _analyze_signature_file(self, sig_file: Path, result: ScanResult) -> None:
        """Analyze a signature file directly."""
        try:
            content = sig_file.read_bytes()

            # Detect signature type
            sig_type = self._detect_signature_type(content)

            finding_data = {
                "message": f"Digital signature file detected: {sig_file.name}",
                "severity": "info",
                "context": str(sig_file),
                "signature_type": sig_type,
                "recommendation": "Verify signature against the corresponding model file",
            }

            if sig_type == "unknown":
                finding_data["severity"] = "warning"
                finding_data["message"] = f"Unknown signature format: {sig_file.name}"

            self._add_signature_finding(result, **finding_data)

        except Exception as e:
            result.add_issue(
                f"Failed to read signature file: {sig_file.name}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e)},
            )

    def _detect_signature_type(self, content: bytes) -> str:
        """Detect the type of signature from content."""

        if b"-----BEGIN PGP SIGNATURE-----" in content:
            return "PGP"
        elif b"-----BEGIN CERTIFICATE-----" in content:
            return "X.509"
        elif b"-----BEGIN PKCS7-----" in content:
            return "PKCS#7"
        elif content.startswith(b"0\x82"):  # ASN.1 DER encoding
            return "DER"
        elif content.startswith(b"MII"):  # Base64 encoded certificate/signature
            return "Base64"
        else:
            return "unknown"

    def _verify_signature(self, model_file: Path, sig_file: Path, result: ScanResult) -> None:
        """Verify a signature against a model file."""
        try:
            sig_content = sig_file.read_bytes()
            sig_type = self._detect_signature_type(sig_content)

            if sig_type == "PGP":
                self._verify_pgp_signature(model_file, sig_file, result)
            elif sig_type in ["X.509", "PKCS#7"]:
                self._verify_x509_signature(model_file, sig_file, result)
            else:
                self._add_signature_finding(
                    result,
                    message=f"Unsupported signature type: {sig_type}",
                    severity="warning",
                    context=str(sig_file),
                    signature_type=sig_type,
                    recommendation="Use standard signature formats (PGP, X.509, PKCS#7)",
                )

        except Exception as e:
            result.add_issue(
                f"Failed to verify signature: {sig_file.name}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e)},
            )

    def _verify_pgp_signature(self, model_file: Path, sig_file: Path, result: ScanResult) -> None:
        """Verify PGP signature using gpg command."""
        try:
            # Check if gpg is available
            if not self._command_available("gpg"):
                self._add_signature_finding(
                    result,
                    message="PGP signature found but gpg not available for verification",
                    severity="warning",
                    context=str(sig_file),
                    signature_type="PGP",
                    recommendation="Install gnupg to enable signature verification",
                )
                return

            # Try to verify signature
            cmd = ["gpg", "--verify", str(sig_file), str(model_file)]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse gpg output
            output = process.stderr  # gpg writes status to stderr

            if process.returncode == 0:
                # Extract signer info
                signer = self._extract_pgp_signer(output)

                self._add_signature_finding(
                    result,
                    message=f"Valid PGP signature verified for {model_file.name}",
                    severity="info",
                    context=str(sig_file),
                    signature_type="PGP",
                    signature_valid=True,
                    signer=signer,
                    recommendation="Signature is valid - model integrity confirmed",
                )
            else:
                # Parse error
                error_type = self._parse_pgp_error(output)

                self._add_signature_finding(
                    result,
                    message=f"PGP signature verification failed: {error_type}",
                    severity="critical",
                    context=str(sig_file),
                    signature_type="PGP",
                    signature_valid=False,
                    recommendation="Model may have been tampered with or signed with untrusted key",
                )

        except subprocess.TimeoutExpired:
            self._add_signature_finding(
                result,
                message="PGP signature verification timed out",
                severity="warning",
                context=str(sig_file),
                signature_type="PGP",
                recommendation="Signature verification took too long - check system resources",
            )
        except FileNotFoundError:
            self._add_signature_finding(
                result,
                message="gpg command not found",
                severity="warning",
                context=str(sig_file),
                signature_type="PGP",
                recommendation="Install gnupg to enable PGP signature verification",
            )

    def _verify_x509_signature(self, model_file: Path, sig_file: Path, result: ScanResult) -> None:
        """Verify X.509/PKCS#7 signature using openssl."""
        try:
            # Check if openssl is available
            if not self._command_available("openssl"):
                self._add_signature_finding(
                    result,
                    message="X.509 signature found but openssl not available for verification",
                    severity="warning",
                    context=str(sig_file),
                    signature_type="X.509",
                    recommendation="Install openssl to enable certificate verification",
                )
                return

            # Try to verify with openssl
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp_file:
                tmp_file.write(model_file.read_bytes())
                tmp_path = tmp_file.name

            try:
                cmd = ["openssl", "cms", "-verify", "-in", str(sig_file), "-content", tmp_path, "-noverify"]
                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if process.returncode == 0:
                    self._add_signature_finding(
                        result,
                        message=f"Valid X.509 signature verified for {model_file.name}",
                        severity="info",
                        context=str(sig_file),
                        signature_type="X.509",
                        signature_valid=True,
                        recommendation="Signature is valid - model integrity confirmed",
                    )
                else:
                    self._add_signature_finding(
                        result,
                        message="X.509 signature verification failed",
                        severity="critical",
                        context=str(sig_file),
                        signature_type="X.509",
                        signature_valid=False,
                        recommendation="Model may have been tampered with or certificate is invalid",
                    )
            finally:
                os.unlink(tmp_path)

        except subprocess.TimeoutExpired:
            self._add_signature_finding(
                result,
                message="X.509 signature verification timed out",
                severity="warning",
                context=str(sig_file),
                signature_type="X.509",
                recommendation="Signature verification took too long - check system resources",
            )
        except Exception as e:
            result.add_issue(
                f"X.509 verification error: {e!s}",
                severity=IssueSeverity.WARNING,
                details={"error": str(e)},
            )

    def _command_available(self, command: str) -> bool:
        """Check if a command is available in PATH."""
        try:
            subprocess.run([command, "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _extract_pgp_signer(self, gpg_output: str) -> str | None:
        """Extract signer information from gpg output."""
        # Look for "Good signature from" pattern
        match = re.search(r'Good signature from "([^"]+)"', gpg_output)
        if match:
            return match.group(1)

        # Look for signature ID pattern
        match = re.search(r"Signature made.*using.*key ID ([A-F0-9]+)", gpg_output)
        if match:
            return f"Key ID: {match.group(1)}"

        return None

    def _parse_pgp_error(self, gpg_output: str) -> str:
        """Parse PGP verification error from gpg output."""
        if "BAD signature" in gpg_output:
            return "Invalid signature"
        elif "public key not found" in gpg_output or "No public key" in gpg_output:
            return "Public key not found"
        elif "expired" in gpg_output:
            return "Signature expired"
        else:
            return "Unknown error"

    def _add_signature_finding(self, result: ScanResult, **kwargs: Any) -> None:
        """Add a signature-specific finding to the result."""
        # Create SignatureFinding with all provided kwargs
        finding = SignatureFinding(**kwargs)

        # Map severity string to IssueSeverity enum
        severity_map = {
            "info": IssueSeverity.INFO,
            "warning": IssueSeverity.WARNING,
            "critical": IssueSeverity.CRITICAL,
        }
        severity = severity_map.get(kwargs.get("severity", "info"), IssueSeverity.WARNING)

        # Add issue using the proper add_issue method
        result.add_issue(
            kwargs.get("message", ""),
            severity=severity,
            location=kwargs.get("context"),
            details=finding.model_dump(exclude_none=True),
        )

    def extract_metadata(self, path: str) -> dict[str, Any]:
        """Extract signature-related metadata from the file."""
        metadata: dict[str, Any] = {}
        file_path = Path(path)

        try:
            # Find signature files
            signature_files = self._find_signature_files(file_path)

            if signature_files:
                metadata["has_signatures"] = True
                metadata["signature_count"] = len(signature_files)
                metadata["signature_files"] = [str(f) for f in signature_files]

                # Analyze each signature file
                signatures = []
                for sig_file in signature_files:
                    try:
                        content = sig_file.read_bytes()
                        sig_type = self._detect_signature_type(content)

                        sig_info = {
                            "file": str(sig_file),
                            "type": sig_type,
                            "size": len(content),
                        }

                        # Add type-specific metadata
                        if sig_type == "PGP":
                            sig_info.update(self._extract_pgp_metadata(content))
                        elif sig_type in ["X.509", "PKCS#7"]:
                            sig_info.update(self._extract_x509_metadata(content))

                        signatures.append(sig_info)

                    except Exception as e:
                        signatures.append({
                            "file": str(sig_file),
                            "error": str(e),
                        })

                metadata["signatures"] = signatures
            else:
                metadata["has_signatures"] = False
                metadata["signature_count"] = 0

        except Exception as e:
            metadata["extraction_error"] = str(e)

        return metadata

    def _extract_pgp_metadata(self, content: bytes) -> dict[str, Any]:
        """Extract metadata from PGP signature content."""
        metadata: dict[str, Any] = {}

        try:
            content_str = content.decode("utf-8", errors="ignore")

            # Look for PGP signature block
            if "-----BEGIN PGP SIGNATURE-----" in content_str:
                # Extract the signature block
                start = content_str.find("-----BEGIN PGP SIGNATURE-----")
                end = content_str.find("-----END PGP SIGNATURE-----")

                if start != -1 and end != -1:
                    sig_block = content_str[start:end + len("-----END PGP SIGNATURE-----")]
                    metadata["armored"] = True
                    metadata["signature_block_length"] = len(sig_block)

            # Additional PGP-specific metadata could be added here
            # (would require more sophisticated PGP parsing)

        except Exception:
            pass

        return metadata

    def _extract_x509_metadata(self, content: bytes) -> dict[str, Any]:
        """Extract metadata from X.509/PKCS#7 signature content."""
        metadata: dict[str, Any] = {}

        try:
            if self._command_available("openssl"):
                # Use openssl to extract certificate/signature info
                with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp_file:
                    tmp_file.write(content)
                    tmp_path = tmp_file.name

                try:
                    # Try to parse as certificate
                    cmd = ["openssl", "x509", "-in", tmp_path, "-text", "-noout"]
                    process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                    if process.returncode == 0:
                        metadata["certificate_parsed"] = True
                        # Could parse more details from certificate text here
                    else:
                        # Try as PKCS#7
                        cmd = ["openssl", "pkcs7", "-in", tmp_path, "-print", "-noout"]
                        process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                        if process.returncode == 0:
                            metadata["pkcs7_parsed"] = True

                finally:
                    os.unlink(tmp_path)

        except Exception:
            pass

        return metadata

