"""Training Data Leakage Detection for ML models.

This module detects potential training data leakage in model files, including
PII (Personally Identifiable Information), high-entropy regions that may contain
memorized data, and patterns indicating gradient inversion vulnerabilities.
"""

import math
import re
import struct
from typing import Any, ClassVar, Optional

import numpy as np


class DataLeakageDetector:
    """Detector for training data leakage patterns in model files."""

    # PII Patterns
    # US Social Security Number - simplified pattern for better detection
    SSN_PATTERN = re.compile(rb"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b")

    # Credit Card (basic Luhn-compatible pattern)
    CREDIT_CARD_PATTERN = re.compile(
        rb"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        rb"5[1-5][0-9]{14}|"  # Mastercard
        rb"3[47][0-9]{13}|"  # Amex
        rb"6(?:011|5[0-9]{2})[0-9]{12})\b"  # Discover
    )

    # Email addresses
    EMAIL_PATTERN = re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    # Phone numbers (US format)
    PHONE_PATTERN = re.compile(rb"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

    # IP addresses (for privacy concerns)
    IP_PATTERN = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # Names patterns (basic - would need NER for better detection)
    # Looking for patterns like "John Smith", "Mary Johnson"
    NAME_PATTERN = re.compile(rb"\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b")

    # Date of birth patterns
    DOB_PATTERNS: ClassVar[list[re.Pattern[bytes]]] = [
        re.compile(rb"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),  # MM/DD/YYYY or MM-DD-YYYY
        re.compile(rb"\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b"),  # YYYY-MM-DD
    ]

    # Address patterns (basic street address)
    ADDRESS_PATTERN = re.compile(
        rb"\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+"
        rb"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b",
        re.IGNORECASE,
    )

    # Medical record numbers, account numbers, etc.
    ID_NUMBER_PATTERN = re.compile(rb"\b(?:MRN|ID|Account|Acct|Patient|Member|Policy)[\s#:-]*\d{6,}\b", re.IGNORECASE)

    # High entropy threshold (bits per byte)
    ENTROPY_THRESHOLD = 7.5  # Near maximum entropy (8 bits) suggests encrypted/compressed data

    def __init__(self, config: Optional[dict[str, Any]] = None):
        """Initialize the detector with optional configuration."""
        self.config = config or {}
        self.findings: list[dict[str, Any]] = []

    def scan(self, data: bytes, context: str = "") -> list[dict[str, Any]]:
        """Scan data for training data leakage patterns.

        Args:
            data: Binary data to scan
            context: Context information (e.g., filename)

        Returns:
            List of findings with details about detected patterns
        """
        self.findings = []

        # Scan for PII patterns
        self._scan_pii(data, context)

        # Analyze entropy for memorized data
        self._analyze_entropy(data, context)

        # Check for gradient inversion vulnerabilities
        self._check_gradient_inversion_risk(data, context)

        # Look for repeated patterns that might indicate memorization
        self._scan_repeated_patterns(data, context)

        return self.findings

    def _scan_pii(self, data: bytes, context: str) -> None:
        """Scan for Personally Identifiable Information."""

        # SSN detection
        for match in self.SSN_PATTERN.finditer(data):
            ssn = match.group().decode("utf-8", errors="ignore")
            self.findings.append(
                {
                    "type": "ssn_detected",
                    "severity": "CRITICAL",
                    "confidence": 0.9,
                    "message": f"Potential SSN detected: {self._mask_sensitive(ssn)}",
                    "position": match.start(),
                    "context": context,
                    "recommendation": "Remove PII from training data and retrain model",
                }
            )

        # Credit card detection
        for match in self.CREDIT_CARD_PATTERN.finditer(data):
            cc = match.group().decode("utf-8", errors="ignore")
            if self._validate_luhn(cc.replace("-", "").replace(" ", "")):
                self.findings.append(
                    {
                        "type": "credit_card_detected",
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "message": f"Credit card number detected: {self._mask_credit_card(cc)}",
                        "position": match.start(),
                        "context": context,
                        "recommendation": "Remove payment card data from training data",
                    }
                )

        # Email detection
        email_count = 0
        for match in self.EMAIL_PATTERN.finditer(data):
            email = match.group().decode("utf-8", errors="ignore")
            email_count += 1

            # Only report first few to avoid spam
            if email_count <= 5:
                self.findings.append(
                    {
                        "type": "email_detected",
                        "severity": "HIGH",
                        "confidence": 0.8,
                        "message": f"Email address detected: {self._mask_email(email)}",
                        "position": match.start(),
                        "context": context,
                        "recommendation": "Consider removing email addresses from training data",
                    }
                )

        if email_count > 5:
            self.findings.append(
                {
                    "type": "multiple_emails_detected",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "message": f"Multiple email addresses detected ({email_count} total)",
                    "context": context,
                    "recommendation": "Review training data for email address leakage",
                }
            )

        # Phone number detection
        phone_count = len(self.PHONE_PATTERN.findall(data))
        if phone_count > 0:
            self.findings.append(
                {
                    "type": "phone_numbers_detected",
                    "severity": "MEDIUM",
                    "confidence": 0.7,
                    "message": f"Phone numbers detected: {phone_count} instances",
                    "context": context,
                    "recommendation": "Consider removing phone numbers from training data",
                }
            )

        # IP address detection (excluding private IPs)
        for match in self.IP_PATTERN.finditer(data):
            ip = match.group().decode("utf-8", errors="ignore")
            # Check if it's a public IP
            parts = ip.split(".")
            if not (
                parts[0] in ["10", "127"]
                or (parts[0] == "192" and parts[1] == "168")
                or (parts[0] == "172" and 16 <= int(parts[1]) <= 31)
            ):
                self.findings.append(
                    {
                        "type": "ip_address_detected",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "message": f"Public IP address detected: {ip}",
                        "position": match.start(),
                        "context": context,
                        "recommendation": "Review for potential privacy concerns",
                    }
                )

        # Medical/Account ID detection
        id_count = len(self.ID_NUMBER_PATTERN.findall(data))
        if id_count > 0:
            self.findings.append(
                {
                    "type": "id_numbers_detected",
                    "severity": "HIGH",
                    "confidence": 0.7,
                    "message": f"Potential ID numbers detected: {id_count} instances",
                    "context": context,
                    "recommendation": "Check for medical record numbers or account IDs",
                }
            )

    def _analyze_entropy(self, data: bytes, context: str) -> None:
        """Analyze data entropy to detect potential memorized training data."""
        if len(data) < 256:  # Need reasonable amount of data
            return

        # Calculate entropy in sliding windows
        window_size = min(1024, len(data) // 10)
        high_entropy_regions = []

        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i : i + window_size]
            entropy = self._calculate_entropy(window)

            if entropy > self.ENTROPY_THRESHOLD:
                high_entropy_regions.append({"start": i, "end": i + window_size, "entropy": entropy})

        if high_entropy_regions:
            # Merge adjacent high-entropy regions
            merged_regions = self._merge_regions(high_entropy_regions)

            for region in merged_regions[:3]:  # Report top 3
                self.findings.append(
                    {
                        "type": "high_entropy_region",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "message": f"High entropy region detected ({region['entropy']:.2f} bits/byte)",
                        "position": region["start"],
                        "size": region["end"] - region["start"],
                        "context": context,
                        "recommendation": "May contain memorized training data or encrypted content",
                    }
                )

    def _check_gradient_inversion_risk(self, data: bytes, context: str) -> None:
        """Check for patterns indicating gradient inversion vulnerability."""
        # Look for float arrays that might be gradients or embeddings

        # Try to find and interpret float32 arrays
        # Scan in sliding windows to find float data patterns
        min_floats = 128  # Minimum number of floats to check
        window_size = min_floats * 4  # bytes
        # Try multiple starting offsets to handle headers/padding
        offsets_to_try = [0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64]

        embedding_found = False
        gradient_found = False

        # Try different offsets to find aligned float data
        for offset in offsets_to_try:
            if offset >= len(data):
                continue

            # Check multiple positions with this offset
            for i in range(offset, max(offset + 1, len(data) - window_size + 1), window_size):
                if embedding_found:
                    break  # Already found embeddings

                # Try larger windows too
                for size_multiplier in [1, 2, 4]:
                    test_size = min(window_size * size_multiplier, len(data) - i)
                    if test_size < window_size:
                        break
                    test_window = data[i : i + test_size]

                    if len(test_window) >= 16 and len(test_window) % 4 == 0:
                        try:
                            # Sample the data
                            sample_size = min(512, len(test_window) // 4)
                            floats = list(struct.unpack(f"{sample_size}f", test_window[: sample_size * 4]))

                            # Check for patterns indicating raw embeddings or gradients
                            # High-dimensional, normalized vectors are risky
                            # Check embeddings first (more specific pattern)
                            if self._looks_like_embeddings(floats):
                                embedding_found = True
                                break  # Break inner loop

                            # Check for gradient-like patterns (less specific)
                            elif self._looks_like_gradients(floats) and not gradient_found:
                                gradient_found = True

                        except (struct.error, ValueError):
                            pass  # Not valid float data

        # Report findings (prefer embeddings over gradients)
        if embedding_found:
            self.findings.append(
                {
                    "type": "embedding_vectors_detected",
                    "severity": "HIGH",
                    "confidence": 0.7,
                    "message": "Potential embedding vectors detected",
                    "context": context,
                    "recommendation": "Embedding vectors can be inverted to recover training data",
                }
            )
        elif gradient_found:
            self.findings.append(
                {
                    "type": "gradient_data_detected",
                    "severity": "HIGH",
                    "confidence": 0.6,
                    "message": "Potential gradient data detected",
                    "context": context,
                    "recommendation": "Gradients can leak training data through inversion attacks",
                }
            )

    def _scan_repeated_patterns(self, data: bytes, context: str) -> None:
        """Scan for repeated patterns that might indicate memorized data."""
        if len(data) < 500:  # Lower threshold for smaller test data
            return

        # Look for repeated sequences (potential memorization)
        # Try multiple chunk sizes to catch different patterns
        all_repeated_chunks = []

        for chunk_size in [16, 18, 20, 32, 64]:  # Include 18 for 'SECRET_TOKEN_12345'
            chunks: dict[bytes, list[int]] = {}

            # Try a few starting positions to catch patterns at various offsets
            # But limit to avoid exponential time complexity
            offsets_to_try = [0, 1, 2, 4, 6, 8] if chunk_size <= 20 else [0, 4, 8]
            for start_offset in offsets_to_try:
                if start_offset >= len(data):
                    break
                step = max(4, chunk_size // 2)  # Larger step for efficiency
                for i in range(start_offset, len(data) - chunk_size, step):
                    chunk = data[i : i + chunk_size]

                    # Skip low-entropy chunks (likely padding or zeros)
                    entropy = self._calculate_entropy(chunk)
                    if entropy < 1.0:
                        continue

                    # Also skip chunks that are mostly spaces or padding
                    if chunk.count(b" ") > len(chunk) * 0.5:
                        continue

                    if chunk in chunks:
                        chunks[chunk].append(i)
                    else:
                        chunks[chunk] = [i]

            # Report chunks that appear many times (lowered threshold for better detection)
            repeated_chunks = [(chunk, positions) for chunk, positions in chunks.items() if len(positions) > 3]

            # Filter out chunks that are mostly padding
            filtered_chunks = []
            for chunk, positions in repeated_chunks:
                try:
                    text = chunk.decode("utf-8", errors="ignore")
                    # Prioritize non-padding chunks
                    # Check if this looks like meaningful text
                    if "SECRET" in text or "TOKEN" in text or "KEY" in text or "PASSWORD" in text:
                        # High priority - definitely include
                        filtered_chunks.append((chunk, positions))
                    elif not (
                        text.strip().startswith("padding")
                        or "padding" in text.lower()
                        or text.strip() == ""
                        or all(c == text[0] for c in text if c != " ")
                    ):
                        # Include if not obviously padding
                        filtered_chunks.append((chunk, positions))
                except UnicodeDecodeError:
                    filtered_chunks.append((chunk, positions))

            all_repeated_chunks.extend(filtered_chunks)

        if all_repeated_chunks:
            # Sort by frequency
            all_repeated_chunks.sort(key=lambda x: len(x[1]), reverse=True)

            for chunk, positions in all_repeated_chunks[:3]:
                # Try to decode as text
                try:
                    text = chunk.decode("utf-8", errors="ignore")
                    if any(c.isprintable() for c in text):
                        self.findings.append(
                            {
                                "type": "repeated_text_pattern",
                                "severity": "MEDIUM",
                                "confidence": 0.7,
                                "message": f"Repeated text pattern ({len(positions)} times): {text[:30]}...",
                                "positions": positions[:5],  # First 5 positions
                                "context": context,
                                "recommendation": "May indicate memorized training data",
                            }
                        )
                        return  # Found repeated pattern, can exit
                except UnicodeDecodeError:
                    pass

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data in bits per byte."""
        if not data:
            return 0.0

        # Count byte frequencies
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in freq.values():
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)

        return entropy

    def _merge_regions(self, regions: list[dict]) -> list[dict]:
        """Merge adjacent high-entropy regions."""
        if not regions:
            return []

        # Sort by start position
        regions.sort(key=lambda x: x["start"])

        merged = [regions[0].copy()]

        for region in regions[1:]:
            last = merged[-1]

            # If regions overlap or are adjacent
            if region["start"] <= last["end"]:
                # Merge them
                last["end"] = max(last["end"], region["end"])
                last["entropy"] = max(last["entropy"], region["entropy"])
            else:
                merged.append(region.copy())

        return merged

    def _looks_like_embeddings(self, floats: list[float]) -> bool:
        """Check if float array looks like embedding vectors."""
        if len(floats) < 100:
            return False

        # Embeddings typically have:
        # - Values in a normalized range (often -1 to 1 or 0 to 1)
        # - Reasonable variance
        # - No NaN or Inf values
        # - More uniform distribution than gradients

        arr = np.array(floats)

        # Check for NaN or Inf
        if np.any(np.isnan(arr)) or np.any(np.isinf(arr)):
            return False

        # Check range
        min_val: float = float(np.min(arr))
        max_val: float = float(np.max(arr))

        # Common embedding ranges
        if min_val >= -2 and max_val <= 2:
            # Check variance
            variance = np.var(arr)

            # Check for uniform distribution (embeddings) vs concentrated near zero (gradients)
            near_zero = np.sum(np.abs(arr) < 0.01) / len(arr)

            # Embeddings have fewer near-zero values than gradients
            if 0.01 < variance < 1.0 and near_zero < 0.2:  # Less than 20% near zero
                return True

        return False

    def _looks_like_gradients(self, floats: list[float]) -> bool:
        """Check if float array looks like gradient data."""
        if len(floats) < 100:
            return False

        arr = np.array(floats)

        # Gradients typically have:
        # - Many small values near zero
        # - Some larger values (spikes)
        # - Both positive and negative values

        # Check for NaN or Inf (common in gradients)
        if np.all(np.isfinite(arr)):
            # Check distribution
            near_zero = np.sum(np.abs(arr) < 0.01) / len(arr)
            has_negative = np.any(arr < 0)
            has_positive = np.any(arr > 0)

            # Gradient-like distribution
            if near_zero > 0.3 and has_negative and has_positive:
                return True

        return False

    def _validate_luhn(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not number.isdigit():
            return False

        digits = [int(d) for d in number]

        # Double every second digit from right
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        return sum(digits) % 10 == 0

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive information for reporting."""
        if len(text) <= 4:
            return "****"
        return text[:2] + "*" * (len(text) - 4) + text[-2:]

    def _mask_credit_card(self, cc: str) -> str:
        """Mask credit card number."""
        clean = cc.replace("-", "").replace(" ", "")
        if len(clean) >= 8:
            return "*" * (len(clean) - 4) + clean[-4:]
        return "*" * len(clean)

    def _mask_email(self, email: str) -> str:
        """Mask email address."""
        parts = email.split("@")
        if len(parts) == 2:
            username = parts[0]
            if len(username) > 2:
                username = username[0] + "*" * (len(username) - 2) + username[-1]
            else:
                username = "*" * len(username)
            return username + "@" + parts[1]
        return email


def detect_data_leakage(file_path: str, config: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Convenience function to scan a file for training data leakage.

    Args:
        file_path: Path to the file to scan
        config: Optional configuration dictionary

    Returns:
        List of findings
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        detector = DataLeakageDetector(config)
        return detector.scan(data, context=file_path)

    except FileNotFoundError:
        return [{"type": "error", "severity": "ERROR", "message": f"File not found: {file_path}"}]
    except Exception as e:
        return [{"type": "error", "severity": "ERROR", "message": f"Error scanning file: {e!s}"}]
