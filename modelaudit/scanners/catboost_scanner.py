"""Scanner for CatBoost native model files (.cbm)."""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import struct
from typing import Any, ClassVar
from urllib.parse import urlparse

from .base import BaseScanner, IssueSeverity, ScanResult

CATBOOST_MAGIC = b"CBM1"
_SIZE_SENTINEL = 0xFFFFFFFF

_PRINTABLE_TEXT_PATTERN = re.compile(rb"[\x20-\x7E]{6,}")
_COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bos\.system\s*\(", re.IGNORECASE), "os.system invocation"),
    (
        re.compile(r"\bsubprocess\.(?:popen|run|call|check_output|check_call)\s*\(", re.IGNORECASE),
        "subprocess invocation",
    ),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE), "dynamic code execution"),
    (re.compile(r"\b__import__\s*\(", re.IGNORECASE), "dynamic import invocation"),
    (
        re.compile(r"\b(?:cmd\.exe\s*/c|powershell(?:\.exe)?\b|bash\s+-c|sh\s+-c)\b", re.IGNORECASE),
        "shell interpreter invocation",
    ),
]
_PROCESS_CONTEXT_PATTERN = re.compile(
    r"\b(?:cmd\.exe|powershell(?:\.exe)?|/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|curl\s+|wget\s+|nc\s+|netcat\s+)\b",
    re.IGNORECASE,
)
_URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.IGNORECASE)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
_SCRIPT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^#!\s*/", re.MULTILINE), "shebang marker"),
    (re.compile(r"<script\b", re.IGNORECASE), "embedded HTML script"),
    (re.compile(r"\b(?:import\s+os|import\s+subprocess|from\s+os\s+import)\b", re.IGNORECASE), "python import block"),
]
_BASE64_PAYLOAD_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{100,}={0,2})")
_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

_SUSPICIOUS_NETWORK_KEYWORDS = (
    "webhook",
    "callback",
    "collect",
    "upload",
    "exfil",
    "requestbin",
    "pastebin",
    "ngrok",
)
_TRUSTED_REFERENCE_DOMAINS = {
    "catboost.ai",
    "github.com",
    "raw.githubusercontent.com",
    "huggingface.co",
}
_BENIGN_METADATA_KEYS = {
    "feature_names",
    "class_names",
    "params",
    "loss_function",
    "eval_metric",
    "metadata",
    "model_guid",
    "cat_features_hash_to_string",
    "cat_feature_hash_to_string",
}


class _CatBoostParseError(ValueError):
    """Raised when CatBoost structure parsing fails."""


class CatBoostScanner(BaseScanner):
    """Scanner for CatBoost .cbm model files with bounded static inspection."""

    name: ClassVar[str] = "catboost"
    description: ClassVar[str] = "Scans CatBoost native .cbm files for suspicious metadata and string indicators"
    supported_extensions: ClassVar[list[str]] = [".cbm"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.core_scan_budget = int(self.config.get("catboost_core_scan_budget", 10 * 1024 * 1024))
        self.trailing_scan_budget = int(self.config.get("catboost_trailing_scan_budget", 4 * 1024 * 1024))
        self.max_extracted_strings = int(self.config.get("catboost_max_extracted_strings", 10_000))

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False

        if os.path.splitext(path)[1].lower() not in cls.supported_extensions:
            return False

        try:
            file_size = os.path.getsize(path)
            if file_size < 8:
                return False

            with open(path, "rb") as f:
                if f.read(4) != CATBOOST_MAGIC:
                    return False
                core_size, header_size = cls._read_core_size(f)

            if core_size <= 0:
                return False

            return header_size + core_size <= file_size
        except OSError:
            return False
        except (_CatBoostParseError, struct.error):
            return False

    @staticmethod
    def _read_core_size(file_obj: Any) -> tuple[int, int]:
        size32_raw = file_obj.read(4)
        if len(size32_raw) != 4:
            raise _CatBoostParseError("Missing CatBoost core-size field")

        size32 = struct.unpack("<I", size32_raw)[0]
        if size32 != _SIZE_SENTINEL:
            return int(size32), 8

        size64_raw = file_obj.read(8)
        if len(size64_raw) != 8:
            raise _CatBoostParseError("Missing CatBoost extended core-size field")

        size64 = struct.unpack("<Q", size64_raw)[0]
        return int(size64), 16

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        self.add_file_integrity_check(path, result)

        try:
            core_blob, trailing_blob, header_size, declared_core_size = self._parse_sections(path, file_size, result)
        except _CatBoostParseError as error:
            result.add_check(
                name="CatBoost Structure Parsing",
                passed=False,
                message=f"Failed to parse CatBoost structure: {error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"error_type": type(error).__name__},
                why="Corrupted or truncated model files should be treated as suspicious input.",
            )
            result.finish(success=False)
            return result
        except OSError as error:
            result.add_check(
                name="CatBoost File Read",
                passed=False,
                message=f"Unable to read CatBoost file: {error}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(error), "error_type": type(error).__name__},
            )
            result.finish(success=False)
            return result

        result.metadata.update(
            {
                "header_size": header_size,
                "declared_core_size": declared_core_size,
                "inspected_core_bytes": len(core_blob),
                "inspected_trailing_bytes": len(trailing_blob),
            },
        )
        result.bytes_scanned = header_size + len(core_blob) + len(trailing_blob)

        extracted_strings = self._extract_text_fragments(core_blob, "core") + self._extract_text_fragments(
            trailing_blob,
            "trailing",
        )
        result.metadata["extracted_string_count"] = len(extracted_strings)

        self._analyze_text_fragments(extracted_strings, result, path)

        result.finish(success=not result.has_errors)
        return result

    def _parse_sections(
        self,
        path: str,
        file_size: int,
        result: ScanResult,
    ) -> tuple[bytes, bytes, int, int]:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != CATBOOST_MAGIC:
                result.add_check(
                    name="CatBoost Header Signature Check",
                    passed=False,
                    message="File does not start with CatBoost CBM1 signature",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"expected_magic": CATBOOST_MAGIC.decode("ascii"), "actual_magic_hex": magic.hex()},
                )
                raise _CatBoostParseError("invalid CatBoost header signature")

            result.add_check(
                name="CatBoost Header Signature Check",
                passed=True,
                message="CatBoost header signature (CBM1) validated",
                location=path,
            )

            declared_core_size, header_size = self._read_core_size(f)
            if declared_core_size <= 0:
                raise _CatBoostParseError("declared core section size must be positive")
            if header_size + declared_core_size > file_size:
                result.add_check(
                    name="CatBoost Core Section Bounds Check",
                    passed=False,
                    message="Declared CatBoost core section size exceeds file bounds",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "header_size": header_size,
                        "declared_core_size": declared_core_size,
                        "file_size": file_size,
                    },
                )
                raise _CatBoostParseError("declared core section size exceeds file bounds")

            result.add_check(
                name="CatBoost Core Section Bounds Check",
                passed=True,
                message="CatBoost core section bounds are valid",
                location=path,
                details={"header_size": header_size, "declared_core_size": declared_core_size},
            )

            core_bytes_to_read = min(declared_core_size, self.core_scan_budget)
            core_blob = f.read(core_bytes_to_read)
            if len(core_blob) != core_bytes_to_read:
                raise _CatBoostParseError("failed to read bounded CatBoost core section")

            core_remaining = declared_core_size - core_bytes_to_read
            if core_remaining > 0:
                f.seek(core_remaining, os.SEEK_CUR)

            trailing_total = file_size - (header_size + declared_core_size)
            trailing_bytes_to_read = min(trailing_total, self.trailing_scan_budget)
            trailing_blob = f.read(trailing_bytes_to_read)

            result.add_check(
                name="CatBoost Bounded Parse Check",
                passed=True,
                message="CatBoost parsing completed within configured byte budgets",
                location=path,
                details={
                    "core_scan_budget": self.core_scan_budget,
                    "trailing_scan_budget": self.trailing_scan_budget,
                    "core_bytes_scanned": core_bytes_to_read,
                    "core_bytes_skipped": core_remaining,
                    "trailing_bytes_scanned": trailing_bytes_to_read,
                    "trailing_bytes_skipped": max(0, trailing_total - trailing_bytes_to_read),
                },
            )

            return core_blob, trailing_blob, header_size, declared_core_size

    def _extract_text_fragments(self, blob: bytes, section: str) -> list[dict[str, str]]:
        fragments: list[dict[str, str]] = []
        if not blob:
            return fragments

        for match in _PRINTABLE_TEXT_PATTERN.finditer(blob):
            value = match.group(0).decode("utf-8", errors="ignore").strip()
            if not value:
                continue
            fragments.append({"text": value, "section": section})
            if len(fragments) >= self.max_extracted_strings:
                break

        return fragments

    @staticmethod
    def _summarize_matches(matches: list[dict[str, str]], limit: int = 5) -> list[dict[str, str]]:
        summarized: list[dict[str, str]] = []
        for item in matches[:limit]:
            text = item.get("text", "")
            excerpt = text if len(text) <= 160 else f"{text[:157]}..."
            summarized.append(
                {
                    "section": item.get("section", "unknown"),
                    "pattern": item.get("pattern", ""),
                    "excerpt": excerpt,
                },
            )
        return summarized

    @staticmethod
    def _is_private_or_loopback_ip(candidate: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

    @staticmethod
    def _is_trusted_reference_url(url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            return False

        if not host:
            return False

        host = host.lower()
        if host in _TRUSTED_REFERENCE_DOMAINS:
            return True

        return any(host.endswith(f".{domain}") for domain in _TRUSTED_REFERENCE_DOMAINS)

    def _analyze_text_fragments(self, fragments: list[dict[str, str]], result: ScanResult, path: str) -> None:
        command_matches: list[dict[str, str]] = []
        process_context_matches: list[dict[str, str]] = []
        network_matches: list[dict[str, str]] = []
        script_matches: list[dict[str, str]] = []
        encoded_matches: list[dict[str, str]] = []

        for fragment in fragments:
            text = fragment["text"]
            lowered = text.lower().strip()

            if lowered in _BENIGN_METADATA_KEYS:
                continue

            for pattern, reason in _COMMAND_PATTERNS:
                if pattern.search(text):
                    command_matches.append({"text": text, "section": fragment["section"], "pattern": reason})
                    break

            if _PROCESS_CONTEXT_PATTERN.search(text):
                process_context_matches.append(
                    {
                        "text": text,
                        "section": fragment["section"],
                        "pattern": "shell/process context",
                    },
                )

            for url_match in _URL_PATTERN.finditer(text):
                url = url_match.group(0)
                lowered_url = url.lower()
                if self._is_trusted_reference_url(url):
                    continue

                if any(keyword in lowered_url for keyword in _SUSPICIOUS_NETWORK_KEYWORDS):
                    network_matches.append(
                        {"text": url, "section": fragment["section"], "pattern": "suspicious network URL"},
                    )

            for ip_match in _IP_PATTERN.finditer(text):
                host = ip_match.group(0).split(":", 1)[0]
                if self._is_private_or_loopback_ip(host):
                    continue
                network_matches.append(
                    {"text": ip_match.group(0), "section": fragment["section"], "pattern": "public IP"}
                )

            for pattern, reason in _SCRIPT_PATTERNS:
                if pattern.search(text):
                    script_matches.append({"text": text, "section": fragment["section"], "pattern": reason})
                    break

            if _HEX_ESCAPE_PATTERN.search(text):
                encoded_matches.append(
                    {
                        "text": text,
                        "section": fragment["section"],
                        "pattern": "hex-escaped payload pattern",
                    },
                )
                continue

            for match in _BASE64_PAYLOAD_PATTERN.finditer(text):
                payload = match.group(0)
                if len(payload) < 120:
                    continue
                padded_payload = payload + "=" * ((4 - (len(payload) % 4)) % 4)
                decoded_text = ""
                try:
                    decoded_text = base64.b64decode(padded_payload, validate=False).decode("utf-8", errors="ignore")
                except Exception:
                    decoded_text = ""

                decoded_lower = decoded_text.lower()
                if any(
                    token in decoded_lower for token in ["os.system", "subprocess", "bash -c", "http://", "https://"]
                ):
                    encoded_matches.append(
                        {
                            "text": payload,
                            "section": fragment["section"],
                            "pattern": "base64 payload with executable/network indicators",
                        },
                    )
                    break

        if command_matches:
            result.add_check(
                name="Command Primitive Check",
                passed=False,
                message="Suspicious command execution primitives detected in CatBoost text-bearing sections",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "matches": self._summarize_matches(command_matches),
                    "total_matches": len(command_matches),
                },
                why="Model artifacts should not embed command-execution primitives.",
            )
        else:
            result.add_check(
                name="Command Primitive Check",
                passed=True,
                message="No command execution primitives detected",
                location=path,
            )

        if network_matches:
            result.add_check(
                name="Network Indicator Check",
                passed=False,
                message="Suspicious network indicators detected in CatBoost text-bearing sections",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "matches": self._summarize_matches(network_matches),
                    "total_matches": len(network_matches),
                },
                why="Hardcoded exfiltration endpoints in model metadata can indicate malicious intent.",
            )
        else:
            result.add_check(
                name="Network Indicator Check",
                passed=True,
                message="No suspicious network indicators detected",
                location=path,
            )

        if encoded_matches:
            result.add_check(
                name="Encoded Payload Indicator Check",
                passed=False,
                message="Encoded payload indicators detected in CatBoost text-bearing sections",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "matches": self._summarize_matches(encoded_matches),
                    "total_matches": len(encoded_matches),
                },
                why="Encoded payloads can be used to conceal executable instructions in model metadata.",
            )
        else:
            result.add_check(
                name="Encoded Payload Indicator Check",
                passed=True,
                message="No encoded payload indicators detected",
                location=path,
            )

        if script_matches:
            result.add_check(
                name="Script Fragment Check",
                passed=False,
                message="Executable script fragments detected in CatBoost text-bearing sections",
                severity=IssueSeverity.WARNING,
                location=path,
                details={
                    "matches": self._summarize_matches(script_matches),
                    "total_matches": len(script_matches),
                },
                why="Embedded scripts are atypical in CatBoost model files and should be treated as suspicious.",
            )
        else:
            result.add_check(
                name="Script Fragment Check",
                passed=True,
                message="No executable script fragments detected",
                location=path,
            )

        if command_matches and (process_context_matches or network_matches):
            context_matches = process_context_matches + network_matches
            result.add_check(
                name="Command/Network Correlation Check",
                passed=False,
                message="Correlated command and process/network indicators detected",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "command_examples": self._summarize_matches(command_matches),
                    "context_examples": self._summarize_matches(context_matches),
                    "command_match_count": len(command_matches),
                    "context_match_count": len(context_matches),
                },
                why="Correlated command primitives plus process/network context strongly indicate exploit intent.",
            )
        else:
            result.add_check(
                name="Command/Network Correlation Check",
                passed=True,
                message="No high-confidence command/network correlation detected",
                location=path,
            )
