"""Scanner for Apple CoreML model files (.mlmodel)."""

from __future__ import annotations

import base64
import binascii
import os
import re
from pathlib import Path, PurePosixPath
from typing import ClassVar, NamedTuple

from .base import BaseScanner, IssueSeverity, ScanResult

_MAX_VARINT_BYTES = 10

_NETWORK_PATTERN = re.compile(
    r"(?i)\b(?:https?://|wss?://|ftp://|file://|s3://|gs://|[a-z0-9.-]+\.(?:com|net|org|io|ai)(?:/|\b))"
)
_COMMAND_PATTERN = re.compile(
    r"(?i)(?:"
    r"\bos\.system\b|\bos\.popen\b|"
    r"\bsubprocess\.(?:Popen|run|call|check_call|check_output)\b|"
    r"\b(?:bash|sh|zsh|powershell(?:\.exe)?|cmd(?:\.exe)?)\b|"
    r"\b(?:curl|wget)\b\s+https?://|"
    r"\b(?:rm\s+-rf|chmod\s+\+x|python\s+-c)\b|"
    r"/bin/(?:sh|bash)"
    r")"
)
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_SAFE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._:/\-\s]{1,256}$")


class _ProtoField(NamedTuple):
    field_number: int
    wire_type: int
    value: int | bytes
    declared_length: int | None = None
    truncated: bool = False


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read a protobuf varint from data[offset:]."""
    value = 0
    shift = 0
    pos = offset

    for _ in range(_MAX_VARINT_BYTES):
        if pos >= len(data):
            return None

        byte_val = data[pos]
        pos += 1
        value |= (byte_val & 0x7F) << shift

        if (byte_val & 0x80) == 0:
            return value, pos

        shift += 7

    return None


def _parse_message(
    data: bytes,
    *,
    max_fields: int,
    allow_truncated: bool = False,
) -> tuple[list[_ProtoField], str | None]:
    """Parse a protobuf message into raw fields.

    This parser is intentionally narrow and safe:
    - bounded by `max_fields`
    - no dynamic schema loading
    - optional truncated handling for bounded prefix parsing
    """
    fields: list[_ProtoField] = []
    offset = 0

    while offset < len(data):
        if len(fields) >= max_fields:
            return fields, f"field count exceeded limit ({max_fields})"

        key_info = _read_varint(data, offset)
        if key_info is None:
            return fields, "truncated or invalid field key"
        key, offset = key_info

        field_number = key >> 3
        wire_type = key & 0x07
        if field_number <= 0:
            return fields, "invalid field number 0"

        if wire_type == 0:  # varint
            value_info = _read_varint(data, offset)
            if value_info is None:
                return fields, f"invalid varint value for field {field_number}"
            value, offset = value_info
            fields.append(_ProtoField(field_number, wire_type, value))
            continue

        if wire_type == 1:  # fixed64
            end = offset + 8
            if end > len(data):
                if allow_truncated:
                    return fields, None
                return fields, f"truncated fixed64 field {field_number}"
            value = int.from_bytes(data[offset:end], "little")
            offset = end
            fields.append(_ProtoField(field_number, wire_type, value))
            continue

        if wire_type == 2:  # length-delimited
            length_info = _read_varint(data, offset)
            if length_info is None:
                return fields, f"invalid length varint for field {field_number}"
            declared_length, offset = length_info
            end = offset + declared_length

            if end > len(data):
                if allow_truncated:
                    fields.append(
                        _ProtoField(
                            field_number,
                            wire_type,
                            data[offset:],
                            declared_length=declared_length,
                            truncated=True,
                        )
                    )
                    return fields, None
                return fields, f"truncated length-delimited field {field_number}"

            fields.append(
                _ProtoField(
                    field_number,
                    wire_type,
                    data[offset:end],
                    declared_length=declared_length,
                )
            )
            offset = end
            continue

        if wire_type == 5:  # fixed32
            end = offset + 4
            if end > len(data):
                if allow_truncated:
                    return fields, None
                return fields, f"truncated fixed32 field {field_number}"
            value = int.from_bytes(data[offset:end], "little")
            offset = end
            fields.append(_ProtoField(field_number, wire_type, value))
            continue

        return fields, f"unsupported wire type {wire_type} for field {field_number}"

    return fields, None


def _len_fields(fields: list[_ProtoField], field_number: int) -> list[_ProtoField]:
    return [f for f in fields if f.field_number == field_number and f.wire_type == 2 and isinstance(f.value, bytes)]


def _first_varint(fields: list[_ProtoField], field_number: int) -> int | None:
    for field in fields:
        if field.field_number == field_number and field.wire_type == 0 and isinstance(field.value, int):
            return field.value
    return None


def _decode_string(value: bytes, max_length: int = 8192) -> str:
    """Decode UTF-8 safely with bounded length."""
    return value[:max_length].decode("utf-8", errors="ignore").strip()


def _is_within_directory(path: Path, base_dir: Path) -> bool:
    try:
        path.relative_to(base_dir)
        return True
    except ValueError:
        return False


class CoreMLScanner(BaseScanner):
    """Scanner for CoreML protobuf models."""

    name = "coreml"
    description = "Scans CoreML .mlmodel files for custom code paths and suspicious metadata"
    supported_extensions: ClassVar[list[str]] = [".mlmodel"]

    # Bounded parse limits to avoid large-memory processing spikes
    MAX_PARSE_BYTES: ClassVar[int] = 10 * 1024 * 1024  # 10 MB
    CAN_HANDLE_READ_BYTES: ClassVar[int] = 1024 * 1024  # 1 MB
    MAX_TOP_LEVEL_FIELDS: ClassVar[int] = 10000
    MAX_NESTED_FIELDS: ClassVar[int] = 4000
    MAX_USER_METADATA_ENTRIES: ClassVar[int] = 512

    # CoreML model oneof fields from Model.proto
    MODEL_TYPE_FIELDS: ClassVar[frozenset[int]] = frozenset(
        {
            200,
            201,
            202,
            300,
            301,
            302,
            303,
            304,
            400,
            401,
            402,
            403,
            404,
            500,
            501,
            502,
            555,
            556,
            560,
            600,
            601,
            602,
            603,
            604,
            606,
            607,
            609,
            610,
            900,
            2000,
            2001,
            2002,
            2003,
            2004,
            2005,
            2006,
        }
    )
    NEURAL_NETWORK_FIELDS: ClassVar[frozenset[int]] = frozenset({303, 403, 500})
    CUSTOM_MODEL_FIELD: ClassVar[int] = 555
    LINKED_MODEL_FIELD: ClassVar[int] = 556

    SAFE_USER_METADATA_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "com.github.apple.coremltools.version",
            "com.github.apple.coremltools.source",
            "com.github.apple.coremltools.source_dialect",
            "com.github.apple.coremltools.converter",
            "com.apple.coreml.model.preview.type",
            "com.apple.coreml.model.preview.params",
            "coremltools-version",
            "coremltools-source-dialect",
        }
    )

    EXECUTABLE_METADATA_KEY_HINTS: ClassVar[tuple[str, ...]] = (
        "script",
        "command",
        "entrypoint",
        "hook",
        "callback",
        "loader",
        "plugin",
        "runtime",
        "url",
        "endpoint",
        "download",
    )

    SAFE_LINKED_PATH_PREFIXES: ClassVar[tuple[str, ...]] = ("$BUNDLE_MAIN", "$BUNDLE_IDENTIFIER(")

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        if os.path.splitext(path)[1].lower() not in cls.supported_extensions:
            return False

        file_size = os.path.getsize(path)
        if file_size < 8:
            return False

        try:
            read_size = min(file_size, cls.CAN_HANDLE_READ_BYTES)
            with open(path, "rb") as handle:
                prefix = handle.read(read_size)

            top_fields, parse_error = _parse_message(
                prefix,
                max_fields=cls.MAX_TOP_LEVEL_FIELDS,
                allow_truncated=file_size > cls.CAN_HANDLE_READ_BYTES,
            )
            if parse_error:
                return False

            return cls._has_coreml_structure(top_fields)
        except Exception:
            return False

    @classmethod
    def _has_coreml_structure(cls, fields: list[_ProtoField]) -> bool:
        spec_version = _first_varint(fields, 1)
        if spec_version is None or spec_version <= 0 or spec_version > 10000:
            return False

        description_fields = _len_fields(fields, 2)
        if not description_fields:
            return False

        has_model_type = any(field.field_number in cls.MODEL_TYPE_FIELDS and field.wire_type == 2 for field in fields)
        if not has_model_type:
            return False

        # Description should decode as a protobuf message with expected field IDs.
        desc_message = description_fields[0].value
        if not isinstance(desc_message, bytes):
            return False

        parsed_desc, desc_error = _parse_message(desc_message, max_fields=512, allow_truncated=True)
        if desc_error:
            return False

        return any(field.field_number in {1, 10, 20, 21, 100} for field in parsed_desc)

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        # Add file integrity check for compliance.
        self.add_file_integrity_check(path, result)

        try:
            read_limit = min(file_size, self.MAX_PARSE_BYTES)
            with open(path, "rb") as handle:
                data = handle.read(read_limit)
            result.bytes_scanned = len(data)
        except Exception as exc:
            result.add_check(
                name="CoreML File Read",
                passed=False,
                message=f"Failed to read CoreML file: {exc}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(exc), "exception_type": type(exc).__name__},
            )
            result.finish(success=False)
            return result

        if file_size > self.MAX_PARSE_BYTES:
            result.add_check(
                name="CoreML Bounded Parse Window",
                passed=True,
                message=(
                    f"CoreML analysis bounded to first {self.MAX_PARSE_BYTES:,} bytes of "
                    f"{file_size:,} bytes for safe static parsing"
                ),
                location=path,
                details={
                    "bytes_scanned": len(data),
                    "file_size": file_size,
                    "max_parse_bytes": self.MAX_PARSE_BYTES,
                },
            )

        top_fields, parse_error = _parse_message(
            data,
            max_fields=self.MAX_TOP_LEVEL_FIELDS,
            allow_truncated=file_size > self.MAX_PARSE_BYTES,
        )
        if parse_error:
            result.add_check(
                name="CoreML Protobuf Parse",
                passed=False,
                message=f"Invalid CoreML protobuf structure: {parse_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"parse_error": parse_error},
            )
            result.finish(success=False)
            return result

        if not self._has_coreml_structure(top_fields):
            result.add_check(
                name="CoreML Structural Validation",
                passed=False,
                message="File does not match expected CoreML .mlmodel protobuf structure",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        result.add_check(
            name="CoreML Structural Validation",
            passed=True,
            message="CoreML protobuf structure validated",
            location=path,
        )

        spec_version = _first_varint(top_fields, 1)
        if spec_version is not None:
            result.metadata["specification_version"] = spec_version

        model_type_fields = sorted(
            {
                field.field_number
                for field in top_fields
                if field.wire_type == 2 and field.field_number in self.MODEL_TYPE_FIELDS
            }
        )
        result.metadata["model_type_fields"] = model_type_fields

        metadata_findings = self._analyze_description(top_fields, path, result)
        custom_findings = self._analyze_custom_blocks(top_fields, path, result)
        linked_path_findings = self._analyze_linked_model_paths(top_fields, path, result)

        if metadata_findings == 0:
            result.add_check(
                name="CoreML Metadata Security Check",
                passed=True,
                message="No suspicious CoreML metadata patterns detected",
                location=path,
            )

        if custom_findings == 0:
            result.add_check(
                name="CoreML Custom Code Path Check",
                passed=True,
                message="No custom layer or custom model code paths detected",
                location=path,
            )

        if linked_path_findings == 0:
            result.add_check(
                name="CoreML Linked Model Path Check",
                passed=True,
                message="No unsafe linked-model path references detected",
                location=path,
            )

        result.finish(success=not result.has_errors)
        return result

    def _analyze_description(self, top_fields: list[_ProtoField], path: str, result: ScanResult) -> int:
        findings = 0
        description_messages = _len_fields(top_fields, 2)
        if not description_messages:
            return findings

        description_payload = description_messages[0].value
        if not isinstance(description_payload, bytes):
            return findings

        desc_fields, desc_error = _parse_message(description_payload, max_fields=self.MAX_NESTED_FIELDS)
        if desc_error:
            result.add_check(
                name="CoreML Description Parse",
                passed=False,
                message=f"Unable to parse CoreML model description: {desc_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"field_path": "description", "parse_error": desc_error},
            )
            return findings + 1

        metadata_messages = _len_fields(desc_fields, 100)
        if not metadata_messages:
            return findings

        metadata_payload = metadata_messages[0].value
        if not isinstance(metadata_payload, bytes):
            return findings

        metadata_fields, metadata_error = _parse_message(metadata_payload, max_fields=self.MAX_NESTED_FIELDS)
        if metadata_error:
            result.add_check(
                name="CoreML Metadata Parse",
                passed=False,
                message=f"Unable to parse CoreML metadata section: {metadata_error}",
                severity=IssueSeverity.INFO,
                location=path,
                details={"field_path": "description.metadata", "parse_error": metadata_error},
            )
            return findings + 1

        builtin_metadata_fields = {
            1: "shortDescription",
            2: "versionString",
            3: "author",
            4: "license",
        }
        model_metadata: dict[str, str] = {}

        for field_number, field_name in builtin_metadata_fields.items():
            values = _len_fields(metadata_fields, field_number)
            if not values:
                continue
            raw_value = values[0].value
            if not isinstance(raw_value, bytes):
                continue
            text_value = _decode_string(raw_value)
            if text_value:
                model_metadata[field_name] = text_value
                findings += self._scan_metadata_value(
                    key=field_name,
                    value=text_value,
                    path=path,
                    result=result,
                    field_path=f"description.metadata.{field_name}",
                    user_defined=False,
                )

        if model_metadata:
            result.metadata["coreml_metadata"] = model_metadata

        user_defined: dict[str, str] = {}
        user_defined_fields = _len_fields(metadata_fields, 100)[: self.MAX_USER_METADATA_ENTRIES]
        for index, entry_field in enumerate(user_defined_fields):
            entry_payload = entry_field.value
            if not isinstance(entry_payload, bytes):
                continue

            entry_fields, entry_error = _parse_message(entry_payload, max_fields=32)
            if entry_error:
                result.add_check(
                    name="CoreML User Metadata Entry Parse",
                    passed=False,
                    message=f"Malformed user-defined metadata entry at index {index}: {entry_error}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "field_path": f"description.metadata.userDefined[{index}]",
                        "parse_error": entry_error,
                    },
                )
                findings += 1
                continue

            key_field = _len_fields(entry_fields, 1)
            value_field = _len_fields(entry_fields, 2)
            if not key_field or not value_field:
                continue

            raw_key = key_field[0].value
            raw_value = value_field[0].value
            if not isinstance(raw_key, bytes) or not isinstance(raw_value, bytes):
                continue

            key = _decode_string(raw_key, max_length=512)
            value = _decode_string(raw_value)
            if not key:
                key = f"<empty-key-{index}>"

            user_defined[key] = value
            findings += self._scan_metadata_value(
                key=key,
                value=value,
                path=path,
                result=result,
                field_path=f"description.metadata.userDefined[{key}]",
                user_defined=True,
            )

        if user_defined:
            result.metadata["user_defined_metadata"] = user_defined

        return findings

    def _scan_metadata_value(
        self,
        *,
        key: str,
        value: str,
        path: str,
        result: ScanResult,
        field_path: str,
        user_defined: bool,
    ) -> int:
        findings = 0
        key_lower = key.lower()
        value_for_scan = value.strip()
        executable_context = any(hint in key_lower for hint in self.EXECUTABLE_METADATA_KEY_HINTS)

        if user_defined and key_lower in self.SAFE_USER_METADATA_KEYS and _SAFE_VALUE_PATTERN.fullmatch(value_for_scan):
            return findings

        has_command_pattern = bool(_COMMAND_PATTERN.search(value_for_scan))
        has_network_pattern = bool(_NETWORK_PATTERN.search(value_for_scan))
        if has_command_pattern or has_network_pattern:
            severity = IssueSeverity.CRITICAL if (has_command_pattern and executable_context) else IssueSeverity.WARNING
            pattern_type = "command" if has_command_pattern else "network"
            result.add_check(
                name="CoreML Metadata Pattern Check",
                passed=False,
                message=f"Suspicious {pattern_type} pattern in CoreML metadata key '{key}'",
                severity=severity,
                location=path,
                details={
                    "metadata_key": key,
                    "field_path": field_path,
                    "pattern_type": pattern_type,
                    "user_defined": user_defined,
                },
                why="Model metadata should not contain command execution or untrusted network invocation directives.",
            )
            findings += 1

        decoded_payload = self._decode_base64_payload(value_for_scan)
        if decoded_payload is not None:
            decoded_has_command = bool(_COMMAND_PATTERN.search(decoded_payload))
            decoded_has_network = bool(_NETWORK_PATTERN.search(decoded_payload))
            severity = IssueSeverity.WARNING
            if decoded_has_command and (executable_context or has_command_pattern):
                severity = IssueSeverity.CRITICAL

            result.add_check(
                name="CoreML Encoded Metadata Payload Check",
                passed=False,
                message=f"Encoded metadata payload detected for key '{key}'",
                severity=severity,
                location=path,
                details={
                    "metadata_key": key,
                    "field_path": field_path,
                    "decoded_preview": decoded_payload[:200],
                    "decoded_has_command": decoded_has_command,
                    "decoded_has_network": decoded_has_network,
                    "user_defined": user_defined,
                },
                why=(
                    "Encoded blobs in metadata can hide payloads. They are warning-level by default and are elevated "
                    "only when combined with additional execution signals."
                ),
            )
            findings += 1

        return findings

    def _decode_base64_payload(self, value: str) -> str | None:
        compact = "".join(value.split())
        if len(compact) < 120 or len(compact) > 8192:
            return None
        if len(compact) % 4 != 0:
            return None
        if not _BASE64_PATTERN.fullmatch(compact):
            return None

        try:
            decoded = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            return None

        if len(decoded) < 32:
            return None

        text = decoded.decode("utf-8", errors="ignore")
        if not text:
            return None

        printable = sum(1 for ch in text if ch.isprintable() or ch in {"\n", "\r", "\t"})
        if printable / len(text) < 0.75:
            return None

        return text

    def _analyze_custom_blocks(self, top_fields: list[_ProtoField], path: str, result: ScanResult) -> int:
        findings = 0
        layer_count = 0
        custom_layer_count = 0

        for model_field in top_fields:
            if model_field.field_number not in self.NEURAL_NETWORK_FIELDS or model_field.wire_type != 2:
                continue
            payload = model_field.value
            if not isinstance(payload, bytes):
                continue

            network_fields, network_error = _parse_message(
                payload, max_fields=self.MAX_NESTED_FIELDS, allow_truncated=True
            )
            if network_error:
                continue

            layer_fields = _len_fields(network_fields, 1)
            for layer_index, layer_field in enumerate(layer_fields):
                layer_payload = layer_field.value
                if not isinstance(layer_payload, bytes):
                    continue
                layer_count += 1
                parsed_layer, layer_error = _parse_message(
                    layer_payload, max_fields=self.MAX_NESTED_FIELDS, allow_truncated=True
                )
                if layer_error:
                    continue

                layer_name = ""
                layer_name_field = _len_fields(parsed_layer, 1)
                if layer_name_field and isinstance(layer_name_field[0].value, bytes):
                    layer_name = _decode_string(layer_name_field[0].value, max_length=256)
                if not layer_name:
                    layer_name = f"layer_{layer_index}"

                custom_fields = _len_fields(parsed_layer, 500)
                for custom_field in custom_fields:
                    custom_payload = custom_field.value
                    if not isinstance(custom_payload, bytes):
                        continue
                    custom_layer_count += 1
                    parsed_custom, custom_error = _parse_message(
                        custom_payload,
                        max_fields=self.MAX_NESTED_FIELDS,
                        allow_truncated=True,
                    )
                    if custom_error:
                        continue

                    class_name = ""
                    class_name_fields = _len_fields(parsed_custom, 10)
                    if class_name_fields and isinstance(class_name_fields[0].value, bytes):
                        class_name = _decode_string(class_name_fields[0].value, max_length=256)

                    field_path = (
                        f"model[{model_field.field_number}].layers[{layer_index}].custom"
                        if class_name
                        else f"model[{model_field.field_number}].layers[{layer_index}].custom(<unnamed>)"
                    )
                    result.add_check(
                        name="CoreML Custom Layer Check",
                        passed=False,
                        message=f"Custom CoreML layer detected: '{class_name or 'unknown'}' in layer '{layer_name}'",
                        severity=IssueSeverity.CRITICAL,
                        location=path,
                        details={
                            "field_path": f"{field_path}.className",
                            "layer_name": layer_name,
                            "class_name": class_name or "<unknown>",
                            "model_type_field": model_field.field_number,
                        },
                        why=(
                            "CoreML custom layers can load project-specific code paths and should be treated as "
                            "untrusted."
                        ),
                    )
                    findings += 1

                    findings += self._scan_custom_parameter_map(
                        parsed_custom,
                        path=path,
                        result=result,
                        field_path=f"{field_path}.parameters",
                    )

        custom_model_fields = _len_fields(top_fields, self.CUSTOM_MODEL_FIELD)
        for custom_model_field in custom_model_fields:
            payload = custom_model_field.value
            if not isinstance(payload, bytes):
                continue

            custom_model, custom_model_error = _parse_message(
                payload, max_fields=self.MAX_NESTED_FIELDS, allow_truncated=True
            )
            if custom_model_error:
                continue

            class_name = ""
            class_name_fields = _len_fields(custom_model, 10)
            if class_name_fields and isinstance(class_name_fields[0].value, bytes):
                class_name = _decode_string(class_name_fields[0].value, max_length=256)

            result.add_check(
                name="CoreML Custom Model Class Check",
                passed=False,
                message=f"CoreML custom model class detected: '{class_name or 'unknown'}'",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={
                    "field_path": "model[555].className",
                    "class_name": class_name or "<unknown>",
                },
                why="CoreML custom models execute host application code during model use and require trust validation.",
            )
            findings += 1

            findings += self._scan_custom_parameter_map(
                custom_model,
                path=path,
                result=result,
                field_path="model[555].parameters",
            )

        result.metadata["layer_count"] = layer_count
        result.metadata["custom_layer_count"] = custom_layer_count
        result.metadata["has_custom_model"] = bool(custom_model_fields)
        return findings

    def _scan_custom_parameter_map(
        self,
        message_fields: list[_ProtoField],
        *,
        path: str,
        result: ScanResult,
        field_path: str,
    ) -> int:
        findings = 0

        parameter_entries = _len_fields(message_fields, 30)
        for entry_index, parameter_entry in enumerate(parameter_entries):
            entry_payload = parameter_entry.value
            if not isinstance(entry_payload, bytes):
                continue

            entry_fields, entry_error = _parse_message(entry_payload, max_fields=32, allow_truncated=True)
            if entry_error:
                continue

            key_fields = _len_fields(entry_fields, 1)
            value_fields = _len_fields(entry_fields, 2)
            if not key_fields or not value_fields:
                continue

            raw_key = key_fields[0].value
            raw_value = value_fields[0].value
            if not isinstance(raw_key, bytes) or not isinstance(raw_value, bytes):
                continue

            param_key = _decode_string(raw_key, max_length=256)
            value_message_fields, value_error = _parse_message(raw_value, max_fields=32, allow_truncated=True)
            if value_error:
                continue

            string_values = _len_fields(value_message_fields, 20)
            if not string_values:
                continue

            raw_string_value = string_values[0].value
            if not isinstance(raw_string_value, bytes):
                continue
            string_value = _decode_string(raw_string_value)
            if not string_value:
                continue

            has_command = bool(_COMMAND_PATTERN.search(string_value))
            has_network = bool(_NETWORK_PATTERN.search(string_value))
            if not (has_command or has_network):
                continue

            severity = IssueSeverity.CRITICAL if has_command else IssueSeverity.WARNING
            result.add_check(
                name="CoreML Custom Parameter Pattern Check",
                passed=False,
                message=f"Suspicious content in custom CoreML parameter '{param_key}'",
                severity=severity,
                location=path,
                details={
                    "field_path": f"{field_path}[{entry_index}]",
                    "parameter_key": param_key,
                    "has_command_pattern": has_command,
                    "has_network_pattern": has_network,
                },
                why="Custom layer/model parameters should not include command execution or remote fetch directives.",
            )
            findings += 1

        return findings

    def _analyze_linked_model_paths(self, top_fields: list[_ProtoField], path: str, result: ScanResult) -> int:
        findings = 0
        linked_model_fields = _len_fields(top_fields, self.LINKED_MODEL_FIELD)
        if not linked_model_fields:
            return findings

        base_dir = Path(path).resolve().parent
        for linked_model_field in linked_model_fields:
            payload = linked_model_field.value
            if not isinstance(payload, bytes):
                continue

            linked_model_message, parse_error = _parse_message(payload, max_fields=64, allow_truncated=True)
            if parse_error:
                continue

            linked_model_file_fields = _len_fields(linked_model_message, 1)
            for linked_model_file_field in linked_model_file_fields:
                file_payload = linked_model_file_field.value
                if not isinstance(file_payload, bytes):
                    continue

                linked_model_file, file_error = _parse_message(file_payload, max_fields=64, allow_truncated=True)
                if file_error:
                    continue

                file_name = self._extract_string_parameter(linked_model_file, field_number=1)
                search_path = self._extract_string_parameter(linked_model_file, field_number=2)

                if file_name:
                    findings += self._evaluate_linked_path(
                        raw_value=file_name,
                        field_path="model[556].linkedModelFile.linkedModelFileName.defaultValue",
                        base_dir=base_dir,
                        path=path,
                        result=result,
                    )

                if search_path:
                    segments = [segment.strip() for segment in search_path.split(":") if segment.strip()]
                    for index, segment in enumerate(segments):
                        findings += self._evaluate_linked_path(
                            raw_value=segment,
                            field_path=f"model[556].linkedModelFile.linkedModelSearchPath.defaultValue[{index}]",
                            base_dir=base_dir,
                            path=path,
                            result=result,
                        )

        return findings

    def _extract_string_parameter(self, message_fields: list[_ProtoField], field_number: int) -> str | None:
        parameter_fields = _len_fields(message_fields, field_number)
        if not parameter_fields:
            return None

        payload = parameter_fields[0].value
        if not isinstance(payload, bytes):
            return None

        parsed_parameter, parse_error = _parse_message(payload, max_fields=16, allow_truncated=True)
        if parse_error:
            return None

        default_value_fields = _len_fields(parsed_parameter, 1)
        if not default_value_fields or not isinstance(default_value_fields[0].value, bytes):
            return None

        value = _decode_string(default_value_fields[0].value, max_length=512)
        return value if value else None

    def _evaluate_linked_path(
        self,
        *,
        raw_value: str,
        field_path: str,
        base_dir: Path,
        path: str,
        result: ScanResult,
    ) -> int:
        normalized_value = raw_value.strip()
        if not normalized_value:
            return 0

        if any(normalized_value.startswith(prefix) for prefix in self.SAFE_LINKED_PATH_PREFIXES):
            return 0

        severity = IssueSeverity.WARNING
        reason: str | None = None

        if normalized_value.startswith("~"):
            reason = "home-path expansion in linked model reference"
        elif os.path.isabs(normalized_value):
            reason = "absolute linked model path"
        else:
            posix_parts = PurePosixPath(normalized_value).parts
            if ".." in posix_parts:
                severity = IssueSeverity.CRITICAL
                reason = "path traversal segments in linked model path"
            else:
                resolved_path = (base_dir / normalized_value).resolve()
                if not _is_within_directory(resolved_path, base_dir):
                    severity = IssueSeverity.CRITICAL
                    reason = "linked model path resolves outside model directory"

        if reason is None:
            return 0

        result.add_check(
            name="CoreML Linked Model Path Check",
            passed=False,
            message=f"Unsafe CoreML linked-model path reference: {normalized_value}",
            severity=severity,
            location=path,
            details={
                "field_path": field_path,
                "raw_path": normalized_value,
                "reason": reason,
            },
            why=(
                "Linked model references should stay within trusted model directories and avoid "
                "traversal/absolute paths."
            ),
        )
        return 1
