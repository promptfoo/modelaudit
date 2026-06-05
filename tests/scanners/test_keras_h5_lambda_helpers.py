import base64

import pytest

from modelaudit.scanner_results import CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.keras_h5_scanner import KerasH5Scanner


def _scan_lambda_config(config: dict[str, object]) -> ScanResult:
    scanner = KerasH5Scanner()
    scanner.current_file_path = "model.h5"
    result = ScanResult(scanner_name=scanner.name, scanner=scanner)
    scanner._check_lambda_layer(config, result)
    return result


@pytest.mark.parametrize(
    "layer_class",
    [
        "keras.layers.experimental.core.Lambda",
        "tensorflow.keras.layers.core.Lambda",
        "tensorflow.python.keras.layers.legacy.Lambda",
        "tf.keras.layers.core.Lambda",
        "tf_keras.layers.core.Lambda",
    ],
)
def test_trusted_keras_submodule_lambda_classes_are_scanned(layer_class: str) -> None:
    assert KerasH5Scanner._is_lambda_layer_class(layer_class) is True


@pytest.mark.parametrize(
    "layer_class",
    [
        "custom.tensorflow.keras.layers.Lambda",
        "keras.attacker.Lambda",
        "keras.layers.attacker.Lambda",
        "keras.src.layers.core.lambda_layer.attacker.Lambda",
        "keras_custom.layers.Lambda",
        "tensorflow.keras.layers_evil.Lambda",
        "tensorflow.python.keras.layers.core.attacker.Lambda",
        "tensorflow.keras_custom.layers.Lambda",
        "tf_keras_custom.layers.Lambda",
    ],
)
def test_custom_namespace_lambda_lookalikes_are_not_trusted(layer_class: str) -> None:
    assert KerasH5Scanner._is_lambda_layer_class(layer_class) is False


def test_dict_format_mask_without_type_marker_is_scanned() -> None:
    encoded_code = base64.b64encode(b"import os\nos.system('id')").decode()

    result = _scan_lambda_config(
        {
            "name": "dict_mask",
            "function": "relu",
            "function_type": "function",
            "module": "keras.activations",
            "mask": {"class_name": "__lambda__", "config": {"code": encoded_code}},
        }
    )

    assert any(
        check.name == "Lambda Layer Code Analysis"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("layer_name") == "dict_mask.mask"
        for check in result.checks
    )


def test_nested_callable_dict_dangerous_reference_is_critical() -> None:
    result = _scan_lambda_config({"function": {"module": "os", "config": "system"}})

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.FAILED
        and check.severity == IssueSeverity.CRITICAL
        and check.details.get("reference_source") == "function_dict"
        for check in result.checks
    )


def test_nested_callable_dict_allowlisted_reference_passes() -> None:
    result = _scan_lambda_config({"function": {"module": "keras.ops", "config": "identity"}})

    assert any(
        check.name == "Lambda Layer Module Reference Check"
        and check.status == CheckStatus.PASSED
        and check.details.get("allowlist_status") == "allowlisted"
        and check.details.get("reference_source") == "function_dict"
        for check in result.checks
    )


def test_nested_callable_dict_substring_near_match_stays_warning_level() -> None:
    result = _scan_lambda_config({"function": {"module": "custom.osmium.transforms", "config": "systematic_normalize"}})

    matching_checks = [check for check in result.checks if check.name == "Lambda Layer Module Reference Check"]
    assert len(matching_checks) == 1
    assert matching_checks[0].status == CheckStatus.FAILED
    assert matching_checks[0].severity == IssueSeverity.WARNING
    assert matching_checks[0].details.get("allowlist_status") == "not_allowlisted"
