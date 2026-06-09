import pickle
import struct
from pathlib import Path

import pytest

from modelaudit.models import ScanResult
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME
from modelaudit.scanners import pickle_scanner
from modelaudit.scanners.pickle_scanner import PickleScanner


class _RebuildTensorProbe:
    def __init__(self) -> None:
        self.values: dict[object, object] = {}

    def __setitem__(self, key: object, value: object) -> None:
        self.values[key] = value


def _rebuild_tensor_probe() -> _RebuildTensorProbe:
    return _RebuildTensorProbe()


def _binunicode8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x8d" + len(encoded).to_bytes(8, "little") + encoded


def _binbytes(value: bytes) -> bytes:
    return b"B" + len(value).to_bytes(4, "little") + value


def _rebuild_tensor_probe_target() -> bytes:
    return _binunicode8(__name__) + _binunicode8("_rebuild_tensor_probe") + b"\x93)R"


def _system_probe_target() -> bytes:
    return _binunicode8("os") + _binunicode8("system") + b"\x93)R"


def _cve_2026_24747_issues(result: ScanResult) -> list[str]:
    return [
        issue.message
        for issue in result.issues
        if "CVE-2026-24747" in issue.message or "CVE-2026-24747" in str(issue.details)
    ]


@pytest.mark.parametrize(("mark", "setitem_opcode"), [(b"", b"s"), (b"(", b"u")])
def test_detects_setitem_after_rebuild_tensor_binunicode8(
    tmp_path: Path,
    mark: bytes,
    setitem_opcode: bytes,
) -> None:
    pickle_bytes = (
        b"\x80\x04"
        + _rebuild_tensor_probe_target()
        + mark
        + _binunicode8("key")
        + _binunicode8("value")
        + setitem_opcode
        + b"."
    )
    test_file = tmp_path / "setitem_rebuild_tensor_binunicode8.pkl"
    test_file.write_bytes(pickle_bytes)

    loaded = pickle.loads(pickle_bytes)
    result = PickleScanner().scan(str(test_file))

    assert isinstance(loaded, _RebuildTensorProbe)
    assert loaded.values == {"key": "value"}
    assert _cve_2026_24747_issues(result), (
        "Expected CVE-2026-24747 detection for BINUNICODE8 rebuild tensor literal. "
        f"Issues: {[issue.message for issue in result.issues]}"
    )


def test_detects_setitem_after_build_on_rebuild_tensor_target(tmp_path: Path) -> None:
    pickle_bytes = (
        b"\x80\x04" + _rebuild_tensor_probe_target() + b"}b" + _binunicode8("key") + _binunicode8("value") + b"s."
    )
    test_file = tmp_path / "setitem_rebuild_tensor_after_build.pkl"
    test_file.write_bytes(pickle_bytes)

    loaded = pickle.loads(pickle_bytes)
    result = PickleScanner().scan(str(test_file))

    assert isinstance(loaded, _RebuildTensorProbe)
    assert loaded.values == {"key": "value"}
    assert _cve_2026_24747_issues(result)


@pytest.mark.parametrize("key_opcode", [b"F1.25\n", b"G" + struct.pack(">d", 1.25)])
def test_detects_setitem_with_scalar_key_on_rebuild_tensor_target(tmp_path: Path, key_opcode: bytes) -> None:
    pickle_bytes = b"\x80\x04" + _rebuild_tensor_probe_target() + key_opcode + _binunicode8("value") + b"s."
    test_file = tmp_path / "setitem_rebuild_tensor_scalar_key.pkl"
    test_file.write_bytes(pickle_bytes)

    loaded = pickle.loads(pickle_bytes)
    result = PickleScanner().scan(str(test_file))

    assert isinstance(loaded, _RebuildTensorProbe)
    assert loaded.values == {1.25: "value"}
    assert _cve_2026_24747_issues(result)


@pytest.mark.parametrize(
    "target_opcode",
    [
        b"(" + _binunicode8(__name__) + _binunicode8("_rebuild_tensor_probe") + b"\x93o",
        b"(i" + __name__.encode() + b"\n_rebuild_tensor_probe\n",
    ],
)
def test_helper_tracks_legacy_rebuild_tensor_object_targets(target_opcode: bytes) -> None:
    pickle_bytes = b"\x80\x02" + target_opcode + _binunicode8("key") + _binunicode8("value") + b"s."

    assert pickle_scanner._pickle_has_rebuild_tensor_setitem_abuse(pickle_bytes)


@pytest.mark.parametrize("key_opcode", [b"Popaque\n", b"\x82\x01", b"\x97"])
def test_helper_preserves_rebuild_target_for_opaque_keys(key_opcode: bytes) -> None:
    pickle_bytes = b"\x80\x05" + _rebuild_tensor_probe_target() + key_opcode + _binunicode8("value") + b"s."

    assert pickle_scanner._pickle_has_rebuild_tensor_setitem_abuse(pickle_bytes)


def test_helper_preserves_rebuild_target_across_pop_mark() -> None:
    pickle_bytes = (
        b"\x80\x04" + _rebuild_tensor_probe_target() + b"(N1" + _binunicode8("key") + _binunicode8("value") + b"s."
    )

    assert pickle_scanner._pickle_has_rebuild_tensor_setitem_abuse(pickle_bytes)


def test_detects_setitem_near_binunicode8_dangerous_global(tmp_path: Path) -> None:
    pickle_bytes = (
        b"\x80\x04"
        + _binunicode8("os")
        + _binunicode8("system")
        + b"\x93"
        + b")R"
        + (b"N0" * 40)
        + _binunicode8("key")
        + _binunicode8("value")
        + b"s."
    )
    test_file = tmp_path / "setitem_binunicode8_dangerous_global.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    matching_checks = [
        check
        for check in result.checks
        if check.name == "CVE-2026-24747 SETITEM Abuse Detection"
        and (check.details or {}).get("pattern_type") == "setitem_near_dangerous_global"
    ]
    assert matching_checks, (
        "Expected live setitem_near_dangerous_global detection for BINUNICODE8 STACK_GLOBAL. "
        f"Checks: {[(check.name, check.message, check.details) for check in result.checks]}"
    )
    assert any("os.system" in check.message for check in matching_checks)


def test_escaped_stack_global_operands_do_not_depend_on_raw_seed_or_result_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(pickle_scanner, "_result_opcode_counts", lambda _result: {})
    monkeypatch.setattr(pickle_scanner, "_result_import_references", lambda _result: [])
    pickle_bytes = b"S'\\x6f\\x73'\nS'\\x73ystem'\n\x93)RS'key'\nS'value'\ns."
    path = tmp_path / "escaped-stack-global.pkl"
    path.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 SETITEM Abuse Detection" and check.details.get("associated_global") == "os.system"
        for check in result.checks
    )


def test_no_binunicode8_setitem_false_positive(tmp_path: Path) -> None:
    pickle_bytes = b"\x80\x04}" + _binunicode8("key") + _binunicode8("value") + b"s."
    test_file = tmp_path / "normal_dict_binunicode8_setitem.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    assert _cve_2026_24747_issues(result) == []


@pytest.mark.parametrize(("module", "global_name"), [("builtins", "dict"), ("collections", "OrderedDict")])
@pytest.mark.parametrize(("mark", "setitem_opcode"), [(b"", b"s"), (b"(", b"u")])
def test_no_binunicode8_interesting_mapping_key_false_positive(
    tmp_path: Path,
    mark: bytes,
    setitem_opcode: bytes,
    module: str,
    global_name: str,
) -> None:
    pickle_bytes = (
        b"\x80\x04"
        + _binunicode8(module)
        + _binunicode8(global_name)
        + b"\x93)R"
        + mark
        + _binunicode8("_rebuild_tensor")
        + _binunicode8("ordinary value")
        + setitem_opcode
        + b"."
    )
    test_file = tmp_path / "mapping_interesting_key_binunicode8.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    assert _cve_2026_24747_issues(result) == []


@pytest.mark.parametrize(("mark", "setitem_opcode"), [(b"", b"s"), (b"(", b"u")])
def test_no_binunicode8_interesting_dict_key_false_positive(
    tmp_path: Path,
    mark: bytes,
    setitem_opcode: bytes,
) -> None:
    pickle_bytes = (
        b"\x80\x04}" + mark + _binunicode8("_rebuild_tensor") + _binunicode8("ordinary value") + setitem_opcode + b"."
    )
    test_file = tmp_path / "normal_dict_interesting_key_binunicode8.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    assert _cve_2026_24747_issues(result) == []


@pytest.mark.parametrize(("mark", "setitem_opcode"), [(b"", b"s"), (b"(", b"u")])
@pytest.mark.parametrize(
    ("module", "global_name"),
    [("torch._utils", "_rebuild_tensor_v2"), ("os", "system")],
)
def test_no_binunicode8_interesting_dict_value_false_positive(
    tmp_path: Path,
    mark: bytes,
    setitem_opcode: bytes,
    module: str,
    global_name: str,
) -> None:
    pickle_bytes = (
        b"\x80\x04}"
        + mark
        + _binunicode8("ordinary key")
        + _binunicode8(module)
        + _binunicode8(global_name)
        + b"\x93"
        + setitem_opcode
        + b"."
    )
    test_file = tmp_path / "normal_dict_interesting_value_binunicode8.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    assert _cve_2026_24747_issues(result) == []


def test_no_binunicode8_interesting_list_value_false_positive(tmp_path: Path) -> None:
    pickle_bytes = b"\x80\x04]NaK\x00" + _binunicode8("_rebuild_tensor") + b"s."
    test_file = tmp_path / "list_interesting_value_binunicode8.pkl"
    test_file.write_bytes(pickle_bytes)

    result = PickleScanner().scan(str(test_file))

    assert _cve_2026_24747_issues(result) == []


def test_byte_literals_do_not_form_stack_global_names() -> None:
    pickle_bytes = b"\x80\x04" + _binbytes(b"os") + _binbytes(b"system") + b"\x93."

    summary = pickle_scanner._pickle_opcode_summary(pickle_bytes)

    assert summary["dangerous_globals"] == []
    assert not pickle_scanner._pickle_has_setitem_abuse_for_entries(
        pickle_bytes,
        global_needles=("os.system",),
    )


@pytest.mark.parametrize(
    "padding",
    [b"", b"\x00", b"\t", b"\n", b"\x0b", b"\x0c", b"\r", b" ", b"\x00\n"],
)
def test_detects_rebuild_tensor_setitem_in_later_pickle_stream(tmp_path: Path, padding: bytes) -> None:
    first_stream = pickle.dumps({"safe": True}, protocol=4)
    malicious_stream = (
        b"\x80\x04" + _rebuild_tensor_probe_target() + _binunicode8("key") + _binunicode8("value") + b"s."
    )
    path = tmp_path / "later-rebuild-tensor-stream.pkl"
    path.write_bytes(first_stream + padding + malicious_stream)

    result = PickleScanner().scan(str(path))

    matching_checks = [check for check in result.checks if check.name == "CVE-2026-24747 Pattern Detection"]
    assert matching_checks
    assert any(
        check.rule_code == "S209"
        and check.details.get("pickle_stream_index") == 1
        and check.details.get("pickle_stream_offset", 0) > 0
        and check.details.get("pickle_stream_parse_incomplete") is False
        for check in matching_checks
    )


def test_detects_protocol_zero_rebuild_tensor_setitem_in_later_pickle_stream(tmp_path: Path) -> None:
    first_stream = pickle.dumps(None, protocol=4)
    malicious_stream = b"N0ctorch._utils\n_rebuild_tensor_v2\n)R" + _binunicode8("key") + _binunicode8("value") + b"s."
    path = tmp_path / "later-protocol-zero-rebuild-tensor-stream.pkl"
    path.write_bytes(first_stream + malicious_stream)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 Pattern Detection"
        and check.rule_code == "S209"
        and check.details.get("pickle_stream_index") == 1
        for check in result.checks
    )


@pytest.mark.parametrize("padding", [b"", b"\x00", b"\n"])
def test_detects_system_setitem_in_later_pickle_stream(tmp_path: Path, padding: bytes) -> None:
    first_stream = pickle.dumps({"safe": True}, protocol=4)
    malicious_stream = b"\x80\x04" + _system_probe_target() + _binunicode8("key") + _binunicode8("value") + b"s."
    path = tmp_path / "later-system-stream.pkl"
    path.write_bytes(first_stream + padding + malicious_stream)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 SETITEM Abuse Detection"
        and check.rule_code == "S209"
        and check.details.get("associated_global") == "os.system"
        and check.details.get("pickle_stream_index") == 1
        and check.details.get("pickle_stream_parse_incomplete") is False
        for check in result.checks
    )
    assert result.metadata.get("pickle_cve_raw_detector_skipped") is not True


def test_later_pickle_stream_does_not_depend_on_python_opcode_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_opcode_summary(_payload: bytes) -> dict[str, object]:
        raise AssertionError("stream-scoped SETITEM analysis should not use the Python opcode summary")

    monkeypatch.setattr(pickle_scanner, "_pickle_opcode_summary", fail_opcode_summary)
    first_stream = pickle.dumps({"safe": True}, protocol=4)
    malicious_stream = b"\x80\x04" + _system_probe_target() + _binunicode8("key") + _binunicode8("value") + b"s."
    path = tmp_path / "later-rust-metadata-stream.pkl"
    path.write_bytes(first_stream + b"\x00\n" + malicious_stream)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 SETITEM Abuse Detection" and check.details.get("pickle_stream_index") == 1
        for check in result.checks
    )


def test_raw_text_after_complete_pickle_cannot_borrow_setitem_metadata(tmp_path: Path) -> None:
    path = tmp_path / "raw-tail-state-bleed.pkl"
    path.write_bytes(
        pickle.dumps({"safe": "value"}, protocol=4)
        + b"_rebuild_tensor SETITEM storage_offset nbytes ordinary trailing text"
    )

    result = PickleScanner().scan(str(path))

    assert _cve_2026_24747_issues(result) == []
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME


def test_complete_stream_preserves_tensor_metadata_mismatch_attribution(tmp_path: Path) -> None:
    path = tmp_path / "tensor-metadata-mismatch.pkl"
    path.write_bytes(b"ctorch._utils\n_rebuild_tensor_v2\n(Vstorage_size\nVnbytes\ntR.")

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 Pattern Detection"
        and "PyTorch tensor metadata mismatch indicators" in check.details.get("patterns_matched", [])
        and check.details.get("pickle_stream_index") == 0
        and check.details.get("pickle_stream_parse_incomplete") is False
        for check in result.checks
    )


def test_incomplete_ordinary_dict_with_rebuild_key_remains_clean(tmp_path: Path) -> None:
    path = tmp_path / "incomplete-ordinary-dict.pkl"
    path.write_bytes(b"\x80\x04}" + _binunicode8("_rebuild_tensor") + _binunicode8("value") + b"s")

    result = PickleScanner().scan(str(path))

    assert _cve_2026_24747_issues(result) == []


def test_incomplete_unknown_setitem_target_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "incomplete-unknown-target.pkl"
    path.write_bytes(b"\x80\x04" + _binunicode8("_rebuild_tensor") + _binunicode8("value") + b"s")

    result = PickleScanner().scan(str(path))

    assert _cve_2026_24747_issues(result)
    assert any(
        check.name == "CVE-2026-24747 Pattern Detection"
        and check.rule_code == "S209"
        and check.details.get("pickle_stream_index") == 0
        and check.details.get("pickle_stream_parse_incomplete") is True
        for check in result.checks
    )
    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME


@pytest.mark.parametrize("prefix", [b"]0", b"\x880", b"\x890", b"h\x000"])
def test_incomplete_later_stream_with_discarded_root_fails_closed(tmp_path: Path, prefix: bytes) -> None:
    first_stream = pickle.dumps(None, protocol=4)
    incomplete_stream = prefix + _system_probe_target() + _binunicode8("key") + _binunicode8("value") + b"s"
    path = tmp_path / "incomplete-prefixed-later-stream.pkl"
    path.write_bytes(first_stream + incomplete_stream)

    result = PickleScanner().scan(str(path))

    assert any(
        check.name == "CVE-2026-24747 SETITEM Abuse Detection"
        and check.rule_code == "S209"
        and check.details.get("pickle_stream_index") == 1
        and check.details.get("pickle_stream_parse_incomplete") is True
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("module", "global_name"),
    [("notos", "systematic"), (__name__, "not_rebuild_tensor_probe")],
)
def test_global_name_substrings_do_not_trigger_setitem_cve(
    tmp_path: Path,
    module: str,
    global_name: str,
) -> None:
    target = _binunicode8(module) + _binunicode8(global_name) + b"\x93)R"
    path = tmp_path / "near-match-global.pkl"
    path.write_bytes(b"\x80\x04" + target + _binunicode8("key") + _binunicode8("value") + b"s.")

    result = PickleScanner().scan(str(path))

    assert _cve_2026_24747_issues(result) == []


def test_benign_later_stream_dictionary_remains_clean(tmp_path: Path) -> None:
    first_stream = pickle.dumps({"safe": True}, protocol=4)
    later_stream = b"\x80\x04}" + _binunicode8("_rebuild_tensor") + _binunicode8("ordinary value") + b"s."
    path = tmp_path / "benign-later-dict.pkl"
    path.write_bytes(first_stream + b"\x00\n" + later_stream)

    result = PickleScanner().scan(str(path))

    assert _cve_2026_24747_issues(result) == []
    assert result.metadata["pickle_cve_streams_analyzed"] == 2


def test_seedless_pickle_skips_python_setitem_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_setitem_analysis(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("seedless pickle should not run Python SETITEM analysis")

    monkeypatch.setattr(pickle_scanner, "_analyze_pickle_setitem_entries", fail_setitem_analysis)
    path = tmp_path / "seedless.pkl"
    path.write_bytes(pickle.dumps([None] * 2048, protocol=4))

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_cve_raw_detector_skipped"] is True


def test_pickle_cve_stream_limit_allows_exact_limit(tmp_path: Path) -> None:
    safe_stream = pickle.dumps(None, protocol=4)
    path = tmp_path / "maximum-pickle-streams.pkl"
    path.write_bytes(safe_stream * 64)

    result = PickleScanner().scan(str(path))

    assert result.success is True
    assert result.metadata["pickle_cve_streams_analyzed"] == 64
    assert not any(check.name == "Pickle CVE Stream Coverage" for check in result.checks)


def test_pickle_cve_stream_limit_fails_closed(tmp_path: Path) -> None:
    safe_stream = pickle.dumps(None, protocol=4)
    path = tmp_path / "too-many-pickle-streams.pkl"
    path.write_bytes(safe_stream * 65)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_cve_stream_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["pickle_cve_streams_analyzed"] == 64
    assert any(
        check.name == "Pickle CVE Stream Coverage"
        and check.rule_code == "S902"
        and check.details.get("max_streams") == 64
        and check.details.get("analysis_incomplete") is True
        for check in result.checks
    )


@pytest.mark.parametrize("prefix", [b"", b"h\x000"])
def test_pickle_cve_stream_limit_rejects_incomplete_extra_stream(tmp_path: Path, prefix: bytes) -> None:
    safe_stream = pickle.dumps(None, protocol=4)
    incomplete_stream = (
        prefix + b"N0ctorch._utils\n_rebuild_tensor_v2\n)R" + _binunicode8("key") + _binunicode8("value") + b"s"
    )
    path = tmp_path / "incomplete-extra-pickle-stream.pkl"
    path.write_bytes((safe_stream * 64) + incomplete_stream)

    result = PickleScanner().scan(str(path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert "pickle_cve_stream_limit_exceeded" in result.metadata["scan_outcome_reasons"]
    assert result.metadata["pickle_cve_streams_analyzed"] == 64
    assert any(
        check.name == "Pickle CVE Stream Coverage"
        and check.rule_code == "S902"
        and check.details.get("max_streams") == 64
        and check.details.get("analysis_incomplete") is True
        for check in result.checks
    )
