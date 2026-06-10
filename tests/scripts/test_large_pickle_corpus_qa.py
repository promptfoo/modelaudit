from __future__ import annotations

import json
import zipfile
from argparse import Namespace
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from scripts import large_pickle_corpus_qa


def test_builtin_corpus_manifest_has_expected_size_and_unique_ids() -> None:
    entries = large_pickle_corpus_qa.CORPUS_ENTRIES

    assert len(entries) == 25
    assert len({entry.id for entry in entries}) == 25
    assert sum(1 for entry in entries if entry.id.startswith("P")) == 7
    assert sum(1 for entry in entries if entry.id.startswith("B")) == 18
    assert len(large_pickle_corpus_qa.REPLACEMENT_ENTRIES) == 5


def test_select_entries_respects_smoke_tier() -> None:
    entries = large_pickle_corpus_qa._select_entries(ids=None, tier="smoke")

    assert [entry.id for entry in entries] == ["B01", "B05", "P01"]


def test_select_entries_can_include_replacement_queue() -> None:
    entries = large_pickle_corpus_qa._select_entries(ids=None, tier="full", include_replacements=True)

    assert len(entries) == 30
    assert entries[-5].id == "R01"


def test_generate_synthetic_variants_writes_manifest(tmp_path: Path) -> None:
    records = large_pickle_corpus_qa._write_synthetic_variants(tmp_path)

    assert len(records) == 15
    assert (tmp_path / "synthetic-manifest.json").exists()
    assert (tmp_path / "V12_pytorch_zip_data_pkl.pt").exists()
    assert (tmp_path / "V13_malformed_7z_like.pt").exists()
    assert all(Path(str(record["path"])).exists() for record in records)
    assert all(record["sha256"] for record in records)


def test_package_scannable_path_includes_pytorch_zip_suffixes(tmp_path: Path) -> None:
    assert large_pickle_corpus_qa._is_package_scannable_path(
        tmp_path / "model.pt",
        {"kind": "zip"},
    )
    assert not large_pickle_corpus_qa._is_package_scannable_path(
        tmp_path / "archive.zip",
        {"kind": "zip"},
    )


def test_iter_pickle_zip_members_extracts_data_pickle_and_skips_near_matches(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.zip"
    malicious_payload = large_pickle_corpus_qa.raw_os_system_reduce_payload()
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data.pkl", malicious_payload)
        archive.writestr("data.pkl.txt", b"benign near match")
        archive.writestr("notes.txt", b"not a pickle")

    members = list(
        large_pickle_corpus_qa._iter_pickle_zip_members(
            archive_path,
            run_dir=tmp_path,
            artifact_id="A01",
        )
    )

    assert [member_name for member_name, _member_path in members] == ["data.pkl"]
    member_path = members[0][1]
    assert member_path.read_bytes() == malicious_payload

    scan_row = large_pickle_corpus_qa._scan_package(member_path, engine="rust", artifact_id="A01:data.pkl")
    assert scan_row["result"]["critical_count"] >= 1


def test_pickle_zip_member_paths_are_unique_portable_and_contained(tmp_path: Path) -> None:
    archive_path = tmp_path / "model.zip"
    malicious_payload = large_pickle_corpus_qa.raw_os_system_reduce_payload()
    benign_payload = b"\x80\x04N."
    member_names = ["../../data.pkl", "..__..__data.pkl", "evil?.pkl", "duplicate.pkl", "duplicate.pkl"]
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member_names[0], malicious_payload)
        archive.writestr(member_names[1], benign_payload)
        archive.writestr(member_names[2], benign_payload)
        archive.writestr(member_names[3], malicious_payload)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr(member_names[4], benign_payload)

    members = list(
        large_pickle_corpus_qa._iter_pickle_zip_members(
            archive_path,
            run_dir=tmp_path,
            artifact_id="A01",
        )
    )

    assert [member_name for member_name, _member_path in members] == member_names
    member_paths = [member_path for _member_name, member_path in members]
    member_root = (tmp_path / "members" / "A01").resolve()
    assert len(set(member_paths)) == len(member_names)
    assert all(member_path.parent == member_root for member_path in member_paths)
    assert all(member_path.name.endswith(".pkl") for member_path in member_paths)
    assert member_paths[0].read_bytes() == malicious_payload
    assert member_paths[1].read_bytes() == benign_payload
    assert member_paths[3].read_bytes() == malicious_payload
    assert member_paths[4].read_bytes() == benign_payload

    for member_index in (0, 3):
        malicious_scan = large_pickle_corpus_qa._scan_package(
            member_paths[member_index],
            engine="rust",
            artifact_id=f"A01:{member_names[member_index]}",
        )
        assert malicious_scan["result"]["critical_count"] >= 1
    for member_index in (1, 4):
        benign_scan = large_pickle_corpus_qa._scan_package(
            member_paths[member_index],
            engine="rust",
            artifact_id=f"A01:{member_names[member_index]}",
        )
        assert benign_scan["result"]["critical_count"] == 0


@pytest.mark.parametrize(
    ("artifact_id", "artifact_path"),
    [
        ("../escaped", "model.pkl"),
        ("C:escaped", "model.pkl"),
        ("A01", "../../escaped.pkl"),
        ("A01", "/tmp/escaped.pkl"),
        ("A01", "C:/escaped.pkl"),
        ("A01", "C:escaped.pkl"),
        ("A01", "."),
        ("A01", "nested/./model.pkl"),
        ("A01", "nested//model.pkl"),
        ("A01", r"..\..\escaped.pkl"),
        ("A01", r"\\server\share\escaped.pkl"),
    ],
)
def test_download_entry_rejects_unsafe_lock_paths_before_writing(
    tmp_path: Path,
    artifact_id: str,
    artifact_path: str,
) -> None:
    corpus_root = tmp_path / "corpus"
    entry = {
        "id": artifact_id,
        "repo_id": "trusted/model",
        "path": artifact_path,
        "revision": "main",
    }

    with pytest.raises(ValueError, match="unsafe corpus artifact"):
        large_pickle_corpus_qa._download_entry(
            entry,
            corpus_root=corpus_root,
            etag_timeout_s=1,
            direct_fallback=False,
            direct_only=True,
        )

    assert not corpus_root.exists()


def test_download_validates_unsafe_entry_before_budget_skip(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    lock_path = tmp_path / "lock.json"
    large_pickle_corpus_qa._write_lock(
        lock_path,
        [
            {
                "id": "../escaped",
                "repo_id": "trusted/model",
                "path": "model.pkl",
                "revision": "main",
                "remote_size_bytes": 1,
            }
        ],
        tier="custom",
    )

    exit_code = large_pickle_corpus_qa.main(
        [
            "download",
            "--lock",
            str(lock_path),
            "--corpus-root",
            str(corpus_root),
            "--budget-gb",
            "0",
            "--direct-only",
        ]
    )

    entry = json.loads(lock_path.read_text(encoding="utf-8"))["entries"][0]
    assert exit_code == 1
    assert entry["download_status"] == "error"
    assert entry["download_error"] == "ValueError: unsafe corpus artifact id: '../escaped'"
    assert not corpus_root.exists()


def test_download_keeps_safe_selected_over_budget_entry_skipped(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    lock_path = tmp_path / "lock.json"
    large_pickle_corpus_qa._write_lock(
        lock_path,
        [
            {
                "id": "A01",
                "repo_id": "trusted/model",
                "path": "checkpoint-2148/pytorch_model.bin",
                "revision": "main",
                "remote_size_bytes": 1,
                "download_status": "error",
                "download_error": "stale selected error",
            },
            {
                "id": "A02",
                "repo_id": "trusted/other-model",
                "path": "model.pkl",
                "revision": "main",
                "remote_size_bytes": 1,
                "download_status": "error",
                "download_error": "unselected prior error",
            },
        ],
        tier="custom",
    )

    exit_code = large_pickle_corpus_qa.main(
        [
            "download",
            "--lock",
            str(lock_path),
            "--corpus-root",
            str(corpus_root),
            "--budget-gb",
            "0",
            "--direct-only",
            "--ids",
            "A01",
        ]
    )

    selected, unselected = json.loads(lock_path.read_text(encoding="utf-8"))["entries"]
    assert exit_code == 0
    assert selected["download_status"] == "skipped_budget"
    assert "download_error" not in selected
    assert unselected["download_status"] == "error"
    assert unselected["download_error"] == "unselected prior error"
    assert not corpus_root.exists()


def test_download_entry_keeps_safe_nested_path_inside_artifact_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus_root = tmp_path / "corpus"
    entry = {
        "id": "A01",
        "repo_id": "trusted/model",
        "path": "checkpoint-2148/pytorch_model.bin",
        "revision": "main",
    }

    def fake_direct_download(_entry: Mapping[str, Any], local_path: Path) -> Path:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(b"benign model")
        return local_path

    monkeypatch.setattr(large_pickle_corpus_qa, "_direct_download_entry", fake_direct_download)

    result = large_pickle_corpus_qa._download_entry(
        entry,
        corpus_root=corpus_root,
        etag_timeout_s=1,
        direct_fallback=False,
        direct_only=True,
    )

    artifact_root = (corpus_root / "raw" / "A01").resolve()
    expected_path = artifact_root / "checkpoint-2148" / "pytorch_model.bin"
    assert Path(result["local_path"]) == expected_path
    assert expected_path.is_relative_to(artifact_root)
    assert expected_path.read_bytes() == b"benign model"


def test_download_entry_rejects_symlink_escape(
    tmp_path: Path,
    requires_symlinks: None,
) -> None:
    corpus_root = tmp_path / "corpus"
    artifact_root = corpus_root / "raw" / "A01"
    artifact_root.mkdir(parents=True)
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    (artifact_root / "checkpoint-2148").symlink_to(outside_root, target_is_directory=True)
    entry = {
        "id": "A01",
        "repo_id": "trusted/model",
        "path": "checkpoint-2148/pytorch_model.bin",
        "revision": "main",
    }

    with pytest.raises(ValueError, match="escapes output root"):
        large_pickle_corpus_qa._download_entry(
            entry,
            corpus_root=corpus_root,
            etag_timeout_s=1,
            direct_fallback=False,
            direct_only=True,
        )

    assert not (outside_root / "pytorch_model.bin").exists()


def test_direct_download_rejects_symlinked_partial_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requires_symlinks: None,
) -> None:
    output_dir = tmp_path / "corpus" / "raw" / "A01"
    output_dir.mkdir(parents=True)
    local_path = output_dir / "model.pkl"
    outside_path = tmp_path / "outside.pkl"
    outside_path.write_bytes(b"unchanged")
    local_path.with_name("model.pkl.part").symlink_to(outside_path)

    def fail_urlopen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("download must not start for an escaping partial path")

    monkeypatch.setattr(large_pickle_corpus_qa, "urlopen", fail_urlopen)

    with pytest.raises(ValueError, match="escapes output root"):
        large_pickle_corpus_qa._direct_download_entry(
            {"repo_id": "trusted/model", "path": "model.pkl", "revision": "main"},
            local_path,
        )

    assert outside_path.read_bytes() == b"unchanged"


def test_pickle_member_path_rejects_artifact_id_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe corpus artifact id"):
        large_pickle_corpus_qa._member_file_path(tmp_path / "run", "../escaped", "data.pkl", member_index=0)

    assert not (tmp_path / "escaped").exists()


def test_third_party_output_rejects_artifact_id_escape(tmp_path: Path) -> None:
    spec = next(iter(large_pickle_corpus_qa.TOOL_SPECS.values()))

    with pytest.raises(ValueError, match="unsafe corpus artifact id"):
        large_pickle_corpus_qa._scan_third_party(
            tmp_path / "artifact.pkl",
            artifact_id="../escaped",
            spec=spec,
            tools_root=tmp_path / "tools",
            run_dir=tmp_path / "run",
            timeout_s=1,
        )

    assert not (tmp_path / "third-party-raw").exists()


def test_preflight_offline_writes_lockfile(tmp_path: Path) -> None:
    lock_path = tmp_path / "lock.json"
    args = Namespace(
        corpus_root=str(tmp_path / "corpus"),
        ids=["B01", "P01"],
        offline=True,
        out=str(lock_path),
        revision="main",
        tier="full",
        include_replacements=False,
    )

    assert large_pickle_corpus_qa.cmd_preflight(args) == 0

    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert payload["entry_count"] == 2
    assert [entry["id"] for entry in payload["entries"]] == ["B01", "P01"]
    assert all(entry["preflight_status"] == "pending" for entry in payload["entries"])


def test_finalize_lock_uses_preflight_ok_replacements(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    output = tmp_path / "selected.json"
    large_pickle_corpus_qa._write_lock(
        source,
        [
            {"id": "B01", "preflight_status": "ok"},
            {"id": "B02", "preflight_status": "error"},
            {"id": "P01", "preflight_status": "ok"},
            {"id": "R01", "preflight_status": "ok"},
            {"id": "R02", "preflight_status": "error"},
        ],
        tier="full",
    )

    exit_code = large_pickle_corpus_qa.cmd_finalize_lock(Namespace(lock=str(source), out=str(output), target_count=3))

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert [entry["id"] for entry in payload["entries"]] == ["B01", "P01", "R01"]
    assert payload["unavailable_primary_ids"] == ["B02"]
    assert payload["selected_replacement_ids"] == ["R01"]


def test_classify_preserves_lock_selection_metadata(tmp_path: Path) -> None:
    local_path = tmp_path / "artifact.pkl"
    local_path.write_bytes(b"\x80\x04}.")
    lock_path = tmp_path / "selected.json"
    large_pickle_corpus_qa._write_lock(
        lock_path,
        [{"id": "B01", "local_path": str(local_path)}],
        tier="full",
        extra={"selection_status": "ok", "selected_replacement_ids": ["R01"]},
    )

    exit_code = large_pickle_corpus_qa.cmd_classify(Namespace(lock=str(lock_path)))

    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert payload["selection_status"] == "ok"
    assert payload["selected_replacement_ids"] == ["R01"]
    assert payload["entries"][0]["classification"]["exists"] is True


def test_scan_fails_closed_for_unsafe_lock_id(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact_path = tmp_path / "artifact.pkl"
    artifact_path.write_bytes(b"\x80\x04N.")
    lock_path = tmp_path / "lock.json"
    run_dir = tmp_path / "run"
    large_pickle_corpus_qa._write_lock(
        lock_path,
        [{"id": "../escaped", "local_path": str(artifact_path)}],
        tier="custom",
    )

    exit_code = large_pickle_corpus_qa.main(
        [
            "scan",
            "--lock",
            str(lock_path),
            "--out",
            str(run_dir),
            "--no-synthetic",
        ]
    )

    captured = capsys.readouterr()
    scan_rows = large_pickle_corpus_qa._read_jsonl(run_dir / "scan-results.jsonl")
    assert exit_code == 2
    assert "QA scan failed with 1 scan error(s)" in captured.err
    assert len(scan_rows) == 1
    assert scan_rows[0]["scanner"] == "harness"
    assert scan_rows[0]["mode"] == "invalid-lock-entry"
    assert scan_rows[0]["status"] == "error"
    assert scan_rows[0]["error"] == "ValueError: unsafe corpus artifact id: '../escaped'"


def test_scan_error_exit_takes_precedence_over_blocking_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact_path = tmp_path / "artifact.pkl"
    artifact_path.write_bytes(b"\x80\x04N.")
    lock_path = tmp_path / "lock.json"
    run_dir = tmp_path / "run"
    large_pickle_corpus_qa._write_lock(
        lock_path,
        [{"id": "A01", "local_path": str(artifact_path)}],
        tier="custom",
    )
    scan_rows = [
        {
            "artifact_id": "A01",
            "scanner": "modelaudit-picklescan",
            "mode": "rust",
            "result": {"status": "error", "verdict": "unknown", "success": False, "rule_codes": []},
        },
        {
            "artifact_id": "A01",
            "scanner": "modelaudit-root",
            "mode": "default:rust",
            "result": {"status": "complete", "verdict": "clean", "success": True, "rule_codes": []},
        },
    ]

    def fake_scan_records_for_entry(
        *_args: object, **_kwargs: object
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return scan_rows, []

    monkeypatch.setattr(large_pickle_corpus_qa, "_scan_records_for_entry", fake_scan_records_for_entry)

    exit_code = large_pickle_corpus_qa.main(
        [
            "scan",
            "--lock",
            str(lock_path),
            "--out",
            str(run_dir),
            "--no-synthetic",
            "--fail-on-drift",
        ]
    )

    captured = capsys.readouterr()
    drift = json.loads((run_dir / "parity-drift.json").read_text(encoding="utf-8"))
    assert exit_code == 2
    assert "QA scan failed with 1 scan error(s)" in captured.err
    assert drift["drift_count"] == 1
    assert drift["drifts"][0]["delta"] == "status_drift"


def test_parity_drift_detects_root_false_negative() -> None:
    rows = [
        {
            "artifact_id": "P01",
            "scanner": "modelaudit-picklescan",
            "mode": "rust",
            "result": {
                "status": "complete",
                "verdict": "malicious",
                "success": True,
                "rule_codes": ["DANGEROUS_CALL"],
            },
        },
        {
            "artifact_id": "P01",
            "scanner": "modelaudit-root",
            "mode": "default:rust",
            "result": {
                "status": "complete",
                "verdict": "clean",
                "success": True,
                "rule_codes": [],
            },
        },
    ]

    drift = large_pickle_corpus_qa._build_parity_drift(rows)

    assert drift["drift_count"] == 1
    assert drift["drifts"][0]["scope"] == "package_vs_root:default"
    assert drift["drifts"][0]["delta"] == "potential_fn"


def test_coverage_matrix_tracks_required_rule_codes() -> None:
    rows = [
        {
            "artifact_id": "V01",
            "result": {
                "rule_codes": ["DANGEROUS_CALL", "S213"],
            },
        },
    ]

    coverage = large_pickle_corpus_qa._build_coverage_matrix(rows)

    assert coverage["coverage"]["DANGEROUS_CALL"] == ["V01"]
    assert coverage["coverage"]["S213"] == ["V01"]


def test_third_party_differential_counts_error_verdicts_as_failures() -> None:
    differential = large_pickle_corpus_qa._build_third_party_differential(
        [
            {"tool": "fickling", "status": "complete", "exit_code": 1, "verdict": "error"},
            {"tool": "picklescan", "status": "complete", "exit_code": 1, "verdict": "malicious"},
        ]
    )

    assert differential["failure_count"] == 1
    assert differential["failures"][0]["tool"] == "fickling"


def test_third_party_differential_classifies_modelaudit_disagreements() -> None:
    scan_rows = [
        {
            "artifact_id": "V06",
            "scanner": "modelaudit-picklescan",
            "mode": "rust",
            "result": {
                "verdict": "malicious",
                "rule_codes": ["S213"],
                "messages": ["Nested pickle payload detected"],
            },
        },
        {
            "artifact_id": "B01",
            "scanner": "modelaudit-picklescan",
            "mode": "rust",
            "result": {
                "verdict": "clean",
                "rule_codes": [],
                "messages": [],
            },
        },
    ]
    third_party_rows = [
        {"artifact_id": "V06", "tool": "modelscan", "status": "complete", "exit_code": 0, "verdict": "clean"},
        {"artifact_id": "B01", "tool": "picklescan", "status": "complete", "exit_code": 1, "verdict": "malicious"},
        {"artifact_id": "V06", "tool": "fickling", "status": "complete", "exit_code": 2, "verdict": "error"},
    ]

    differential = large_pickle_corpus_qa._build_third_party_differential(
        third_party_rows,
        scan_rows=scan_rows,
    )

    assert differential["failure_count"] == 1
    assert differential["comparison_count"] == 2
    assert differential["disagreement_count"] == 2
    assert differential["summary_by_delta"] == {
        "modelaudit_only_positive": 1,
        "third_party_only_positive": 1,
    }
    assert differential["disagreements"][0]["modelaudit_rule_codes"] == ["S213"]


def test_modelscan_verdict_uses_issue_counts_not_scanner_names(tmp_path: Path) -> None:
    output_json = tmp_path / "modelscan.json"
    output_json.write_text(
        json.dumps(
            {
                "summary": {"total_issues": 0},
                "issues": [],
                "errors": [],
                "scanner": "modelscan.scanners.PyTorchUnsafeOpScan",
            }
        ),
        encoding="utf-8",
    )

    verdict = large_pickle_corpus_qa._third_party_verdict(
        "modelscan",
        3,
        "",
        "",
        output_json,
    )

    assert verdict == "error"


def test_picklescan_verdict_uses_summary_counts(tmp_path: Path) -> None:
    clean = large_pickle_corpus_qa._third_party_verdict(
        "picklescan",
        0,
        "----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 0\nDangerous globals: 0\n",
        "",
        tmp_path / "missing.json",
    )
    malicious = large_pickle_corpus_qa._third_party_verdict(
        "picklescan",
        1,
        "----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\nDangerous globals: 1\n",
        "",
        tmp_path / "missing.json",
    )

    assert clean == "clean"
    assert malicious == "malicious"


def test_third_party_verdict_treats_tracebacks_as_tool_errors(tmp_path: Path) -> None:
    verdict = large_pickle_corpus_qa._third_party_verdict(
        "fickling",
        1,
        "",
        "Traceback (most recent call last):\nAttributeError: simulated crash\n",
        tmp_path / "missing.json",
    )

    assert verdict == "error"
