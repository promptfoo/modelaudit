import json

from modelaudit.core import scan_model_directory_or_file
from modelaudit.utils.integrity import compute_file_hash


def test_baseline_hash_detection(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_bytes(b"model")
    actual_hash = compute_file_hash(str(model_file))

    results = scan_model_directory_or_file(
        str(model_file),
        baseline_hash="deadbeef",
    )
    assert any(
        "drift detected" in issue["message"].lower() for issue in results["issues"]
    )

    db = {
        "known_bad": {actual_hash: {"origin": "test"}},
        "known_good": {},
    }
    db_path = tmp_path / "db.json"
    db_path.write_text(json.dumps(db))
    results = scan_model_directory_or_file(
        str(model_file),
        hash_db_path=str(db_path),
    )
    assert any(
        "known malicious" in issue["message"].lower() for issue in results["issues"]
    )
