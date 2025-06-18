import json

from modelaudit.utils.integrity import check_hash, compute_file_hash, load_hash_db


def test_compute_file_hash(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"abc")
    digest = compute_file_hash(str(test_file))
    assert len(digest) == 64


def test_hash_db_checks(tmp_path):
    test_file = tmp_path / "good.bin"
    content = b"good"
    test_file.write_bytes(content)
    file_hash = compute_file_hash(str(test_file))

    db = {
        "known_good": {file_hash: {"name": "good"}},
        "known_bad": {},
    }
    db_path = tmp_path / "db.json"
    db_path.write_text(json.dumps(db))

    loaded = load_hash_db(str(db_path))
    status, meta = check_hash(file_hash, loaded)
    assert status == "known_good"
    assert meta["name"] == "good"

    status, _ = check_hash("dead", loaded)
    assert status is None
