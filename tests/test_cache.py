from modelaudit.core import scan_model_directory_or_file


def test_cache_hit(tmp_path, monkeypatch):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello")
    config_dir = tmp_path / "promptfoo_config"
    monkeypatch.setenv("PROMPTFOO_CONFIG_DIR", str(config_dir))

    results1 = scan_model_directory_or_file(str(test_file))
    assert results1.get("files_cached", 0) == 0

    results2 = scan_model_directory_or_file(str(test_file))
    assert results2.get("files_cached", 0) == 1
    assert len(results1["issues"]) == len(results2["issues"])


def test_cache_invalidated_on_change(tmp_path, monkeypatch):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello")
    config_dir = tmp_path / "promptfoo_config"
    monkeypatch.setenv("PROMPTFOO_CONFIG_DIR", str(config_dir))

    scan_model_directory_or_file(str(test_file))
    test_file.write_bytes(b"changed")
    results = scan_model_directory_or_file(str(test_file))
    assert results.get("files_cached", 0) == 0


def test_cache_disabled(tmp_path, monkeypatch):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello")
    config_dir = tmp_path / "promptfoo_config"
    monkeypatch.setenv("PROMPTFOO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("PROMPTFOO_CACHE_ENABLED", "false")

    results1 = scan_model_directory_or_file(str(test_file))
    assert results1.get("files_cached", 0) == 0

    results2 = scan_model_directory_or_file(str(test_file))
    assert results2.get("files_cached", 0) == 0  # Should still be 0 when cache is disabled
