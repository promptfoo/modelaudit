import msgpack

from modelaudit.scanners.flax_msgpack_scanner import FlaxMsgpackScanner


def create_msgpack_file(path):
    data = {"params": {"w": list(range(5))}}
    with open(path, "wb") as f:
        f.write(msgpack.packb(data, use_bin_type=True))


def test_flax_msgpack_valid(tmp_path):
    path = tmp_path / "model.msgpack"
    create_msgpack_file(path)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert result.metadata.get("top_level_type") == "dict"
    assert not result.has_errors


def test_flax_msgpack_corrupted(tmp_path):
    path = tmp_path / "corrupt.msgpack"
    create_msgpack_file(path)
    data = path.read_bytes()[:-10]
    path.write_bytes(data)

    scanner = FlaxMsgpackScanner()
    result = scanner.scan(str(path))

    assert result.has_errors
    assert any("invalid" in issue.message.lower() for issue in result.issues)
