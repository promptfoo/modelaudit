import fsspec
from fsspec.implementations.local import LocalFileSystem

from modelaudit.utils import streaming


def _setup_local(monkeypatch) -> None:
    """Configure streaming helpers to use local file system."""
    monkeypatch.setattr(streaming, "get_fs_protocol", lambda u: "file")
    monkeypatch.setattr(fsspec, "filesystem", lambda protocol, token=None: LocalFileSystem())


def test_get_streaming_preview_detects_onnx(tmp_path, monkeypatch):
    _setup_local(monkeypatch)
    file_path = tmp_path / "model.onnx"
    file_path.write_bytes(b"\x08\x01\x12\x00onnxmodel")
    preview = streaming.get_streaming_preview(f"file://{file_path}")
    assert preview is not None
    assert preview["detected_format"] == "ONNX"


def test_get_streaming_preview_avoids_false_positive(tmp_path, monkeypatch):
    _setup_local(monkeypatch)
    file_path = tmp_path / "not_onnx.bin"
    file_path.write_bytes(b"\x08\x08random")
    preview = streaming.get_streaming_preview(f"file://{file_path}")
    assert preview is not None
    assert preview["detected_format"] is None
