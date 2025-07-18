import pickle
import zipfile

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.executorch_scanner import ExecuTorchScanner


def create_executorch_archive(tmp_path, *, malicious: bool = False):
    zip_path = tmp_path / "model.ptl"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("version", "1")
        data: dict[str, object] = {"weights": [1, 2, 3]}
        if malicious:

            class Evil:
                def __reduce__(self):
                    return (eval, ("print('evil')",))

            data["malicious"] = Evil()
        z.writestr("bytecode.pkl", pickle.dumps(data))
    return zip_path


def test_executorch_scanner_can_handle(tmp_path):
    path = create_executorch_archive(tmp_path)
    assert ExecuTorchScanner.can_handle(str(path))
    other = tmp_path / "model.h5"
    other.write_bytes(b"data")
    assert not ExecuTorchScanner.can_handle(str(other))


def test_executorch_scanner_safe_model(tmp_path):
    path = create_executorch_archive(tmp_path)
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(path))
    assert result.success is True
    assert result.bytes_scanned > 0
    critical = [i for i in result.issues if i.severity == IssueSeverity.CRITICAL]
    assert not critical


def test_executorch_scanner_malicious(tmp_path):
    path = create_executorch_archive(tmp_path, malicious=True)
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(path))
    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
    assert any("eval" in i.message.lower() for i in result.issues)


def test_executorch_scanner_invalid_zip(tmp_path):
    file_path = tmp_path / "bad.ptl"
    file_path.write_bytes(b"not zip")
    scanner = ExecuTorchScanner()
    result = scanner.scan(str(file_path))
    assert not result.success
    assert any("executorch" in i.message.lower() for i in result.issues)
