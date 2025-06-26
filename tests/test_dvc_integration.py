import pickle

from modelaudit.core import scan_model_directory_or_file
from modelaudit.utils import resolve_dvc_file


def test_resolve_dvc_file(tmp_path):
    target = tmp_path / "model.pkl"
    with target.open("wb") as f:
        pickle.dump({"a": 1}, f)

    dvc_file = tmp_path / "model.pkl.dvc"
    dvc_file.write_text("outs:\n- path: model.pkl\n")

    resolved = resolve_dvc_file(str(dvc_file))
    assert resolved == [str(target)]


def test_scan_dvc_pointer(tmp_path):
    target = tmp_path / "model.pkl"
    with target.open("wb") as f:
        pickle.dump({"b": 2}, f)

    dvc_file = tmp_path / "model.pkl.dvc"
    dvc_file.write_text("outs:\n- path: model.pkl\n")

    results = scan_model_directory_or_file(str(dvc_file))
    assert results["files_scanned"] == 1
    assert any(target.name in asset["path"] for asset in results["assets"])
