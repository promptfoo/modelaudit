import zipfile
from pathlib import Path

import numpy as np
from safetensors.numpy import save_file

from modelaudit.core import scan_model_directory_or_file


def create_safetensors_file(path: Path) -> None:
    data = {"t1": np.arange(4, dtype=np.float32)}
    save_file(data, str(path))


def test_assets_safetensors(tmp_path: Path) -> None:
    file_path = tmp_path / "model.safetensors"
    create_safetensors_file(file_path)

    results = scan_model_directory_or_file(str(file_path))
    assert results["assets"][0]["path"] == str(file_path)


def test_assets_zip(tmp_path: Path) -> None:
    zip_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("a.txt", "hello")
        z.writestr("b.txt", "world")

    results = scan_model_directory_or_file(str(zip_path))
    top_asset = results["assets"][0]
    inner = {a["path"] for a in top_asset.get("contents", [])}
    assert f"{zip_path}:a.txt" in inner
    assert f"{zip_path}:b.txt" in inner
