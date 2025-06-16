import base64
import json
import os
import pickle
import zipfile
from pathlib import Path

import h5py

# Optional: TensorFlow is only needed to regenerate these protobufs if you want
# to build them from scratch. Here we embed the minimal bytes directly.
SAFE_SAVEDMODEL_B64 = "EhISEAoOCgVDb25zdBIFQ29uc3Q="
MALICIOUS_SAVEDMODEL_B64 = "EiESHwoOCgVDb25zdBIFQ29uc3QKDQoDYmFkEgZQeUZ1bmM="


def make_pickles(out_dir: Path) -> None:
    class Evil:
        def __reduce__(self):
            return (os.system, ("echo malicious",))

    with open(out_dir / "evil_pickle.pkl", "wb") as f:
        pickle.dump(Evil(), f)

    with open(out_dir / "safe_pickle.pkl", "wb") as f:
        pickle.dump({"ok": True}, f)


def make_keras(out_dir: Path) -> None:
    safe_cfg = {"class_name": "Sequential", "config": {"name": "seq", "layers": []}}
    mal_cfg = {
        "class_name": "Sequential",
        "config": {
            "name": "seq",
            "layers": [
                {"class_name": "Lambda", "config": {"function": "lambda x: eval('1')"}}
            ],
        },
    }

    with h5py.File(out_dir / "safe_keras.h5", "w") as f:
        f.attrs["model_config"] = json.dumps(safe_cfg)

    with h5py.File(out_dir / "malicious_keras.h5", "w") as f:
        f.attrs["model_config"] = json.dumps(mal_cfg)


def make_pytorch_zips(out_dir: Path) -> None:
    class Evil:
        def __reduce__(self):
            return (eval, ("1+1",))

    def write_zip(path: Path, obj: object) -> None:
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("version", "3")
            z.writestr("data.pkl", pickle.dumps(obj))

    write_zip(out_dir / "safe_pytorch.pt", {"ok": True})
    write_zip(out_dir / "malicious_pytorch.pt", Evil())


def make_savedmodels(out_dir: Path) -> None:
    safe_dir = out_dir / "safe_tf"
    mal_dir = out_dir / "malicious_tf"
    safe_dir.mkdir(exist_ok=True)
    mal_dir.mkdir(exist_ok=True)

    (safe_dir / "saved_model.pb").write_bytes(base64.b64decode(SAFE_SAVEDMODEL_B64))
    (mal_dir / "saved_model.pb").write_bytes(base64.b64decode(MALICIOUS_SAVEDMODEL_B64))


def make_manifests(out_dir: Path) -> None:
    safe = {"name": "safe_model", "config": {"param": 1}}
    mal = {
        "name": "evil_model",
        "config": {"api_key": "SECRET", "url": "http://malicious.example.com"},
    }
    (out_dir / "safe_config.json").write_text(json.dumps(safe))
    (out_dir / "config.json").write_text(json.dumps(mal))


def make_zips(out_dir: Path) -> None:
    class Evil:
        def __reduce__(self):
            return (os.system, ("echo zip",))

    with zipfile.ZipFile(out_dir / "safe_zip.zip", "w") as z:
        z.writestr("readme.txt", "safe")

    with zipfile.ZipFile(out_dir / "malicious_zip.zip", "w") as z:
        z.writestr("../evil.txt", "bad")
        z.writestr("evil.pkl", pickle.dumps(Evil()))


def main() -> None:
    out_dir = Path(__file__).parent
    make_pickles(out_dir)
    make_keras(out_dir)
    make_pytorch_zips(out_dir)
    make_savedmodels(out_dir)
    make_manifests(out_dir)
    make_zips(out_dir)


if __name__ == "__main__":
    main()
