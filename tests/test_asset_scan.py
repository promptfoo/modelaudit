from pathlib import Path

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file

ASSETS = [
    ("evil_pickle.pkl", 1),
    ("malicious_keras.h5", 1),
    ("malicious_pytorch.pt", 1),
    ("malicious_tf", 1),
    ("malicious_manifest.json", 1),
    ("malicious_zip.zip", 1),
    ("safe_pickle.pkl", 0),
    ("safe_keras.h5", 0),
    ("safe_pytorch.pt", 0),
    ("safe_tf", 0),
    ("safe_manifest.json", 0),
    ("safe_zip.zip", 0),
]


@pytest.mark.parametrize("asset,expected", ASSETS)
def test_asset_scan_exit_codes(asset: str, expected: int) -> None:
    path = Path(__file__).parent / "assets" / asset
    results = scan_model_directory_or_file(str(path))
    exit_code = determine_exit_code(results)
    assert exit_code == expected
