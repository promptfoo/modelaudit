import pickle
from pathlib import Path

from modelaudit.utils.rewrite import safe_rewrite_pickle


def test_safe_rewrite_pickle(tmp_path):
    evil_pickle = Path(__file__).parent / "evil.pickle"
    rewritten, diff = safe_rewrite_pickle(
        str(evil_pickle), output_path=str(tmp_path / "rewritten.pkl")
    )
    assert Path(rewritten).exists()
    with open(rewritten, "rb") as f:
        obj = pickle.load(f)
    assert obj == "sanitized"
    assert "os.system" not in diff
