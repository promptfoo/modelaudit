import dill
import joblib
from sklearn.linear_model import LinearRegression

from modelaudit.scanners.base import IssueSeverity
from modelaudit.scanners.pickle_scanner import PickleScanner
from tests.evil_pickle import EvilClass


def test_joblib_sklearn_model(tmp_path):
    model = LinearRegression().fit([[0], [1], [2]], [0, 1, 2])
    path = tmp_path / "model.joblib"
    joblib.dump(model, path)

    scanner = PickleScanner()
    result = scanner.scan(str(path))

    assert result.success is True
    assert not result.has_errors


def test_dill_malicious_detection(tmp_path):
    path = tmp_path / "evil.dill"
    with path.open("wb") as f:
        dill.dump(EvilClass(), f)

    scanner = PickleScanner()
    result = scanner.scan(str(path))

    assert any(i.severity == IssueSeverity.CRITICAL for i in result.issues)
