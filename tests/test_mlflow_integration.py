import sys

import pytest

from modelaudit.mlflow_integration import scan_mlflow_model


def test_scan_mlflow_model_import_error(monkeypatch):
    """scan_mlflow_model should raise ImportError when mlflow is missing."""
    monkeypatch.setitem(sys.modules, "mlflow", None)
    with pytest.raises(ImportError):
        scan_mlflow_model("models:/dummy/1")
