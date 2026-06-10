"""Security regressions for generated Hugging Face whitelist modules."""

import importlib.util
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest


def _load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("script_name", "generated_set_name", "generator_args"),
    [
        ("fetch_hf_top_models.py", "POPULAR_MODELS", lambda payload: ([payload],)),
        (
            "fetch_hf_org_models.py",
            "ORGANIZATION_MODELS",
            lambda payload: ({"trusted": [payload]},),
        ),
    ],
)
def test_whitelist_generator_emits_model_ids_as_safe_python_literals(
    tmp_path: Path,
    script_name: str,
    generated_set_name: str,
    generator_args: Callable[[str], tuple[object, ...]],
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / script_name)
    marker = tmp_path / "executed.txt"
    payload = f"safe\\\",\n    (__import__('pathlib').Path({str(marker)!r}).write_text('executed') or 'x'),\n    #"
    output_path = tmp_path / f"{Path(script_name).stem}_generated.py"

    script.generate_whitelist_module(*generator_args(payload), output_path)
    generated = _load_module(output_path)

    assert marker.exists() is False
    assert payload in getattr(generated, generated_set_name)
