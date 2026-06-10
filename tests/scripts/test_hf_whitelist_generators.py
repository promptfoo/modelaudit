"""Security regressions for generated Hugging Face whitelist modules."""

import importlib.util
import json
import re
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from types import ModuleType

import pytest

FETCH_PAGE_CASES = [
    (
        "fetch_hf_top_models.py",
        "fetch_models_page",
        (0,),
        "Hugging Face models response must be a JSON object",
    ),
    (
        "fetch_hf_org_models.py",
        "fetch_organization_models_page",
        ("trusted", 0),
        "Hugging Face organization response must be a JSON object",
    ),
]


def _load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("script_name", "generated_set_name", "generator_args"),
    [
        ("fetch_hf_top_models.py", "POPULAR_MODELS", lambda model_ids: (model_ids,)),
        (
            "fetch_hf_org_models.py",
            "ORGANIZATION_MODELS",
            lambda model_ids: ({"trusted": model_ids},),
        ),
    ],
)
def test_whitelist_generator_emits_model_ids_as_safe_python_literals(
    tmp_path: Path,
    script_name: str,
    generated_set_name: str,
    generator_args: Callable[[list[str]], tuple[object, ...]],
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / script_name)
    marker = tmp_path / "executed.txt"
    payload = f"safe\\\",\n    (__import__('pathlib').Path({str(marker)!r}).write_text('executed') or 'x'),\n    #"
    model_ids = [payload, "z/ordinary", 'a/quote"and\\backslash', "unicode/模型/😀/\u2028", payload]
    output_path = tmp_path / f"{Path(script_name).stem}_generated.py"

    script.generate_whitelist_module(*generator_args(model_ids), output_path)
    generated = _load_module(output_path)

    assert marker.exists() is False
    assert getattr(generated, generated_set_name) == set(model_ids)
    generated_source = output_path.read_text(encoding="utf-8")
    for model_id in set(model_ids):
        assert f"    {json.dumps(model_id, ensure_ascii=False)}," in generated_source


def test_org_whitelist_generator_emits_org_names_as_safe_comments(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / "fetch_hf_org_models.py")
    marker = tmp_path / "executed.txt"
    payload = f'evil"""\n__import__("pathlib").Path({str(marker)!r}).write_text("executed")\n"""'
    output_path = tmp_path / "organizations_generated.py"

    script.generate_whitelist_module({payload: ["trusted/model"]}, output_path)
    generated = _load_module(output_path)

    assert marker.exists() is False
    assert {"trusted/model"} == generated.ORGANIZATION_MODELS
    assert f"#   - {json.dumps(payload, ensure_ascii=False)}: 1 models" in output_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("script_name", "generator_args", "error_message"),
    [
        ("fetch_hf_top_models.py", ([123],), "Model IDs must be strings"),
        ("fetch_hf_org_models.py", ({"trusted": [123]},), "Model IDs must be strings"),
        ("fetch_hf_org_models.py", ({123: ["trusted/model"]},), "Organization names must be strings"),
    ],
)
def test_whitelist_generator_rejects_non_string_codegen_inputs(
    tmp_path: Path,
    script_name: str,
    generator_args: tuple[object, ...],
    error_message: str,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / script_name)
    output_path = tmp_path / "generated.py"

    with pytest.raises(ValueError, match=error_message):
        script.generate_whitelist_module(*generator_args, output_path)

    assert output_path.exists() is False


@pytest.mark.parametrize(("script_name", "fetch_name", "fetch_args", "error_message"), FETCH_PAGE_CASES)
@pytest.mark.parametrize("response_body", [b"[]", b"null"])
def test_fetch_page_rejects_non_object_response(
    monkeypatch: pytest.MonkeyPatch,
    script_name: str,
    fetch_name: str,
    fetch_args: tuple[object, ...],
    error_message: str,
    response_body: bytes,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / script_name)

    def fake_urlopen(*_args: object, **_kwargs: object) -> BytesIO:
        return BytesIO(response_body)

    monkeypatch.setattr(script, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match=re.escape(error_message)):
        getattr(script, fetch_name)(*fetch_args)


@pytest.mark.parametrize(("script_name", "fetch_name", "fetch_args", "error_message"), FETCH_PAGE_CASES)
def test_fetch_page_accepts_object_response(
    monkeypatch: pytest.MonkeyPatch,
    script_name: str,
    fetch_name: str,
    fetch_args: tuple[object, ...],
    error_message: str,
) -> None:
    del error_message
    repo_root = Path(__file__).resolve().parents[2]
    script = _load_module(repo_root / "scripts" / script_name)

    def fake_urlopen(*_args: object, **_kwargs: object) -> BytesIO:
        return BytesIO(b'{"models": []}')

    monkeypatch.setattr(script, "urlopen", fake_urlopen)

    assert getattr(script, fetch_name)(*fetch_args) == {"models": []}
