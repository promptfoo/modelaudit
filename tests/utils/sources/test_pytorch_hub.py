from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest

from modelaudit.utils.sources.pytorch_hub import (
    _artifact_download_paths,
    _extract_weight_urls,
    _open_destination_file,
    _safe_destination_path,
    download_pytorch_hub_model,
    download_pytorch_hub_model_streaming,
    is_pytorch_hub_url,
)


class TestPytorchHubURLDetection:
    def test_valid_urls(self):
        valid = [
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            "https://pytorch.org/hub/ultralytics_yolov5/",
            "HTTPS://PYTORCH.ORG/hub/pytorch_vision_resnet/",
        ]
        for url in valid:
            assert is_pytorch_hub_url(url)

    def test_invalid_urls(self):
        invalid = [
            "https://example.com/model",
            "pytorch.org/hub/model",  # missing scheme
            "",
        ]
        for url in invalid:
            assert not is_pytorch_hub_url(url)


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_success(mock_get, mock_head, mock_check, tmp_path):
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"abc"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    result = download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )
    assert (tmp_path / "resnet50.pth").exists()
    assert result == tmp_path


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_includes_supported_non_pt_extensions(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".pt", ".pth", ".safetensors", ".onnx", ".bin", ".zip", ".tar.gz"}
    html = (
        '<a href="https://download.pytorch.org/models/resnet50.pth">pt</a>'
        '<a href="https://download.pytorch.org/models/resnet50.safetensors">safetensors</a>'
        '<a href="https://download.pytorch.org/models/resnet50.onnx">onnx</a>'
        '<a href="https://download.pytorch.org/models/resnet50.bin">bin</a>'
        '<a href="https://download.pytorch.org/models/resnet50.zip">zip</a>'
    )

    assert _extract_weight_urls(html) == [
        "https://download.pytorch.org/models/resnet50.pth",
        "https://download.pytorch.org/models/resnet50.safetensors",
        "https://download.pytorch.org/models/resnet50.onnx",
        "https://download.pytorch.org/models/resnet50.bin",
        "https://download.pytorch.org/models/resnet50.zip",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_ignores_unsupported_extensions_and_hosts(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        '<a href="https://download.pytorch.org/models/model.onnx">onnx</a>'
        '<a href="https://download.pytorch.org/models/diagram.png">png</a>'
        '<a href="https://example.com/models/model.onnx">external</a>'
        '<a href="https://download.pytorch.org/assets/model.onnx">wrong path</a>'
    )

    assert _extract_weight_urls(html) == ["https://download.pytorch.org/models/model.onnx"]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_rejects_normalized_paths_outside_models(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        '<a href="https://download.pytorch.org/models/model.onnx">safe</a>'
        '<a href="https://download.pytorch.org/models/../assets/model.onnx">dot segment</a>'
        '<a href="https://download.pytorch.org/models/%2e%2e/assets/model.onnx">encoded dot segment</a>'
        '<a href="https://download.pytorch.org/models/%252e%252e/assets/model.onnx">double encoded dot segment</a>'
        '<a href="https://download.pytorch.org/models/%252f..%252fassets/model.onnx">double encoded separator</a>'
        '<a href="https://download.pytorch.org/models/%5c..%5cassets%5cmodel.onnx">encoded backslash</a>'
    )

    assert _extract_weight_urls(html) == ["https://download.pytorch.org/models/model.onnx"]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_downloads_supported_non_pt_links(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.onnx">onnx</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"abc"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    result = download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert result == tmp_path
    assert (tmp_path / "resnet50.onnx").read_bytes() == b"abc"


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_strips_query_from_local_filename(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/resnet50.onnx?download=1"
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">onnx</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"abc"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert (tmp_path / "resnet50.onnx").read_bytes() == b"abc"
    assert not (tmp_path / "resnet50.onnx?download=1").exists()
    mock_get.assert_any_call(weight_url, stream=True, timeout=30)


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_preserves_nested_artifacts_with_same_basename(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = (
        '<a href="https://download.pytorch.org/models/foo/model.onnx">foo</a>'
        '<a href="https://download.pytorch.org/models/bar/model.onnx">bar</a>'
    )
    html_resp.raise_for_status = lambda: None
    foo_resp = MagicMock()
    foo_resp.__enter__.return_value = foo_resp
    foo_resp.iter_content.return_value = [b"foo"]
    foo_resp.raise_for_status = lambda: None
    bar_resp = MagicMock()
    bar_resp.__enter__.return_value = bar_resp
    bar_resp.iter_content.return_value = [b"bar"]
    bar_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, foo_resp, bar_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert (tmp_path / "foo" / "model.onnx").read_bytes() == b"foo"
    assert (tmp_path / "bar" / "model.onnx").read_bytes() == b"bar"


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_uniquifies_query_variant_artifact_paths(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = (
        '<a href="https://download.pytorch.org/models/model.onnx?variant=one">one</a>'
        '<a href="https://download.pytorch.org/models/model.onnx?variant=two">two</a>'
    )
    html_resp.raise_for_status = lambda: None
    one_resp = MagicMock()
    one_resp.__enter__.return_value = one_resp
    one_resp.iter_content.return_value = [b"one"]
    one_resp.raise_for_status = lambda: None
    two_resp = MagicMock()
    two_resp.__enter__.return_value = two_resp
    two_resp.iter_content.return_value = [b"two"]
    two_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, one_resp, two_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert (tmp_path / "model.onnx").read_bytes() == b"one"
    assert (tmp_path / "__modelaudit_duplicate_2" / "model.onnx").read_bytes() == b"two"


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_rejects_symlinked_cache_parent(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/nested/model.onnx">onnx</a>'
    html_resp.raise_for_status = lambda: None
    mock_get.return_value = html_resp

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    try:
        (cache_dir / "nested").symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on host symlink support
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="Unsafe PyTorch Hub cache path"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=cache_dir,
        )

    assert not (outside_dir / "model.onnx").exists()
    mock_get.assert_called_once_with("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10)


def test_download_pytorch_hub_model_invalid_url():
    with pytest.raises(ValueError):
        download_pytorch_hub_model("https://example.com/model")


def test_extract_weight_urls_multi_part_extensions():
    html = (
        '<a href="https://download.pytorch.org/models/resnet50.pth.tar.gz">gz</a>'
        '<a href="https://download.pytorch.org/models/resnet50.pth.zip">zip</a>'
    )
    assert _extract_weight_urls(html) == [
        "https://download.pytorch.org/models/resnet50.pth.tar.gz",
        "https://download.pytorch.org/models/resnet50.pth.zip",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_canonicalizes_entities_case_and_fragments(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        '<a href="HTTPS://DOWNLOAD.PYTORCH.ORG/models/MODEL.ONNX#one">one</a>'
        '<a href="HTTPS://DOWNLOAD.PYTORCH.ORG/models/MODEL.ONNX#two">duplicate</a>'
        '<a href="https://download.pytorch.org/models/query.onnx?x=1&amp;y=2">query</a>'
        '<a href="https://download.pytorch.org/models/nested.onnx?x=1&amp;amp;y=2">nested entity</a>'
    )

    assert _extract_weight_urls(html) == [
        "https://download.pytorch.org/models/MODEL.ONNX",
        "https://download.pytorch.org/models/query.onnx?x=1&y=2",
        "https://download.pytorch.org/models/nested.onnx?x=1&amp;y=2",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_does_not_synthesize_truncated_links(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        '<a href="https://download.pytorch.org/models/backslash.onnx\\suffix">backslash</a>'
        '<a href="https://download.pytorch.org/models/dots.onnx...">dots</a>'
        '<a href="https://download.pytorch.org/models/paren.onnx).txt">paren</a>'
        "Malformed https://download.pytorch.org/models/prose.onnx..."
    )

    assert _extract_weight_urls(html) == []


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_trims_punctuation_only_from_prose(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        "Download https://download.pytorch.org/models/prose.onnx. "
        "Query https://download.pytorch.org/models/query.onnx?download=1. "
        "Entity https://download.pytorch.org/models/entity.onnx?x=1&amp;y=2. "
        "Mixed https://download.pytorch.org/models/mixed.onnx)]. "
        '<a href="https://download.pytorch.org/models/attribute.onnx...">attribute</a>'
    )

    assert _extract_weight_urls(html) == [
        "https://download.pytorch.org/models/prose.onnx",
        "https://download.pytorch.org/models/query.onnx?download=1",
        "https://download.pytorch.org/models/entity.onnx?x=1&y=2",
        "https://download.pytorch.org/models/mixed.onnx",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_recovers_malformed_unclosed_attribute(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}

    assert _extract_weight_urls('<a href="https://download.pytorch.org/models/model.onnx') == [
        "https://download.pytorch.org/models/model.onnx"
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_rejects_excessive_recursive_encoding(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    path = "/models/%2e%2e/model.onnx"
    for _ in range(4):
        path = quote(path, safe="/")

    assert _extract_weight_urls(f"https://download.pytorch.org{path}") == []


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_does_not_invent_double_encoded_extensions(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}

    assert _extract_weight_urls("https://download.pytorch.org/models/model%252Eonnx") == []


def test_artifact_download_paths_are_portable_and_do_not_conflict() -> None:
    urls = [
        "https://download.pytorch.org/models/CON.onnx",
        "https://download.pytorch.org/models/file%3Astream.onnx",
        "https://download.pytorch.org/models/%1Bred.onnx",
        "https://download.pytorch.org/models/trailing%20/model.onnx",
        "https://download.pytorch.org/models/Foo/model.onnx",
        "https://download.pytorch.org/models/foo/MODEL.onnx",
        "https://download.pytorch.org/models/caf%C3%A9/model.onnx",
        "https://download.pytorch.org/models/cafe%CC%81/MODEL.onnx",
        "https://download.pytorch.org/models/prefix.onnx",
        "https://download.pytorch.org/models/prefix.onnx/part.pth",
        "https://download.pytorch.org/models/reverse.onnx/part.pth",
        "https://download.pytorch.org/models/reverse.onnx",
    ]

    assert [path.as_posix() for _, path in _artifact_download_paths(urls)] == [
        "__modelaudit_CON.onnx",
        "file%3Astream.onnx",
        "%1Bred.onnx",
        "trailing%20/model.onnx",
        "Foo/model.onnx",
        "__modelaudit_duplicate_2/foo/MODEL.onnx",
        "caf\u00e9/model.onnx",
        "__modelaudit_duplicate_2/cafe\u0301/MODEL.onnx",
        "prefix.onnx",
        "__modelaudit_duplicate_2/prefix.onnx/part.pth",
        "reverse.onnx/part.pth",
        "__modelaudit_duplicate_2/reverse.onnx",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_preserves_nested_non_pt_artifact(
    mock_get: MagicMock,
    mock_extensions: MagicMock,
) -> None:
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/nested/model.onnx">onnx</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"model"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    downloads = download_pytorch_hub_model_streaming(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        show_progress=False,
    )
    dest_file, is_last = next(downloads)

    assert is_last
    assert dest_file.parts[-2:] == ("nested", "model.onnx")
    assert dest_file.read_bytes() == b"model"
    with pytest.raises(StopIteration):
        next(downloads)
    assert not dest_file.exists()


def test_open_destination_file_rechecks_parent_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_dir = tmp_path / "cache"
    nested_dir = cache_dir / "nested"
    outside_dir = tmp_path / "outside"
    nested_dir.mkdir(parents=True)
    outside_dir.mkdir()
    original_safe_destination = _safe_destination_path
    swapped = False

    def swap_parent_after_validation(dest_dir: Path, relative_path: Path) -> Path:
        nonlocal swapped
        dest_file = original_safe_destination(dest_dir, relative_path)
        if not swapped:
            nested_dir.rmdir()
            try:
                nested_dir.symlink_to(outside_dir, target_is_directory=True)
            except OSError as exc:  # pragma: no cover - depends on host symlink support
                pytest.skip(f"symlinks unavailable: {exc}")
            swapped = True
        return dest_file

    monkeypatch.setattr(
        "modelaudit.utils.sources.pytorch_hub._safe_destination_path",
        swap_parent_after_validation,
    )

    with (
        pytest.raises((OSError, ValueError)),
        _open_destination_file(cache_dir, Path("nested/model.onnx")) as handle,
    ):
        handle.write(b"unsafe")

    assert not (outside_dir / "model.onnx").exists()


def test_open_destination_file_accepts_symlinked_cache_root(tmp_path: Path) -> None:
    real_cache = tmp_path / "real-cache"
    cache_link = tmp_path / "cache-link"
    real_cache.mkdir()
    try:
        cache_link.symlink_to(real_cache, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on host symlink support
        pytest.skip(f"symlinks unavailable: {exc}")

    with _open_destination_file(cache_link, Path("model.onnx")) as handle:
        handle.write(b"model")

    assert (real_cache / "model.onnx").read_bytes() == b"model"
