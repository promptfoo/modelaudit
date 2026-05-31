from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.utils.sources.pytorch_hub import (
    _extract_weight_urls,
    download_pytorch_hub_model,
    is_pytorch_hub_url,
)


class TestPytorchHubURLDetection:
    def test_valid_urls(self):
        valid = [
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            "https://pytorch.org/hub/ultralytics_yolov5/",
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
