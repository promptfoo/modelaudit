from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modelaudit.utils.sources.pytorch_hub import (
    _extract_weight_urls,
    download_pytorch_hub_model,
    download_pytorch_hub_model_streaming,
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


@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_rejects_known_total_over_max_size(
    mock_get: MagicMock,
    mock_head: MagicMock,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    mock_get.return_value = html_resp

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "5"}
    mock_head.return_value = head_resp

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        list(
            download_pytorch_hub_model_streaming(
                "https://pytorch.org/hub/pytorch_vision_resnet/",
                show_progress=False,
                max_size=4,
            )
        )

    mock_get.assert_called_once_with("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10)


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_enforces_max_size_while_streaming(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    stream_dir = tmp_path / "stream"
    stream_dir.mkdir()
    mock_mkdtemp.return_value = str(stream_dir)
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.headers = {}
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = False
    head_resp.headers = {}
    mock_head.return_value = head_resp

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        list(
            download_pytorch_hub_model_streaming(
                "https://pytorch.org/hub/pytorch_vision_resnet/",
                show_progress=False,
                max_size=4,
            )
        )

    assert not stream_dir.exists()


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
