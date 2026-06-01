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


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_rejects_known_total_over_max_size(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    tmp_path: Path,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    mock_get.return_value = html_resp

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "4"}
    mock_head.return_value = head_resp

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=3,
        )

    mock_check.assert_not_called()
    mock_get.assert_called_once_with("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10)
    assert not (tmp_path / "resnet50.pth").exists()


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_cleans_temp_dir_after_preflight_size_rejection(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    mock_get.return_value = html_resp

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "4"}
    mock_head.return_value = head_resp

    temp_dir = tmp_path / "modelaudit_pth_test"
    mock_mkdtemp.return_value = str(temp_dir)

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            max_size=3,
        )

    mock_check.assert_not_called()
    assert not temp_dir.exists()


@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_enforces_max_size_while_streaming(
    mock_get: MagicMock,
    mock_head: MagicMock,
    tmp_path: Path,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = False
    head_resp.headers = {}
    mock_head.return_value = head_resp

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=4,
        )

    assert not (tmp_path / "resnet50.pth").exists()


@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_preserves_existing_cache_file_after_size_rejection(
    mock_get: MagicMock,
    mock_head: MagicMock,
    tmp_path: Path,
) -> None:
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

    cached_file = tmp_path / "resnet50.pth"
    cached_file.write_bytes(b"trusted-cache")

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=4,
        )

    assert cached_file.read_bytes() == b"trusted-cache"
    assert not list(tmp_path.glob(".*.part"))


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_does_not_follow_existing_cache_symlink(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    tmp_path: Path,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.headers = {"content-length": "3"}
    file_resp.iter_content.return_value = [b"abc"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    outside_file = tmp_path / "outside.pth"
    outside_file.write_bytes(b"trusted-cache")
    cached_file = tmp_path / "resnet50.pth"
    try:
        cached_file.symlink_to(outside_file)
    except OSError as exc:  # pragma: no cover - depends on host symlink support
        pytest.skip(f"symlinks unavailable: {exc}")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert outside_file.read_bytes() == b"trusted-cache"
    assert not cached_file.is_symlink()
    assert cached_file.read_bytes() == b"abc"


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_enforces_max_size_and_cleans_temp_dir(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    html_resp = MagicMock()
    html_resp.text = '<a href="https://download.pytorch.org/models/resnet50.pth">link</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = False
    head_resp.headers = {}
    mock_head.return_value = head_resp

    temp_dir = tmp_path / "modelaudit_pth_stream_test"
    temp_dir.mkdir()
    mock_mkdtemp.return_value = str(temp_dir)

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        list(
            download_pytorch_hub_model_streaming(
                "https://pytorch.org/hub/pytorch_vision_resnet/",
                show_progress=False,
                max_size=4,
            )
        )

    assert not temp_dir.exists()


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


def test_extract_weight_urls_deduplicates_repeated_links() -> None:
    url = "https://download.pytorch.org/models/resnet50.pth"
    assert _extract_weight_urls(f'<a href="{url}">first</a><a href="{url}">second</a>') == [url]
