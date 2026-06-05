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
def test_download_pytorch_hub_model_success(
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
    head_resp.status_code = 200
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
    head_resp.status_code = 200
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
    head_resp.status_code = 200
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
    file_resp.headers = {"content-length": "3"}
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = False
    head_resp.status_code = 405
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
def test_download_pytorch_hub_model_rolls_back_cache_on_cumulative_size_rejection(
    mock_get: MagicMock,
    mock_head: MagicMock,
    tmp_path: Path,
) -> None:
    first_url = "https://download.pytorch.org/models/first.pth"
    second_url = "https://download.pytorch.org/models/second.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{first_url}">first</a><a href="{second_url}">second</a>'
    html_resp.raise_for_status = lambda: None

    first_resp = MagicMock()
    first_resp.__enter__.return_value = first_resp
    first_resp.headers = {"content-length": "3"}
    first_resp.iter_content.return_value = [b"new"]
    first_resp.raise_for_status = lambda: None
    second_resp = MagicMock()
    second_resp.__enter__.return_value = second_resp
    second_resp.headers = {"content-length": "3"}
    second_resp.iter_content.return_value = [b"two"]
    second_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, first_resp, second_resp]

    head_resp = MagicMock()
    head_resp.status_code = 405
    head_resp.headers = {}
    mock_head.return_value = head_resp

    first_cache = tmp_path / "first.pth"
    second_cache = tmp_path / "second.pth"
    first_cache.write_bytes(b"old-first")
    second_cache.write_bytes(b"old-second")

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=5,
        )

    assert first_cache.read_bytes() == b"old-first"
    assert second_cache.read_bytes() == b"old-second"
    assert not list(tmp_path.glob(".modelaudit_pth_stage_*"))


@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_rolls_back_cache_on_commit_failure(
    mock_get: MagicMock,
    mock_head: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_url = "https://download.pytorch.org/models/first.pth"
    second_url = "https://download.pytorch.org/models/second.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{first_url}">first</a><a href="{second_url}">second</a>'
    html_resp.raise_for_status = lambda: None

    file_responses = []
    for payload in (b"new-first", b"new-second"):
        file_resp = MagicMock()
        file_resp.__enter__.return_value = file_resp
        file_resp.headers = {}
        file_resp.iter_content.return_value = [payload]
        file_resp.raise_for_status = lambda: None
        file_responses.append(file_resp)
    mock_get.side_effect = [html_resp, *file_responses]

    head_resp = MagicMock()
    head_resp.status_code = 405
    head_resp.headers = {}
    mock_head.return_value = head_resp

    first_cache = tmp_path / "first.pth"
    second_cache = tmp_path / "second.pth"
    first_cache.write_bytes(b"old-first")
    second_cache.write_bytes(b"old-second")

    original_replace = Path.replace

    def _fail_second_commit(path: Path, target: Path) -> Path:
        target_path = Path(target)
        if (
            path.name == "second.pth"
            and path.parent.name.startswith(".modelaudit_pth_stage_")
            and target_path == second_cache
        ):
            raise OSError("simulated second-file commit failure")
        return original_replace(path, target_path)

    monkeypatch.setattr(Path, "replace", _fail_second_commit)

    with pytest.raises(OSError, match="simulated second-file commit failure"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=100,
        )

    assert first_cache.read_bytes() == b"old-first"
    assert second_cache.read_bytes() == b"old-second"
    assert not list(tmp_path.glob(".modelaudit_pth_stage_*"))


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_allows_exact_cumulative_limit(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    tmp_path: Path,
) -> None:
    urls = [
        "https://download.pytorch.org/models/first.pth",
        "https://download.pytorch.org/models/second.pth",
    ]
    html_resp = MagicMock()
    html_resp.text = "".join(f'<a href="{url}">weight</a>' for url in urls)
    html_resp.raise_for_status = lambda: None

    file_responses = []
    for payload in (b"one", b"two"):
        file_resp = MagicMock()
        file_resp.__enter__.return_value = file_resp
        file_resp.headers = {"content-length": "3"}
        file_resp.iter_content.return_value = [payload]
        file_resp.raise_for_status = lambda: None
        file_responses.append(file_resp)
    mock_get.side_effect = [html_resp, *file_responses]

    head_resp = MagicMock()
    head_resp.status_code = 200
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    result = download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
        max_size=6,
    )

    assert result == tmp_path
    assert (tmp_path / "first.pth").read_bytes() == b"one"
    assert (tmp_path / "second.pth").read_bytes() == b"two"
    assert mock_head.call_count == 2
    assert all(call.kwargs["allow_redirects"] is True for call in mock_head.call_args_list)
    assert head_resp.close.call_count == 2


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_handles_huge_advertised_size(
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
    head_resp.status_code = 200
    head_resp.headers = {"content-length": str(10**400)}
    mock_head.return_value = head_resp

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=3,
        )

    mock_check.assert_not_called()
    mock_get.assert_called_once_with("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10)


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
    head_resp.status_code = 405
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
    head_resp.status_code = 200
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
    file_resp.headers = {"content-length": "3"}
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = False
    head_resp.status_code = 405
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


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_rejects_known_total_before_temp_dir(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_mkdtemp: MagicMock,
) -> None:
    weight_url = "https://download.pytorch.org/models/resnet50.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">link</a>'
    html_resp.raise_for_status = lambda: None
    mock_get.return_value = html_resp

    head_resp = MagicMock()
    head_resp.status_code = 200
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

    mock_mkdtemp.assert_not_called()
    mock_get.assert_called_once_with("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10)
    mock_head.assert_called_once_with(weight_url, timeout=10, allow_redirects=True)


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_enforces_cumulative_actual_size(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    stream_dir = tmp_path / "stream"
    stream_dir.mkdir()
    mock_mkdtemp.return_value = str(stream_dir)
    first_url = "https://download.pytorch.org/models/first.pth"
    second_url = "https://download.pytorch.org/models/second.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{first_url}">first</a><a href="{second_url}">second</a>'
    html_resp.raise_for_status = lambda: None

    file_responses = []
    for payload in (b"abc", b"def"):
        file_resp = MagicMock()
        file_resp.__enter__.return_value = file_resp
        file_resp.headers = {"content-length": "1"}
        file_resp.iter_content.return_value = [payload]
        file_resp.raise_for_status = lambda: None
        file_responses.append(file_resp)
    mock_get.side_effect = [html_resp, *file_responses]

    head_resp = MagicMock()
    head_resp.status_code = 405
    head_resp.headers = {}
    mock_head.return_value = head_resp

    generator = download_pytorch_hub_model_streaming(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        show_progress=False,
        max_size=5,
    )
    first_path, is_last = next(generator)
    assert first_path.read_bytes() == b"abc"
    assert is_last is False

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        next(generator)

    assert not stream_dir.exists()


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_allows_exact_size_limit(
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
    file_resp.headers = {"content-length": "6"}
    file_resp.iter_content.return_value = [b"abc", b"def"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.status_code = 200
    head_resp.headers = {"content-length": "6"}
    mock_head.return_value = head_resp

    yielded = [
        (file_path.read_bytes(), is_last)
        for file_path, is_last in download_pytorch_hub_model_streaming(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            show_progress=False,
            max_size=6,
        )
    ]

    assert yielded == [(b"abcdef", True)]
    assert not stream_dir.exists()


@patch("modelaudit.utils.sources.pytorch_hub.tempfile.mkdtemp")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_streaming_deduplicates_links_before_budget_check(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_mkdtemp: MagicMock,
    tmp_path: Path,
) -> None:
    stream_dir = tmp_path / "stream"
    stream_dir.mkdir()
    mock_mkdtemp.return_value = str(stream_dir)
    weight_url = "https://download.pytorch.org/models/resnet50.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">first</a><a href="{weight_url}">second</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.headers = {"content-length": "3"}
    file_resp.iter_content.return_value = [b"abc"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock()
    head_resp.status_code = 200
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp

    yielded = [
        (file_path.read_bytes(), is_last)
        for file_path, is_last in download_pytorch_hub_model_streaming(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            show_progress=False,
            max_size=4,
        )
    ]

    assert yielded == [(b"abc", True)]
    assert not stream_dir.exists()
    mock_head.assert_called_once_with(weight_url, timeout=10, allow_redirects=True)
    assert mock_get.call_count == 2


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
