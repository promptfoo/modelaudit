import os
from pathlib import Path
from unittest.mock import MagicMock, call, patch
from urllib.parse import quote

import pytest
import requests

from modelaudit.utils.sources.pytorch_hub import (
    _artifact_download_paths,
    _commit_staged_weight_files_secure,
    _extract_weight_urls,
    _get_total_size,
    _open_trusted_artifact_response,
    _supports_secure_cache_commit,
    download_pytorch_hub_model,
    download_pytorch_hub_model_streaming,
    is_pytorch_hub_url,
)


class TestPytorchHubURLDetection:
    def test_valid_urls(self) -> None:
        valid = [
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            "https://pytorch.org/hub/ultralytics_yolov5/",
            "HTTPS://PYTORCH.ORG/hub/pytorch_vision_resnet/",
        ]
        for url in valid:
            assert is_pytorch_hub_url(url)

    def test_invalid_urls(self) -> None:
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
    file_resp.status_code = 200
    file_resp.headers = {"content-length": "3"}
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
    mock_get.assert_any_call(weight_url, stream=True, timeout=30, allow_redirects=False)


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_redacts_signed_query_from_errors(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/resnet50.onnx?token=top-secret"
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">onnx</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.status_code = 403
    file_resp.raise_for_status.side_effect = requests.HTTPError(f"403 for {weight_url}")
    mock_get.side_effect = [html_resp, file_resp]
    mock_head.return_value.ok = False

    with pytest.raises(Exception) as exc_info:
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
        )

    assert "top-secret" not in str(exc_info.value)
    assert "https://download.pytorch.org/models/resnet50.onnx" in str(exc_info.value)


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_rejects_external_artifact_redirect(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/resnet50.onnx"
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">onnx</a>'
    html_resp.raise_for_status = lambda: None
    redirect_resp = MagicMock()
    redirect_resp.__enter__.return_value = redirect_resp
    redirect_resp.status_code = 302
    redirect_resp.headers = {"location": "https://example.com/resnet50.onnx"}
    mock_get.side_effect = [html_resp, redirect_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    with pytest.raises(ValueError, match="Unsafe PyTorch Hub model URL"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
        )

    mock_get.assert_has_calls(
        [
            call("https://pytorch.org/hub/pytorch_vision_resnet/", timeout=10),
            call(weight_url, stream=True, timeout=30, allow_redirects=False),
        ]
    )
    assert not (tmp_path / "resnet50.onnx").exists()


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_follows_trusted_artifact_redirect(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/resnet50.onnx"
    redirected_url = "https://download.pytorch.org/models/releases/resnet50.onnx"
    mock_extensions.return_value = {".onnx"}
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">onnx</a>'
    html_resp.raise_for_status = lambda: None
    redirect_resp = MagicMock()
    redirect_resp.__enter__.return_value = redirect_resp
    redirect_resp.status_code = 302
    redirect_resp.headers = {"location": "/models/releases/resnet50.onnx"}
    file_resp = MagicMock()
    file_resp.__enter__.return_value = file_resp
    file_resp.status_code = 200
    file_resp.iter_content.return_value = [b"model"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, redirect_resp, file_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "5"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    result = download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert result == tmp_path
    assert (tmp_path / "resnet50.onnx").read_bytes() == b"model"
    mock_get.assert_any_call(redirected_url, stream=True, timeout=30, allow_redirects=False)


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_rejects_format_changing_redirect(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    mock_extensions: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/model.onnx"
    redirected_url = "https://download.pytorch.org/models/model.pkl"
    mock_extensions.return_value = {".onnx", ".pkl"}
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">onnx</a>'
    html_resp.raise_for_status = lambda: None
    redirect_resp = MagicMock()
    redirect_resp.__enter__.return_value = redirect_resp
    redirect_resp.status_code = 302
    redirect_resp.headers = {"location": redirected_url}
    mock_get.side_effect = [html_resp, redirect_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "5"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    with pytest.raises(ValueError, match="changed artifact format"):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
        )

    assert call(redirected_url, stream=True, timeout=30, allow_redirects=False) not in mock_get.mock_calls
    assert not (tmp_path / "model.onnx").exists()


@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_open_trusted_artifact_response_rejects_non_artifact_success_status(mock_get: MagicMock) -> None:
    weight_url = "https://download.pytorch.org/models/model.onnx"
    response = MagicMock()
    response.__enter__.return_value = response
    response.status_code = 204
    response.raise_for_status = lambda: None
    mock_get.return_value = response

    with (
        pytest.raises(requests.HTTPError, match="Unexpected status code 204"),
        _open_trusted_artifact_response(weight_url),
    ):
        pass


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_open_trusted_artifact_response_allows_equivalent_pytorch_suffix_redirect(
    mock_get: MagicMock,
    mock_extensions: MagicMock,
) -> None:
    weight_url = "https://download.pytorch.org/models/model.pt"
    redirected_url = "https://download.pytorch.org/models/releases/model.pth"
    mock_extensions.return_value = {".pt", ".pth"}
    redirect_response = MagicMock()
    redirect_response.__enter__.return_value = redirect_response
    redirect_response.status_code = 302
    redirect_response.headers = {"location": redirected_url}
    artifact_response = MagicMock()
    artifact_response.__enter__.return_value = artifact_response
    artifact_response.status_code = 200
    mock_get.side_effect = [redirect_response, artifact_response]

    with _open_trusted_artifact_response(weight_url) as response:
        assert response is artifact_response

    mock_get.assert_has_calls(
        [
            call(weight_url, stream=True, timeout=30, allow_redirects=False),
            call(redirected_url, stream=True, timeout=30, allow_redirects=False),
        ]
    )


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
        '<a href="https://download.pytorch.org/models/backups/model.onnx">backup</a>'
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
    backup_resp = MagicMock()
    backup_resp.__enter__.return_value = backup_resp
    backup_resp.iter_content.return_value = [b"backup"]
    backup_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, foo_resp, bar_resp, backup_resp]

    head_resp = MagicMock()
    head_resp.ok = True
    head_resp.headers = {"content-length": "3"}
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    for parent in (tmp_path / "foo", tmp_path / "bar", tmp_path / "backups"):
        parent.mkdir()
        (parent / "model.onnx").write_bytes(b"old")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert (tmp_path / "foo" / "model.onnx").read_bytes() == b"foo"
    assert (tmp_path / "bar" / "model.onnx").read_bytes() == b"bar"
    assert (tmp_path / "backups" / "model.onnx").read_bytes() == b"backup"


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
@pytest.mark.parametrize(
    "commit_error",
    [OSError("simulated second-file commit failure"), KeyboardInterrupt("simulated commit interruption")],
)
def test_download_pytorch_hub_model_rolls_back_cache_on_commit_failure(
    mock_get: MagicMock,
    mock_head: MagicMock,
    commit_error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_url = "https://download.pytorch.org/models/nested/first.pth"
    second_url = "https://download.pytorch.org/models/nested/second.pth"
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

    first_cache = tmp_path / "nested" / "first.pth"
    second_cache = tmp_path / "nested" / "second.pth"
    first_cache.parent.mkdir()
    first_cache.write_bytes(b"old-first")
    second_cache.write_bytes(b"old-second")

    original_replace = Path.replace

    def _fail_second_commit(path: Path, target: Path) -> Path:
        target_path = Path(target)
        if (
            path.name == "second.pth"
            and path.parents[1].name == "files"
            and path.parents[2].name.startswith(".modelaudit_pth_stage_")
            and target_path == second_cache
        ):
            raise commit_error
        return original_replace(path, target_path)

    monkeypatch.setattr(Path, "replace", _fail_second_commit)
    monkeypatch.setattr(
        "modelaudit.utils.sources.pytorch_hub._supports_secure_cache_commit",
        lambda: False,
    )

    with pytest.raises(type(commit_error)):
        download_pytorch_hub_model(
            "https://pytorch.org/hub/pytorch_vision_resnet/",
            cache_dir=tmp_path,
            max_size=100,
        )

    assert first_cache.read_bytes() == b"old-first"
    assert second_cache.read_bytes() == b"old-second"
    assert not list(tmp_path.glob(".modelaudit_pth_stage_*"))


def test_secure_cache_commit_rolls_back_nested_files_on_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not _supports_secure_cache_commit():
        pytest.skip("secure directory-descriptor cache commits are unavailable")

    relative_paths = [Path("nested/first.pth"), Path("nested/second.pth")]
    artifacts = [(f"https://download.pytorch.org/models/{path.as_posix()}", path) for path in relative_paths]
    files_dir = tmp_path / "stage" / "files"
    backup_dir = tmp_path / "stage" / "backups"
    dest_dir = tmp_path / "cache"
    for root in (files_dir, dest_dir):
        (root / "nested").mkdir(parents=True)
    backup_dir.mkdir(parents=True)
    for path in relative_paths:
        (files_dir / path).write_bytes(f"new-{path.stem}".encode())
        (dest_dir / path).write_bytes(f"old-{path.stem}".encode())

    original_rename = os.rename

    def interrupt_second_install(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        if Path(source) == files_dir / relative_paths[1] and destination == relative_paths[1].name:
            raise KeyboardInterrupt("simulated commit interruption")
        original_rename(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(os, "rename", interrupt_second_install)

    with pytest.raises(KeyboardInterrupt, match="simulated commit interruption"):
        _commit_staged_weight_files_secure(artifacts, files_dir, backup_dir, dest_dir)

    assert (dest_dir / relative_paths[0]).read_bytes() == b"old-first"
    assert (dest_dir / relative_paths[1]).read_bytes() == b"old-second"


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_replaces_cache_hardlink_atomically(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/model.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">weight</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock(status_code=200, headers={"content-length": "3"})
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"new"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock(status_code=200, ok=True, headers={"content-length": "3"})
    mock_head.return_value = head_resp
    mock_check.return_value = (True, "ok")

    outside_file = tmp_path / "outside.pth"
    outside_file.write_bytes(b"old")
    cached_file = tmp_path / "model.pth"
    try:
        cached_file.hardlink_to(outside_file)
    except OSError as exc:  # pragma: no cover - depends on host hardlink support
        pytest.skip(f"hardlinks unavailable: {exc}")

    download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=tmp_path,
    )

    assert cached_file.read_bytes() == b"new"
    assert outside_file.read_bytes() == b"old"


@patch("modelaudit.utils.sources.pytorch_hub.check_disk_space")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
@patch("modelaudit.utils.sources.pytorch_hub.requests.get")
def test_download_pytorch_hub_model_pins_symlinked_cache_root(
    mock_get: MagicMock,
    mock_head: MagicMock,
    mock_check: MagicMock,
    tmp_path: Path,
) -> None:
    weight_url = "https://download.pytorch.org/models/model.pth"
    html_resp = MagicMock()
    html_resp.text = f'<a href="{weight_url}">weight</a>'
    html_resp.raise_for_status = lambda: None
    file_resp = MagicMock(status_code=200, headers={"content-length": "3"})
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"new"]
    file_resp.raise_for_status = lambda: None
    mock_get.side_effect = [html_resp, file_resp]

    head_resp = MagicMock(status_code=200, ok=True, headers={"content-length": "3"})
    mock_head.return_value = head_resp

    real_cache = tmp_path / "real-cache"
    outside_cache = tmp_path / "outside-cache"
    cache_link = tmp_path / "cache-link"
    real_cache.mkdir()
    outside_cache.mkdir()
    try:
        cache_link.symlink_to(real_cache, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on host symlink support
        pytest.skip(f"symlinks unavailable: {exc}")

    def swap_cache_link(path: Path, required_bytes: int) -> tuple[bool, str]:
        assert path == real_cache
        assert required_bytes == 3
        cache_link.unlink()
        cache_link.symlink_to(outside_cache, target_is_directory=True)
        return True, "ok"

    mock_check.side_effect = swap_cache_link

    result = download_pytorch_hub_model(
        "https://pytorch.org/hub/pytorch_vision_resnet/",
        cache_dir=cache_link,
    )

    assert result == real_cache
    assert (real_cache / "model.pth").read_bytes() == b"new"
    assert not (outside_cache / "model.pth").exists()


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
    assert all(call.kwargs["allow_redirects"] is False for call in mock_head.call_args_list)
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


def test_extract_weight_urls_deduplicates_repeated_links() -> None:
    url = "https://download.pytorch.org/models/resnet50.pth"
    assert _extract_weight_urls(f'<a href="{url}">first</a><a href="{url}">second</a>') == [url]


def test_download_pytorch_hub_model_invalid_url() -> None:
    with pytest.raises(ValueError):
        download_pytorch_hub_model("https://example.com/model")


def test_extract_weight_urls_multi_part_extensions() -> None:
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
def test_extract_weight_urls_decodes_entities_once_in_raw_text(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}
    html = (
        "<!-- https://download.pytorch.org/models/comment.onnx?x=1&amp;y=2 -->"
        "<script>const model = 'https://download.pytorch.org/models/script.onnx?x=1&amp;y=2';</script>"
    )

    assert _extract_weight_urls(html) == [
        "https://download.pytorch.org/models/comment.onnx?x=1&y=2",
        "https://download.pytorch.org/models/script.onnx?x=1&y=2",
    ]


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_does_not_invent_prefix_from_attribute(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}

    assert _extract_weight_urls('<a href="https://download.pytorch.org/models/model.onnx&quot;.txt">model</a>') == []


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
def test_extract_weight_urls_rejects_invalid_encoded_utf8(mock_extensions: MagicMock) -> None:
    """Invalid encoded bytes must not collapse into a local artifact identity."""
    mock_extensions.return_value = {".onnx"}

    assert _extract_weight_urls("https://download.pytorch.org/models/%FF.onnx") == []


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
def test_extract_weight_urls_does_not_invent_double_encoded_extensions(mock_extensions: MagicMock) -> None:
    mock_extensions.return_value = {".onnx"}

    assert _extract_weight_urls("https://download.pytorch.org/models/model%252Eonnx") == []


@patch("modelaudit.utils.sources.pytorch_hub._get_model_extensions")
@patch("modelaudit.utils.sources.pytorch_hub.requests.head")
def test_get_total_size_follows_only_trusted_artifact_redirects(
    mock_head: MagicMock,
    mock_extensions: MagicMock,
) -> None:
    original_url = "https://download.pytorch.org/models/model.onnx"
    redirected_url = "https://download.pytorch.org/models/releases/model.onnx"
    mock_extensions.return_value = {".onnx"}
    redirect_response = MagicMock(status_code=302, headers={"location": redirected_url})
    artifact_response = MagicMock(status_code=200, ok=True, headers={"content-length": "123"})
    mock_head.side_effect = [redirect_response, artifact_response]

    assert _get_total_size([original_url]) == 123
    assert mock_head.mock_calls == [
        call(original_url, timeout=10, allow_redirects=False),
        call(redirected_url, timeout=10, allow_redirects=False),
    ]
    redirect_response.close.assert_called_once_with()
    artifact_response.close.assert_called_once_with()


def test_artifact_download_paths_are_portable_and_do_not_conflict() -> None:
    urls = [
        "https://download.pytorch.org/models/CON.onnx",
        "https://download.pytorch.org/models/COM%C2%B9.onnx",
        "https://download.pytorch.org/models/LPT%C2%B3.onnx",
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
        "__modelaudit_COM¹.onnx",
        "__modelaudit_LPT³.onnx",
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
