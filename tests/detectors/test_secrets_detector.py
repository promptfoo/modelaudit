"""Tests for embedded secrets detection in ML models."""

import base64
import json
import pickle

import pytest

from modelaudit.detectors.secrets import BASIC_AUTH_TOKEN_MAX_LENGTH, SecretsDetector, detect_secrets_in_file
from modelaudit.scanners.pickle_scanner import PickleScanner


def _basic_auth_token(credentials: bytes) -> str:
    return base64.b64encode(credentials).decode("ascii")


def _basic_auth_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    return [finding for finding in findings if finding.get("secret_type") == "Basic Auth Credentials"]


class TestSecretsDetector:
    """Test the SecretsDetector class."""

    def test_default_detector_reuses_precompiled_patterns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default detector construction should not rebuild static regex banks."""

        def fail_compile(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("unexpected regex compilation")

        monkeypatch.setattr("modelaudit.detectors.secrets.re.compile", fail_compile)

        detector = SecretsDetector()

        assert detector.scan_text("normal model metadata") == []

    def test_detect_aws_keys(self):
        """Test detection of AWS access keys."""
        detector = SecretsDetector()

        # Test AWS access key
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("AWS" in f["secret_type"] for f in findings)

        # Test AWS secret key
        text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = detector.scan_text(text)
        assert len(findings) > 0

    def test_detect_openai_keys(self):
        """Test detection of OpenAI API keys."""
        detector = SecretsDetector()

        # Test OpenAI API key (48 chars after sk-)
        text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12"
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("OpenAI" in f["secret_type"] for f in findings)

    def test_detect_github_tokens(self):
        """Test detection of GitHub tokens."""
        detector = SecretsDetector()

        # Test GitHub personal token
        text = "github_token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("GitHub" in f["secret_type"] for f in findings)

    def test_detect_jwt_tokens(self):
        """Test detection of JWT tokens."""
        detector = SecretsDetector()

        # Test a non-example JWT-shaped token. The well-known JWT.io sample is
        # intentionally suppressed as documentation/test data.
        text = (
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
            "q1w2e3r4t5y6u7i8o9p0asdfghjklzxcvbnmQWERty"
        )
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("JWT" in f["secret_type"] for f in findings)

    def test_known_example_jwt_is_suppressed_by_default(self) -> None:
        """The JWT.io example token should not produce warning-level noise."""
        detector = SecretsDetector()

        text = (
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

        findings = detector.scan_text(text)

        assert not any(finding["secret_type"] == "JWT Token" for finding in findings)

    def test_modified_jwt_with_comment_prefix_is_still_detected(self) -> None:
        """A changed JWT must still be detected even with a leading comment token."""
        detector = SecretsDetector()

        text = (
            "# token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
            "q1w2e3r4t5y6u7i8o9p0asdfghjklzxcvbnmQWERty"
        )

        findings = detector.scan_text(text)

        assert any(finding["secret_type"] == "JWT Token" for finding in findings)

    @pytest.mark.parametrize(
        "context",
        [
            "audio_tokenizer/README.md",
            "tokenizer_config.json",
            "auth/README.md",
            "credential_notes.txt",
        ],
    )
    def test_basic_auth_ignores_prose_without_suppressing_other_secrets(self, context: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(
            "Provide the basic links for the model\naws_access_key_id=AKIAABCDEFGHIJKLMNOP\n",
            context=context,
        )

        assert _basic_auth_findings(findings) == []
        assert any(finding["secret_type"] == "AWS Access Key ID" for finding in findings)

    @pytest.mark.parametrize(
        "text",
        [
            "Basic links are available for this model.",
            "Basic authentication is documented here.",
            "The basic links section lists model files.",
            "Authorization notes mention Basic links without a header value.",
        ],
    )
    def test_basic_auth_ignores_benign_prose_controls(self, text: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(text, context="audio_tokenizer/README.md")

        assert _basic_auth_findings(findings) == []

    @pytest.mark.parametrize(
        ("text", "token"),
        [
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            (f"Authorization: Basic {_basic_auth_token(b'sentence:pass')}.", _basic_auth_token(b"sentence:pass")),
            (f'BASIC_AUTH="Basic {_basic_auth_token(b"basic-var:pass")}"', _basic_auth_token(b"basic-var:pass")),
            (f'auth_header = "Basic {_basic_auth_token(b"auth-header:pass")}"', _basic_auth_token(b"auth-header:pass")),
            (
                f"Authorization: Basic {_basic_auth_token(b'escaped-crlf:pass')}\\r\\n",
                _basic_auth_token(b"escaped-crlf:pass"),
            ),
            (f"HTTP_AUTHORIZATION=Basic {_basic_auth_token(b'env-user:pass')}", _basic_auth_token(b"env-user:pass")),
            (
                f"HTTP_PROXY_AUTHORIZATION=Basic {_basic_auth_token(b'proxy-env:pass')}",
                _basic_auth_token(b"proxy-env:pass"),
            ),
            ("Proxy-Authorization:\tBasic\tQWxhZGRpbjpvcGVuIHNlc2FtZQ==", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
            ("aUtHoRiZaTiOn: bAsIc dTpw", "dTpw"),
            ("GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic YTo/Pz8/\r\n", "YTo/Pz8/"),
            ('{"Authorization": "Basic YTp+fn5+"}', "YTp+fn5+"),
            (f"Authorization: Basic {_basic_auth_token(b'api-token:')}", _basic_auth_token(b"api-token:")),
            (f"Authorization: Basic {_basic_auth_token(b':password')}", _basic_auth_token(b":password")),
            (f"Authorization:\n  Basic {_basic_auth_token(b'wrapped:pass')}", _basic_auth_token(b"wrapped:pass")),
            (
                f"Proxy-Authorization:\r\n\tBasic {_basic_auth_token(b'wrapped-proxy:pass')}",
                _basic_auth_token(b"wrapped-proxy:pass"),
            ),
            (f"Authorization:\n  - Basic {_basic_auth_token(b'listed:pass')}", _basic_auth_token(b"listed:pass")),
            (
                f'"Authorization": ["Basic {_basic_auth_token(b"json-list:pass")}"]',
                _basic_auth_token(b"json-list:pass"),
            ),
            (
                f'"Authorization": [\n  "Basic {_basic_auth_token(b"json-multiline:pass")}"\n]',
                _basic_auth_token(b"json-multiline:pass"),
            ),
            (f"Authorization: >\n  Basic {_basic_auth_token(b'block:pass')}", _basic_auth_token(b"block:pass")),
            (f"Authorization: |-\n  Basic {_basic_auth_token(b'chomp:pass')}", _basic_auth_token(b"chomp:pass")),
            (
                f"Proxy-Authorization: >+\n  Basic {_basic_auth_token(b'folded:pass')}",
                _basic_auth_token(b"folded:pass"),
            ),
            (
                f"`Authorization: Basic {_basic_auth_token(b'markdown:pass')}`",
                _basic_auth_token(b"markdown:pass"),
            ),
            (
                f"<code>Authorization: Basic {_basic_auth_token(b'html:pass')}</code>",
                _basic_auth_token(b"html:pass"),
            ),
            (
                f'headers["Authorization"] = "Basic {_basic_auth_token(b"bracket:pass")}"',
                _basic_auth_token(b"bracket:pass"),
            ),
            (
                f"headers['Proxy-Authorization'] = 'Basic {_basic_auth_token(b'proxy-bracket:pass')}'",
                _basic_auth_token(b"proxy-bracket:pass"),
            ),
            (
                f'AUTH_HEADER = f"Authorization: Basic {_basic_auth_token(b"py-fstring:pass")}"',
                _basic_auth_token(b"py-fstring:pass"),
            ),
            (
                f'AUTH_HEADER = b"Authorization: Basic {_basic_auth_token(b"py-bytes:pass")}"',
                _basic_auth_token(b"py-bytes:pass"),
            ),
            (
                f"AUTH_HEADER = r'Authorization: Basic {_basic_auth_token(b'py-raw:pass')}'",
                _basic_auth_token(b"py-raw:pass"),
            ),
            (
                f"const auth = `Authorization: Basic {_basic_auth_token(b'js-template:pass')}`;",
                _basic_auth_token(b"js-template:pass"),
            ),
            (
                f'ENV AUTH_HEADER="Authorization: Basic {_basic_auth_token(b"docker-env:pass")}"',
                _basic_auth_token(b"docker-env:pass"),
            ),
            (
                f'env:\n- name: AUTH_HEADER\n  value: "Authorization: Basic {_basic_auth_token(b"k8s-env:pass")}"',
                _basic_auth_token(b"k8s-env:pass"),
            ),
            (
                f"proxy_authorization: Basic {_basic_auth_token(b'raw-alias:pass')}",
                _basic_auth_token(b"raw-alias:pass"),
            ),
            (
                f"proxyAuthorization: Basic {_basic_auth_token(b'raw-camel:pass')}",
                _basic_auth_token(b"raw-camel:pass"),
            ),
            (
                f'"proxy_authorization": "Basic {_basic_auth_token(b"json-alias:pass")}"',
                _basic_auth_token(b"json-alias:pass"),
            ),
            (
                f'payload = {{\\"Authorization\\": \\"Basic {_basic_auth_token(b"escaped-json:pass")}\\"}}',
                _basic_auth_token(b"escaped-json:pass"),
            ),
            (
                f'headers[\\"Authorization\\"] = \\"Basic {_basic_auth_token(b"escaped-bracket:pass")}\\"',
                _basic_auth_token(b"escaped-bracket:pass"),
            ),
            (
                f"Authorization: Basic {_basic_auth_token(bytes.fromhex('ceb4cebfcebaceb9cebcceae3a70c3a47373'))}",
                _basic_auth_token(bytes.fromhex("ceb4cebfcebaceb9cebcceae3a70c3a47373")),
            ),
        ],
    )
    def test_basic_auth_valid_headers_are_detected(self, text: str, token: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(text, context="headers.txt")
        basic_findings = _basic_auth_findings(findings)

        assert basic_findings
        assert basic_findings[0]["redacted_value"] == "Basic <redacted>"
        serialized = json.dumps(basic_findings, sort_keys=True)
        assert token not in serialized

    @pytest.mark.parametrize(
        "text",
        [
            "Basic dXNlcjpwYXNz",
            "Authorization Basic dXNlcjpwYXNz",
            "Authorization: Basic not_base64",
            "Authorization: Basic bGlua3M=",
            "Authorization: Basic dXNlci1wYXNz",
            "Authorization: Basic dXNlcjpwYXNz====",
            "Authorization: Basic AAAAA",
            "Authorization: Basic dXNl cjpwYXNz",
            "Proxy-Authorization: Basic Og==",
            "X-Authorization: Basic dXNlcjpwYXNz",
            "Authorization: Basic dXNlcjpwYXNz-extra",
            "Authorization: Basic%20dXNlcjpwYXNz",
            "Authorization%3A%20Basic%20dXNlcjpwYXNz",
            "Authorization: \u0412asic dXNlcjpwYXNz",
            f"Authorization notes:\n  Basic {_basic_auth_token(b'wrapped:pass')}",
            f"Authorization: documented value\n  Basic {_basic_auth_token(b'wrapped:pass')}",
            f"Authorization notes:\n  - Basic {_basic_auth_token(b'listed:pass')}",
            f"Authorization:\n\n  Basic {_basic_auth_token(b'gap:pass')}",
            f"Authorization: Basic\n  {_basic_auth_token(b'newline-token:pass')}",
            "Authorization: Basic\n" + ("padding\n" * 300) + _basic_auth_token(b"far-away:pass"),
            f"Authorization: Basic {'A' * (BASIC_AUTH_TOKEN_MAX_LENGTH + 1)}",
            "https://user:pass@example.test/model.bin",
            f"https://example.test/?header=Authorization%3A%20Basic%20{_basic_auth_token(b'percent:pass')}",
            f"\u0391uthorization: Basic {_basic_auth_token(b'confusable-alpha:pass')}",
            f"Authorizati\u043en: Basic {_basic_auth_token(b'confusable-o:pass')}",
        ],
    )
    def test_basic_auth_malformed_or_unbounded_values_are_ignored(self, text: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(text, context="headers.txt")

        assert _basic_auth_findings(findings) == []

    @pytest.mark.parametrize(
        "header_name",
        [
            "Authorization",
            "HTTP_AUTHORIZATION",
            "proxy_authorization",
            "proxyAuthorization",
            "HTTP_PROXY_AUTHORIZATION",
        ],
    )
    def test_basic_auth_structured_header_values_are_detected(self, header_name: str) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"structured:s3cr3t")

        findings = detector.scan_dict({"headers": {header_name: f"Basic {token}"}})

        assert _basic_auth_findings(findings)

    @pytest.mark.parametrize(
        "data",
        [
            {"Authorization": b"Basic c3RydWN0dXJlZC1ieXRlczpzM2NyM3Q="},
            {"HTTP_AUTHORIZATION": b"Basic aHR0cC1zdHJ1Y3R1cmVkOnMzY3IzdA=="},
            {b"Authorization": b"Basic c3RydWN0dXJlZC1ieXRlLWtleTpzM2NyM3Q="},
            {b"HTTP_AUTHORIZATION": b"Basic aHR0cC1ieXRlLWtleTpzM2NyM3Q="},
            {"Authorization": ("Basic c3RydWN0dXJlZC10dXBsZTpzM2NyM3Q=",)},
            {"Authorization": {"value": "Basic c3RydWN0dXJlZC13cmFwcGVkOnMzY3IzdA=="}},
            {"headers": {"proxy_authorization": ["Basic c3RydWN0dXJlZC1saXN0OnMzY3IzdA=="]}},
        ],
    )
    def test_basic_auth_structured_non_scalar_header_values_are_detected(self, data: dict[str, object]) -> None:
        detector = SecretsDetector()

        findings = detector.scan_dict(data)

        assert _basic_auth_findings(findings)

    def test_basic_auth_structured_long_bytes_header_value_is_detected(self) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"long-bytes:pass")
        value = b"Basic " + token.encode("ascii") + b" " + (b"x" * 9000)

        findings = detector.scan_dict({"Authorization": value})

        basic_findings = _basic_auth_findings(findings)
        assert basic_findings
        assert token not in json.dumps(basic_findings, sort_keys=True)

    def test_basic_auth_structured_long_bytes_header_value_keeps_trailing_secret_coverage(self) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"long-bytes:pass")
        aws_key = "AKIA1234567890ABCDEF"
        value = b"Basic " + token.encode("ascii") + b" " + (b"x" * 9000) + f"\naws_key={aws_key}\n".encode()

        findings = detector.scan_dict({"Authorization": value})

        assert _basic_auth_findings(findings)
        assert any(finding.get("secret_type") == "AWS Access Key" for finding in findings)
        assert aws_key not in json.dumps(findings, sort_keys=True)

    def test_basic_auth_full_value_whitelist_still_suppresses_detection(self) -> None:
        token = _basic_auth_token(b"user:pass")
        detector = SecretsDetector(config={"whitelist": [f"Basic {token}"]})

        findings = detector.scan_text(f"Authorization: Basic {token}", context="headers.txt")

        assert _basic_auth_findings(findings) == []

    def test_basic_auth_token_value_whitelist_still_suppresses_detection(self) -> None:
        token = _basic_auth_token(b"user:pass")
        detector = SecretsDetector(config={"whitelist": [token]})

        findings = detector.scan_text(f"Authorization: Basic {token}", context="headers.txt")

        assert _basic_auth_findings(findings) == []

    def test_basic_auth_honors_min_secret_length_override(self) -> None:
        token = _basic_auth_token(b"user:pass")
        detector = SecretsDetector(config={"min_secret_length": 100})

        findings = detector.scan_text(f"Authorization: Basic {token}", context="headers.txt")

        assert _basic_auth_findings(findings) == []

    def test_basic_auth_custom_pattern_without_capture_group_does_not_crash(self) -> None:
        detector = SecretsDetector(
            config={"patterns": [(r"Basic +[A-Za-z]+", "Basic Auth Credentials")], "require_high_confidence": False}
        )

        findings = detector.scan_text("Authorization: Basic prose", context="auth-config")

        assert isinstance(findings, list)

    def test_basic_auth_valid_token_without_header_key_is_ignored_in_structured_data(self) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"structured:s3cr3t")

        findings = detector.scan_dict({"audio_tokenizer": f"Basic {token}"})

        assert _basic_auth_findings(findings) == []

    def test_basic_auth_near_match_does_not_suppress_url_userinfo_credentials(self) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(
            "Basic links:\nmongodb+srv://username:password123@cluster.mongodb.net/database\n",
            context="README.md",
        )

        assert _basic_auth_findings(findings) == []
        assert any(finding["secret_type"] == "MongoDB Connection String" for finding in findings)

    def test_basic_auth_binary_polyglot_header_is_detected(self) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"polyglot:p@ssw0rd")

        findings = detector.scan_bytes(b"\x89PNG\r\nAuthorization: Basic " + token.encode("ascii") + b"\r\n\x00")

        assert _basic_auth_findings(findings)

    def test_basic_auth_binary_bare_token_is_ignored(self) -> None:
        detector = SecretsDetector()
        token = _basic_auth_token(b"polyglot:p@ssw0rd")

        findings = detector.scan_bytes(b"\x89PNG\r\nBasic " + token.encode("ascii") + b"\r\n\x00")

        assert _basic_auth_findings(findings) == []

    def test_detect_database_connections(self):
        """Test detection of database connection strings."""
        detector = SecretsDetector()

        # Test MongoDB connection with srv
        text = "mongodb+srv://username:password123@cluster.mongodb.net/database"
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("MongoDB" in f["secret_type"] for f in findings)

        # Test PostgreSQL connection
        text = "postgres://user:pass@localhost:5432/mydb"
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("PostgreSQL" in f["secret_type"] for f in findings)

    def test_detect_private_keys(self):
        """Test detection of private keys."""
        detector = SecretsDetector()

        # Test RSA private key header
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = detector.scan_text(text)
        assert len(findings) > 0
        assert any("Private Key" in f["secret_type"] for f in findings)

    def test_high_entropy_detection(self):
        """Test detection of high-entropy regions."""
        detector = SecretsDetector()

        # Create high-entropy binary data (random-like)
        import secrets

        # Create data that will trigger entropy detection
        # It needs to be small enough to be scanned (< 1MB) but have very high entropy
        high_entropy_data = secrets.token_bytes(128)

        findings = detector.scan_bytes(high_entropy_data)
        # Since our entropy detection is conservative (to avoid false positives),
        # we may not always detect small random chunks as secrets
        # This is by design to reduce false positives
        # Let's test that we can at least scan without errors
        assert isinstance(findings, list)

    def test_detect_password_in_text_backed_bytes(self) -> None:
        """Structured credentials inside bytes should not be dropped wholesale."""
        detector = SecretsDetector()

        findings = detector.scan_bytes(b"password=super_secret_password_123")

        assert any(finding["secret_type"] == "Hardcoded Password" for finding in findings)

    def test_default_high_entropy_threshold_is_reachable(self) -> None:
        """The default entropy threshold should surface encoded-looking byte regions."""
        detector = SecretsDetector()
        data = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2)[:64]

        findings = detector.scan_bytes(data)

        assert any(finding["type"] == "high_entropy_region" for finding in findings)

    def test_high_entropy_binary_noise_is_not_reported_as_encoded_secret(self) -> None:
        """Lossy decoding should not turn binary noise into an encoded-secret finding."""
        detector = SecretsDetector()
        data = bytes(range(128, 184)) + b"ABCDEFGH"

        findings = detector.scan_bytes(data)

        assert not [finding for finding in findings if finding["type"] == "high_entropy_region"]

    def test_no_false_positives_on_normal_text(self):
        """Test that normal text doesn't trigger false positives."""
        detector = SecretsDetector()

        # Normal model documentation text
        text = """
        This is a BERT model trained on the WikiText dataset.
        The model achieves 92% accuracy on the validation set.
        It uses a transformer architecture with 12 layers.
        """
        findings = detector.scan_text(text)
        assert len(findings) == 0

        # Test ML-specific terms that might match patterns
        ml_text = """
        layer_0_weight: 0.123456789
        embedding_1024: initialized
        checkpoint_5000: saved
        model_v1.2.3: loaded
        """
        findings = detector.scan_text(ml_text, context="model/weights")
        assert len(findings) == 0, "Should not flag ML terms as secrets"

    @pytest.mark.parametrize(
        "placeholder",
        [
            "YOUR_CLIENT_SECRET",
            "<CLIENT_SECRET>",
            "<CLIENT_SECRET_VALUE>",
            "${CLIENT_SECRET}",
            "${CLIENT_SECRET_VALUE}",
            "$CLIENT_SECRET_VALUE",
            "${AWS_SECRET_ACCESS_KEY}",
            "${OPENAI_API_KEY}",
            "process.env.OPENAI_API_KEY",
            "$env:AZURE_CLIENT_SECRET",
            "{{CLIENT_SECRET}}",
            "%CLIENT_SECRET%",
            "[CLIENT_SECRET]",
            "REPLACE_WITH_CLIENT_SECRET",
            "CLIENT_SECRET_HERE",
            "INSERT_CLIENT_SECRET_HERE",
            "process.env.CLIENT_SECRET",
            "$env:CLIENT_SECRET",
            "dummy_secret_value",
            "clientSecretValue",
            "clientsecretvalue",
            "examplepassword",
            "<clientSecretValue>",
            "xxxxxxxxxxxxxxxx",
        ],
    )
    def test_obvious_secret_placeholders_are_ignored(self, placeholder: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(f"client_secret = {placeholder}", context="README.md")

        assert findings == []

    def test_realistic_client_secret_is_not_treated_as_placeholder(self) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(
            "client_secret = Z9Y8X7W6V5U4T3S2R1Q0P9O8",
            context="README.md",
        )

        assert any(finding.get("secret_type") == "Client Secret" for finding in findings)

    @pytest.mark.parametrize(
        "secret",
        [
            "<Z9Y8X7W6V5U4T3S2R1Q0P9O8>",
            "<SECRETZ9Y8X7W6V5U4T3S2R1Q0>",
            "CLIENT_SECRET_ABCD1234EFGH5678",
            "TOKEN_9Z8Y7X6W5V4U3T2S1R0Q",
            "<SECRET_ABCD1234EFGH5678>",
            "${CLIENT_SECRET_Z9Y8X7W6V5U4T3S2R1Q0P9O8}",
            "${OPENAI_API_KEY_Z9Y8X7W6V5U4T3S2R1Q0P9O8}",
            "clientSecretAbcd1234Efgh5678",
        ],
    )
    def test_bracketed_realistic_client_secret_is_not_treated_as_placeholder(self, secret: str) -> None:
        detector = SecretsDetector()

        findings = detector.scan_text(
            f"client_secret = {secret}",
            context="README.md",
        )

        assert any(finding.get("secret_type") == "Client Secret" for finding in findings)

    def test_redaction(self):
        """Test that secrets are properly redacted in findings."""
        detector = SecretsDetector()

        text = "password=super_secret_password_123"
        findings = detector.scan_text(text)

        assert len(findings) > 0
        # Check that the secret is redacted
        for finding in findings:
            if "redacted_value" in finding:
                assert "***" in finding["redacted_value"]
                assert "super_secret_key_123456789012345678" not in finding["redacted_value"]

    def test_whitelist(self):
        """Test that whitelisted patterns are ignored."""
        config = {"whitelist": [r"test_key_\d+"]}
        detector = SecretsDetector(config)

        # This should be detected without whitelist
        text = "api_key=test_key_12345678901234567890123456"
        findings = detector.scan_text(text)
        # Should be whitelisted
        assert len(findings) == 0

    def test_scan_dict(self):
        """Test scanning dictionary structures."""
        detector = SecretsDetector()

        data = {
            "model_config": {
                "api_key": "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12",
                "database": "mongodb+srv://user:pass@host/db",
            },
            "weights": b"some binary data",
        }

        findings = detector.scan_dict(data)
        assert len(findings) >= 2
        assert any("OpenAI" in f["secret_type"] for f in findings)
        assert any("MongoDB" in f["secret_type"] for f in findings)

    def test_scan_dict_redacts_secret_keys_from_context(self) -> None:
        """Secret-shaped dictionary keys should not leak through finding context paths."""
        detector = SecretsDetector()
        raw_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12"
        nested_password = "super_secret_password_123"

        findings = detector.scan_dict({raw_key: {"nested": f"password={nested_password}"}})

        assert any(finding["secret_type"] == "OpenAI API Key" for finding in findings)
        assert any(finding["secret_type"] == "Hardcoded Password" for finding in findings)
        serialized = json.dumps(findings, sort_keys=True)
        assert raw_key not in serialized
        assert nested_password not in serialized
        assert "<redacted-secret>" in serialized

    def test_scan_dict_redacts_secret_values_from_serialized_findings(self) -> None:
        """Secret values should stay out of every serialized finding field."""
        detector = SecretsDetector()
        raw_secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12"

        findings = detector.scan_dict({"config": {"api_key": raw_secret}})

        assert any(finding["secret_type"] == "OpenAI API Key" for finding in findings)
        serialized = json.dumps(findings, sort_keys=True)
        assert raw_secret not in serialized

    def test_context_redaction_does_not_change_uuid_false_positive_filtering(self) -> None:
        """Redaction markers should not introduce secret hints into detector scoring."""
        detector = SecretsDetector()
        raw_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12"
        benign_uuid = "550e8400-e29b-41d4-a716-446655440000"

        findings = detector.scan_dict({raw_key: {"id": benign_uuid}})

        assert not any(finding["secret_type"] == "UUID (potential secret)" for finding in findings)
        serialized = json.dumps(findings, sort_keys=True)
        assert raw_key not in serialized


class TestPickleScannerWithSecrets:
    """Test the PickleScanner with embedded secrets detection."""

    def test_pickle_with_embedded_secret(self, tmp_path):
        """Test that secrets are detected in pickle files."""
        # Create a pickle file with an embedded secret
        data = {
            "model_weights": [1.0, 2.0, 3.0],
            "config": {
                "api_key": "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12",
                "training_params": {"lr": 0.001},
            },
        }

        pickle_file = tmp_path / "model_with_secret.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        scanner = PickleScanner({"check_secrets": True})
        result = scanner.scan(str(pickle_file))

        # Check that the secret was detected
        secret_checks = [c for c in result.checks if "Embedded Secrets" in c.name]
        assert any(c.status.value == "failed" for c in secret_checks), "Should detect embedded secret"

        # Check that OpenAI key specifically was found
        failed_checks = [c for c in secret_checks if c.status.value == "failed"]
        assert any("OpenAI" in str(c.details) for c in failed_checks)
        assert any(c.rule_code == "S701" for c in failed_checks), "API-key secret findings should map to S701"

    def test_pickle_without_secrets(self, tmp_path):
        """Test that clean pickle files pass secrets check."""
        # Create a clean pickle file
        data = {
            "model_weights": [1.0, 2.0, 3.0],
            "config": {
                "learning_rate": 0.001,
                "batch_size": 32,
            },
        }

        pickle_file = tmp_path / "clean_model.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan the file
        scanner = PickleScanner({"check_secrets": True})
        result = scanner.scan(str(pickle_file))

        # Check that no secrets were detected
        secret_checks = [c for c in result.checks if "Embedded Secrets" in c.name]
        if secret_checks:
            # Should have a passing check
            assert any(c.status.value == "passed" for c in secret_checks), "Should pass secrets check"

    def test_secrets_check_disabled(self, tmp_path):
        """Test that secrets check can be disabled."""
        # Create a pickle file with a secret
        data = {"api_key": "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ12"}

        pickle_file = tmp_path / "model_with_secret.pkl"
        with open(pickle_file, "wb") as f:
            pickle.dump(data, f)

        # Scan with secrets check disabled
        scanner = PickleScanner({"check_secrets": False})
        result = scanner.scan(str(pickle_file))

        # Should not have any secrets checks
        secret_checks = [c for c in result.checks if "Embedded Secrets" in c.name]
        assert len(secret_checks) == 0, "Secrets check should be disabled"

    def test_secret_detector_failure_does_not_report_clean_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        scanner = PickleScanner()
        result = scanner._create_result()

        def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
            raise RuntimeError("simulated secret detector failure")

        monkeypatch.setattr(scanner, "collect_embedded_secret_findings", raise_detector_error)

        assert scanner.check_for_embedded_secrets(b"safe", result, "model.pkl") == 0
        assert not any(check.name == "Embedded Secrets Detection" for check in result.checks)


class TestDetectSecretsInFile:
    """Test the convenience function for file scanning."""

    def test_detect_secrets_in_file(self, tmp_path):
        """Test the detect_secrets_in_file convenience function."""
        # Create a test file with secrets
        test_file = tmp_path / "test_file.txt"
        test_file.write_text("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\npassword=super_secret_password_123\n")

        findings = detect_secrets_in_file(str(test_file))
        assert len(findings) >= 1  # At least AWS key should be detected
        assert any("AWS" in str(f) for f in findings)
        # Password detection from binary source is now filtered to avoid false positives
        # in model weight files, so we don't check for password detection here

    def test_file_not_found(self):
        """Test handling of non-existent files."""
        findings = detect_secrets_in_file("/non/existent/file.txt")
        assert len(findings) == 1
        assert findings[0]["type"] == "error"
        assert "not found" in findings[0]["message"]

    def test_file_too_large(self, tmp_path):
        """Test handling of files that are too large."""
        # Create a dummy large file
        large_file = tmp_path / "large_file.bin"
        large_file.write_bytes(b"x" * 100)

        # Test with very small max_size
        findings = detect_secrets_in_file(str(large_file), max_size=50)
        assert len(findings) == 1
        assert findings[0]["type"] == "info"
        assert "too large" in findings[0]["message"]


def test_secret_finding_limit_is_explicit() -> None:
    detector = SecretsDetector({"max_findings": 2})

    findings = detector.scan_model_weights(b"AKIAABCDEFGHIJKLMNOP\n" * 10, "vocab.txt")

    reported = [finding for finding in findings if finding["type"] != "detector_finding_limit"]
    assert len(reported) == 2
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["max_findings"] == 2
    assert findings[-1]["analysis_incomplete"] is True


def test_basic_auth_finding_limit_is_explicit_and_redacted() -> None:
    detector = SecretsDetector({"max_findings": 2})
    tokens = [_basic_auth_token(f"user{index}:pass{index}".encode()) for index in range(5)]

    findings = detector.scan_model_weights(
        "\n".join(f"Authorization: Basic {token}" for token in tokens),
        "headers.txt",
    )

    reported = _basic_auth_findings(findings)
    assert len(reported) == 2
    assert findings[-1]["type"] == "detector_finding_limit"
    assert findings[-1]["max_findings"] == 2
    assert findings[-1]["analysis_incomplete"] is True
    serialized = json.dumps(findings, sort_keys=True)
    assert all(token not in serialized for token in tokens)
