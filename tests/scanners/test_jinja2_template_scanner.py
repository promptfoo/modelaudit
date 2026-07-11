"""Tests for Jinja2TemplateScanner covering CVE-2024-34359 and SSTI detection."""

import json
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from modelaudit.config.rule_config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import jinja2_template_scanner
from modelaudit.scanners.base import Check, CheckStatus, IssueSeverity, ScanResult
from modelaudit.scanners.jinja2_template_scanner import Jinja2TemplateScanner
from tests.helpers import create_mock_gguf

JINJA2_ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets" / "samples" / "jinja2"
MALICIOUS_JSON_FIXTURES = tuple(sorted((JINJA2_ASSETS_DIR / "malicious").glob("*.json"))) + tuple(
    sorted((JINJA2_ASSETS_DIR / "obfuscated").glob("*.json"))
)
BENIGN_JSON_FIXTURES = tuple(sorted((JINJA2_ASSETS_DIR / "benign").glob("*.json")))
MALICIOUS_STANDALONE_FIXTURES = (
    JINJA2_ASSETS_DIR / "standalone" / "malicious_standalone.jinja",
    JINJA2_ASSETS_DIR / "standalone" / "malicious_subprocess.template",
)
BENIGN_STANDALONE_FIXTURES = (
    JINJA2_ASSETS_DIR / "standalone" / "benign_chat.j2",
    JINJA2_ASSETS_DIR / "standalone" / "suspicious_benign.template",
)
MALICIOUS_YAML_FIXTURES = (JINJA2_ASSETS_DIR / "yaml" / "malicious_config.yaml",)
BENIGN_YAML_FIXTURES = (JINJA2_ASSETS_DIR / "yaml" / "model_config.yaml",)


def _fixture_id(path: Path) -> str:
    return path.name


def _copy_as_tokenizer_config(source: Path, tmp_path: Path) -> Path:
    """Route committed JSON template fixtures through the production tokenizer-config path."""
    target_dir = tmp_path / "huggingface" / source.parent.name / source.stem
    target_dir.mkdir(parents=True)
    target = target_dir / "tokenizer_config.json"
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _jinja_detection_checks(result: ScanResult) -> list[Check]:
    return [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]


def test_directory_scan_preserves_path_sensitive_yaml_routing(tmp_path: Path) -> None:
    misc_dir = tmp_path / "misc"
    model_dir = tmp_path / "model"
    misc_dir.mkdir()
    model_dir.mkdir()

    payload = "{{ cycler.__init__.__globals__.os.popen('id').read() }}\n"
    misc_file = misc_dir / "settings.yaml"
    model_file = model_dir / "settings.yaml"
    misc_file.write_text(payload, encoding="utf-8")
    model_file.write_text(payload, encoding="utf-8")

    result = scan_model_directory_or_file(str(tmp_path), cache_enabled=False, skip_file_types=False)

    assert result.files_scanned == 2
    assert determine_exit_code(result) == 1
    assert any(issue.location and str(model_file) in issue.location for issue in result.issues)
    assert not any(issue.location and str(misc_file) in issue.location for issue in result.issues)


def test_jinja_scanner_reuses_precompiled_patterns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scanner construction should reuse the shared static regex set."""

    def fail_compile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unexpected regex compilation")

    monkeypatch.setattr(jinja2_template_scanner.re, "compile", fail_compile)

    scanner = Jinja2TemplateScanner()

    assert scanner._compiled_patterns


class TestJinja2TemplateScannerCanHandle:
    """Test the can_handle method."""

    def test_can_handle_jinja_extension(self, tmp_path: Path) -> None:
        """Test that scanner handles .jinja files."""
        jinja_file = tmp_path / "template.jinja"
        jinja_file.write_text("{{ content }}")

        assert Jinja2TemplateScanner.can_handle(str(jinja_file)) is True

    def test_can_handle_j2_extension(self, tmp_path: Path) -> None:
        """Test that scanner handles .j2 files."""
        j2_file = tmp_path / "template.j2"
        j2_file.write_text("{{ content }}")

        assert Jinja2TemplateScanner.can_handle(str(j2_file)) is True

    def test_can_handle_template_extension(self, tmp_path: Path) -> None:
        """Test that scanner handles .template files."""
        template_file = tmp_path / "config.template"
        template_file.write_text("{{ content }}")

        assert Jinja2TemplateScanner.can_handle(str(template_file)) is True

    def test_can_handle_tokenizer_config_json(self, tmp_path: Path) -> None:
        """Test that scanner handles tokenizer_config.json."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text('{"chat_template": "{{ content }}"}')

        assert Jinja2TemplateScanner.can_handle(str(tokenizer_file)) is True

    def test_can_handle_yaml_in_model_dir(self, tmp_path: Path) -> None:
        """Test that scanner handles YAML files in model directories."""
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text("template: '{{ content }}'")

        assert Jinja2TemplateScanner.can_handle(str(yaml_file)) is True

    def test_cannot_handle_regular_json(self, tmp_path: Path) -> None:
        """Test that scanner rejects regular JSON files."""
        json_file = tmp_path / "data.json"
        json_file.write_text('{"key": "value"}')

        assert Jinja2TemplateScanner.can_handle(str(json_file)) is False

    def test_cannot_handle_nonexistent_file(self) -> None:
        """Test that scanner rejects nonexistent files."""
        assert Jinja2TemplateScanner.can_handle("/nonexistent/path/template.jinja") is False

    def test_cannot_handle_directory(self, tmp_path: Path) -> None:
        """Test that scanner rejects directories."""
        template_dir = tmp_path / "templates.jinja"
        template_dir.mkdir()

        assert Jinja2TemplateScanner.can_handle(str(template_dir)) is False


class TestJinja2TemplateScannerCVE2024_34359:
    """Test CVE-2024-34359: SSTI in llama-cpp-python via chat_template."""

    def test_detects_cve_2024_34359_payload(self, tmp_path: Path) -> None:
        """Test detection of CVE-2024-34359 payload."""
        config = {
            "tokenizer_class": "LlamaTokenizer",
            "chat_template": (
                "{% for c in [].__class__.__base__.__subclasses__() %}"
                "{% if c.__name__ == 'catch_warnings' %}"
                "{{ c()._module.__builtins__['__import__']('os').system('touch /tmp/pwned') }}"
                "{% endif %}{% endfor %}"
            ),
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        # Should detect multiple patterns
        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

        # Should detect object traversal and global access patterns
        patterns = {c.details.get("pattern_type") for c in failed_checks if c.details}
        assert "object_traversal" in patterns or "global_access" in patterns

    def test_detects_subclasses_traversal(self, tmp_path: Path) -> None:
        """Test detection of __subclasses__ traversal pattern."""
        template_file = tmp_path / "malicious.jinja"
        template_file.write_text("{{ ''.__class__.__mro__[1].__subclasses__() }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

        patterns = {c.details.get("pattern_type") for c in failed_checks if c.details}
        assert "object_traversal" in patterns


class TestJinja2TemplateScannerPatternCategories:
    """Test detection of various SSTI pattern categories."""

    def test_detects_critical_injection(self, tmp_path: Path) -> None:
        """Test detection of critical injection patterns."""
        template_file = tmp_path / "critical.jinja"
        template_file.write_text("{{ lipsum.__globals__.os.popen('id').read() }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

    def test_detects_global_access(self, tmp_path: Path) -> None:
        """Test detection of global namespace access patterns."""
        template_file = tmp_path / "globals.jinja"
        template_file.write_text("{{ self.__init__.__globals__['os'] }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

        patterns = {c.details.get("pattern_type") for c in failed_checks if c.details}
        assert "global_access" in patterns or "object_traversal" in patterns

    @pytest.mark.parametrize(
        ("name", "template"),
        [
            ("lipsum", "{{ lipsum.__globals__.os }}"),
            ("lipsum-spaced", "{{ lipsum . __globals__ . os }}"),
            ("flashes", "{{ get_flashed_messages.__globals__.os }}"),
            ("flashes-spaced", "{{ get_flashed_messages. __globals__ .os }}"),
            ("lipsum-subscript", "{{ lipsum.__globals__['os'] }}"),
            ("lipsum-spaced-subscript", "{{ lipsum.__globals__ ['os'] }}"),
            ("lipsum-parenthesized-subscript", "{{ (lipsum.__globals__)['os'] }}"),
            ("lipsum-parenthesized-receiver", "{{ (lipsum).__globals__['os'] }}"),
            ("lipsum-nested-parenthesized-receiver", "{{ ((lipsum)).__globals__['os'] }}"),
            ("composite-parenthesized-receiver", "{{ (foo or lipsum).__globals__['os'] }}"),
            ("proven-expression-receiver", "{{ (none or lipsum).__globals__.get('os') }}"),
            ("parenthesized-expression-globals", "{{ ((none or lipsum).__globals__)['os'] }}"),
            ("nested-receiver-subscript", "{{ obj.lipsum.__globals__['os'] }}"),
            ("spaced-nested-receiver-subscript", "{{ obj . lipsum.__globals__['os'] }}"),
        ],
    )
    def test_detects_named_global_access_once(
        self,
        tmp_path: Path,
        name: str,
        template: str,
    ) -> None:
        template_file = tmp_path / f"{name}.jinja"
        template_file.write_text(template)

        result = Jinja2TemplateScanner().scan(str(template_file))

        global_access_checks = [
            check
            for check in result.checks
            if check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
        ]
        assert len(global_access_checks) == 1

    @pytest.mark.parametrize(
        "template",
        [
            "{% set lipsum = {'__globals__': {'os': 'docs'}} %}{{ lipsum.__globals__.os }}",
            "{% with lipsum = {'__globals__': {'os': 'docs'}} %}{{ lipsum.__globals__.os }}{% endwith %}",
            "{% for x, lipsum in pairs %}{{ lipsum.__globals__.os }}{% endfor %}",
            "{% macro demo(lipsum) %}{{ lipsum.__globals__.os }}{% endmacro %}",
            "{% set lipsum %}docs{% endset %}{{ lipsum.__globals__.os }}",
            "{% call(lipsum) helper() %}{{ lipsum.__globals__.os }}{% endcall %}",
            "{{ \"docs: lipsum.__globals__ ['os']\" }}",
            "{% set safe = {'__globals__': {'os': 'docs'}} %}{% set lipsum = safe %}{{ lipsum.__globals__.os }}",
            "{% set lipsum = missing %}{{ lipsum.__globals__.os }}",
            "{% set lipsum = 'x' * 1000000000 %}{{ lipsum.__globals__.os }}",
            "{% set saved = lipsum %}{% set lipsum = saved and {} %}{{ lipsum.__globals__.os }}",
            "{% for _ in [] %}{{ lipsum.__globals__.os }}{% endfor %}",
            "{% for _ in {} %}{{ lipsum.__globals__.os }}{% endfor %}",
            "{% for _ in [0] %}{% else %}{{ lipsum.__globals__.os }}{% endfor %}",
            "{{ false and lipsum.__globals__.os }}",
            "{{ true or get_flashed_messages.__globals__.os }}",
            (
                "{% set saved = lipsum %}{% set lipsum = {} %}"
                + "{% if false %}{% set lipsum = saved %}{% endif %}"
                + "{{ lipsum.__globals__.os }}"
            ),
            "{% set x = 0 if true else lipsum.__globals__.os %}{{ x }}",
            "{% set x = lipsum if false %}{{ x.__globals__.os }}",
            "{% import 'helpers.j2' as lipsum %}{{ lipsum.__globals__.os }}",
            "{% from 'helpers.j2' import helper as lipsum %}{{ lipsum.__globals__.os }}",
            "{% macro lipsum() %}{% endmacro %}{{ lipsum.__globals__.os }}",
            "{% macro lipsum() %}{{ lipsum.__globals__.os }}{% endmacro %}",
        ],
    )
    def test_named_global_access_ignores_ast_local_bindings(
        self,
        tmp_path: Path,
        template: str,
    ) -> None:
        if not jinja2_template_scanner.HAS_JINJA2_SANDBOX:
            pytest.skip("Jinja2 AST unavailable")
        template_file = tmp_path / "local-binding.jinja"
        template_file.write_text(template)

        result = Jinja2TemplateScanner().scan(str(template_file))

        assert not any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        "template",
        [
            "{% set saved = lipsum %}{% set lipsum = {} %}{% set lipsum = saved %}{{ lipsum.__globals__.os }}",
            "".join(
                (
                    "{% set saved = lipsum %}{% set lipsum = {} %}",
                    "{% if true %}{% set lipsum = saved %}{% endif %}",
                    "{{ lipsum.__globals__.os }}",
                )
            ),
            "{% set saved = lipsum %}{% set lipsum = [saved][0] %}{{ lipsum.__globals__.os }}",
            "{% set saved = lipsum %}{% set lipsum = saved if true else {} %}{{ lipsum.__globals__.os }}",
            "{% set x = lipsum if cond %}{% set lipsum = x %}{{ lipsum.__globals__.os }}",
            "{% set x = none or lipsum %}{% set lipsum = x %}{{ lipsum.__globals__.os }}",
            "{% set lipsum = condition and lipsum %}{{ lipsum.__globals__.os }}",
            "{% for lipsum in {lipsum: 0} %}{{ lipsum.__globals__.os }}{% endfor %}",
            "".join(
                (
                    "{% set saved = lipsum %}{% set lipsum = {} %}",
                    "{% set lipsum, other = saved, 0 %}{{ lipsum.__globals__.os }}",
                )
            ),
            "{% macro demo(x=lipsum) %}{{ lipsum.__globals__.os }}{% endmacro %}",
            "{% set lipsum, saved = {}, lipsum %}{% set lipsum = saved %}{{ lipsum.__globals__.os }}",
            "{% with lipsum = {}, saved = lipsum %}{% set lipsum = saved %}{{ lipsum.__globals__.os }}{% endwith %}",
            "{% macro lipsum(lipsum=lipsum) %}{{ lipsum.__globals__.os }}{% endmacro %}",
            "{% for lipsum, unused in [(lipsum, 0)] %}{{ lipsum.__globals__.os }}{% endfor %}",
            "{% macro demo(lipsum=lipsum) %}{{ lipsum.__globals__.os }}{% endmacro %}",
            "{% call(lipsum=lipsum) helper() %}{{ lipsum.__globals__.os }}{% endcall %}",
            "{% import lipsum.__globals__.get('os') as helper %}",
            "{% from lipsum.__globals__.get('os') import helper %}",
            "{% set x | replace('a', lipsum.__globals__.os) %}a{% endset %}",
        ],
    )
    def test_named_global_access_detects_ast_dynamic_rebindings(
        self,
        tmp_path: Path,
        template: str,
    ) -> None:
        if not jinja2_template_scanner.HAS_JINJA2_SANDBOX:
            pytest.skip("Jinja2 AST unavailable")
        template_file = tmp_path / "dynamic-binding.jinja"
        template_file.write_text(template)

        result = Jinja2TemplateScanner().scan(str(template_file))

        assert any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in result.checks
        )

    @pytest.mark.parametrize(
        ("template", "expected_detection"),
        [
            (
                "{% for lipsum in [lipsum] if false %}{{ lipsum.__globals__.os }}{% endfor %}",
                False,
            ),
            (
                "{% for lipsum in [lipsum] if false %}{% else %}" + "{{ lipsum.__globals__.os }}{% endfor %}",
                True,
            ),
        ],
    )
    def test_named_global_access_respects_constant_false_loop_filter(
        self,
        tmp_path: Path,
        template: str,
        expected_detection: bool,
    ) -> None:
        template_file = tmp_path / "filtered-loop.jinja"
        template_file.write_text(template)

        result = Jinja2TemplateScanner({"enable_sandbox_test": False}).scan(str(template_file))

        has_global_access = any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in result.checks
        )
        assert has_global_access is expected_detection

    def test_named_global_access_keeps_unrelated_subscript_finding(
        self,
        tmp_path: Path,
    ) -> None:
        template_file = tmp_path / "mixed-globals.jinja"
        template_file.write_text("{% set lipsum = {} %}{{ lipsum.__globals__.os, other.__globals__['os'] }}")

        result = Jinja2TemplateScanner({"enable_sandbox_test": False}).scan(str(template_file))

        global_access_checks = [
            check
            for check in result.checks
            if check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
        ]
        assert len(global_access_checks) == 1
        assert global_access_checks[0].details.get("match_text") == "__globals__["

    def test_named_global_access_fallback_is_conservative_around_statements(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(jinja2_template_scanner, "HAS_JINJA2_SANDBOX", False)
        direct_file = tmp_path / "direct.jinja"
        direct_file.write_text("{{ '{%' }}{{ lipsum . __globals__ . os }}")
        quoted_file = tmp_path / "quoted.jinja"
        quoted_file.write_text("{{ \"docs: (lipsum).__globals__ ['os']\" }}")
        parenthesized_file = tmp_path / "parenthesized.jinja"
        parenthesized_file.write_text("{{ ( (lipsum) ).__globals__.os }}")
        unmatched_file = tmp_path / "unmatched.jinja"
        unmatched_file.write_text("{{ ( lipsum.__globals__.os }}")
        nested_receiver_file = tmp_path / "nested-receiver.jinja"
        nested_receiver_file.write_text("{{ (obj.lipsum).__globals__.os }}")
        scoped_file = tmp_path / "scoped.jinja"
        scoped_file.write_text("{% set lipsum = {'__globals__': {'os': 'docs'}} %}{{ lipsum.__globals__.os }}")
        statement_subscript_file = tmp_path / "statement-subscript.jinja"
        statement_subscript_file.write_text("{% if true %}{{ lipsum.__globals__['os'] }}{% endif %}")

        direct_result = Jinja2TemplateScanner().scan(str(direct_file))
        quoted_result = Jinja2TemplateScanner().scan(str(quoted_file))
        parenthesized_result = Jinja2TemplateScanner().scan(str(parenthesized_file))
        unmatched_result = Jinja2TemplateScanner().scan(str(unmatched_file))
        nested_receiver_result = Jinja2TemplateScanner().scan(str(nested_receiver_file))
        scoped_result = Jinja2TemplateScanner().scan(str(scoped_file))
        statement_subscript_result = Jinja2TemplateScanner().scan(str(statement_subscript_file))

        assert any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in direct_result.checks
        )
        assert any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in parenthesized_result.checks
        )
        assert not any(
            check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
            for check in (
                quoted_result.checks + unmatched_result.checks + nested_receiver_result.checks + scoped_result.checks
            )
        )
        statement_global_checks = [
            check
            for check in statement_subscript_result.checks
            if check.status == CheckStatus.FAILED
            and check.details
            and check.details.get("pattern_type") == "global_access"
        ]
        assert len(statement_global_checks) == 1
        assert statement_global_checks[0].details.get("match_text") == "__globals__["

    def test_detects_builtins_access(self, tmp_path: Path) -> None:
        """Test detection of __builtins__ access patterns."""
        template_file = tmp_path / "builtins.jinja"
        template_file.write_text("{{ config.__class__.__init__.__globals__.__builtins__ }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

    def test_detects_request_object_access(self, tmp_path: Path) -> None:
        """Test detection of request object access."""
        template_file = tmp_path / "request.jinja"
        template_file.write_text("{{ request.application.__globals__.__builtins__ }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0


class TestJinja2TemplateScannerFalsePositives:
    """Test that benign patterns don't cause false positives."""

    def test_benign_chat_template(self, tmp_path: Path) -> None:
        """Test that standard chat templates don't cause false positives."""
        huggingface_dir = tmp_path / "huggingface" / "model"
        huggingface_dir.mkdir(parents=True)

        config = {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": (
                "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}"
            ),
        }

        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        critical_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and c.severity == IssueSeverity.CRITICAL
        ]
        assert len(critical_checks) == 0

    def test_liquidai_template_no_false_positives(self, tmp_path: Path) -> None:
        """Test that LiquidAI-style bracket notation doesn't cause false positives."""
        huggingface_dir = tmp_path / "huggingface" / "LiquidAI" / "LFM2-1.2B"
        huggingface_dir.mkdir(parents=True)

        config = {
            "tokenizer_class": "LlamaTokenizer",
            "chat_template": (
                "{{- bos_token -}}"
                '{%- set ns = namespace(system_prompt="") -%}'
                '{%- if messages[0]["role"] == "system" -%}'
                '  {%- set ns.system_prompt = messages[0]["content"] -%}'
                "{%- endif -%}"
                "{%- for message in messages -%}"
                '  {{- "<|im_start|>" + message["role"] + "\\n" -}}'
                '  {%- set content = message["content"] -%}'
                '  {%- if message["role"] == "tool" -%}'
                '    {%- set content = "<|tool_response_start|>" + content + "<|tool_response_end|>" -%}'
                "  {%- endif -%}"
                '  {{- content + "<|im_end|>\\n" -}}'
                "{%- endfor -%}"
            ),
        }

        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        critical_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and c.severity == IssueSeverity.CRITICAL
        ]
        warning_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and c.severity == IssueSeverity.WARNING
        ]

        assert len(critical_checks) == 0, "Should not have critical issues"
        assert len(warning_checks) == 0, "Should not have warnings for legitimate bracket notation"

    def test_simple_variable_substitution(self, tmp_path: Path) -> None:
        """Test that simple variable substitution doesn't cause issues."""
        template_file = tmp_path / "simple.jinja"
        template_file.write_text("Hello, {{ name }}! Welcome to {{ site }}.")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) == 0

    def test_prose_requests_in_structured_chat_templates_is_not_ssti(self, tmp_path: Path) -> None:
        """Pinned Cohere-style prose should not trip request-call SSTI regexes."""
        huggingface_dir = tmp_path / "huggingface" / "CohereLabs" / "North-Mini-Code-1.0"
        huggingface_dir.mkdir(parents=True)
        prose_template = (
            "{% if tools or documents %}\n"
            "You should make best use of these skills to serve user's requests.\n"
            "Think about how to address requests.\n"
            "{% endif %}\n"
            "{{ message.content }}"
        )
        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps(
                {
                    "chat_template": [
                        {"name": "default", "template": prose_template},
                        {"name": "tool_use", "template": prose_template},
                        {"name": "rag", "template": prose_template},
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert _jinja_detection_checks(result) == []
        assert any(
            check.name == "Jinja2 SSTI Analysis" and check.status == CheckStatus.PASSED for check in result.checks
        )

    def test_active_requests_call_in_chat_template_is_still_critical(self, tmp_path: Path) -> None:
        huggingface_dir = tmp_path / "huggingface" / "model"
        huggingface_dir.mkdir(parents=True)
        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps(
                {
                    "chat_template": [
                        {
                            "name": "default",
                            "template": "{{ requests.get('https://example.test/payload') }}",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        failed_checks = _jinja_detection_checks(result)
        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.details.get("pattern_type") == "critical_injection"
            and check.details.get("pattern") == r"requests\."
            for check in failed_checks
        )

    def test_active_requests_statement_in_chat_template_is_still_critical(self, tmp_path: Path) -> None:
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps(
                {
                    "chat_template": (
                        "{% set response = requests.post('https://example.test/payload') %}{{ response.status_code }}"
                    )
                }
            ),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.details.get("pattern_type") == "critical_injection"
            and check.details.get("match_text") == "requests."
            for check in _jinja_detection_checks(result)
        )

    def test_raw_and_comment_requests_are_not_executable_ssti(self, tmp_path: Path) -> None:
        template_file = tmp_path / "requests-docs.jinja"
        template_file.write_text(
            "{# requests.get('https://example.test/comment') #}\n"
            "{% raw %}{{ requests.get('https://example.test/raw') }}{% endraw %}\n"
            "Use the tool to address user's requests.\n"
            "{{ message.content }}",
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(template_file))

        assert _jinja_detection_checks(result) == []

    def test_active_obfuscated_attribute_traversal_still_detected(self, tmp_path: Path) -> None:
        template_file = tmp_path / "attr-traversal.jinja"
        template_file.write_text(
            "{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}",
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(template_file))

        failed_checks = _jinja_detection_checks(result)
        assert any(check.details.get("pattern_type") == "obfuscation" for check in failed_checks)

    def test_malformed_prose_requests_template_stays_clean(self, tmp_path: Path) -> None:
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps(
                {
                    "chat_template": (
                        "{% if tools %}\nUse available tools to serve user's requests.\nThen respond conversationally."
                    )
                }
            ),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert _jinja_detection_checks(result) == []

    def test_malformed_active_requests_expression_still_detected(self, tmp_path: Path) -> None:
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps({"chat_template": "{{ requests.get('https://example.test/payload')"}),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert any(
            check.severity == IssueSeverity.CRITICAL
            and check.details.get("pattern_type") == "critical_injection"
            and check.details.get("match_text") == "requests."
            for check in _jinja_detection_checks(result)
        )


class TestJinja2TemplateScannerExecutableSpans:
    def test_lexer_spans_include_expressions_and_statements_only(self) -> None:
        spans = Jinja2TemplateScanner._executable_template_spans(
            "literal requests. {{ requests.get('https://example.test') }} "
            "{# requests.get('https://example.test/comment') #} "
            "{% set x = os.system('id') %}"
        )

        assert [span.text for span in spans] == [
            "{{ requests.get('https://example.test') }}",
            "{% set x = os.system('id') %}",
        ]

    def test_delimiter_fallback_ignores_raw_body_and_comments(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(jinja2_template_scanner, "HAS_JINJA2_SANDBOX", False)

        spans = Jinja2TemplateScanner._executable_template_spans(
            "{# requests.get('https://example.test/comment') #}"
            "{% raw %}{{ requests.get('https://example.test/raw') }}{% endraw %}"
            "{{ requests.get('https://example.test/live')"
        )

        assert [span.text for span in spans] == ["{{ requests.get('https://example.test/live')"]

    @pytest.mark.parametrize(
        "template_content",
        [
            pytest.param(
                "{# \" requests.get('https://example.test/comment') #}\n"
                "{{ requests.get('https://example.test/live') }}",
                id="comment-unmatched-quote",
            ),
            pytest.param(
                "{% raw %}"
                "{% set ignored = \"requests.get('https://example.test/raw') %}"
                "{{ requests.get('https://example.test/raw-expression') }}"
                "{% endraw %}\n"
                "{{ requests.get('https://example.test/live') }}",
                id="raw-unmatched-quote",
            ),
        ],
    )
    def test_delimiter_fallback_malformed_ignored_regions_do_not_hide_later_requests(
        self,
        template_content: str,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(jinja2_template_scanner, "HAS_JINJA2_SANDBOX", False)

        spans = Jinja2TemplateScanner._executable_template_spans(template_content)

        assert [span.text for span in spans] == ["{{ requests.get('https://example.test/live') }}"]

        template_file = tmp_path / "malformed-ignored-region.jinja"
        template_file.write_text(template_content, encoding="utf-8")
        result = Jinja2TemplateScanner().scan(str(template_file))

        request_checks = [
            check
            for check in _jinja_detection_checks(result)
            if check.severity == IssueSeverity.CRITICAL
            and check.details.get("pattern_type") == "critical_injection"
            and check.details.get("match_text") == "requests."
        ]
        assert len(request_checks) == 1


class TestJinja2TemplateScannerJSONExtraction:
    """Test JSON template extraction."""

    def test_extracts_chat_template_field(self, tmp_path: Path) -> None:
        """Test extraction of chat_template field from JSON."""
        config = {
            "tokenizer_class": "LlamaTokenizer",
            "chat_template": "{{ self.__init__.__globals__['os'] }}",
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

    def test_extracts_nested_templates(self, tmp_path: Path) -> None:
        """Test extraction of templates from nested JSON structures."""
        config = {
            "model": {
                "name": "test",
                "custom_chat_template": "{{ config.__class__.__init__.__globals__ }}",
            }
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0


class TestJinja2TemplateScannerYAMLExtraction:
    """Test YAML template extraction."""

    def test_extracts_yaml_templates(self, tmp_path: Path) -> None:
        """Test extraction of templates from YAML files."""
        yaml_content = """
model:
  name: test
  chat_template: "{{ lipsum.__globals__.os.popen('id') }}"
"""
        model_dir = tmp_path / "huggingface" / "model"
        model_dir.mkdir(parents=True)
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Jinja2TemplateScanner()

        # Skip if yaml is not available
        try:
            import yaml  # noqa: F401
        except ImportError:
            pytest.skip("PyYAML not installed")

        result = scanner.scan(str(yaml_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

    def test_missing_yaml_dependency_uses_raw_fallback_and_marks_inconclusive(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text(
            "chat_template: \"{{ lipsum.__globals__.os.popen('id') }}\"\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(jinja2_template_scanner, "HAS_YAML", False)

        result = Jinja2TemplateScanner().scan(str(yaml_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_yaml_dependency_unavailable" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(c.details.get("template_location") == "raw_yaml_dependency_fallback" for c in failed_checks)

    def test_missing_yaml_dependency_without_template_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text("model: safe\n", encoding="utf-8")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_YAML", False)

        result = Jinja2TemplateScanner().scan(str(yaml_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_yaml_dependency_unavailable" in result.metadata["scan_outcome_reasons"]
        parsing_checks = [c for c in result.checks if c.name == "Template Config Parsing"]
        assert len(parsing_checks) == 1
        assert parsing_checks[0].message == "Failed to parse yaml config for template extraction"

        aggregate_result = scan_model_directory_or_file(
            str(yaml_file),
            config={"cache_scan_results": False},
        )
        metadata = aggregate_result.file_metadata[str(yaml_file)]
        assert aggregate_result.success is False
        assert metadata.get("scan_outcome") == "inconclusive"
        assert "jinja2_yaml_dependency_unavailable" in metadata.get("scan_outcome_reasons")
        assert determine_exit_code(aggregate_result) == 2


class TestJinja2TemplateScannerEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_template_file(self, tmp_path: Path) -> None:
        """Test handling of empty template file."""
        template_file = tmp_path / "empty.jinja"
        template_file.write_text("")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        # Should complete without error
        assert result.success is True

    def test_handles_invalid_json(self, tmp_path: Path) -> None:
        """Test handling of invalid JSON file."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text("{invalid json content")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_json_parse_failed" in result.metadata["scan_outcome_reasons"]
        parsing_checks = [c for c in result.checks if c.name == "Template Config Parsing"]
        assert len(parsing_checks) == 1
        assert parsing_checks[0].status == CheckStatus.FAILED
        assert parsing_checks[0].severity == IssueSeverity.INFO

    def test_malformed_json_raw_template_fallback_detects_ssti(self, tmp_path: Path) -> None:
        """Malformed tokenizer configs should still scan visible raw template payloads."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            '{"chat_template":"{{ lipsum.__globals__.os.popen(\'id\').read() }}",',
            encoding="utf-8",
        )

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_json_parse_failed" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(c.details.get("template_location") == "raw_json_parse_fallback" for c in failed_checks)
        assert any(c.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for c in failed_checks)

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_malformed_large_json_raw_template_fallback_detects_ssti_in_prefix(self, tmp_path: Path) -> None:
        """Large malformed configs should scan bounded raw windows instead of bailing out."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        payload = "{{ lipsum.__globals__.os.popen('id').read() }}"
        tokenizer_file.write_text(
            '{"chat_template":"' + ("a" * 70000) + payload + ("b" * 220000),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_json_parse_failed" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(str(c.details.get("template_location")).startswith("raw_json_parse_fallback") for c in failed_checks)

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_malformed_large_json_raw_template_fallback_detects_ssti_after_prefix(self, tmp_path: Path) -> None:
        """Raw fallback should find template markers beyond the initial read window."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        payload = "{{ lipsum.__globals__.os.popen('id').read() }}"
        tokenizer_file.write_text(
            '{"chat_template":"' + ("a" * 300000) + payload + ("b" * 70000),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_json_parse_failed" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(str(c.details.get("template_location")).startswith("raw_json_parse_fallback") for c in failed_checks)

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_malformed_large_json_raw_template_fallback_ignores_clustered_benign_markers(
        self,
        tmp_path: Path,
    ) -> None:
        """Clustered early markers should not consume the full fallback window budget."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        benign_prefix = "".join("{{ content }}" for _ in range(8))
        payload = "{{ lipsum.__globals__.os.popen('id').read() }}"
        tokenizer_file.write_text(
            '{"chat_template":"' + benign_prefix + ("a" * 400000) + payload + ("b" * 1000),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_json_parse_failed" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(str(c.details.get("template_location")).startswith("raw_json_parse_fallback") for c in failed_checks)

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_malformed_large_json_benign_raw_template_stays_inconclusive_only(self, tmp_path: Path) -> None:
        """Benign raw-template recovery should not create security findings."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            '{"chat_template":"' + ("a" * 70000) + "{{ content }}" + ("b" * 220000),
            encoding="utf-8",
        )

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )

        metadata = aggregate_result.file_metadata[str(tokenizer_file)]
        security_checks = [
            issue
            for issue in aggregate_result.issues
            if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        assert metadata.get("scan_outcome") == "inconclusive"
        assert security_checks == []
        assert determine_exit_code(aggregate_result) == 2

    def test_malformed_yaml_raw_template_fallback_detects_ssti(self, tmp_path: Path) -> None:
        """Malformed YAML configs should use the same bounded raw template fallback."""
        pytest.importorskip("yaml")
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text(
            "template: \"{{ lipsum.__globals__.os.popen('id').read() }}\"\nbroken: [\n",
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(yaml_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_yaml_parse_failed" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(c.details.get("template_location") == "raw_yaml_parse_fallback" for c in failed_checks)

    def test_malformed_json_without_raw_template_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Malformed structured configs without recoverable templates should fail closed."""
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text("{invalid json content", encoding="utf-8")

        result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"cache_scan_results": False},
        )

        metadata = result.file_metadata[str(tokenizer_file)]
        assert metadata.get("scan_outcome") == "inconclusive"
        assert "jinja2_json_parse_failed" in metadata.get("scan_outcome_reasons")
        assert result.success is False
        assert result.has_errors is False
        assert determine_exit_code(result) == 2

    def test_handles_json_without_templates(self, tmp_path: Path) -> None:
        """Test handling of JSON file without template fields."""
        config = {
            "tokenizer_class": "GPT2Tokenizer",
            "model_name": "test-model",
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        # Should complete successfully
        assert result.success is True

        # Should indicate no templates found
        passed_checks = [c for c in result.checks if c.status == CheckStatus.PASSED]
        assert len(passed_checks) > 0

    def test_handles_large_template(self, tmp_path: Path) -> None:
        """Standalone templates exceeding the size limit must fail closed."""
        # Create template larger than max_template_size (default 50000)
        large_content = "{{ content }}" * 10000  # > 50000 chars

        template_file = tmp_path / "large.jinja"
        template_file.write_text(large_content)

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Template Size Limit"
            and check.status == CheckStatus.FAILED
            and check.details["max_template_size"] == scanner.max_template_size
            for check in result.checks
        )

        aggregate_result = scan_model_directory_or_file(str(template_file), cache_enabled=False)
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

    def test_oversized_json_chat_template_fails_closed(self, tmp_path: Path) -> None:
        default_limit = Jinja2TemplateScanner().max_template_size
        payload = ("a" * (default_limit + 1)) + "{{ lipsum.__globals__.os.popen('id').read() }}"
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps({"chat_template": payload}), encoding="utf-8")

        scanner = Jinja2TemplateScanner({"max_template_size": 64})
        result = scanner.scan(str(tokenizer_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
        assert len(size_checks) == 1
        assert size_checks[0].status == CheckStatus.FAILED
        assert size_checks[0].severity == IssueSeverity.INFO
        assert size_checks[0].details["skipped_template_locations"] == ["chat_template"]
        assert size_checks[0].details["template_size"] == len(payload)
        assert not [c for c in result.checks if c.message == "No Jinja2 templates found in file"]

        aggregate_result = scan_model_directory_or_file(
            str(tokenizer_file),
            config={"max_template_size": 64, "cache_scan_results": False},
        )
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

    def test_oversized_yaml_chat_template_fails_closed(self, tmp_path: Path) -> None:
        yaml = pytest.importorskip("yaml")
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        payload = ("a" * 96) + "{{ lipsum.__globals__.os.popen('id').read() }}"
        yaml_file = model_dir / "config.yaml"
        yaml_file.write_text(yaml.safe_dump({"chat_template": payload}), encoding="utf-8")

        scanner = Jinja2TemplateScanner({"max_template_size": 64})
        result = scanner.scan(str(yaml_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
        assert len(size_checks) == 1
        assert size_checks[0].details["format"] == "yaml"
        assert size_checks[0].details["skipped_template_locations"] == ["chat_template"]
        assert not [c for c in result.checks if c.message == "No Jinja2 templates found in file"]

    def test_oversized_benign_json_template_is_inconclusive_without_security_finding(self, tmp_path: Path) -> None:
        payload = "{{ message['content'] }}" + (" safe" * 32)
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps({"chat_template": payload}), encoding="utf-8")

        scanner = Jinja2TemplateScanner({"max_template_size": 64})
        result = scanner.scan(str(tokenizer_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        assert [c for c in result.checks if c.name == "Template Size Limit"]
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

    def test_many_oversized_json_template_candidates_have_bounded_reporting(self, tmp_path: Path) -> None:
        tokenizer_file = tmp_path / "tokenizer_config.json"
        payload = "{{ message['content'] }}" + (" safe" * 32)
        tokenizer_file.write_text(
            json.dumps({f"template_candidate_{index}": payload for index in range(25)}),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner({"max_template_size": 64}).scan(str(tokenizer_file))

        size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
        assert result.success is False
        assert len(size_checks) == 1
        assert size_checks[0].details["skipped_template_location_count"] == 25
        assert len(size_checks[0].details["skipped_template_locations"]) == 20
        assert size_checks[0].details["skipped_template_locations_truncated"] is True
        assert size_checks[0].details["template_size"] == len(payload)

    def test_json_template_path_collision_does_not_hide_malicious_candidate(self, tmp_path: Path) -> None:
        malicious = "{{ lipsum.__globals__.os.popen('id') }}"
        benign = "{{ message['content'] }}"
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps(
                {
                    "a.b": malicious,
                    "a": {"b": benign},
                }
            ),
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        failed_checks = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(check.details.get("template_location") == "a.b" for check in failed_checks)
        summary = [check for check in result.checks if check.name == "Jinja2 SSTI Analysis Summary"]
        assert len(summary) == 1
        assert summary[0].details["templates_analyzed"] == 2

    def test_direct_gguf_oversized_chat_template_fails_closed(self, tmp_path: Path) -> None:
        pytest.importorskip("gguf")
        gguf_file = create_mock_gguf(
            tmp_path / "large-template.gguf",
            metadata={"tokenizer.chat_template": "{{ content }}" * 10000},
        )

        result = Jinja2TemplateScanner().scan(str(gguf_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
        assert len(size_checks) == 1
        assert size_checks[0].details["format"] == "gguf"
        assert size_checks[0].details["skipped_template_locations"] == ["tokenizer.chat_template"]

    def test_list_backed_gguf_oversized_chat_template_fails_before_iteration(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class ExplodingTemplateList(list[int]):
            def __iter__(self) -> Iterator[int]:
                raise AssertionError("oversized GGUF template must not be materialized")

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template": SimpleNamespace(
                        parts=[ExplodingTemplateList([ord("a")] * 65)],
                        data=[0],
                    )
                }

        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        templates, failures = Jinja2TemplateScanner({"max_template_size": 64})._extract_gguf_templates("fake.gguf")

        assert templates == {}
        assert len(failures) == 1
        assert failures[0]["reason"] == "jinja2_template_size_limit_exceeded"
        assert failures[0]["template_size"] == 65

    def test_named_gguf_chat_template_is_decoded_and_analyzed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = "{{ lipsum.__globals__.os.popen('id') }}"

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template.tool": SimpleNamespace(
                        parts=[payload.encode("utf-8")],
                        data=[0],
                    )
                }

        gguf_file = tmp_path / "model.gguf"
        gguf_file.write_bytes(b"GGUF")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_GGUF", True)
        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        result = Jinja2TemplateScanner({"max_template_size": 128}).scan(str(gguf_file))

        failed_checks = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(check.details.get("template_location") == "tokenizer.chat_template.tool" for check in failed_checks)

    def test_unsupported_gguf_chat_template_value_fails_closed_without_stringifying(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class UnsupportedTemplateValue:
            def __str__(self) -> str:
                raise AssertionError("unsupported GGUF values must not be stringified")

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template": SimpleNamespace(
                        parts=[UnsupportedTemplateValue()],
                        data=[0],
                    )
                }

        gguf_file = tmp_path / "model.gguf"
        gguf_file.write_bytes(b"GGUF")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_GGUF", True)
        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        result = Jinja2TemplateScanner().scan(str(gguf_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_gguf_template_decode_failed" in result.metadata["scan_outcome_reasons"]
        decode_checks = [check for check in result.checks if check.name == "Template Config Parsing"]
        assert len(decode_checks) == 1
        assert decode_checks[0].details["template_location"] == "tokenizer.chat_template"

    def test_gguf_reader_failure_fails_closed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class FailingGGUFReader:
            def __init__(self, _path: str) -> None:
                raise ValueError("malformed GGUF metadata")

        gguf_file = tmp_path / "model.gguf"
        gguf_file.write_bytes(b"GGUF")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_GGUF", True)
        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FailingGGUFReader, raising=False)

        result = Jinja2TemplateScanner().scan(str(gguf_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_gguf_parse_failed" in result.metadata["scan_outcome_reasons"]
        parse_checks = [check for check in result.checks if check.name == "Template Config Parsing"]
        assert len(parse_checks) == 1
        assert parse_checks[0].details["exception"] == "malformed GGUF metadata"

    def test_malformed_named_gguf_template_does_not_hide_later_template(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = "{{ lipsum.__globals__.os.popen('id') }}"

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template.bad": SimpleNamespace(parts=[], data=[]),
                    "tokenizer.chat_template.tool": SimpleNamespace(parts=[payload.encode("utf-8")], data=[0]),
                }

        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        templates, failures = Jinja2TemplateScanner()._extract_gguf_templates("fake.gguf")

        assert templates == {"tokenizer.chat_template.tool": payload}
        assert len(failures) == 1
        assert failures[0]["reason"] == "jinja2_gguf_template_decode_failed"
        assert failures[0]["template_location"] == "tokenizer.chat_template.bad"

    def test_array_backed_gguf_oversized_chat_template_fails_before_stringifying(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class AbbreviatedArrayTemplate:
            nbytes = 65

            def __str__(self) -> str:
                return "{{ content }}"

            def tobytes(self) -> bytes:
                raise AssertionError("oversized GGUF template must not be materialized")

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template": SimpleNamespace(
                        parts=[AbbreviatedArrayTemplate()],
                        data=[0],
                    )
                }

        gguf_file = tmp_path / "model.gguf"
        gguf_file.write_bytes(b"GGUF")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_GGUF", True)
        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        result = Jinja2TemplateScanner({"max_template_size": 64}).scan(str(gguf_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_size_limit_exceeded" in result.metadata["scan_outcome_reasons"]
        size_checks = [c for c in result.checks if c.name == "Template Size Limit"]
        assert len(size_checks) == 1
        assert size_checks[0].details["format"] == "gguf"
        assert size_checks[0].details["skipped_template_locations"] == ["tokenizer.chat_template"]
        assert size_checks[0].details["template_size"] == 65

    def test_array_backed_gguf_chat_template_decodes_before_analysis(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        payload = "{{ lipsum.__globals__.os.popen('id') }}"
        payload_bytes = payload.encode("utf-8")

        class ArrayBackedTemplate:
            nbytes = len(payload_bytes)

            def __str__(self) -> str:
                return "[123 123 ...]"

            def tobytes(self) -> bytes:
                return payload_bytes

        class FakeGGUFReader:
            def __init__(self, _path: str) -> None:
                self.fields = {
                    "tokenizer.chat_template": SimpleNamespace(
                        parts=[ArrayBackedTemplate()],
                        data=[0],
                    )
                }

        gguf_file = tmp_path / "model.gguf"
        gguf_file.write_bytes(b"GGUF")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_GGUF", True)
        monkeypatch.setattr(jinja2_template_scanner, "GGUFReader", FakeGGUFReader, raising=False)

        result = Jinja2TemplateScanner({"max_template_size": 128}).scan(str(gguf_file))

        failed_checks = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
        assert failed_checks
        assert any(check.details.get("template_location") == "tokenizer.chat_template" for check in failed_checks)
        assert not [check for check in result.checks if check.name == "Template Size Limit"]

    def test_small_json_chat_template_still_analyzed(self, tmp_path: Path) -> None:
        payload = "{{ lipsum.__globals__.os.popen('id') }}"
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps({"chat_template": payload}), encoding="utf-8")

        scanner = Jinja2TemplateScanner({"max_template_size": 128, "sandbox_render_timeout_seconds": 2})
        result = scanner.scan(str(tokenizer_file))

        assert result.has_warnings or result.has_errors
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Size Limit"]
        assert [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

    def test_sandbox_probe_output_budget_is_inconclusive_without_security_finding(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].status == CheckStatus.FAILED
        assert budget_checks[0].severity == IssueSeverity.INFO
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        assert budget_checks[0].details["detail"] == "output"
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

        aggregate_result = scan_model_directory_or_file(
            str(template_file),
            config={
                "cache_scan_results": False,
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            },
        )
        assert determine_exit_code(aggregate_result) == 2

    def test_sandbox_probe_output_budget_without_resource_limits(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "HAS_RESOURCE_LIMITS", False)
        template_file = tmp_path / "amplify.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}", encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        assert budget_checks[0].details["detail"] == "output"

    def test_json_chat_template_output_budget_is_inconclusive_without_security_finding(
        self,
        tmp_path: Path,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps({"chat_template": "{{ 'A' * 1000000 }}"}), encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(tokenizer_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        assert budget_checks[0].details["detail"] == "output"
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

    def test_sandbox_probe_preflights_static_range_list_before_starting_worker(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        def fail_get_context(_method: str | None = None) -> None:
            pytest.fail("static range list should fail closed before starting a worker")

        monkeypatch.setattr(jinja2_template_scanner.mp, "get_context", fail_get_context)

        assert scanner._test_template_safety_with_budget("{{ range(10 ** 8)|list }}") == (
            "budget_exceeded",
            "output",
        )

    def test_sandbox_probe_timeout_bounds_low_output_execution(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "cpu.jinja"
        template_file.write_text(
            "{% for i in range(100000) %}{% for j in range(100000) %}{% endfor %}{% endfor %}",
            encoding="utf-8",
        )

        start = time.monotonic()
        result = Jinja2TemplateScanner({"sandbox_render_timeout_seconds": 0.05}).scan(str(template_file))
        elapsed = time.monotonic() - start

        assert elapsed < 5
        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "timeout"

    def test_sandbox_probe_range_overflow_is_inconclusive(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "huge-range.jinja"
        template_file.write_text("{% for i in range(1000000000) %}{% endfor %}", encoding="utf-8")

        result = Jinja2TemplateScanner({"sandbox_render_timeout_seconds": 2}).scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        assert budget_checks[0].details["detail"] == "range"
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

    def test_sandbox_budget_preserves_static_findings_and_security_exit(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "static-and-amplify.jinja"
        template_file.write_text(
            r"{{ '\x41' }}{{ 'A' * 1000000 }}",
            encoding="utf-8",
        )

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(template_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "obfuscation" for c in failed_checks)
        assert not any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

        aggregate_result = scan_model_directory_or_file(
            str(template_file),
            config={
                "cache_scan_results": False,
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            },
        )
        assert determine_exit_code(aggregate_result) == 1

    def test_sandbox_budget_does_not_hide_static_sandbox_risk(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify-and-dunder.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}{{ messages.__class__ }}", encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(template_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

    def test_sandbox_budget_does_not_hide_ast_sandbox_probe_risk(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify-and-private-attr.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}{{ value._private }}", encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 16,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(template_file))

        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "budget_exceeded"
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

    def test_benign_template_below_sandbox_budget_remains_clean(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "benign.jinja"
        template_file.write_text("Hello {{ messages|length }} {{ 'ok' * 2 }}", encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "sandbox_render_max_output_chars": 64,
                "sandbox_render_timeout_seconds": 2,
            }
        ).scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert any(c.name == "Jinja2 SSTI Analysis" and c.status == CheckStatus.PASSED for c in result.checks)
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_sandbox_security_error_still_reports_violation(self) -> None:
        pytest.importorskip("jinja2.sandbox")
        scanner = Jinja2TemplateScanner({"sandbox_render_timeout_seconds": 2})

        safe, failure = scanner._test_template_safety("{{ [].__class__.__mro__ }}", "template_content")

        assert safe is False
        assert failure is None

    def test_disabled_sandbox_probe_skips_render_budget(self, tmp_path: Path) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}", encoding="utf-8")

        result = Jinja2TemplateScanner(
            {
                "enable_sandbox_test": False,
                "sandbox_render_max_output_chars": 16,
            }
        ).scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_keeps_benign_template_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "benign.jinja"
        template_file.write_text("Hello, {{ name }}! Welcome to {{ site }}.", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_ast_sandbox_probe_risk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "private-attr.jinja"
        template_file.write_text("{{ value._private }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.has_errors is True
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

    def test_worker_error_before_result_preserves_ast_sandbox_probe_risk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "private-attr-worker-error.jinja"
        template_file.write_text("{{ value._private }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_error", "exitcode=1"),
        )
        result = scanner.scan(str(template_file))

        assert result.has_errors is True
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

    def test_spawn_startup_timeout_keeps_benign_template_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "benign.jinja"
        template_file.write_text("Hello, {{ name }}! Welcome to {{ site }}.", encoding="utf-8")

        scanner = Jinja2TemplateScanner()

        def startup_timeout_probe(_template_content: str) -> tuple[str, str]:
            return "worker_unavailable", "startup_timeout"

        monkeypatch.setattr(scanner, "_test_template_safety_with_budget", startup_timeout_probe)
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_spawn_worker_exit_before_result_keeps_benign_template_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "benign.jinja"
        template_file.write_text("Hello, {{ name }}! Welcome to {{ site }}.", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_error", "exitcode=1"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_static_expression_range(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-expression.jinja"
        template_file.write_text("{{ range(10 ** 8)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_uses_configured_budget_for_range_fallback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "configured-range-expression.jinja"
        template_file.write_text("{{ range(1000)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    @pytest.mark.parametrize(
        "template_content",
        [
            "{% set r = range %}{{ r(1000)|list }}",
            "{% set ns = namespace(r=range) %}{{ ns.r(1000)|join }}",
            "{% set r = range %}{% for item in r(1000) %}{{ item }}{% endfor %}",
        ],
    )
    def test_unavailable_sandbox_worker_uses_configured_budget_for_range_aliases(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "configured-range-alias.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ range(100001)|min }}",
            "{{ range(100001)|max }}",
            "{{ range(100001)|sum }}",
            "{{ range(100001)|select('odd')|sum }}",
        ],
    )
    def test_unavailable_sandbox_worker_fails_closed_for_cpu_heavy_scalar_range_filters(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-scalar-filter.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ range(100001)|default([])|min }}",
            "{{ range(100001)|d([])|max }}",
            "{% set values = range(100001) %}{{ values|sum }}",
            "{% set r = range %}{{ r(100001)|sum }}",
            "{% set r = range %}{% set s = r %}{{ s(100001)|min }}",
            "{% set r = range %}{{ r(100001)|min }}{% set r = small %}",
            "{% set r, n = range, 100001 %}{{ r(n)|max }}",
            "{% set (r,) = [range] %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set range, r = small, range %}{{ r(100001)|min }}",
            "{% set n = 100000 %}{{ range(n + 1)|min }}",
            "{% set n = 100001 %}{{ range(n)|min }}{% set n = 1 %}",
            "{% if true %}{% set r = range %}{{ r(100001)|sum }}{% endif %}",
            "{% if 1 + 1 %}{% set r = range %}{% endif %}{{ r(100001)|min }}",
            "{% if false %}{% set r = small %}{% elif true %}{% set r = range %}"
            + "{% else %}{% set r = small %}{% endif %}{{ r(100001)|min }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ m(range) }}",
            "{% set r = range %}{% macro m(fn) %}{{ fn(100001)|min }}{% endmacro %}{{ m(r) }}",
            "{% macro m(r=range) %}{{ r(100001)|min }}{% endmacro %}{{ m() }}",
            "{% macro m(r, n) %}{{ r(n)|min }}{% endmacro %}{{ m(range, 100001) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{% set alias = m %}{{ alias(range) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{% set alias, _ = m, 0 %}{{ alias(range) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{% set (alias,) = [m] %}{{ alias(range) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}" + "{% set ns = namespace(m=m) %}{{ ns.m(range) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}"
            + "{% set ns = namespace() %}{% set ns.m = m %}{{ ns.m(range) }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}"
            + "{% set ns = namespace(m=m) %}{% set other = ns %}{{ other.m(range) }}",
            "{% macro m() %}{{ kwargs.r(100001)|min }}{% endmacro %}{{ m(r=range) }}",
            "{% for r in [range] %}{{ r(100001)|min }}{% endfor %}",
            "{% set ns = namespace() %}{% for _ in [0] %}{% set ns.r = range %}{% endfor %}{{ ns.r(100001)|min }}",
            "{% set ns = namespace(r=range) %}{{ ns.r(100001)|min }}",
            "{% set ns = namespace() %}{% set ns.r = range %}{{ ns.r(100001)|min }}",
            "{% set ns = namespace(r=range) %}{% set other = ns %}{{ other.r(100001)|min }}",
            "{% set ns = namespace(xs=range(100001)) %}{{ ns.xs|max }}",
            "{{ range(100001)|min }}{% set range = 1 %}",
            "{{ range(100001)|min }}{% macro range(n) %}1{% endmacro %}",
            "{{ range(10 ** 101, 10 ** 101 + 100001)|min }}",
            "{% set n = 10 ** 101 %}{% set m = 100001 %}{{ range(n, n + m)|min }}",
            "{{ range(((-1) ** 100001) * -100001)|min }}",
            "{% set exponent = 100001 %}{{ range(((-1) ** exponent) * -100001)|sum }}",
            "{{ range((1 // -(10 ** 1000)) * -100001)|min }}",
            "{% set denominator = -(10 ** 1000) %}{{ range((1 // denominator) * -100001)|sum }}",
            "{% set denominator = -(10 ** 1000) %}{{ range((1 % denominator) * -1)|sum }}",
            "{% set huge = 10 ** 1000 %}{{ range((-huge + -huge) * -1)|sum }}",
            "{% set huge = 10 ** 1000 %}{{ range((-huge - huge) * -1)|sum }}",
            "{{ range(10 ** 1000 + -(10 ** 999))|min }}",
            "{% macro m(xs=range(100001)) %}{{ xs|min }}{% endmacro %}{{ m() }}",
            "{% set r = range %}{{ r(10)|list }}",
            "{% set r = range %}{{ r(15)|join }}",
            "{{ [range(100001)]|map('min')|first }}",
            "{{ range(100001)|batch(100001)|first|min }}",
            "{{ range(*[100001])|min }}",
            "{% for n in [1, 100001] %}{{ range(n)|min }}{% endfor %}",
            "{% if condition %}{% macro m() %}{{ range(100001)|min }}{% endmacro %}{% endif %}{{ m() }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% macro good() %}ok{% endmacro %}"
            + "{% if condition %}{% set f=bad %}{% else %}{% set f=good %}{% endif %}{{ f() }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ m(*[range]) }}",
            "{% macro m() %}{{ kwargs['r'](100001)|min }}{% endmacro %}{{ m(**{'r': range}) }}",
            "{% macro m() %}{{ varargs[0](100001)|min }}{% endmacro %}{{ m(range) }}",
            "{% set r = range if condition else range %}{{ r(100001)|min }}",
            "{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ (m if condition else m)(range) }}",
            "{% macro w() %}{{ caller(range) }}{% endmacro %}" + "{% call(r) w() %}{{ r(100001)|min }}{% endcall %}",
            "{% set ns=namespace() %}{% set other=ns %}{% set other.r=range %}{{ ns.r(100001)|min }}",
            "{% set ns=namespace() %}{% macro bind(x) %}{% set x.r=range %}{% endmacro %}"
            + "{{ bind(ns) }}{{ ns.r(100001)|min }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}{% set ns=namespace() %}"
            + "{% macro bind(x) %}{% set x.m=bad %}{% endmacro %}{{ bind(ns) }}{{ ns.m() }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}{% set ns=namespace() %}{% set other=ns %}"
            + "{% macro bind(x) %}{% set x.m=bad %}{% endmacro %}{{ bind(other) }}{{ ns.m() }}",
            "{{ [range][0](100001)|min }}",
            "{{ (range,)[0](100001)|min }}",
            "{{ (range, range)[-1](100001)|min }}",
            "{{ ([range] + [range])[0](100001)|min }}",
            "{{ {'r': range}['r'](100001)|min }}",
            "{{ {'r': range}.get('r')(100001)|min }}",
            "{% set xs=[range] %}{{ xs[0](100001)|min }}",
            "{% set funcs={'r': range} %}{{ funcs['r'](100001)|min }}",
            "{% set funcs={'r': range} %}{{ funcs.get('r')(100001)|min }}",
            "{% set funcs=[[range]] %}{{ funcs[0][0](100001)|min }}",
            "{% set funcs={'outer': {'r': range}} %}{{ funcs.outer.r(100001)|min }}",
            "{% set funcs={'outer': {'items': range}} %}{{ funcs['outer']['items'](100001)|min }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% set funcs={'outer': {'items': bad}} %}{{ funcs['outer']['items']() }}",
            "{% macro small(_count) %}12{% endmacro %}" + "{% set funcs=[small, range] %}{{ funcs[-1](100001)|min }}",
            "{% set funcs={true: range} %}{{ funcs[true](100001)|min }}",
            "{% set values=[100001] %}{{ range(values[0])|min }}",
            "{% set values={'n': 100001} %}{{ range(values.n)|min }}",
            "{% set values=[[100001]] %}{{ range(values[0][0])|min }}",
            "{% set n='100001' %}{{ range(n|int)|min }}",
            "{% set n=100001.9 %}{{ range(n|int)|min }}",
            "{% set n='100001' %}{% set m=n|int %}{{ range(m)|min }}",
            "{{ range(('100000' ~ '1')|int)|min }}",
            "{{ (range|default)(100001)|min }}",
            "{% set r=range|d %}{{ r(100001)|min }}",
            "{{ (missing|default(range))(100001)|min }}",
            "{% set value=missing %}{{ (value|default(range))(100001)|min }}",
            "{% set value=value|default(range) %}{{ value(100001)|min }}",
            "{{ (false|default(range, true))(100001)|min }}",
            "{% set value=0 %}{{ (value|default(range, true))(100001)|min }}",
            "{% macro m() %}{{ (kwargs|default(range, true))(100001)|min }}{% endmacro %}{{ m() }}",
            "{% if unknown %}{% set n='1' %}{% endif %}{{ range((n|default('100001'))|int)|min }}",
            "{% macro small() %}ok{% endmacro %}{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% if unknown %}{% set f=small %}{% endif %}{{ (f|default(bad))() }}",
            "{% macro small() %}ok{% endmacro %}"
            + "{% if unknown %}{% set d={'x':small} %}{% else %}{% set d={} %}{% endif %}"
            + "{{ d.get('x', range)(100001)|min }}",
            "{% if unknown %}{% set d={'x':1} %}{% else %}{% set d={} %}{% endif %}"
            + "{{ range(d.get('x', 100001))|min }}",
            "{% set funcs={} %}{{ funcs.get('r', range)(100001)|min }}",
            "{% set values={} %}{{ range(values.get('n', 100001))|min }}",
            "{% macro m(n) %}{{ range(n|int)|min }}{% endmacro %}{{ m('100001') }}",
            "{% macro m(value) %}{{ (value|default(range))(100001)|min }}{% endmacro %}{{ m(missing) }}",
            "{% macro m() %}{{ range(kwargs.n)|min }}{% endmacro %}{{ m(n=100001) }}",
            "{% macro m() %}{{ range(varargs[0])|min }}{% endmacro %}{{ m(100001) }}",
            "{% set n=100001 %}{{ range(('' ~ n)|int)|min }}",
            "{% set values=[100001] %}{{ range(('' ~ values[0])|int)|min }}",
            "{{ {-1:range}[-1](100001)|min }}",
            "{{ {-1:range}.get(-1)(100001)|min }}",
            "{{ range({-1:100001}[-1])|min }}",
            "{{ {none:range}[none](100001)|min }}",
            "{% set funcs={none:range} %}{{ funcs[none](100001)|min }}",
            "{{ {(1,2):range}[(1,2)](100001)|min }}",
            "{% set funcs={(1,2):range} %}{{ funcs[(1,2)](100001)|min }}",
            "{% set kw={} %}{% macro m() %}{{ range(100001)|min }}{% endmacro %}{{ m(**kw) }}",
            "{% set kw={'x': none} %}{% macro m() %}{{ kwargs }}{{ range(100001)|min }}{% endmacro %}{{ m(**kw) }}",
            "{{ ([range]|first)(100001)|min }}",
            "{{ ([range]|last)(100001)|min }}",
            "{{ ([small, range]|reverse|first)(100001)|min }}",
            "{% for key, r in {'x': range}.items() %}{{ r(100001)|min }}{% endfor %}",
            "{% for r in [range]|reverse %}{{ r(100001)|min }}{% endfor %}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}{{ [bad][0]() }}",
            "{% set args=[range] %}{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ m(*args) }}",
            "{% set kw={'r': range} %}{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ m(**kw) }}",
            "{% set args=[100001] %}{{ range(*args)|min }}",
            "{% macro small(_count) %}0{% endmacro %}"
            + "{% macro recurse(n, f) %}{% if n %}{{ recurse(0, range) }}"
            + "{% else %}{{ f(100001)|min }}{% endif %}{% endmacro %}{{ recurse(1, small) }}",
            "{% if condition %}{% set n=100001 %}{% else %}{% set n=1 %}{% endif %}{{ range(n)|min }}",
            "{% if condition %}{% set n=1 %}{% else %}{% set n=200001 %}{% endif %}" + "{{ range(0, 200001, n)|min }}",
            "{% if condition %}{% set n=-1 %}{% else %}{% set n=-200001 %}{% endif %}"
            + "{{ range(200001, 0, n)|min }}",
            "{% if condition %}{% set n=-200001 %}{% else %}{% set n=100001 %}{% endif %}{{ range(n)|min }}",
            "{% if condition %}{% set n=0 %}{% else %}{% set n=200000 %}{% endif %}"
            + "{% set step=n + 1 %}{{ range(0, 200001, step)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set r=range %}"
            + "{% block b %}{% set r=small %}{% endblock %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set r=range %}"
            + "{% filter string %}{% set r=small %}{% endfilter %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set r=range %}"
            + "{% set x %}{% set r=small %}{% endset %}{{ r(100001)|min }}",
            "{% set ns=namespace() %}{% block b %}{% set ns.r=range %}{% endblock %}" + "{{ ns.r(100001)|min }}",
            "{% set ns=namespace() %}{% filter upper %}{% set ns.r=range %}{% endfilter %}" + "{{ ns.r(100001)|min }}",
            "{% set ns=namespace() %}{% set x %}{% set ns.r=range %}{% endset %}" + "{{ ns.r(100001)|min }}",
            "{% set ns=namespace() %}{% with %}{% set ns.r=range %}{% endwith %}" + "{{ ns.r(100001)|min }}",
            "{{ range((10 ** 1000 + 1) - 10 ** 999)|min }}",
            "{{ range(3 ** 1000 - 2 ** 1000)|min }}",
            "{{ range((-(10 ** 1000)) ** 3, 0)|min }}",
            "{{ range((-2) ** (10 ** 101))|list }}",
            "{{ range((2 ** 400) % 999983)|list }}",
            "{{ range(3 ** 300 - (2 ** 400 + 1))|min }}",
        ],
    )
    def test_unavailable_sandbox_worker_fails_closed_for_wrapped_scalar_range_filters(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "wrapped-range-scalar-filter.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_keeps_direct_range_repr_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "direct-range-expression.jinja"
        template_file.write_text("{{ range(100000) }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    @pytest.mark.parametrize(
        "template_content",
        [
            "{% set range = 1 %}{{ range(100001)|min }}",
            "{% set n = 1 %}{{ range(n)|min }}{% set n = 100001 %}",
            "{% macro small(_count) %}12{% endmacro %}",
            "{% set ns = namespace(r=range) %}{% set ns.r = small %}{{ ns.r(100001)|min }}",
            "{% set range %}not callable{% endset %}{{ range(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% with range = small %}{{ range(100001)|min }}{% endwith %}",
            "{% macro small(_count) %}12{% endmacro %}{% for range in [small] %}{{ range(100001)|min }}{% endfor %}",
            "{{ range(10 ** 101, 10 ** 101 + 100000)|min }}",
            "{% set n = 10 ** 101 %}{% set m = 100000 %}{{ range(n, n + m)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}{{ m(small) }}",
            "{% macro small(_count) %}12{% endmacro %}{% macro m(r=small) %}{{ r(100001)|min }}{% endmacro %}{{ m() }}",
            "{% set r = range %}{% if condition %}{% set r = small %}"
            + "{% else %}{% set r = small %}{% endif %}{{ r(100001)|min }}",
            "{{ range((10 ** 1000) // (10 ** 999))|sum }}",
            "{{ range((10 ** 1000) % (10 ** 999))|sum }}",
            "{{ range(10 ** 1000 + -(10 ** 1000))|sum }}",
            "{% set a = 10 ** 1000 %}{% set b = a %}{{ range(a - b)|min }}",
            "{% set a = 10 ** 1000 %}{% set b = a %}{{ range(a // b)|min }}",
            "{% set a = 10 ** 1000 %}{% set b = a %}{{ range(a % b)|min }}",
            "{{ range(0, 10 ** 1000, 10 ** 1000)|min }}",
            "{% macro m() %}{{ range(100001)|min }}{% endmacro %}",
            "{% for _ in range(0) %}{{ range(100001)|min }}{% endfor %}",
            "{{ range(100001)|min if false else 0 }}",
            "{% set r, x = (range,) %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% macro m(r) %}{{ r(100001)|min }}{% endmacro %}"
            + "{{ m(small, r=range) }}",
            "{% macro m() %}{{ range(100001)|min }}{% endmacro %}{{ m(foo=1) }}",
            "{% macro m() %}{{ range(100001)|min }}{% endmacro %}" + "{% set ns = namespace(m=m) %}{{ ns.m(foo=1) }}",
            "{% set ns = 1 %}{% set ns.r = range %}{{ ns.r(100001)|min }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% set ns = 1 %}{% set ns.m = bad %}{{ ns.m() }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}{% set ns=namespace() %}"
            + "{% macro bind(x) %}{% set x=namespace(m=bad) %}{% endmacro %}{{ bind(ns) }}{{ ns.m() }}",
            "{{ [range][0](100000)|min }}",
            "{% macro small(_count) %}12{% endmacro %}"
            + "{% set funcs={1: small, '1': range} %}{{ funcs[1](100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}"
            + "{% set funcs={1: range, '1': small} %}{{ funcs['1'](100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}"
            + "{% set funcs={'r': range, 'r': small} %}{{ funcs.r(100001)|min }}",
            "{% set funcs={'r': range} %}{{ (funcs|attr('r'))(100001)|min }}",
            "{% set kwargs={'n':100001} %}{% macro m() %}{{ range(kwargs.n)|min }}{% endmacro %}{{ m() }}",
            "{% set varargs=[100001] %}{% macro m() %}{{ range(varargs[0])|min }}{% endmacro %}{{ m() }}",
            "{% set funcs={'items': range} %}{{ funcs.items(100001)|min }}",
            "{% set funcs={'outer': {'items': range}} %}{{ funcs.outer.items(100001)|min }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% set funcs={'outer': {'items': bad}} %}{{ funcs.outer.items() }}",
            "{% set values={'items': 100001} %}{{ range(values.items)|min }}",
            "{% for n in [0] if n %}{{ range(100001)|min }}{% endfor %}",
            "{% for n in [1] if not n %}{{ range(100001)|min }}{% endfor %}",
            "{% for n in [1,2] if n < 0 %}{{ range(100001)|min }}{% endfor %}",
            "{% for n in [1,2] if n == 0 %}{{ range(100001)|min }}{% endfor %}",
            "{% for n in [1,1] if n != 1 %}{{ range(100001)|min }}{% endfor %}",
            "{% for n in {'x':0}.values() if n %}{{ range(100001)|min }}{% endfor %}",
            "{% set value=1 %}{{ (value|default(range))(100001)|min }}",
            "{% set value='ok' %}{{ (value|d(range))(100001)|min }}",
            "{% macro m(value) %}{{ (value|default(range))(100001)|min }}{% endmacro %}{{ m(1) }}",
            "{% macro small(_count) %}12{% endmacro %}{{ (small|default(range))(100001)|min }}",
            "{% set d={'x':'ok'} %}{{ (d.x|default(range))(100001)|min }}",
            "{% set d={'x':{'y':'ok'}} %}{{ (d['x']['y']|default(range))(100001)|min }}",
            "{% set ns=namespace(x='ok') %}{{ (ns.x|default(range))(100001)|min }}",
            "{% set ns=namespace() %}{% set ns.x='ok' %}{{ (ns.x|default(range))(100001)|min }}",
            "{% set value %}ok{% endset %}{{ (value|default(range))(100001)|min }}",
            "{% macro bad() %}{{ range(100001)|min }}{% endmacro %}"
            + "{% macro wrapper(value) %}{{ (value|default(bad))() }}{% endmacro %}{{ wrapper(1) }}",
            "{% set kwargs=range %}{% macro m() %}{{ kwargs(100001)|min }}{% endmacro %}{{ m() }}",
            "{% set varargs=range %}{% macro m() %}{{ varargs(100001)|min }}{% endmacro %}{{ m() }}",
            "{% macro m() %}{{ (kwargs|default(range))(100001)|min }}{% endmacro %}{{ m() }}",
            "{{ range((-(10 ** 1000)) ** 2, 0)|min }}",
            "{% set r = range %}{{ r(4)|list }}",
            "{% set r = range %}{{ r(10)|join }}",
            "{% for n in [100001] if false %}{{ range(n)|min }}{% else %}ok{% endfor %}",
            "{% macro noop(caller=None) %}ok{% endmacro %}" + "{% call noop() %}{{ range(100001)|min }}{% endcall %}",
            "{% macro small(_count) %}12{% endmacro %}{% set ns=namespace(r=range) %}"
            + "{% set other=ns %}{% set other.r=small %}{{ ns.r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set r=small %}"
            + "{% block b %}{% set r=range %}{% endblock %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set r=small %}"
            + "{% filter string %}{% set r=range %}{% endfilter %}{{ r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set ns=namespace(r=range) %}"
            + "{% block b %}{% set ns.r=small %}{% endblock %}{{ ns.r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set ns=namespace(r=range) %}"
            + "{% filter upper %}{% set ns.r=small %}{% endfilter %}{{ ns.r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set ns=namespace(r=range) %}"
            + "{% set x %}{% set ns.r=small %}{% endset %}{{ ns.r(100001)|min }}",
            "{% macro small(_count) %}12{% endmacro %}{% set ns=namespace(r=range) %}"
            + "{% with %}{% set ns.r=small %}{% endwith %}{{ ns.r(100001)|min }}",
            "{% if 1 - 1 %}{{ range(100001)|min }}{% endif %}",
            "{{ range(0, 10 ** 1000, 2 * 10 ** 1000)|min }}",
            "{% if condition %}{% set n=100001 %}{% else %}{% set n=200001 %}{% endif %}"
            + "{{ range(0, 200001, n)|min }}",
        ],
    )
    def test_unavailable_sandbox_worker_keeps_ordered_range_boundaries_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "ordered-range-boundary.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_keeps_small_symbolic_range_delta_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "small-symbolic-range-delta.jinja"
        template_file.write_text(
            "{{ range(10 ** 1000, (10 ** 1000 + 2) - 1) }}",
            encoding="utf-8",
        )

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 65536})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ range(100000)|min }}",
            "{{ range(100000)|max }}",
            "{{ range(100000)|sum }}",
            "{{ range(1000)|slice(10) }}",
        ],
    )
    def test_unavailable_sandbox_worker_keeps_scalar_and_lazy_range_filters_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "bounded-range-filter.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_respects_shadowed_range_macro(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "shadowed-range-macro.jinja"
        template_file.write_text(
            "{% macro range(_count) %}12{% endmacro %}{{ range(100001)|min }}",
            encoding="utf-8",
        )

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    @pytest.mark.parametrize(
        "template_content",
        [
            "{% macro range(_count) %}12{% endmacro %}{{ range(100001)|list }}",
            "{% macro range(_count) %}12{% endmacro %}{{ range(100001)|join }}",
            "{% macro range(_count) %}12{% endmacro %}{% for item in range(100001) %}{{ item }}{% endfor %}",
        ],
    )
    def test_unavailable_sandbox_worker_respects_shadowed_range_in_eager_contexts(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "shadowed-range-eager.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_static_range_analysis_fails_closed_when_macro_expansion_budget_is_exhausted(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_RENDER_ANALYSIS_STEPS", 32)
        definitions: list[str] = []
        assignments: list[str] = []
        for index in range(6):
            next_call = f"f{index + 1}()" if index + 1 < 6 else "0"
            definitions.extend(
                [
                    f"{{% macro a{index}() %}}{{{{ {next_call} }}}}{{% endmacro %}}",
                    f"{{% macro b{index}() %}}{{{{ {next_call} }}}}{{% endmacro %}}",
                ]
            )
            assignments.append(
                f"{{% if condition{index} %}}{{% set f{index}=a{index} %}}"
                f"{{% else %}}{{% set f{index}=b{index} %}}{{% endif %}}"
            )
        template_content = "".join([*definitions, *assignments, "{{ f0() }}"])

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_render_budget_risk(template_content) is True

    def test_static_range_analysis_fails_closed_when_projection_budget_is_exhausted(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_RANGE_PROJECTION_ITEMS", 15_000)
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1_000_000})

        assert scanner._template_has_static_render_budget_risk("{{ range(10000)|list }}" * 2) is True

    def test_static_range_analysis_fails_closed_when_candidate_values_are_truncated(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        values = [1, 2, 3, 4, 6, 7, 8, 9, 5]
        branches = [
            f"{{% {'if' if index == 0 else 'elif'} condition{index} %}}{{% set n={value} %}}"
            for index, value in enumerate(values[:-1])
        ]
        template_content = (
            "".join(branches) + "{% else %}{% set n=5 %}{% endif %}" + "{{ range(0,100001,((n-5)|abs)+1)|min }}"
        )
        template_file = tmp_path / "candidate-truncation.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "test"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"

    def test_static_range_analysis_bounds_candidate_variant_projection(self) -> None:
        pytest.importorskip("jinja2.sandbox")

        def binding(name: str, scale: int, binding_index: int) -> str:
            values = [item * scale for item in range(8)]
            branches = [
                f"{{% {'if' if index == 0 else 'elif'} condition{binding_index}_{index} %}}{{% set {name}={value} %}}"
                for index, value in enumerate(values[:-1])
            ]
            return "".join(branches) + f"{{% else %}}{{% set {name}={values[-1]} %}}{{% endif %}}"

        template_content = (
            "".join(
                binding(name, scale, index)
                for index, (name, scale) in enumerate(zip("abcd", [1, 8, 64, 512], strict=True))
            )
            + "{{ range(10000+a+b+c+d)|list }}"
        )
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 65_536})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    def test_static_range_analysis_charges_empty_macro_candidates(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_RENDER_ANALYSIS_STEPS", 64)
        candidate_count = 16
        macro_definitions = "".join(
            f"{{% macro candidate{index}() %}}{{% endmacro %}}" for index in range(candidate_count)
        )
        conditional_bindings = "".join(
            f"{{% if condition{index} %}}{{% set selected=candidate{index} %}}{{% endif %}}"
            for index in range(candidate_count)
        )
        template_content = macro_definitions + conditional_bindings + "{{ selected() }}" * candidate_count
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    def test_static_range_analysis_bounds_wide_destructuring_state(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_RENDER_ANALYSIS_STEPS", 128)
        binding_count = 16
        prefix = "".join(f"{{% set source{index}={index} %}}" for index in range(binding_count))
        targets = ",".join(f"target{index}" for index in range(binding_count))
        values = ",".join("1" for _ in range(binding_count))
        template_content = prefix + f"{{% set {targets}=[{values}] %}}"
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    def test_static_range_analysis_bounds_nested_container_paths(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_CONTAINER_PATHS", 32)
        nested_value = "1"
        for _ in range(6):
            nested_value = f"[{nested_value}]"
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(f"{{% set value={nested_value} %}}") is True

    @pytest.mark.parametrize("unpack_kind", ["args", "kwargs"])
    def test_static_range_analysis_bounds_repeated_macro_argument_projection(
        self,
        monkeypatch: pytest.MonkeyPatch,
        unpack_kind: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        monkeypatch.setattr(jinja2_template_scanner, "_MAX_STATIC_RENDER_ANALYSIS_STEPS", 2_048)
        if unpack_kind == "args":
            packed_value = "[" + ",".join(str(index) for index in range(16)) + "]"
            macro = "{% macro m() %}{% if varargs %}ok{% endif %}{% endmacro %}"
            call = "{{ m(*packed) }}"
        else:
            packed_value = "{" + ",".join(f"'k{index}':{index}" for index in range(16)) + "}"
            macro = "{% macro m() %}{% if kwargs %}ok{% endif %}{% endmacro %}"
            call = "{{ m(**packed) }}"
        template_content = f"{{% set packed={packed_value} %}}" + macro + call * 4
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    @pytest.mark.parametrize("unpack_kind", ["args", "kwargs"])
    def test_static_range_analysis_allows_bounded_macro_argument_projection(
        self,
        unpack_kind: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        if unpack_kind == "args":
            packed_value = "[" + ",".join(str(index) for index in range(16)) + "]"
            macro = "{% macro m() %}{% if varargs %}ok{% endif %}{% endmacro %}"
            call = "{{ m(*packed) }}"
        else:
            packed_value = "{" + ",".join(f"'k{index}':{index}" for index in range(16)) + "}"
            macro = "{% macro m() %}{% if kwargs %}ok{% endif %}{% endmacro %}"
            call = "{{ m(**packed) }}"
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert (
            scanner._template_has_static_preflight_render_budget_risk(
                f"{{% set packed={packed_value} %}}" + macro + call
            )
            is False
        )

    def test_static_range_analysis_bounds_wide_repeated_macro_unpacking(self) -> None:
        pytest.importorskip("jinja2.sandbox")
        packed_value = "[" + ",".join(str(index) for index in range(2_000)) + "]"
        macro = "{% macro m() %}{% if varargs %}ok{% endif %}{% endmacro %}"
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert (
            scanner._template_has_static_preflight_render_budget_risk(
                f"{{% set packed={packed_value} %}}" + macro + "{{ m(*packed) }}" * 5
            )
            is True
        )

    def test_static_range_analysis_bounds_wide_formal_macro_binding(self) -> None:
        pytest.importorskip("jinja2.sandbox")
        argument_names = ",".join(f"value{index}" for index in range(2_000))
        argument_values = ",".join(str(index) for index in range(2_000))
        template_content = (
            f"{{% set packed=[{argument_values}] %}}"
            f"{{% macro m({argument_names}) %}}ok{{% endmacro %}}"
            "{{ m(*packed) }}"
        )
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    def test_static_range_analysis_bounds_wide_omitted_formal_cleanup(self) -> None:
        pytest.importorskip("jinja2.sandbox")
        argument_names = ",".join(f"value{index}" for index in range(2_000))
        argument_values = ",".join("0" for _ in range(2_000))
        template_content = (
            f"{{% set packed=[{argument_values}] %}}{{% macro m({argument_names}) %}}ok{{% endmacro %}}{{{{ m() }}}}"
        )
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_preflight_render_budget_risk(template_content) is True

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ (namespace(r=range)|attr('r'))(100001)|min }}",
            "{% set ns=namespace(r=range) %}{{ (ns|attr('r'))(100001)|min }}",
        ],
    )
    def test_static_range_analysis_resolves_namespace_attr_filter(self, template_content: str) -> None:
        pytest.importorskip("jinja2.sandbox")
        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._template_has_static_render_budget_risk(template_content) is True

    def test_unavailable_sandbox_worker_respects_overwritten_range_function_alias(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "overwritten-range-function.jinja"
        template_file.write_text(
            "{% macro small(_count) %}12{% endmacro %}"
            "{% set reducer = range %}{% set reducer = small %}{{ reducer(100001)|min }}",
            encoding="utf-8",
        )

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_large_range_loop(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-loop.jinja"
        template_file.write_text("{% for i in range(1000) %}{% endfor %}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_fails_closed_when_lazy_slice_is_iterated(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-slice-loop.jinja"
        template_file.write_text("{% for group in range(1000)|slice(10) %}{% endfor %}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_fails_closed_for_large_range_join(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-join.jinja"
        template_file.write_text("{{ range(1000)|join }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_static_preflight_blocks_range_join_before_worker_start(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")

        def fail_get_context(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("sandbox worker should not start")

        monkeypatch.setattr(jinja2_template_scanner.mp, "get_context", fail_get_context)

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1000})
        status, detail = scanner._test_template_safety_with_budget("{{ range(100000, 200000)|join }}")

        assert status == "budget_exceeded"
        assert detail == "output"

    @pytest.mark.parametrize(
        ("format_string", "arguments", "expected"),
        [
            ("%100000000s", "", True),
            ("%*s", (100000000, ""), True),
            ("%10s", "", False),
        ],
    )
    def test_percent_format_budget_projection(
        self,
        format_string: str,
        arguments: object,
        expected: bool,
    ) -> None:
        exceeds_budget = jinja2_template_scanner._percent_format_exceeds_budget(format_string, arguments, 64)

        assert exceeds_budget is expected

    def test_budgeted_sandbox_intercepts_percent_format_before_render(self) -> None:
        pytest.importorskip("jinja2.sandbox")

        status, detail = jinja2_template_scanner._run_budgeted_sandbox_render("{{ '%1000000s' % '' }}", 64)

        assert status == "budget_exceeded"
        assert detail == "output"

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ range(10 ** 13 + 1, 2 * 10 ** 13)|list }}",
            "{{ range(-(2 * 10 ** 13), -(10 ** 13))|list }}",
            "{{ range(2 * 10 ** 13, 10 ** 13, -1)|list }}",
            "{{ range(10 ** 101, 2 * 10 ** 101)|list }}",
            "{{ range(10 ** 1000 - 10 ** 101)|list }}",
            "{{ range(+(10 ** 8))|list }}",
            "{{ range(10 ** 8 // 1)|list }}",
            "{{ range((10 ** 8) % 100000001)|list }}",
            "{{ range(10 ** 8 if true else 1)|list }}",
            '{{ range("100000000"|int)|list }}',
            "{{ range((-100000000)|abs)|list }}",
        ],
    )
    def test_static_preflight_preserves_large_range_bound_risk(
        self,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")

        def fail_get_context(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("sandbox worker should not start")

        monkeypatch.setattr(jinja2_template_scanner.mp, "get_context", fail_get_context)

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})

        assert scanner._test_template_safety_with_budget(template_content) == ("budget_exceeded", "output")

    @pytest.mark.parametrize(
        "template_content",
        [
            "{{ range(0, 10 ** 8, 0)|list }}",
            "{{ range(0, 10 ** 8, 1, 2)|list }}",
            "{{ range((10 ** 1000) * 0)|list }}",
            "{{ range(0 * (10 ** 1000))|list }}",
            "{{ range((10 ** 1000) ** 0)|list }}",
            "{{ range(2 ** -(10 ** 1000))|list }}",
            "{{ range(0 // (10 ** 1000))|list }}",
            "{{ range(0 % (10 ** 1000))|list }}",
            "{{ range(10 ** 1000 - 10 ** 1000)|list }}",
            "{{ range((10 ** 1000) // (10 ** 1000))|list }}",
            "{{ range((10 ** 1000) % (10 ** 1000))|list }}",
            "{{ range((10 ** 101) // 10 - 10 ** 100)|list }}",
            "{{ range(0, (10 ** 100) % (-(10 ** 100 + 1)), -1)|list }}",
            "{{ range(-(10 ** 1000))|list }}",
            "{{ range(10 ** 1000, 0)|list }}",
        ],
    )
    def test_unavailable_sandbox_worker_keeps_non_amplifying_and_invalid_range_calls_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        template_content: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "invalid-range.jinja"
        template_file.write_text(template_content, encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_keeps_exact_saturated_power_quotient_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "exact-power-quotient.jinja"
        template_file.write_text("{{ range((10 ** 101) // (10 ** 100))|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1000})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    @pytest.mark.parametrize("numeric_text", ["x" * 4097, "0" * 4097])
    def test_unavailable_sandbox_worker_keeps_long_non_amplifying_int_filters_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        numeric_text: str,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "long-int-filter.jinja"
        template_file.write_text(f'{{{{ range("{numeric_text}"|int)|list }}}}', encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_counts_large_range_tail(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "large-range-tail.jinja"
        template_file.write_text("{{ range(200000)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1_000_000})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert any(
            check.name == "Template Sandbox Safety Probe" and check.details["budget_type"] == "worker_unavailable"
            for check in result.checks
        )

    def test_unavailable_sandbox_worker_keeps_small_range_at_large_offset_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "large-offset-small-range.jinja"
        template_file.write_text("{{ range(10 ** 13, 10 ** 13 + 1)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 64})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_materialized_lazy_range_filter(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-select-list.jinja"
        template_file.write_text("{{ range(1000)|select|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_uses_rendered_size_for_range_list_fallback(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "rendered-range-expression.jinja"
        template_file.write_text("{{ range(300)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1000})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_fails_closed_for_multi_arg_static_expression_range(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "range-expression.jinja"
        template_file.write_text("{{ range(0, 10 ** 8)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_keeps_small_multi_arg_range_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "small-range-expression.jinja"
        template_file.write_text("{{ range(99999, 100000)|list }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_static_render_amplification(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify.jinja"
        template_file.write_text("{{ 'A' * 1000000 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_sandbox_render_budget_exceeded" in result.metadata["scan_outcome_reasons"]
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_respects_configured_budget_for_string_repetition(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "bounded-amplify.jinja"
        template_file.write_text("{{ 'A' * 10000 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 65536})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_repeated_large_list_literal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify-list-literal.jinja"
        template_file.write_text("{{ ['ABCDEFGHIJKLMNOPQRST'] * 2 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_fails_closed_for_repeated_dict_list_literal(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "amplify-dict-list-literal.jinja"
        template_file.write_text(r"{{ [{'long_key': 'long_value'}] * 50 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 1000})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"

    def test_unavailable_sandbox_worker_keeps_integer_multiplication_clean(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "integer-multiplication.jinja"
        template_file.write_text("{{ 100000 * 100000 }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner({"sandbox_render_max_output_chars": 16})
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.success is True
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]

    def test_unavailable_sandbox_worker_fails_closed_for_static_sandbox_risk(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("jinja2.sandbox")
        template_file = tmp_path / "dunder.jinja"
        template_file.write_text("{{ messages.__class__ }}", encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        monkeypatch.setattr(
            scanner,
            "_test_template_safety_with_budget",
            lambda _template_content: ("worker_unavailable", "AssertionError"),
        )
        result = scanner.scan(str(template_file))

        assert result.has_errors is True
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"
        failed_checks = [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]
        assert any(c.details.get("pattern_type") == "sandbox_violation" for c in failed_checks)

    def test_sandbox_worker_memory_limit_uses_resource_baseline_without_statm(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[int, tuple[int, int]]] = []

        class Usage:
            ru_maxrss = 2048

        class FakeResource:
            RLIMIT_AS = 1
            RLIM_INFINITY = -1
            RUSAGE_SELF = 0

            def getrlimit(self, _limit_id: int) -> tuple[int, int]:
                return (-1, self.RLIM_INFINITY)

            def getrusage(self, _who: int) -> Usage:
                return Usage()

            def setrlimit(self, limit_id: int, limits: tuple[int, int]) -> None:
                calls.append((limit_id, limits))

        monkeypatch.setattr(jinja2_template_scanner, "HAS_RESOURCE_LIMITS", True)
        monkeypatch.setattr(jinja2_template_scanner, "resource", FakeResource())
        monkeypatch.setattr(jinja2_template_scanner, "_proc_statm_virtual_memory_bytes", lambda: None)
        monkeypatch.setattr(jinja2_template_scanner.platform, "system", lambda: "Linux")

        jinja2_template_scanner._limit_sandbox_worker_memory(1024)

        assert calls == [(1, (2048 * 1024 + 1024, -1))]

    def test_sandbox_worker_memory_limit_adds_configured_budget_to_baseline(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[int, tuple[int, int]]] = []

        class FakeResource:
            RLIMIT_AS = 1
            RLIM_INFINITY = -1

            def getrlimit(self, _limit_id: int) -> tuple[int, int]:
                return (-1, self.RLIM_INFINITY)

            def setrlimit(self, limit_id: int, limits: tuple[int, int]) -> None:
                calls.append((limit_id, limits))

        monkeypatch.setattr(jinja2_template_scanner, "HAS_RESOURCE_LIMITS", True)
        monkeypatch.setattr(jinja2_template_scanner, "resource", FakeResource())
        monkeypatch.setattr(jinja2_template_scanner, "_proc_statm_virtual_memory_bytes", lambda: 1024)

        jinja2_template_scanner._limit_sandbox_worker_memory(512)

        assert calls == [(1, (1536, -1))]

    def test_sandbox_worker_prefers_spawn_when_proc_baseline_is_unavailable(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(jinja2_template_scanner.mp, "get_all_start_methods", lambda: ["fork", "spawn"])
        monkeypatch.setattr(jinja2_template_scanner, "_proc_statm_virtual_memory_bytes", lambda: None)

        assert jinja2_template_scanner._sandbox_worker_start_method() == "spawn"

    def test_path_traversal_suppression_does_not_hide_object_traversal_ssti(self, tmp_path: Path) -> None:
        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(
            json.dumps({"chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"}),
            encoding="utf-8",
        )

        set_config(ModelAuditConfig(suppress={"S405"}))
        try:
            result = Jinja2TemplateScanner().scan(str(tokenizer_file))
        finally:
            reset_config()

        failed_checks = [check for check in result.checks if check.name == "Jinja2 Template Injection Detection"]
        assert any(check.details.get("pattern_type") == "object_traversal" for check in failed_checks)
        assert not any(check.rule_code == "S405" for check in failed_checks)

    def test_invalid_utf8_standalone_template_returns_inconclusive_exit2(self, tmp_path: Path) -> None:
        """Unreadable standalone templates must not look clean."""
        template_file = tmp_path / "invalid.jinja"
        template_file.write_bytes(b"{{ cycler.__init__.__globals__ }}\xff")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        assert "jinja2_template_read_failed" in result.metadata["scan_outcome_reasons"]
        assert any(
            check.name == "Template Read"
            and check.status == CheckStatus.FAILED
            and check.details["exception_type"] == "UnicodeDecodeError"
            for check in result.checks
        )

        aggregate_result = scan_model_directory_or_file(str(template_file), cache_enabled=False)
        assert aggregate_result.success is False
        assert determine_exit_code(aggregate_result) == 2

    def test_handles_unicode_content(self, tmp_path: Path) -> None:
        """Test handling of unicode characters in templates."""
        config = {
            "chat_template": "{{ message }} - \u4f60\u597d - \u0645\u0631\u062d\u0628\u0627",
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        # Should complete successfully
        assert result.success is True


class TestJinja2TemplateScannerConfiguration:
    """Test scanner configuration options."""

    @pytest.mark.parametrize("value", [float("-inf"), float("inf"), float("nan")])
    def test_non_finite_sandbox_budget_config_uses_defaults(self, value: float) -> None:
        scanner = Jinja2TemplateScanner(
            {
                "sandbox_render_timeout_seconds": value,
                "sandbox_render_max_output_chars": value,
                "sandbox_render_max_memory_bytes": value,
            }
        )

        assert scanner.sandbox_render_timeout_seconds == 0.5
        assert scanner.sandbox_render_max_output_chars == 64 * 1024
        assert scanner.sandbox_render_max_memory_bytes == 512 * 1024 * 1024

    def test_sensitivity_high(self, tmp_path: Path) -> None:
        """Test high sensitivity mode."""
        template_file = tmp_path / "test.jinja"
        template_file.write_text("{% for item in items %}{{ item }}{% endfor %}")

        scanner = Jinja2TemplateScanner(config={"sensitivity_level": "high"})
        result = scanner.scan(str(template_file))

        # High sensitivity should still complete
        assert result.success is True

    def test_sensitivity_low(self, tmp_path: Path) -> None:
        """Test low sensitivity mode."""
        template_file = tmp_path / "test.jinja"
        template_file.write_text("{% for item in items %}{{ item }}{% endfor %}")

        scanner = Jinja2TemplateScanner(config={"sensitivity_level": "low"})
        result = scanner.scan(str(template_file))

        # Low sensitivity should still complete
        assert result.success is True

    def test_skip_common_patterns_enabled(self, tmp_path: Path) -> None:
        """Test that common ML patterns are skipped when configured."""
        huggingface_dir = tmp_path / "huggingface" / "model"
        huggingface_dir.mkdir(parents=True)

        config = {
            "chat_template": "{% for message in messages %}{{ message['role'] }}{% endfor %}",
        }

        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner(config={"skip_common_patterns": True})
        result = scanner.scan(str(tokenizer_file))

        # Common patterns should be skipped
        warning_checks = [
            c for c in result.checks if c.status == CheckStatus.FAILED and c.severity == IssueSeverity.WARNING
        ]
        assert len(warning_checks) == 0


class TestJinja2TemplateScannerStandaloneFiles:
    """Test scanning of standalone template files."""

    def test_scans_jinja_file(self, tmp_path: Path) -> None:
        """Test scanning of .jinja file."""
        template_file = tmp_path / "test.jinja"
        template_file.write_text("{{ self.__init__.__globals__['os'] }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0

    def test_scans_j2_file(self, tmp_path: Path) -> None:
        """Test scanning of .j2 file."""
        template_file = tmp_path / "test.j2"
        template_file.write_text("{{ config.__class__.__init__.__globals__ }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        failed_checks = [c for c in result.checks if c.status == CheckStatus.FAILED]
        assert len(failed_checks) > 0


class TestJinja2TemplateCommittedCorpus:
    """Regression coverage for committed Jinja2 template fixtures."""

    def test_committed_corpus_inventory_is_not_empty(self) -> None:
        all_fixtures = (
            MALICIOUS_JSON_FIXTURES
            + BENIGN_JSON_FIXTURES
            + MALICIOUS_STANDALONE_FIXTURES
            + BENIGN_STANDALONE_FIXTURES
            + MALICIOUS_YAML_FIXTURES
            + BENIGN_YAML_FIXTURES
        )

        assert MALICIOUS_JSON_FIXTURES
        assert BENIGN_JSON_FIXTURES
        assert any(path.suffix == ".template" for path in MALICIOUS_STANDALONE_FIXTURES)
        assert any(path.suffix == ".template" for path in BENIGN_STANDALONE_FIXTURES)
        assert all(path.is_file() for path in all_fixtures), [
            str(path.relative_to(JINJA2_ASSETS_DIR)) for path in all_fixtures if not path.is_file()
        ]

    @pytest.mark.parametrize("fixture_path", MALICIOUS_JSON_FIXTURES, ids=_fixture_id)
    def test_malicious_json_fixtures_detect_when_routed_as_tokenizer_config(
        self,
        fixture_path: Path,
        tmp_path: Path,
    ) -> None:
        tokenizer_file = _copy_as_tokenizer_config(fixture_path, tmp_path)

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed malicious Jinja2 fixture to produce a security check: {fixture_path}"

    @pytest.mark.parametrize("fixture_path", BENIGN_JSON_FIXTURES, ids=_fixture_id)
    def test_benign_json_fixtures_remain_quiet_when_routed_as_tokenizer_config(
        self,
        fixture_path: Path,
        tmp_path: Path,
    ) -> None:
        tokenizer_file = _copy_as_tokenizer_config(fixture_path, tmp_path)

        result = Jinja2TemplateScanner().scan(str(tokenizer_file))

        assert not any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed benign Jinja2 fixture to stay quiet: {fixture_path}"

    @pytest.mark.parametrize("fixture_path", MALICIOUS_STANDALONE_FIXTURES, ids=_fixture_id)
    def test_malicious_standalone_fixtures_detect(self, fixture_path: Path) -> None:
        result = Jinja2TemplateScanner().scan(str(fixture_path))

        assert any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed malicious Jinja2 fixture to produce a security check: {fixture_path}"

    @pytest.mark.parametrize("fixture_path", BENIGN_STANDALONE_FIXTURES, ids=_fixture_id)
    def test_benign_standalone_fixtures_remain_quiet(self, fixture_path: Path) -> None:
        result = Jinja2TemplateScanner().scan(str(fixture_path))

        assert not any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed benign Jinja2 fixture to stay quiet: {fixture_path}"

    @pytest.mark.parametrize("fixture_path", MALICIOUS_YAML_FIXTURES, ids=_fixture_id)
    def test_malicious_yaml_fixtures_detect(self, fixture_path: Path) -> None:
        pytest.importorskip("yaml")

        result = Jinja2TemplateScanner().scan(str(fixture_path))

        assert any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed malicious Jinja2 fixture to produce a security check: {fixture_path}"

    @pytest.mark.parametrize("fixture_path", BENIGN_YAML_FIXTURES, ids=_fixture_id)
    def test_benign_yaml_fixtures_remain_quiet(self, fixture_path: Path) -> None:
        pytest.importorskip("yaml")

        result = Jinja2TemplateScanner().scan(str(fixture_path))

        assert not any(
            check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
            for check in result.checks
        ), f"Expected committed benign Jinja2 fixture to stay quiet: {fixture_path}"


class TestJinja2TemplateScannerMetadata:
    """Test that metadata is properly populated."""

    def test_metadata_includes_context(self, tmp_path: Path) -> None:
        """Test that scan results include ML context metadata."""
        huggingface_dir = tmp_path / "huggingface" / "model"
        huggingface_dir.mkdir(parents=True)

        config = {"chat_template": "{{ message }}"}

        tokenizer_file = huggingface_dir / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config))

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(tokenizer_file))

        # Check metadata includes ML context
        assert "ml_context" in result.metadata
        assert result.metadata["ml_context"]["framework"] == "huggingface"

    def test_metadata_includes_file_size(self, tmp_path: Path) -> None:
        """Test that scan results include file size."""
        template_file = tmp_path / "test.jinja"
        template_file.write_text("{{ content }}")

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        assert "file_size" in result.metadata
        assert result.metadata["file_size"] > 0
