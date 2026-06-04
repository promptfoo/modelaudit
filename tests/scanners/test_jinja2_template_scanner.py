"""Tests for Jinja2TemplateScanner covering CVE-2024-34359 and SSTI detection."""

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from modelaudit.config.rule_config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import jinja2_template_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity
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

        scanner = Jinja2TemplateScanner({"max_template_size": 128})
        result = scanner.scan(str(tokenizer_file))

        assert result.has_warnings or result.has_errors
        assert "scan_outcome" not in result.metadata
        assert not [c for c in result.checks if c.name == "Template Size Limit"]
        assert [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

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
