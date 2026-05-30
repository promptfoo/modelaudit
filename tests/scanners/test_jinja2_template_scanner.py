"""Tests for Jinja2TemplateScanner covering CVE-2024-34359 and SSTI detection."""

import json
import time
from pathlib import Path

import pytest

from modelaudit.config.rule_config import ModelAuditConfig, reset_config, set_config
from modelaudit.core import determine_exit_code, scan_model_directory_or_file
from modelaudit.scanners import jinja2_template_scanner
from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.jinja2_template_scanner import Jinja2TemplateScanner

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

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

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

        assert result.success is False
        assert result.metadata["scan_outcome"] == "inconclusive"
        budget_checks = [c for c in result.checks if c.name == "Template Sandbox Safety Probe"]
        assert len(budget_checks) == 1
        assert budget_checks[0].details["budget_type"] == "worker_unavailable"
        assert not [c for c in result.checks if c.name == "Jinja2 Template Injection Detection"]

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
