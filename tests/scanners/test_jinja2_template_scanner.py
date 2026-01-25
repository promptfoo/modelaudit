"""Tests for Jinja2TemplateScanner covering CVE-2024-34359 and SSTI detection."""

import json
from pathlib import Path

import pytest

from modelaudit.scanners.base import CheckStatus, IssueSeverity
from modelaudit.scanners.jinja2_template_scanner import Jinja2TemplateScanner


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

        # Should complete (may or may not succeed depending on implementation)
        assert result is not None

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
        """Test handling of templates exceeding size limit."""
        # Create template larger than max_template_size (default 50000)
        large_content = "{{ content }}" * 10000  # > 50000 chars

        template_file = tmp_path / "large.jinja"
        template_file.write_text(large_content)

        scanner = Jinja2TemplateScanner()
        result = scanner.scan(str(template_file))

        # Should complete without error
        assert result.success is True

    def test_handles_unicode_content(self, tmp_path: Path) -> None:
        """Test handling of unicode characters in templates."""
        config = {
            "chat_template": "{{ message }} - \u4f60\u597d - \u0645\u0631\u062d\u0628\u0627",
        }

        tokenizer_file = tmp_path / "tokenizer_config.json"
        tokenizer_file.write_text(json.dumps(config, ensure_ascii=False))

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
