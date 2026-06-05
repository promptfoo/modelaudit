"""Scanner for text-based ML files like README.md and vocab.txt."""

import ast
import os
import re
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlsplit

from modelaudit.core_results import mark_operational_scan_error
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from modelaudit.scanners.base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

TEXT_CONTENT_SECURITY_SCAN_INCOMPLETE_REASON = "text_content_security_scan_incomplete"
TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON = "text_content_security_detector_failed"
TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON = "text_content_security_finding_limit"
TEXT_CONTENT_SECURITY_CLASSIFICATION_LIMIT_REASON = "text_content_security_classification_limit"
DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES = 100 * 1024 * 1024
DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS = 1024
DETECTOR_FINDING_LIMIT_TYPE = "detector_finding_limit"
DOCUMENTATION_TEXT_FILENAMES = frozenset(
    {
        "license.md",
        "license.rst",
        "license.txt",
        "model_card",
        "model_card.md",
        "model_card.rst",
        "model_card.txt",
        "modelcard.md",
        "readme",
        "readme.md",
        "readme.markdown",
        "readme.rst",
        "readme.txt",
    }
)
PASSIVE_NETWORK_FINDING_TYPES = frozenset(
    {
        "cloud_storage_url",
        "domain",
        "domain_name",
        "ipv4_address",
        "ipv6_address",
        "url_detected",
    }
)
PASSIVE_DATA_TEXT_FILENAMES = frozenset({"classes.txt"})
PASSIVE_DATA_TEXT_PREFIXES = ("label", "token", "vocab")
BARE_NETWORK_URL_TOKEN_PATTERN = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://\S+")
REQUIREMENTS_RAW_URL_PATTERN = re.compile(rb"https?://\S+", re.IGNORECASE)
BARE_NETWORK_IPV4_TOKEN_PATTERN = re.compile(
    rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
BARE_NETWORK_IPV6_TOKEN_PATTERN = re.compile(rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}")
BARE_NETWORK_DOMAIN_TOKEN_PATTERN = re.compile(rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
BARE_NETWORK_TOKEN_PATTERNS = (
    BARE_NETWORK_URL_TOKEN_PATTERN,
    BARE_NETWORK_IPV4_TOKEN_PATTERN,
    BARE_NETWORK_IPV6_TOKEN_PATTERN,
    BARE_NETWORK_DOMAIN_TOKEN_PATTERN,
)
MAX_TEXT_FINDING_CONTEXT_BYTES = 4096
MAX_DOCUMENTATION_FINDING_RETARGET_OCCURRENCES = 1024
DOCUMENTATION_CODE_ASSIGNMENT_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=[\s(\[{\\]{0,4096}[rubfRUBF]*[\"']?$"
)
DOCUMENTATION_PASSIVE_HTML_URL_ATTRIBUTE_PATTERN = re.compile(
    rb"<(?:a\b[^<>]{0,4096}\bhref|img\b[^<>]{0,4096}\bsrc)\s*=\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_HTML_URL_ATTRIBUTE_PATTERN = re.compile(rb"\b(?:href|src)\s*=\s*[\"']?$", re.IGNORECASE)
DOCUMENTATION_CODE_CALL_PATTERN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()]{0,4096}[rubfRUBF]*[\"']$")
DOCUMENTATION_ENCLOSING_CALL_PATTERN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()\n]{0,4096}$")
DOCUMENTATION_MARKDOWN_PREFIX_PATTERN = re.compile(rb"(?:(?:[-*+>]|[0-9]{1,9}[.)])\s+){1,8}")
DOCUMENTATION_CONFIG_MAPPING_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])(?:"
    rb"[\"'](?:endpoint|callback|webhook)(?:[_-][A-Za-z0-9_.-]{1,128})?[\"']"
    rb"|(?:endpoint|callback|webhook)(?:[_-][A-Za-z0-9_.-]{1,128})?"
    rb")\s*:\s*(?:\[\s*)?(?:(?:\r?\n|\r)[ \t]*(?:[-*+]\s+)?)?[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_NESTED_CONFIG_OBJECT_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])[\"']?(?:endpoint|callback|webhook)"
    rb"(?:[_-][A-Za-z0-9_.-]{1,128})?[\"']?\s*(?:=|:)\s*"
    rb"\{[^{}\r\n]{0,4096}[\"']?(?:url|uri)[\"']?\s*:\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_NESTED_CONFIG_PARENT_LINE_PATTERN = re.compile(
    rb"[ \t]*[\"']?(?:endpoint|callback|webhook)(?:[_-][A-Za-z0-9_.-]{1,128})?[\"']?\s*:\s*",
    re.IGNORECASE,
)
DOCUMENTATION_NESTED_CONFIG_VALUE_LINE_PATTERN = re.compile(
    rb"[ \t]+[\"']?(?:url|uri)[\"']?\s*:\s*[\"']?",
    re.IGNORECASE,
)
DOCUMENTATION_CONFIG_TAG_PATTERN = re.compile(
    rb"<(?:endpoint|callback|webhook)(?:[-_:][A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)?>\s*$",
    re.IGNORECASE,
)
DOCUMENTATION_LAMBDA_PATTERN = re.compile(rb"\blambda\b[^:\n]{0,256}:\s*[^\n]*$", re.IGNORECASE)
DOCUMENTATION_PRIVILEGE_OPTION_WITH_ARGUMENT = (
    rb"(?:-(?:C|D|g|h|p|R|T|u)|--(?:chdir|chroot|close-from|command-timeout|group|host|other-user|"
    rb"prompt|role|type|user))"
)
DOCUMENTATION_PRIVILEGE_OPTION = (
    rb"(?:"
    + DOCUMENTATION_PRIVILEGE_OPTION_WITH_ARGUMENT
    + rb"(?:=[^\s]+|\s+[^\s]+)|--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?)"
)
DOCUMENTATION_ENV_ASSIGNMENT = rb"[A-Za-z_][A-Za-z0-9_]{0,127}=(?:[^\s\"']+|\"[^\"\r\n]{0,4096}\"|'[^'\r\n]{0,4096}')"
DOCUMENTATION_ENV_WRAPPER = (
    rb"(?:(?:env(?:\s+--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?){0,8}\s+)?"
    rb"(?:" + DOCUMENTATION_ENV_ASSIGNMENT + rb"\s+){1,16})?"
)
DOCUMENTATION_PRIVILEGE_WRAPPER = (
    rb"(?:(?:sudo|doas)(?:\s+" + DOCUMENTATION_PRIVILEGE_OPTION + rb"){0,8}\s+" + DOCUMENTATION_ENV_WRAPPER + rb")?"
)
DOCUMENTATION_SHELL_WRAPPERS = DOCUMENTATION_ENV_WRAPPER + DOCUMENTATION_PRIVILEGE_WRAPPER
DOCUMENTATION_SHELL_INTERPRETER_WRAPPER = rb"(?:(?:bash|sh|zsh)\s+-c\s+[\"']?\s*)?"
DOCUMENTATION_SHELL_WRAPPED_COMMAND = (
    DOCUMENTATION_SHELL_WRAPPERS + DOCUMENTATION_SHELL_INTERPRETER_WRAPPER + DOCUMENTATION_SHELL_WRAPPERS
)
DOCUMENTATION_SHELL_COMMAND_PATTERN = re.compile(
    rb"^\s*(?:(?:[-*+]|[0-9]{1,9}[.)])\s+)?(?:(?:[$>#]|[A-Za-z0-9._-]+[$#])\s*)?"
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + rb"(?:(?:\$\(|`)\s*)?"
    rb"(?:(?:curl|fetch|invoke-webrequest|iwr|wget)\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\])"
    rb"|(?:powershell(?:\.exe)?|pwsh)\b\s+-[A-Za-z])",
    re.IGNORECASE,
)
DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN = re.compile(
    rb"(?:^|[;&|]\s*)"
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + rb"(?:(?:\$\(|`)\s*)?(?:(?:curl|fetch|invoke-webrequest|iwr|wget)\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\]|$)"
    rb"|(?:powershell(?:\.exe)?|pwsh)\b\s+-[A-Za-z])",
    re.IGNORECASE,
)
DOCUMENTATION_SHELL_SUBSTITUTION_PATTERN = re.compile(
    rb"(?:\$\(|`)\s*" + DOCUMENTATION_SHELL_WRAPPED_COMMAND + rb"(?:curl|fetch|invoke-webrequest|iwr|wget)\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\]|$)",
    re.IGNORECASE,
)
DOCUMENTATION_PACKAGE_INSTALL_PATTERN = re.compile(
    rb"^\s*(?:(?:[-*+]|[0-9]{1,9}[.)])\s+)?(?:(?:[$>#]|[A-Za-z0-9._-]+[$#])\s*)?"
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + rb"(?:"
    rb"(?:(?:python(?:[0-9.]+)?|py(?:\s+-[0-9.]+)?)\s+-m\s+)?pip(?:[0-9.]+)?\s+install"
    rb"|pipx\s+install"
    rb"|uv\s+(?:pip\s+install|add)"
    rb"|(?:conda|mamba|micromamba)\s+install"
    rb"|poetry\s+add"
    rb"|(?:npm|pnpm|bun)\s+(?:install|add)"
    rb"|yarn\s+add"
    rb"|cargo\s+install"
    rb"|gem\s+install"
    rb")\b",
    re.IGNORECASE,
)
DOCUMENTATION_COMPOUND_IMPORT_PREFIX_PATTERN = re.compile(
    rb"^\s*(?:(?:if|elif|else|for|while|with|try|except|finally|match|case|def|class)\b"
    rb"|async\s+(?:for|with|def)\b)[^#\n]{0,4096}:\s*$"
)
DOCUMENTATION_SEMICOLON_CODE_PREFIX_PATTERN = re.compile(
    rb"(?:^|;)\s*(?:"
    rb"[A-Za-z_][A-Za-z0-9_.]*\s*=[^;\n]*"
    rb"|[A-Za-z_][A-Za-z0-9_.]*\s*\([^()\n]{0,4096}\)"
    rb"|(?:from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import|import\s+)[^;\n]*"
    rb"|(?:(?:if|elif|else|for|while|with|try|except|finally|match|case|def|class)\b"
    rb"|async\s+(?:for|with|def)\b)[^;\n]{0,4096}:[^;\n]*"
    rb");\s*$",
)
DOCUMENTATION_SUSPICIOUS_NETWORK_LABEL_PATTERN = re.compile(
    rb"\b(?:beacon|callback|c2|command(?:[_ -]+and[_ -]+control)?|exfil(?:tration)?|phone[_ -]+home|webhook)\b"
    rb"[^\n]{0,32}:\s*$",
    re.IGNORECASE,
)
BENIGN_DOCUMENTATION_CC_PATTERN = re.compile(
    rb"(?:"
    rb"\b(?:not|no|without)\s+(?:a\s+)?(?:known\s+)?(?:malware|backdoor|trojan|botnet|zombie)\b"
    rb"|\b(?:malware|backdoor|trojan|botnet|zombie)[ -]free\b"
    rb"|\b(?:malware|backdoor|trojan|botnet|zombie)\s+"
    rb"(?:analysis|benchmark|classification|classifier|dataset|defen[cs]e|detection|mitigation|research|resistance|robustness|testing)\b"
    rb"|\b(?:detect(?:ing|ion|s)?|mitigat(?:e|ing|ion)|resistan(?:ce|t)|robust(?:ness)?)\s+"
    rb"(?:malware|backdoor|trojan|botnet|zombie)\b"
    rb")",
    re.IGNORECASE,
)
GENERIC_CC_PROSE_PATTERNS = frozenset({"backdoor", "botnet", "malware", "trojan", "zombie"})
REQUIREMENTS_URL_DIRECTIVE_PATTERN = re.compile(
    rb"^(?:(?:--index-url|--extra-index-url|--find-links)(?:\s+|=)"
    rb"|(?:-i|-f)(?:\s+|(?=[A-Za-z][A-Za-z0-9+.-]*://)))",
    re.IGNORECASE,
)
REQUIREMENTS_DIRECT_REFERENCE_PATTERN = re.compile(
    rb"^[A-Za-z0-9_.-]+(?:\[[^\]\r\n]+\])?\s*@\s*[A-Za-z][A-Za-z0-9+.-]*://",
    re.IGNORECASE,
)
TRUSTED_REQUIREMENTS_HOSTS = frozenset(
    {
        "download.pytorch.org",
        "files.pythonhosted.org",
        "pypi.org",
        "pypi.python.org",
    }
)
SENSITIVE_REQUIREMENTS_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "auth",
        "authorization",
        "credential",
        "password",
        "secret",
        "sig",
        "signature",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
    }
)


class TextScanner(BaseScanner):
    """Scanner for text-based ML-related files."""

    name = "text"
    supported_extensions: ClassVar[list[str]] = [".txt", ".md", ".markdown", ".rst"]
    default_max_file_read_size = DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the scanner with optional configuration."""
        super().__init__(config)

    @classmethod
    def _is_readme_documentation_filename(cls, filename: str) -> bool:
        return filename == "readme" or (
            filename.startswith("readme.") and os.path.splitext(filename)[1].lower() in cls.supported_extensions
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        filename = os.path.basename(path).lower()
        if filename == "model_card" or cls._is_readme_documentation_filename(filename):
            return True

        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False

        # Check for ML-related text files
        ml_text_files = {
            "readme.md",
            "readme.rst",
            "readme.txt",
            "readme.markdown",
            "vocab.txt",
            "vocabulary.txt",
            "tokens.txt",
            "tokenizer.txt",
            "labels.txt",
            "classes.txt",
            "model_card.md",
            "model_card.rst",
            "model_card.txt",
            "modelcard.md",
            "license.txt",
            "license.md",
            "license.rst",
            "requirements.txt",
        }

        return filename in ml_text_files or any(filename.startswith(prefix) for prefix in ["vocab", "token", "label"])

    @staticmethod
    def _get_file_size(path: str) -> int:
        """Return file size for bounded text classification."""
        return os.path.getsize(path)

    def _get_content_security_scan_bytes(self) -> int:
        return self._normalize_positive_int_config(
            self.config.get("text_content_scan_bytes", self.max_file_read_size),
            DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES,
        )

    def _get_content_security_max_findings(self) -> int:
        return self._normalize_positive_int_config(
            self.config.get("text_content_max_findings", DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS),
            DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS,
        )

    @classmethod
    def _is_documentation_sidecar(cls, path: str) -> bool:
        filename = os.path.basename(path).lower()
        return filename in DOCUMENTATION_TEXT_FILENAMES or cls._is_readme_documentation_filename(filename)

    @staticmethod
    def _is_passive_data_sidecar(path: str) -> bool:
        filename = os.path.basename(path).lower()
        return filename in PASSIVE_DATA_TEXT_FILENAMES or filename.startswith(PASSIVE_DATA_TEXT_PREFIXES)

    @staticmethod
    def _finding_line_parts(payload: bytes, finding: dict[str, Any]) -> tuple[bytes, int] | None:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return None
        line_start = max(payload.rfind(b"\n", 0, position) + 1, position - MAX_TEXT_FINDING_CONTEXT_BYTES)
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            line_end = len(payload)
        line_end = min(line_end, position + MAX_TEXT_FINDING_CONTEXT_BYTES)
        return payload[line_start:line_end], position - line_start

    @classmethod
    def _finding_line(cls, payload: bytes, finding: dict[str, Any]) -> bytes | None:
        line_parts = cls._finding_line_parts(payload, finding)
        return line_parts[0].strip() if line_parts is not None else None

    @staticmethod
    def _finding_line_prefix_is_truncated(payload: bytes, finding: dict[str, Any]) -> bool:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return False
        return position - (payload.rfind(b"\n", 0, position) + 1) > MAX_TEXT_FINDING_CONTEXT_BYTES

    @staticmethod
    def _documentation_line_has_import_statement(line: bytes) -> bool:
        source = line.lstrip()
        markdown_prefix = DOCUMENTATION_MARKDOWN_PREFIX_PATTERN.match(source)
        if markdown_prefix is not None:
            source = source[markdown_prefix.end() :].lstrip()
        if source.startswith((b">>>", b"...")):
            source = source[3:].lstrip()
        try:
            parsed = ast.parse(source.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError, ValueError):
            return False
        return any(isinstance(statement, (ast.Import, ast.ImportFrom)) for statement in parsed.body)

    @staticmethod
    def _documentation_shell_comment_before_position(line: bytes, position: int) -> bool:
        quote: int | None = None
        escaped = False
        for index, value in enumerate(line[:position]):
            if escaped:
                escaped = False
                continue
            if value == ord("\\") and quote != ord("'"):
                escaped = True
                continue
            if quote is not None:
                if value == quote:
                    quote = None
                continue
            if value in {ord("'"), ord('"')}:
                quote = value
                continue
            if value == ord("#") and (index == 0 or line[index - 1] in b" \t;|&()"):
                return True
        return False

    @staticmethod
    def _documentation_nested_config_is_actionable(prefix: bytes) -> bool:
        if DOCUMENTATION_NESTED_CONFIG_OBJECT_PATTERN.search(prefix) is not None:
            return True
        lines = prefix.splitlines()
        if len(lines) < 2:
            return False
        parent_line, value_line = lines[-2:]
        if (
            DOCUMENTATION_NESTED_CONFIG_PARENT_LINE_PATTERN.fullmatch(parent_line) is None
            or DOCUMENTATION_NESTED_CONFIG_VALUE_LINE_PATTERN.fullmatch(value_line) is None
        ):
            return False
        parent_indent = len(parent_line) - len(parent_line.lstrip(b" \t"))
        value_indent = len(value_line) - len(value_line.lstrip(b" \t"))
        return value_indent > parent_indent

    @staticmethod
    def _documentation_assignment_is_actionable(prefix: bytes) -> bool:
        return (
            DOCUMENTATION_CODE_ASSIGNMENT_PATTERN.search(prefix) is not None
            and DOCUMENTATION_PASSIVE_HTML_URL_ATTRIBUTE_PATTERN.search(prefix) is None
        )

    @classmethod
    def _documentation_line_is_code_shaped(cls, line: bytes, position: int) -> bool:
        prefix = line[:position]
        stripped = line.lstrip()
        shell_context_is_actionable = not cls._documentation_shell_comment_before_position(line, position)
        return (
            (
                shell_context_is_actionable
                and (
                    DOCUMENTATION_SHELL_COMMAND_PATTERN.match(stripped) is not None
                    or DOCUMENTATION_PACKAGE_INSTALL_PATTERN.match(stripped) is not None
                    or DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN.search(prefix) is not None
                    or DOCUMENTATION_SHELL_SUBSTITUTION_PATTERN.search(prefix) is not None
                )
            )
            or DOCUMENTATION_SUSPICIOUS_NETWORK_LABEL_PATTERN.search(prefix) is not None
            or (
                DOCUMENTATION_HTML_URL_ATTRIBUTE_PATTERN.search(prefix) is None
                and cls._documentation_assignment_is_actionable(prefix)
            )
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or cls._documentation_nested_config_is_actionable(prefix)
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
            or DOCUMENTATION_LAMBDA_PATTERN.search(prefix) is not None
            or cls._documentation_line_has_import_statement(line)
            or stripped.startswith((b"def ", b"class "))
        )

    @classmethod
    def _documentation_previous_line_continues_command(cls, payload: bytes, position: int) -> bool:
        line_start = payload.rfind(b"\n", 0, position) + 1
        if line_start <= 0:
            return False
        current_line_prefix = payload[line_start:position]
        if cls._documentation_shell_comment_before_position(current_line_prefix, len(current_line_prefix)):
            return False

        context_start = max(0, line_start - MAX_TEXT_FINDING_CONTEXT_BYTES)
        previous_line_end = line_start - 1
        while previous_line_end >= context_start:
            previous_line_start = max(
                payload.rfind(b"\n", context_start, previous_line_end) + 1,
                context_start,
            )
            previous_line = payload[previous_line_start:previous_line_end].rstrip()
            if not previous_line.endswith(b"\\"):
                return False
            if cls._documentation_shell_comment_before_position(previous_line, len(previous_line)):
                return False

            stripped = previous_line.lstrip()
            if (
                DOCUMENTATION_SHELL_COMMAND_PATTERN.match(stripped) is not None
                or DOCUMENTATION_PACKAGE_INSTALL_PATTERN.match(stripped) is not None
            ):
                return True
            if previous_line_start == context_start:
                return context_start > 0
            previous_line_end = previous_line_start - 1
        return False

    @classmethod
    def _documentation_finding_is_actionable(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        if cls._finding_line_prefix_is_truncated(payload, finding):
            return True
        line_parts = cls._finding_line_parts(payload, finding)
        if line_parts is not None and cls._documentation_line_is_code_shaped(*line_parts):
            return True
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return False
        if cls._documentation_previous_line_continues_command(payload, position):
            return True
        prefix = payload[max(0, position - MAX_TEXT_FINDING_CONTEXT_BYTES) : position]
        return (
            cls._documentation_assignment_is_actionable(prefix)
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or cls._documentation_nested_config_is_actionable(prefix)
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
        )

    @staticmethod
    def _documentation_finding_tokens(finding: dict[str, Any]) -> tuple[bytes, ...]:
        finding_type = finding.get("type")
        if finding_type == "network_function":
            function = finding.get("function")
            return (function.encode().lower(),) if isinstance(function, str) and function else ()
        if finding_type == "cc_pattern":
            pattern = finding.get("pattern")
            return (pattern.encode().lower(),) if isinstance(pattern, str) and pattern else ()
        if finding_type == "suspicious_port":
            port = finding.get("port")
            if not isinstance(port, int):
                return ()
            port_bytes = str(port).encode()
            return (b":" + port_bytes, b"port=" + port_bytes, b"port " + port_bytes)
        if finding_type != "network_library":
            return ()

        library = finding.get("library")
        pattern = finding.get("pattern")
        if not isinstance(library, str) or not library:
            return (pattern.encode().lower(),) if isinstance(pattern, str) and pattern else ()
        tokens = (
            pattern,
            f"import {library}",
            f"from {library}",
            f"{library}.connect",
            f"{library}.request",
            f"{library}.__init__",
        )
        return tuple(token.encode().lower() for token in dict.fromkeys(tokens) if isinstance(token, str) and token)

    @classmethod
    def _retarget_documentation_finding(
        cls,
        payload: bytes,
        lowered_payload: bytes,
        finding: dict[str, Any],
        remaining_occurrences: int,
        allow_exhaustion_probe: bool,
    ) -> tuple[dict[str, Any], bool, int]:
        finding_type = finding.get("type")
        token_bytes_options = cls._documentation_finding_tokens(finding)
        if not token_bytes_options:
            return finding, False, remaining_occurrences

        original_position = finding.get("position")
        search_start = (
            0
            if finding_type == "network_library"
            else original_position
            if isinstance(original_position, int) and original_position >= 0
            else 0
        )
        while True:
            if remaining_occurrences <= 0:
                return {**finding, "position": None, "severity": "INFO"}, True, 0
            matches = (
                (position, token_bytes)
                for token_bytes in token_bytes_options
                if (position := lowered_payload.find(token_bytes, search_start)) >= 0
            )
            next_match = min(matches, default=None, key=lambda match: match[0])
            if next_match is None:
                return finding, False, remaining_occurrences
            match_position, token_bytes = next_match
            remaining_occurrences -= 1
            position = match_position
            if finding_type == "suspicious_port":
                position += len(token_bytes) - len(str(finding["port"]).encode())
            candidate = {**finding, "position": position}
            if finding_type == "network_library":
                candidate["pattern"] = token_bytes.decode()
            if finding_type == "network_function":
                actionable = not cls._documentation_network_function_is_prose(payload, candidate)
            elif finding_type == "network_library":
                actionable = not cls._documentation_network_library_is_prose(payload, candidate)
            elif finding_type == "suspicious_port":
                actionable = cls._documentation_finding_is_actionable(payload, candidate)
            else:
                actionable = not cls._documentation_cc_finding_is_benign_prose(payload, candidate)
            if actionable:
                candidate.pop("snippet", None)
                return candidate, False, remaining_occurrences
            search_start = match_position + len(token_bytes)
            if remaining_occurrences <= 0:
                if allow_exhaustion_probe and not any(
                    lowered_payload.find(option, search_start) >= 0 for option in token_bytes_options
                ):
                    return candidate, False, 0
                return {**finding, "position": None, "severity": "INFO"}, True, 0

    @classmethod
    def _documentation_network_function_is_prose(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        line_parts = cls._finding_line_parts(payload, finding)
        function = finding.get("function")
        if (
            line_parts is None
            or not isinstance(function, str)
            or cls._finding_line_prefix_is_truncated(payload, finding)
        ):
            return False
        line, position = line_parts
        cursor = position + len(function.encode())
        while cursor < len(line) and line[cursor : cursor + 1] in {b" ", b"\t"}:
            cursor += 1
        has_call_syntax = line[cursor : cursor + 1] == b"("
        if not has_call_syntax and line[cursor : cursor + 1] == b"\\" and not line[cursor + 1 :].strip():
            finding_position = finding.get("position")
            if isinstance(finding_position, int):
                line_end = payload.find(b"\n", finding_position)
                if line_end >= 0:
                    next_line_end = payload.find(b"\n", line_end + 1)
                    if next_line_end < 0:
                        next_line_end = len(payload)
                    next_line = payload[
                        line_end + 1 : min(next_line_end, line_end + 1 + MAX_TEXT_FINDING_CONTEXT_BYTES)
                    ]
                    has_call_syntax = next_line.lstrip().startswith(b"(")
        return (
            not has_call_syntax
            and not cls._documentation_line_is_code_shaped(
                line,
                position,
            )
            and DOCUMENTATION_ENCLOSING_CALL_PATTERN.search(line[:position]) is None
        )

    @classmethod
    def _documentation_network_library_is_prose(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        line_parts = cls._finding_line_parts(payload, finding)
        pattern = finding.get("pattern")
        if (
            line_parts is None
            or not isinstance(pattern, str)
            or cls._finding_line_prefix_is_truncated(payload, finding)
        ):
            return False
        line, position = line_parts
        pattern_bytes = pattern.encode()
        cursor = position + len(pattern_bytes)
        while cursor < len(line) and line[cursor : cursor + 1] in {b" ", b"\t"}:
            cursor += 1
        if not pattern.casefold().startswith(("import ", "from ")) and line[cursor : cursor + 1] == b"(":
            return False

        prefix = line[:position]
        import_is_executable = (
            cls._documentation_line_has_import_statement(line)
            or DOCUMENTATION_SEMICOLON_CODE_PREFIX_PATTERN.search(prefix) is not None
            or DOCUMENTATION_COMPOUND_IMPORT_PREFIX_PATTERN.fullmatch(prefix) is not None
        )
        return (
            not import_is_executable
            and not cls._documentation_line_is_code_shaped(line, position)
            and DOCUMENTATION_ENCLOSING_CALL_PATTERN.search(prefix) is None
        )

    @classmethod
    def _documentation_cc_finding_is_benign_prose(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        pattern = finding.get("pattern")
        line_parts = cls._finding_line_parts(payload, finding)
        if (
            pattern not in GENERIC_CC_PROSE_PATTERNS
            or line_parts is None
            or cls._finding_line_prefix_is_truncated(payload, finding)
        ):
            return False
        line, position = line_parts
        return not cls._documentation_line_is_code_shaped(line, position) and any(
            match.start() <= position < match.end() for match in BENIGN_DOCUMENTATION_CC_PATTERN.finditer(line)
        )

    @classmethod
    def _standard_requirements_network_finding(cls, path: str, payload: bytes, finding: dict[str, Any]) -> bool:
        if os.path.basename(path).lower() != "requirements.txt":
            return False
        line = cls._finding_line(payload, finding)
        if line is None:
            return False
        stripped = line.strip()
        line_parts = cls._finding_line_parts(payload, finding)
        if line_parts is None:
            return False
        finding_line, position = line_parts
        raw_url_match = next(
            (
                match
                for match in REQUIREMENTS_RAW_URL_PATTERN.finditer(finding_line)
                if match.start() <= position < match.end()
            ),
            None,
        )
        if raw_url_match is None:
            return False
        try:
            raw_url = urlsplit(raw_url_match.group().decode("utf-8", errors="ignore"))
            if raw_url.username is not None or raw_url.password is not None:
                return False
            if any(
                key.casefold().replace("-", "_") in SENSITIVE_REQUIREMENTS_QUERY_KEYS
                for key, _value in parse_qsl(raw_url.query, keep_blank_values=True)
            ):
                return False
            if stripped.startswith(b"#"):
                return True
            raw_port = raw_url.port
        except ValueError:
            return False
        if raw_url.hostname is None or raw_url.hostname.casefold() not in TRUSTED_REQUIREMENTS_HOSTS:
            return False
        if raw_url.scheme.casefold() != "https" or raw_port not in {None, 443}:
            return False
        return (
            REQUIREMENTS_URL_DIRECTIVE_PATTERN.match(stripped) is not None
            or REQUIREMENTS_DIRECT_REFERENCE_PATTERN.match(stripped) is not None
            or BARE_NETWORK_URL_TOKEN_PATTERN.fullmatch(stripped) is not None
        )

    @classmethod
    def _is_bare_data_network_token(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        line = cls._finding_line(payload, finding)
        if not line or b"@" in line:
            return False
        finding_type = finding.get("type")
        if finding_type in PASSIVE_NETWORK_FINDING_TYPES:
            if BARE_NETWORK_URL_TOKEN_PATTERN.fullmatch(line):
                return True
            line_text = line.decode("utf-8", errors="ignore").casefold()
            return any(
                isinstance(value, str) and line_text == value.casefold()
                for value in (finding.get("domain"), finding.get("ip"))
            )

        line_text = line.decode("utf-8", errors="ignore").casefold()
        candidates: tuple[Any, ...]
        if finding_type == "cc_pattern":
            candidates = (finding.get("pattern"),)
        elif finding_type == "network_function":
            candidates = (finding.get("function"),)
        elif finding_type == "network_library":
            candidates = (finding.get("pattern"), finding.get("library"))
        else:
            return False
        return any(isinstance(value, str) and line_text == value.casefold() for value in candidates)

    @staticmethod
    def _all_network_candidate_lines_are_bare(payload: bytes) -> bool:
        for line in payload.splitlines():
            stripped = line.strip()
            if not stripped or not any(pattern.search(stripped) for pattern in BARE_NETWORK_TOKEN_PATTERNS):
                continue
            if b"@" in stripped or not any(pattern.fullmatch(stripped) for pattern in BARE_NETWORK_TOKEN_PATTERNS):
                return False
        return True

    @staticmethod
    def _split_detector_finding_limit(
        findings: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        limit_finding = next(
            (finding for finding in findings if finding.get("type") == DETECTOR_FINDING_LIMIT_TYPE),
            None,
        )
        return (
            [finding for finding in findings if finding.get("type") != DETECTOR_FINDING_LIMIT_TYPE],
            limit_finding,
        )

    @classmethod
    def _passive_network_reporting_limit(
        cls,
        path: str,
        payload: bytes,
        findings: list[dict[str, Any]],
        finding_limit: dict[str, Any],
    ) -> bool:
        if finding_limit.get("truncated_finding_type") not in PASSIVE_NETWORK_FINDING_TYPES:
            return False
        truncated_finding = finding_limit.get("truncated_finding")
        return (
            cls._is_passive_data_sidecar(path)
            and all(finding.get("severity") == "INFO" for finding in findings)
            and isinstance(truncated_finding, dict)
            and cls._is_bare_data_network_token(payload, truncated_finding)
            and cls._all_network_candidate_lines_are_bare(payload)
        )

    @classmethod
    def _sidecar_network_finding_is_informational(
        cls,
        path: str,
        payload: bytes,
        finding: dict[str, Any],
    ) -> bool:
        if cls._is_documentation_sidecar(path):
            finding_type = finding.get("type")
            return (
                (
                    finding_type in PASSIVE_NETWORK_FINDING_TYPES
                    and not cls._documentation_finding_is_actionable(payload, finding)
                )
                or (
                    finding_type == "network_function"
                    and cls._documentation_network_function_is_prose(payload, finding)
                )
                or (finding_type == "network_library" and cls._documentation_network_library_is_prose(payload, finding))
                or (finding_type == "cc_pattern" and cls._documentation_cc_finding_is_benign_prose(payload, finding))
                or (
                    finding_type == "suspicious_port" and not cls._documentation_finding_is_actionable(payload, finding)
                )
            )
        if cls._is_passive_data_sidecar(path):
            return cls._is_bare_data_network_token(payload, finding)
        return finding.get("type") in PASSIVE_NETWORK_FINDING_TYPES and cls._standard_requirements_network_finding(
            path,
            payload,
            finding,
        )

    @classmethod
    def _downgrade_sidecar_network_findings(
        cls,
        path: str,
        payload: bytes,
        findings: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], bool]:
        classified_findings: list[dict[str, Any]] = []
        classification_incomplete = False
        remaining_occurrences = MAX_DOCUMENTATION_FINDING_RETARGET_OCCURRENCES
        documentation_sidecar = cls._is_documentation_sidecar(path)
        lowered_payload = payload.lower() if documentation_sidecar else b""
        last_retargetable_index = max(
            (index for index, finding in enumerate(findings) if cls._documentation_finding_tokens(finding)),
            default=-1,
        )
        for index, finding in enumerate(findings):
            retarget_incomplete = False
            if documentation_sidecar:
                finding, retarget_incomplete, remaining_occurrences = cls._retarget_documentation_finding(
                    payload,
                    lowered_payload,
                    finding,
                    remaining_occurrences,
                    index == last_retargetable_index,
                )
                classification_incomplete = classification_incomplete or retarget_incomplete
            if not retarget_incomplete and cls._sidecar_network_finding_is_informational(path, payload, finding):
                finding = {**finding, "severity": "INFO"}
            classified_findings.append(finding)
        return classified_findings, classification_incomplete

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _finish_metadata_read_failure(result: ScanResult, path: str, error: OSError) -> ScanResult:
        mark_inconclusive_scan_result(result, "text_metadata_read_failed")
        mark_operational_scan_error(result, "text_metadata_read_failed")
        result.add_check(
            name="Text File Metadata Read",
            passed=False,
            message=f"Unable to inspect text file metadata: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": "text_metadata_read_failed",
            },
        )
        result.finish(success=False)
        return result

    @staticmethod
    def _mark_content_security_scan_incomplete(
        result: ScanResult,
        path: str,
        *,
        reason: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name="Text Content Security Coverage",
            passed=False,
            message=message,
            severity=IssueSeverity.INFO,
            location=path,
            details={
                **details,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    def _run_content_security_checks(self, path: str, result: ScanResult, file_size: int) -> int:
        check_secrets = self._get_bool_config("check_secrets", True)
        check_network = self._get_bool_config("check_network_comm", True)
        if not check_secrets:
            result.metadata.setdefault("disabled_checks", []).append("Embedded Secrets Detection")
        if not check_network:
            result.metadata.setdefault("disabled_checks", []).append("Network Communication Detection")
        if not check_secrets and not check_network:
            return 0

        read_limit = self._get_content_security_scan_bytes()
        max_findings = self._get_content_security_max_findings()
        try:
            with open(path, "rb") as file_obj:
                payload = file_obj.read(read_limit + 1)
        except OSError as error:
            self._mark_content_security_scan_incomplete(
                result,
                path,
                reason="text_content_read_failed",
                message=f"Unable to read text content for security detectors: {error!s}",
                details={
                    "exception": str(error),
                    "exception_type": type(error).__name__,
                    "file_size": file_size,
                    "read_limit": read_limit,
                },
            )
            return 0

        truncated = len(payload) > read_limit
        inspected_payload = payload[:read_limit]
        inspected_bytes = len(inspected_payload)

        detector_incomplete = False
        if check_secrets:
            try:
                secret_findings = self.collect_embedded_secret_findings(
                    inspected_payload,
                    path,
                    raise_on_error=True,
                    max_findings=max_findings,
                )
                secret_findings, finding_limit = self._split_detector_finding_limit(secret_findings)
                if secret_findings or not truncated:
                    self.add_embedded_secret_findings(secret_findings, result, context=path)
                if finding_limit is not None:
                    detector_incomplete = True
                    self._mark_content_security_scan_incomplete(
                        result,
                        path,
                        reason=TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON,
                        message="Embedded secret findings exceeded the configured reporting limit",
                        details=finding_limit,
                    )
            except Exception as error:
                detector_incomplete = True
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Embedded secret detector failed for text content: {error!s}",
                    details={
                        "detector": "secrets",
                        "exception": str(error),
                        "exception_type": type(error).__name__,
                    },
                )

        if check_network:
            try:
                network_findings = self.collect_network_communication_findings(
                    inspected_payload,
                    path,
                    raise_on_error=True,
                    max_findings=max_findings,
                )
                network_findings, finding_limit = self._split_detector_finding_limit(network_findings)
                network_findings, classification_incomplete = self._downgrade_sidecar_network_findings(
                    path,
                    inspected_payload,
                    network_findings,
                )
                if network_findings or not truncated:
                    self.add_network_communication_findings(network_findings, result, context=path)
                if classification_incomplete:
                    detector_incomplete = True
                    self._mark_content_security_scan_incomplete(
                        result,
                        path,
                        reason=TEXT_CONTENT_SECURITY_CLASSIFICATION_LIMIT_REASON,
                        message="Documentation network finding classification exceeded the work limit",
                        details={
                            "max_classification_occurrences": MAX_DOCUMENTATION_FINDING_RETARGET_OCCURRENCES,
                        },
                    )
                if finding_limit is not None:
                    if self._passive_network_reporting_limit(
                        path,
                        inspected_payload,
                        network_findings,
                        finding_limit,
                    ):
                        result.add_check(
                            name="Network Communication Reporting Limit",
                            passed=False,
                            message="Passive network references exceeded the reporting limit",
                            severity=IssueSeverity.INFO,
                            location=path,
                            details={
                                **finding_limit,
                                "analysis_incomplete": False,
                                "reporting_incomplete": True,
                            },
                        )
                    else:
                        detector_incomplete = True
                        self._mark_content_security_scan_incomplete(
                            result,
                            path,
                            reason=TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON,
                            message="Network communication findings exceeded the configured reporting limit",
                            details=finding_limit,
                        )
            except Exception as error:
                detector_incomplete = True
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Network communication detector failed for text content: {error!s}",
                    details={
                        "detector": "network_communication",
                        "exception": str(error),
                        "exception_type": type(error).__name__,
                    },
                )

        if truncated:
            self._mark_content_security_scan_incomplete(
                result,
                path,
                reason=TEXT_CONTENT_SECURITY_SCAN_INCOMPLETE_REASON,
                message=f"Text content security scan truncated at configured limit ({read_limit} bytes)",
                details={
                    "file_size": file_size,
                    "read_limit": read_limit,
                    "inspected_bytes": inspected_bytes,
                    "enabled_detectors": [
                        detector
                        for detector, enabled in (("secrets", check_secrets), ("network_communication", check_network))
                        if enabled
                    ],
                },
            )
        elif not detector_incomplete:
            result.add_check(
                name="Text Content Security Coverage",
                passed=True,
                message="Text content security detectors completed",
                location=path,
                details={
                    "file_size": file_size,
                    "read_limit": read_limit,
                    "inspected_bytes": inspected_bytes,
                },
            )

        return inspected_bytes

    def scan(self, path: str) -> ScanResult:
        """Scan a text file for security issues."""
        result = self._create_scan_result_after_preflight(path, check_size_limit=False)
        if not result.success:
            if self._is_unreadable_path_result(result):
                return self._finish_metadata_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return result

        try:
            # Get file size
            file_size = self._get_file_size(path)
            result.metadata["file_size"] = file_size

            # Check if file exceeds expected size for text files
            if file_size > 100 * 1024 * 1024:  # 100MB
                result.add_check(
                    name="File Size Check",
                    passed=False,
                    message=f"Unusually large text file: {file_size / (1024 * 1024):.1f}MB",
                    rule_code="S902",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"file_size": file_size},
                )
            else:
                result.add_check(
                    name="File Size Check",
                    passed=True,
                    message="Text file size is reasonable",
                    location=path,
                    details={"file_size": file_size},
                    rule_code=None,  # Passing check
                )

            filename = os.path.basename(path).lower()

            # Identify file type - these are informational checks, not security issues
            if filename in DOCUMENTATION_TEXT_FILENAMES:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Model documentation file",
                    location=path,
                    details={"file_type": "documentation"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["vocab.txt", "vocabulary.txt", "tokens.txt", "tokenizer.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Tokenizer vocabulary file",
                    location=path,
                    details={"file_type": "vocabulary"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["labels.txt", "classes.txt"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Classification labels file",
                    location=path,
                    details={"file_type": "labels"},
                    rule_code=None,  # Passing check
                )
            elif filename in ["license.txt", "license.md"]:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="License file",
                    location=path,
                    details={"file_type": "license"},
                    rule_code=None,  # Passing check
                )
            elif filename == "requirements.txt":
                # Could scan for suspicious dependencies in the future
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="Python requirements file",
                    location=path,
                    details={"file_type": "requirements"},
                    rule_code=None,  # Passing check
                )
            else:
                result.add_check(
                    name="File Type Identification",
                    passed=True,
                    message="ML-related text file",
                    location=path,
                    details={"file_type": "text"},
                    rule_code=None,  # Passing check
                )

            result.bytes_scanned = self._run_content_security_checks(path, result, file_size)
            result.finish(
                success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME and not result.has_errors,
            )

        except OSError as e:
            self._finish_metadata_read_failure(result, path, e)
        except Exception as e:
            result.add_check(
                name="Text File Scan",
                passed=False,
                message=f"Error scanning text file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e)},
                rule_code="S902",
            )
            result.finish(success=False)

        return result
