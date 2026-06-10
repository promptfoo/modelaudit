"""Scanner for Llamafile executable model artifacts."""

from __future__ import annotations

import ipaddress
import os
import re
import struct
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO, ClassVar
from urllib.parse import urlsplit

from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ..utils.file.detection import (
    LLAMAFILE_MARKER,
    LLAMAFILE_ROUTE_SCAN_BYTES,
    LLAMAFILE_ROUTE_TAIL_SCAN_BYTES,
    find_structural_torch7_offset,
    find_torch7_candidate_offset,
    is_llamafile_executable,
)
from ._evidence_redaction import redact_evidence_string
from .archive_dispatch import merge_executable_zip_container_findings
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult

__all__ = ["LLAMAFILE_MARKER", "LLAMAFILE_ROUTE_SCAN_BYTES", "LLAMAFILE_ROUTE_TAIL_SCAN_BYTES", "LlamafileScanner"]

GGUF_MARKER = b"GGUF"
LLAMAFILE_GGUF_ANALYSIS_INCOMPLETE_REASON = "llamafile_gguf_analysis_incomplete"
LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON = "llamafile_gguf_ambiguous_payload"
LLAMAFILE_GGUF_CANDIDATE_SCAN_LIMIT_REASON = "llamafile_gguf_candidate_scan_limited"
LLAMAFILE_GGUF_HEADER_LIMIT_REASON = "llamafile_gguf_header_resource_limit"
LLAMAFILE_GGUF_HEADER_INCOMPLETE_REASON = "llamafile_gguf_header_incomplete"
LLAMAFILE_GGUF_ZIP_MEMBER_INCOMPLETE_REASON = "llamafile_gguf_zip_member_incomplete"
LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON = "llamafile_payload_scan_limited"
LLAMAFILE_RUNTIME_PREVIEW_READ_REASON = "llamafile_runtime_preview_read_failed"
LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON = "llamafile_runtime_scan_limited"
LLAMAFILE_RUNTIME_STRING_CANDIDATE_LIMIT_REASON = "llamafile_runtime_string_candidate_limited"
LLAMAFILE_RUNTIME_STRING_SCAN_LIMIT_REASON = "llamafile_runtime_string_scan_limited"
LLAMAFILE_RUNTIME_UTF16_AMBIGUOUS_REASON = "llamafile_runtime_utf16_ambiguous"
LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON = "llamafile_runtime_interpreter_token_limited"
LLAMAFILE_RUNTIME_TRANSFER_OPTION_AMBIGUOUS_REASON = "llamafile_runtime_transfer_option_ambiguous"
LLAMAFILE_RUNTIME_TRANSFER_TOKEN_LIMIT_REASON = "llamafile_runtime_transfer_token_limited"
LLAMAFILE_RUNTIME_STREAM_READ_REASON = "llamafile_runtime_stream_read_failed"
LLAMAFILE_TORCH7_CARVE_FAILURE_REASON = "llamafile_torch7_payload_carve_failed"
LLAMAFILE_TORCH7_ANALYSIS_INCOMPLETE_REASON = "llamafile_torch7_analysis_incomplete"
LLAMAFILE_RUNTIME_MAX_EVIDENCE = 5
LLAMAFILE_RUNTIME_EVIDENCE_INPUT_CHARS = 1024
LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES = 100_000
LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS = 32
LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS = 4096
LLAMAFILE_RUNTIME_STREAM_CHUNK_BYTES = 1024 * 1024
LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES = 1024 * 1024
LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES = 1024
LLAMAFILE_GGUF_MAX_PAYLOAD_CANDIDATE_SCANS = 16
TORCH7_SIGNATURE_WINDOW_BYTES = 4096
TORCH7_BINARY_MARKER = b"T7\x00\x00"
TORCH7_ACTIONABLE_SIGNAL_CHUNK_BYTES = 64 * 1024
TORCH7_ACTIONABLE_SIGNAL_CARRY_BYTES = 1024
LLAMAFILE_TORCH7_MAX_CANDIDATE_SCANS = 16

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}

PRINTABLE_TEXT_RE = re.compile(rb"[ -~]{8,}")
PRINTABLE_BYTES = bytes(range(32, 127))
OVERSIZED_PRINTABLE_TEXT_RE = re.compile(rb"[ -~]{1048577}")
UTF16LE_PRINTABLE_TEXT_RE = re.compile(rb"(?:[ -~]\x00){8,}")
UTF16BE_PRINTABLE_TEXT_RE = re.compile(rb"(?:\x00[ -~]){8,}")
COMMAND_HINTS = (
    b"bash",
    b"sh",
    b"python",
    b"cmd",
    b"powershell",
    b"os.system",
    b"subprocess.",
    b"curl",
    b"wget",
)
TORCH7_PRINTABLE_TEXT_RE = re.compile(rb"[\t\n\r -~]{6,512}")
TORCH7_EXEC_PRIMITIVE_BYTES_RE = re.compile(
    rb"(?i)\b(?:os\.execute|io\.popen|loadstring|dofile|loadfile|setfenv|getfenv)\s*\("
)
TORCH7_DYNAMIC_LOAD_BYTES_RE = re.compile(rb"(?i)\b(?:package\.loadlib|ffi\.load|loadlib)\b")
TORCH7_REQUIRE_BYTES_RE = re.compile(
    rb"(?is)\brequire(?:\s|--[^\r\n]*(?:\r?\n|\Z))*"
    rb"(?:\((?:\s|--[^\r\n]*(?:\r?\n|\Z))*(?:['\"]([^'\"]+)['\"]|\[(=*)\[(.*?)\]\2\])"
    rb"(?:\s|--[^\r\n]*(?:\r?\n|\Z))*\)|['\"]([^'\"]+)['\"]|\[(=*)\[(.*?)\]\5\])"
)
TORCH7_SAFE_REQUIRE_MODULES = frozenset(
    {
        b"torch",
        b"nn",
        b"nngraph",
        b"image",
        b"paths",
        b"math",
        b"string",
        b"table",
        b"cunn",
        b"cutorch",
        b"optim",
    }
)
TORCH7_NETWORK_OR_SHELL_BYTES_RE = re.compile(
    rb"(?i)\b(?:https?://|ftp://|socket\.|luasocket|curl|wget|powershell(?:\.exe)?|"
    rb"cmd(?:\.exe)?\s+/c|/bin/sh|/bin/bash|bash\s+-c|sh\s+-c|netcat|nc\s+)"
)
SAFE_LOCALHOST_URL_RE = re.compile(
    r"https?://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1)(?::\d+)?(?=[/?#\s]|$)(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)
SAFE_JSON_SCHEMA_URL_RE = re.compile(
    r"https?://(?:www\.)?json-schema\.org(?::\d+)?(?=[/?#\s]|$)(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)
TRANSFER_TOKEN_RE = re.compile(r""""(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|&&|\|\||[;|&]|(?:\\.|[^\s;|&])+""")
TRANSFER_COMMAND_WORD_RE = re.compile(
    r"(?<![\w.-])(?P<tool>curl|wget)(?:\.exe)?"
    r"""(?=(?:"(?=[\s;|&]|$)|'(?=[\s;|&]|$)|[\s;|&]|$))""",
    re.IGNORECASE,
)
TRANSFER_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,}|xn--[a-z0-9-]{2,})\.?(?::\d+)?$",
    re.IGNORECASE,
)
TRANSFER_VALUE_OPTIONS = frozenset(
    {
        "--connect-timeout",
        "--connect-to",
        "--cacert",
        "--cert",
        "--cookie",
        "--data",
        "--data-raw",
        "--directory-prefix",
        "--dns-servers",
        "--doh-url",
        "--form",
        "--ftp-password",
        "--ftp-user",
        "--header",
        "--http-password",
        "--http-user",
        "--interface",
        "--limit-rate",
        "--max-time",
        "--noproxy",
        "--oauth2-bearer",
        "--output",
        "--password",
        "--post-data",
        "--proxy",
        "--proxy-user",
        "--quota",
        "--referer",
        "--request",
        "--resolve",
        "--retry",
        "--socks4",
        "--socks4a",
        "--socks5",
        "--socks5-hostname",
        "--timeout",
        "--tries",
        "--user",
        "--user-agent",
        "--wait",
        "--write-out",
        "--upload-file",
    }
)
CURL_SHORT_VALUE_OPTIONS = frozenset(
    {
        "-A",
        "-b",
        "-c",
        "-C",
        "-d",
        "-D",
        "-e",
        "-E",
        "-F",
        "-H",
        "-h",
        "-K",
        "-m",
        "-o",
        "-P",
        "-r",
        "-t",
        "-T",
        "-u",
        "-U",
        "-w",
        "-x",
        "-X",
        "-y",
        "-Y",
        "-z",
    }
)
WGET_SHORT_VALUE_OPTIONS = frozenset(
    {"-A", "-a", "-B", "-e", "-I", "-i", "-l", "-o", "-O", "-P", "-Q", "-R", "-t", "-T", "-U", "-w", "-X"}
)
TRANSFER_URL_OPTIONS = frozenset({"--url"})
TRANSFER_FLAG_OPTIONS = frozenset(
    {
        "--compressed",
        "--continue",
        "--create-dirs",
        "--fail",
        "--fail-with-body",
        "--head",
        "--insecure",
        "--location",
        "--no-check-certificate",
        "--no-verbose",
        "--parallel",
        "--quiet",
        "--remote-name",
        "--show-error",
        "--silent",
        "--spider",
        "--timestamping",
        "--verbose",
    }
)
CURL_SHORT_FLAG_OPTIONS = frozenset(
    {
        "-#",
        "-0",
        "-1",
        "-2",
        "-3",
        "-4",
        "-6",
        "-a",
        "-B",
        "-f",
        "-g",
        "-G",
        "-I",
        "-J",
        "-k",
        "-L",
        "-M",
        "-N",
        "-O",
        "-q",
        "-R",
        "-s",
        "-S",
        "-v",
        "-V",
        "-Z",
    }
)
WGET_SHORT_FLAG_OPTIONS = frozenset(
    {"-4", "-6", "-b", "-c", "-d", "-E", "-F", "-H", "-h", "-k", "-m", "-N", "-n", "-p", "-q", "-S", "-v", "-V", "-x"}
)
TRANSFER_NETWORK_VALUE_OPTIONS = frozenset(
    {
        "--connect-to",
        "--dns-servers",
        "--doh-url",
        "--proxy",
        "--resolve",
        "--socks4",
        "--socks4a",
        "--socks5",
        "--socks5-hostname",
    }
)
TRANSFER_USERINFO_RE = re.compile(
    r"(?P<userinfo_prefix>(?:(?:https?|ftp)://)?[^\s:/;|&@]{1,100}:)"
    r"(?P<userinfo_password>[^@\s;|&]{1,1024})"
    r"(?=@(?:\[[0-9a-f:]+\]|[a-z0-9.-]+))",
    re.IGNORECASE,
)
TRANSFER_TRUNCATED_USERINFO_RE = re.compile(
    r"(?P<userinfo_prefix>(?:https?|ftp)://[^\s:/;|&@]{1,100}:)"
    r"(?P<userinfo_password>[^@\s;|&]{1,1024})$",
    re.IGNORECASE,
)
TRANSFER_TRUNCATED_BARE_USERINFO_RE = re.compile(
    r"(?P<userinfo_prefix>\b(?:curl|wget)(?:\.exe)?\b[^\r\n;|&]{0,512}?\s[^\s:/;|&@]{1,100}:)"
    r"(?P<userinfo_password>[^@\s;|&]{1,1024})$",
    re.IGNORECASE,
)
TRANSFER_CREDENTIAL_OPTION_RE = re.compile(
    r"(?P<credential_prefix>(?:--(?:ftp-password|ftp-user|http-password|http-user|oauth2-bearer|password|"
    r"proxy-user|user)(?:=|\s+)|(?<![a-z0-9-])-[uU](?:\s+|(?=[^-\s]))))"
    r"(?:\"(?P<credential_double>(?:\\.|[^\"\\\r\n]){0,1024})(?:\"|$)|"
    r"'(?P<credential_single>(?:\\.|[^'\\\r\n]){0,1024})(?:'|$)|"
    r"(?P<credential_bare>(?:\\.|[^\s;|&\\\"']){1,1024}))",
    re.IGNORECASE,
)
URL_TOKEN_RE = re.compile(
    r"https?://(?:[^@\s/?#]+@)?(?:\[[^\]]+\]|[^\s/:?#]+)(?::\d+)?(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)
COMMAND_INDICATOR_RE = re.compile(
    r"(?:\b(?:bash|sh|zsh|dash|ksh|fish)\s+-(?-i:(?![a-z]*n)[a-z]*c[a-z]*)(?:\s|$)"
    r"|\bpython(?:\d+(?:\.\d+)?)?\s+-(?-i:c)(?:\s|$)"
    r"|\bcmd(?:\.exe)?(?:\s+/(?:s|q|d|a|u|v(?::(?:on|off))?|e:(?:on|off)|f:(?:on|off))){0,8}"
    r"\s+/(?:c|k)(?:\s|$)"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\s+(?:[-/][a-z]|invoke-(?:webrequest|restmethod|expression)\b|"
    r"start-process\b|iex\b|whoami\b|[^\s;|&]+\.(?:exe|ps1|cmd|bat)\b)"
    r"|\bos\.system\s*\("
    r"|\bsubprocess\.(?:run|call|popen|check_call|check_output|getoutput|getstatusoutput)\s*\()",
    re.IGNORECASE,
)
INTERPRETER_WORD_RE = re.compile(
    r"(?<![\w.-])(?P<name>(?:bash|sh|zsh|dash|ksh|fish)(?:\.exe)?|"
    r"python(?:\d+(?:\.\d+)?)?(?:\.exe)?)"
    r"[\"']?(?=\s|$)",
    re.IGNORECASE,
)
QUOTED_WRAPPER_COMMAND_RE = re.compile(
    r"(?<![\w.-])[\"'](?:[^\"'\r\n]{0,240}[\\/])?cmd(?:\.exe)?[\"']"
    r"(?:\s+/(?:s|q|d|a|u|v(?::(?:on|off))?|e:(?:on|off)|f:(?:on|off))){0,8}"
    r"\s+/(?:c|k)(?=\s|$)"
    r"|(?<![\w.-])[\"'](?:[^\"'\r\n]{0,240}[\\/])?(?:powershell|pwsh)(?:\.exe)?[\"']\s+"
    r"(?:[-/][a-z]|invoke-(?:webrequest|restmethod|expression)\b|start-process\b|iex\b|whoami\b|"
    r"[^\s;|&]+\.(?:exe|ps1|cmd|bat)\b)",
    re.IGNORECASE,
)

NETWORK_TOKENS = (
    "http://",
    "https://",
    "tcp://",
    "udp://",
    "connect(",
)
NETWORK_CODE_RE = re.compile(r"\bsocket(?:\.|\s*\()", re.IGNORECASE)

# Patterns found in the legitimate llamafile/cosmopolitan runtime that are
# NOT indicators of compromise.  These appear in error messages, debug format
# strings, and server status output.
LLAMAFILE_RUNTIME_SAFE_EXACT_PATTERNS: tuple[str, ...] = (
    "llamafile",
    "llama.cpp",
    "cosmopolitan",
    "binfmt_misc",
    "%rSYS",
    "llama_new_context_with_model",
    "error: APE is running on WIN32 inside WSL. You need to run: "
    "sudo sh -c 'echo -1 > /proc/sys/fs/binfmt_misc/WSLInterop'",
    "usage: bash -c COMMAND",
)

LLAMAFILE_RUNTIME_SAFE_FRAGMENT_PATTERNS: tuple[str, ...] = (
    "llama server listening",
    "json-schema.org",
    "%'18T connect",
    "%'18T socket",
)
LLAMAFILE_RUNTIME_SAFE_EXACT_LOWER: set[str] = {pattern.lower() for pattern in LLAMAFILE_RUNTIME_SAFE_EXACT_PATTERNS}
LLAMAFILE_RUNTIME_SAFE_FRAGMENT_LOWER: set[str] = {
    pattern.lower() for pattern in LLAMAFILE_RUNTIME_SAFE_FRAGMENT_PATTERNS
}


def _has_command_indicator(text: str) -> bool:
    """Return whether text contains command-shaped execution syntax."""
    command_signal, _, _, _, _ = _runtime_text_signals(text)
    return command_signal


def _remote_transfer_targets_network(text: str) -> bool:
    """Return whether a curl/wget command has a literal non-local target."""
    _, remote_target, _, _, _ = _transfer_invocation_signals(text)
    return remote_target


def _unquote_transfer_token(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _interpreter_command_analysis(text: str) -> tuple[int | None, bool]:
    """Return an executable command start and whether argv analysis hit its bound."""
    shell_names = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
    shell_long_flags = {
        "--debug",
        "--debugger",
        "--noediting",
        "--noprofile",
        "--norc",
        "--posix",
        "--login",
        "--restricted",
        "--verbose",
    }
    zsh_long_flags = {
        "--emacs",
        "--interactivecomments",
        "--no-globalrcs",
        "--no-rcs",
        "--privileged",
        "--shinstdin",
        "--singlecommand",
    }
    shell_value_options = {"--init-file", "--rcfile"}
    python_flag_letters = frozenset("bBdEiIOPqRsSuvx")

    token_scan_limited = False
    for executable in INTERPRETER_WORD_RE.finditer(text):
        name = executable.group("name").lower().removesuffix(".exe")
        args: list[str] = []
        for token_match in TRANSFER_TOKEN_RE.finditer(text, executable.end()):
            raw_token = token_match.group()
            quoted = len(raw_token) >= 2 and raw_token[0] == raw_token[-1] and raw_token[0] in {'"', "'"}
            token = _unquote_transfer_token(raw_token)
            if not quoted:
                token = re.sub(r"\\(.)", r"\1", token)
            if token in {";", "|", "||", "&&"}:
                break
            args.append(token)
            if len(args) > LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS:
                break
        argv_limited = len(args) > LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS
        if argv_limited:
            args.pop()

        if name in shell_names:
            noexec = False
            dump_translatable_strings = False
            index = 0
            while index < len(args):
                token = args[index]
                if token in {"-o", "+o", "-O", "+O"}:
                    if index + 1 >= len(args):
                        token_scan_limited |= argv_limited
                        break
                    option_name = args[index + 1]
                    if token == "-o" and option_name == "noexec":
                        noexec = True
                    elif token == "+o" and option_name == "noexec":
                        noexec = False
                    index += 2
                    continue
                option, separator, _ = token.partition("=")
                if option in shell_value_options:
                    index += 1 if separator else 2
                    continue
                if name == "zsh" and token in {"--exec", "--noexec"}:
                    noexec = token == "--noexec"
                    index += 1
                    continue
                if token in shell_long_flags or (name == "zsh" and token in zsh_long_flags):
                    index += 1
                    continue
                if token.startswith("--"):
                    break
                if not token.startswith(("-", "+")) or len(token) < 2 or token == "--":
                    break
                letters = token[1:]
                if token.startswith("-"):
                    noexec |= "n" in letters
                    dump_translatable_strings |= "D" in letters
                    if "c" in letters:
                        if not noexec and not dump_translatable_strings and index + 1 < len(args):
                            return executable.start(), False
                        if not noexec and not dump_translatable_strings:
                            token_scan_limited |= argv_limited
                        break
                elif "n" in letters:
                    noexec = False
                index += 1
            else:
                token_scan_limited |= argv_limited
            continue

        index = 0
        while index < len(args):
            token = args[index]
            if token == "-c":
                if index + 1 < len(args):
                    return executable.start(), False
                token_scan_limited |= argv_limited
                break
            if token in {"-X", "-W"}:
                index += 2
                continue
            if (token.startswith("-X") or token.startswith("-W")) and len(token) > 2:
                index += 1
                continue
            option, separator, _ = token.partition("=")
            if option == "--check-hash-based-pycs":
                index += 1 if separator else 2
                continue
            if not token.startswith("-") or len(token) < 2:
                break
            letters = token[1:]
            command_index = letters.find("c")
            command_prefix = letters[:command_index] if command_index >= 0 else ""
            if command_index >= 0 and all(letter in python_flag_letters for letter in command_prefix):
                if command_index + 1 < len(letters) or index + 1 < len(args):
                    return executable.start(), False
                token_scan_limited |= argv_limited
                break
            if not letters or any(letter not in python_flag_letters for letter in letters):
                break
            index += 1
        else:
            token_scan_limited |= argv_limited
    return None, token_scan_limited


def _interpreter_command_start(text: str) -> int | None:
    """Return the first bounded shell/Python invocation that executes command text."""
    command_start, _ = _interpreter_command_analysis(text)
    return command_start


def _classify_transfer_target(token: str) -> tuple[bool, bool]:
    """Return whether a token is a transfer target and whether it is remote."""
    target = _unquote_transfer_token(token).strip().strip("(){}<>,")
    for separator in ("&&", "||", ";", "|"):
        target = target.split(separator, 1)[0]
    if not target:
        return False, False
    if target.startswith("$"):
        return True, False

    lowered = target.lower()
    if lowered.startswith("file:") or lowered.startswith(("/", "./", "../", "~/")):
        return True, False

    if "://" in target:
        try:
            parsed = urlsplit(target)
        except ValueError:
            return True, True
        if parsed.scheme.lower() == "file":
            return True, False
        if parsed.hostname is None:
            return False, False
        return True, not _is_local_endpoint_token(parsed.hostname)

    host_token = target.split("/", 1)[0]
    if "@" in host_token:
        userinfo, _, host_token = host_token.rpartition("@")
        if ":" not in userinfo and "/" not in target:
            return False, False
    try:
        parsed_host = urlsplit(f"//{host_token}").hostname
    except ValueError:
        return True, True
    if "/" in target:
        if parsed_host is None:
            return False, False
        return True, not _is_local_endpoint_token(parsed_host)
    try:
        ipaddress.ip_address(parsed_host or "")
    except ValueError:
        pass
    else:
        return True, not _is_local_endpoint_token(parsed_host or "")
    if parsed_host is not None and (
        TRANSFER_DOMAIN_RE.fullmatch(host_token) is not None
        or _is_local_endpoint_token(parsed_host)
        or host_token.startswith("[")
    ):
        return True, not _is_local_endpoint_token(parsed_host)
    return False, False


def _transfer_network_option_is_remote(option: str, value: str) -> bool:
    """Return whether a transfer option routes traffic to a remote endpoint."""
    fields: list[str] = []
    field_start = 0
    bracket_depth = 0
    for index, character in enumerate(value):
        if character == "[":
            bracket_depth += 1
        elif character == "]" and bracket_depth:
            bracket_depth -= 1
        elif character == ":" and not bracket_depth:
            fields.append(value[field_start:index])
            field_start = index + 1
    fields.append(value[field_start:])

    if option == "--connect-to":
        if len(fields) != 4:
            return True
        replacement_host = fields[2] or fields[0]
        return not _is_local_endpoint_token(replacement_host)
    if option == "--resolve":
        return len(fields) == 3 and any(
            not _is_local_endpoint_token(address) for address in fields[2].split(",") if address
        )
    if option == "--dns-servers":
        return any(not _is_local_endpoint_token(server) for server in value.split(",") if server)
    recognized, remote = _classify_transfer_target(value)
    return recognized and remote


def _transfer_invocation_signals(text: str) -> tuple[bool, bool, bool, bool, str]:
    """Parse bounded curl/wget argument strings without an option-count bypass."""
    if TRANSFER_COMMAND_WORD_RE.search(text) is None:
        return False, False, False, False, text
    invocation_seen = False
    remote_target_seen = False
    token_scan_limited = False
    option_arity_ambiguous = False
    opaque_value_spans: list[tuple[int, int]] = []
    for command_count, command_match in enumerate(TRANSFER_COMMAND_WORD_RE.finditer(text), start=1):
        if command_count > 64:
            token_scan_limited = True
            break
        command_tool = command_match.group("tool").lower()
        command_end = command_match.end()
        if command_end < len(text) and text[command_end] in {'"', "'"}:
            command_end += 1

        tokens: list[tuple[str, int, int]] = []
        tokens_truncated = False
        for token_match in TRANSFER_TOKEN_RE.finditer(text, command_end):
            if len(tokens) >= LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS:
                tokens_truncated = True
                break
            token = _unquote_transfer_token(token_match.group())
            tokens.append((token, token_match.start(), token_match.end()))
            if token in {";", "|", "||", "&&"}:
                break

        positional_only = False
        network_option_remote = False
        positional_targets: list[tuple[bool, bool]] = []
        tentative_option_targets: list[tuple[bool, bool, tuple[int, int]]] = []
        parse_terminated = False
        index = 0
        while index < len(tokens):
            token, token_start, token_end = tokens[index]
            if token in {";", "|", "||", "&&"}:
                parse_terminated = True
                break
            if not positional_only and token == "--":
                positional_only = True
                index += 1
                continue
            if not positional_only and token.startswith("--"):
                option, separator, attached_value = token.partition("=")
                option = option.lower()
                if option in TRANSFER_URL_OPTIONS:
                    if not separator and index + 1 < len(tokens):
                        index += 1
                        attached_value = tokens[index][0]
                    recognized, remote = _classify_transfer_target(attached_value)
                    positional_targets.append((recognized, remote))
                elif option in TRANSFER_FLAG_OPTIONS:
                    pass
                elif separator:
                    if option in TRANSFER_NETWORK_VALUE_OPTIONS:
                        network_option_remote |= _transfer_network_option_is_remote(option, attached_value)
                    opaque_value_spans.append((token_start, token_end))
                elif index + 1 < len(tokens):
                    index += 1
                    value, value_start, value_end = tokens[index]
                    if option in TRANSFER_VALUE_OPTIONS:
                        if option in TRANSFER_NETWORK_VALUE_OPTIONS:
                            network_option_remote |= _transfer_network_option_is_remote(option, value)
                        opaque_value_spans.append((value_start, value_end))
                    else:
                        tentative_option_targets.append((*_classify_transfer_target(value), (value_start, value_end)))
                index += 1
                continue
            if not positional_only and token.startswith("-") and len(token) >= 2:
                value_options = CURL_SHORT_VALUE_OPTIONS if command_tool == "curl" else WGET_SHORT_VALUE_OPTIONS
                flag_options = CURL_SHORT_FLAG_OPTIONS if command_tool == "curl" else WGET_SHORT_FLAG_OPTIONS
                body = token[1:]
                value_position = next(
                    (position for position, letter in enumerate(body) if f"-{letter}" in value_options),
                    None,
                )
                if value_position is not None:
                    option = f"-{body[value_position]}"
                    if any(f"-{letter}" not in flag_options for letter in body[:value_position]):
                        option_arity_ambiguous = True
                    attached_value = body[value_position + 1 :]
                    if not attached_value and index + 1 < len(tokens):
                        index += 1
                        attached_value = tokens[index][0]
                        opaque_value_spans.append((tokens[index][1], tokens[index][2]))
                    else:
                        opaque_value_spans.append((token_start, token_end))
                    if command_tool == "curl" and option == "-x":
                        network_option_remote |= _transfer_network_option_is_remote("--proxy", attached_value)
                elif all(f"-{letter}" in flag_options for letter in body):
                    pass
                elif index + 1 < len(tokens):
                    index += 1
                    value, value_start, value_end = tokens[index]
                    tentative_option_targets.append((*_classify_transfer_target(value), (value_start, value_end)))
                else:
                    option_arity_ambiguous = True
                index += 1
                continue

            recognized, remote = _classify_transfer_target(token)
            if not recognized:
                parse_terminated = True
                break
            positional_targets.append((recognized, remote))
            index += 1
        if tokens_truncated and not parse_terminated:
            token_scan_limited = True
        targets = [target for target in positional_targets if target[0]]
        tentative_targets = [(recognized, remote) for recognized, remote, _ in tentative_option_targets if recognized]
        if tentative_targets and (
            not targets or (not any(remote for _, remote in targets) and any(remote for _, remote in tentative_targets))
        ):
            option_arity_ambiguous = True
        opaque_value_spans.extend(span for _, _, span in tentative_option_targets)
        invocation_seen |= bool(targets)
        remote_target_seen |= network_option_remote or any(remote for _, remote in targets)

    if not opaque_value_spans:
        return invocation_seen, remote_target_seen, token_scan_limited, option_arity_ambiguous, text
    parts: list[str] = []
    cursor = 0
    for start, end in sorted(set(opaque_value_spans)):
        if start < cursor:
            continue
        parts.extend((text[cursor:start], " " * (end - start)))
        cursor = end
    parts.append(text[cursor:])
    return invocation_seen, remote_target_seen, token_scan_limited, option_arity_ambiguous, "".join(parts)


def _strip_local_urls(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            return match.group(0)
        return "" if host is not None and _is_local_endpoint_token(host) else match.group(0)

    return URL_TOKEN_RE.sub(replace, text)


def _redact_transfer_userinfo(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        start = match.start("userinfo_password") - match.start()
        end = match.end("userinfo_password") - match.start()
        return f"{value[:start]}<redacted>{value[end:]}"

    redacted = TRANSFER_USERINFO_RE.sub(
        replace,
        text,
    )

    def redact_option(match: re.Match[str]) -> str:
        if match.group("credential_double") is not None:
            return f'{match.group("credential_prefix")}"<redacted>"'
        if match.group("credential_single") is not None:
            return f"{match.group('credential_prefix')}'<redacted>'"
        return f"{match.group('credential_prefix')}<redacted>"

    return TRANSFER_CREDENTIAL_OPTION_RE.sub(redact_option, redacted)


def _redacted_runtime_evidence(text: str) -> str:
    command_anchors = [
        match.start()
        for pattern in (
            COMMAND_INDICATOR_RE,
            QUOTED_WRAPPER_COMMAND_RE,
            TRANSFER_COMMAND_WORD_RE,
        )
        if (match := pattern.search(text)) is not None
    ]
    if (interpreter_start := _interpreter_command_start(text)) is not None:
        command_anchors.append(interpreter_start)
    remote_url_anchors: list[int] = []
    for match in URL_TOKEN_RE.finditer(text):
        try:
            host = urlsplit(match.group()).hostname
        except ValueError:
            host = None
        if host is None or not _is_local_endpoint_token(host):
            remote_url_anchors.append(match.start())
    network_match = NETWORK_CODE_RE.search(text)
    network_anchors = remote_url_anchors + ([network_match.start()] if network_match is not None else [])
    start = min(command_anchors or network_anchors, default=0)
    excerpt = text[start : start + LLAMAFILE_RUNTIME_EVIDENCE_INPUT_CHARS]
    if start > 0:
        excerpt = f"...{excerpt}"
    truncated_right = start + LLAMAFILE_RUNTIME_EVIDENCE_INPUT_CHARS < len(text)
    if truncated_right:
        excerpt = f"{excerpt}..."
    excerpt = _redact_transfer_userinfo(excerpt)
    if truncated_right:
        excerpt = excerpt.removesuffix("...")
        for pattern in (TRANSFER_TRUNCATED_USERINFO_RE, TRANSFER_TRUNCATED_BARE_USERINFO_RE):
            excerpt = pattern.sub(
                lambda match: f"{match.group('userinfo_prefix')}<redacted>",
                excerpt,
            )
        excerpt = f"{excerpt}..."
    return redact_evidence_string(excerpt, max_chars=200)


def _runtime_fragment_has_remote_endpoint(candidate: str) -> bool:
    """Classify the concrete endpoint following a connect/socket format fragment."""
    stripped = candidate.strip().strip("(){}<>,;")
    if stripped.lower().startswith("to "):
        stripped = stripped[3:].lstrip()
    if not stripped or "%" in stripped:
        return False
    token = stripped.split(maxsplit=1)[0].strip("(){}<>,;")
    if not token or token.lower() in {"closed", "failed", "failure", "error", "opened", "opening"}:
        return False
    return not _is_local_endpoint_token(token)


def _has_remote_runtime_fragment(text: str) -> bool:
    for match in re.finditer(r"%'18t\s+(?:connect|socket)", text, re.IGNORECASE):
        if _runtime_fragment_has_remote_endpoint(text[match.end() :]):
            return True
    return False


def _has_network_indicator(text: str) -> bool:
    _, network_signal, _, _, _ = _runtime_text_signals(text)
    return network_signal


def _runtime_text_signals(text: str) -> tuple[bool, bool, bool, bool, bool]:
    (
        transfer_invocation,
        remote_transfer,
        transfer_token_scan_limited,
        transfer_option_ambiguous,
        transfer_sanitized,
    ) = _transfer_invocation_signals(text)
    interpreter_start, interpreter_token_scan_limited = _interpreter_command_analysis(text)
    normalized = _strip_local_urls(transfer_sanitized)
    normalized_lower = normalized.lower()
    command_signal = (
        COMMAND_INDICATOR_RE.search(text) is not None
        or interpreter_start is not None
        or QUOTED_WRAPPER_COMMAND_RE.search(text) is not None
        or transfer_invocation
    )
    network_signal = (
        any(token in normalized_lower for token in NETWORK_TOKENS)
        or NETWORK_CODE_RE.search(normalized_lower) is not None
        or remote_transfer
        or _has_remote_runtime_fragment(text)
    )
    return (
        command_signal,
        network_signal,
        transfer_token_scan_limited,
        transfer_option_ambiguous,
        interpreter_token_scan_limited,
    )


def _is_local_endpoint_token(token: str) -> bool:
    """Return True when an extracted endpoint token resolves to a local-only address."""
    host = token.strip().lower()
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]

    if host in {"localhost", "::1", "0.0.0.0"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback or ip.ipv4_mapped.is_unspecified
    return ip.is_loopback or ip.is_unspecified


def _utf16_printable_suffix_start(blob: bytes, *, little_endian: bool) -> int:
    """Return the start of a trailing ASCII-compatible UTF-16 run."""
    end = len(blob)
    has_partial_unit = bool(blob) and (32 <= blob[-1] <= 126 if little_endian else blob[-1] == 0)
    pair_end = end - int(has_partial_unit)
    pair_start = pair_end % 2
    first_bytes = blob[pair_start:pair_end:2]
    second_bytes = blob[pair_start + 1 : pair_end : 2]
    if little_endian:
        printable_bytes, null_bytes = first_bytes, second_bytes
    else:
        null_bytes, printable_bytes = first_bytes, second_bytes
    printable_count = len(printable_bytes) - len(printable_bytes.rstrip(PRINTABLE_BYTES))
    null_count = len(null_bytes) - len(null_bytes.rstrip(b"\x00"))
    return pair_end - 2 * min(printable_count, null_count)


def _iter_utf16_runtime_strings(
    blob: bytes,
    *,
    little_endian: bool | None = None,
    max_candidates: int | None = None,
    ambiguity_state: list[bool] | None = None,
) -> Iterator[bytes]:
    byte_orders = (little_endian,) if little_endian is not None else (True, False)
    candidates: list[tuple[int, int, bytes, bool]] = []
    for byte_order in byte_orders:
        pattern = UTF16LE_PRINTABLE_TEXT_RE if byte_order else UTF16BE_PRINTABLE_TEXT_RE
        character_offset = 0 if byte_order else 1
        for order_candidates, match in enumerate(pattern.finditer(blob), start=1):
            candidates.append((match.start(), match.end(), match.group()[character_offset::2], byte_order))
            if max_candidates is not None and order_candidates > max_candidates:
                break

    selected_count = 0
    previous_byte_order: bool | None = None
    previous_end = -1
    group_end = -1
    group: list[tuple[int, int, bytes, bool]] = []

    def select_group() -> list[tuple[int, int, bytes, bool]]:
        nonlocal previous_byte_order, previous_end
        outer = [
            candidate
            for candidate in group
            if not any(
                other[0] <= candidate[0]
                and candidate[1] <= other[1]
                and other[1] - other[0] > candidate[1] - candidate[0]
                for other in group
            )
        ]
        group_start = min(candidate[0] for candidate in outer)
        equivalent_decoding = (
            len({candidate[3] for candidate in outer}) > 1 and len({candidate[2] for candidate in outer}) == 1
        )
        if equivalent_decoding:
            outer = [min(outer, key=lambda candidate: (candidate[0], candidate[1]))]
        elif len({candidate[3] for candidate in outer}) > 1:
            boundary_scores = {
                candidate: int(candidate[0] == 0) + int(candidate[1] == len(blob)) for candidate in outer
            }
            best_score = max(boundary_scores.values())
            best = [candidate for candidate in outer if boundary_scores[candidate] == best_score]
            if best_score > 0 and len({candidate[3] for candidate in best}) == 1:
                outer = best
            else:
                gap = blob[previous_end:group_start] if 0 <= previous_end <= group_start else b""
                matching_order = [candidate for candidate in outer if candidate[3] == previous_byte_order]
                if (
                    previous_byte_order is not None
                    and len(gap) <= 1
                    and not any(32 <= byte <= 126 for byte in gap)
                    and matching_order
                ):
                    outer = matching_order
                else:
                    signal_profiles = {_runtime_text_signals(candidate[2].decode("latin-1")) for candidate in outer}
                    if len(signal_profiles) == 1:
                        outer = [min(outer, key=lambda candidate: (candidate[0], candidate[1]))]
                        equivalent_decoding = True
                    else:
                        if ambiguity_state is not None:
                            ambiguity_state[0] = True
                        outer = []

        byte_orders_seen = {candidate[3] for candidate in outer}
        previous_byte_order = (
            next(iter(byte_orders_seen)) if len(byte_orders_seen) == 1 and not equivalent_decoding else None
        )
        previous_end = max(candidate[1] for candidate in outer) if previous_byte_order is not None else -1
        return sorted(outer, key=lambda item: (item[0], item[1]))

    for candidate in sorted(candidates, key=lambda item: (item[0], -(item[1] - item[0]))):
        start, end, _, _ = candidate
        if not group or start >= group_end:
            if group:
                for selected in select_group():
                    yield selected[2]
                    selected_count += 1
                    if max_candidates is not None and selected_count > max_candidates:
                        return
            group = [candidate]
            group_end = end
            continue
        group.append(candidate)
        group_end = max(group_end, end)
    if group:
        for selected in select_group():
            yield selected[2]
            selected_count += 1
            if max_candidates is not None and selected_count > max_candidates:
                return


class LlamafileScanner(BaseScanner):
    """Scanner for Llamafile binaries that package runtime + embedded model data."""

    name = "llamafile"
    description = "Scans Llamafile executables and embedded GGUF payloads"
    supported_extensions: ClassVar[list[str]] = [".llamafile", ".exe", ""]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.preview_bytes = int(self.config.get("llamafile_preview_bytes", 2 * 1024 * 1024))
        self.max_payload_scan_bytes = int(self.config.get("llamafile_payload_scan_bytes", 512 * 1024 * 1024))
        self.max_payload_carve_bytes = int(self.config.get("llamafile_payload_carve_bytes", 256 * 1024 * 1024))
        self.max_torch7_candidate_scans = int(
            self.config.get("llamafile_torch7_max_candidate_scans", LLAMAFILE_TORCH7_MAX_CANDIDATE_SCANS)
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        return is_llamafile_executable(path)

    @classmethod
    def _detect_executable_format(cls, path: Path) -> str | None:
        try:
            with path.open("rb") as handle:
                header = handle.read(4)
        except OSError:
            return None

        if header.startswith(ELF_MAGIC):
            return "elf"
        if header.startswith(PE_MAGIC):
            return "pe"
        if header in MACHO_MAGICS:
            return "mach-o"
        return None

    @staticmethod
    def _read_executable_bytes(handle: BinaryIO, offset: int, size: int, file_size: int) -> bytes | None:
        if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
            return None
        handle.seek(offset)
        data = handle.read(size)
        return data if len(data) == size else None

    @classmethod
    def _elf_mapped_file_end(
        cls,
        handle: BinaryIO,
        file_size: int,
        *,
        base_offset: int = 0,
        require_nonempty_load_segment: bool = False,
        required_machine: int | None = None,
    ) -> int | None:
        ident = cls._read_executable_bytes(handle, base_offset, 16, file_size)
        if ident is None or not ident.startswith(ELF_MAGIC):
            return None

        elf_class = ident[4]
        endian = "<" if ident[5] == 1 else ">" if ident[5] == 2 else None
        if endian is None or elf_class not in {1, 2}:
            return None

        header_size = 64 if elf_class == 2 else 52
        header = cls._read_executable_bytes(handle, base_offset, header_size, file_size)
        if header is None:
            return None
        if required_machine is not None and struct.unpack_from(f"{endian}H", header, 18)[0] != required_machine:
            return None

        if elf_class == 2:
            program_offset = struct.unpack_from(f"{endian}Q", header, 32)[0]
            program_entry_size = struct.unpack_from(f"{endian}H", header, 54)[0]
            program_count = struct.unpack_from(f"{endian}H", header, 56)[0]
            minimum_entry_size = 56
        else:
            program_offset = struct.unpack_from(f"{endian}I", header, 28)[0]
            program_entry_size = struct.unpack_from(f"{endian}H", header, 42)[0]
            program_count = struct.unpack_from(f"{endian}H", header, 44)[0]
            minimum_entry_size = 32

        if (
            program_count == 0
            or program_count == 0xFFFF
            or program_count > 4096
            or program_entry_size < minimum_entry_size
            or program_offset > file_size - base_offset
            or program_count > (file_size - base_offset - program_offset) // program_entry_size
        ):
            return None

        mapped_end = base_offset + program_offset + program_count * program_entry_size
        nonempty_load_segment_found = False
        for index in range(program_count):
            entry = cls._read_executable_bytes(
                handle,
                base_offset + program_offset + index * program_entry_size,
                minimum_entry_size,
                file_size,
            )
            if entry is None:
                return None
            if struct.unpack_from(f"{endian}I", entry, 0)[0] != 1:  # PT_LOAD
                continue
            if elf_class == 2:
                segment_offset = struct.unpack_from(f"{endian}Q", entry, 8)[0]
                segment_size = struct.unpack_from(f"{endian}Q", entry, 32)[0]
            else:
                segment_offset = struct.unpack_from(f"{endian}I", entry, 4)[0]
                segment_size = struct.unpack_from(f"{endian}I", entry, 16)[0]
            if segment_offset > file_size - base_offset or segment_size > file_size - base_offset - segment_offset:
                return None
            if segment_size > 0:
                nonempty_load_segment_found = True
                mapped_end = max(mapped_end, base_offset + segment_offset + segment_size)
        if require_nonempty_load_segment and not nonempty_load_segment_found:
            return None
        return mapped_end or None

    @classmethod
    def _pe_mapped_file_end(
        cls,
        handle: BinaryIO,
        file_size: int,
        *,
        max_scan_bytes: int | None = None,
        search_boundary_is_complete: bool = False,
    ) -> int | None:
        dos_header = cls._read_executable_bytes(handle, 0, 64, file_size)
        if dos_header is None or not dos_header.startswith(PE_MAGIC):
            return None

        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
        coff_header = cls._read_executable_bytes(handle, pe_offset, 24, file_size)
        if coff_header is None or coff_header[:4] != b"PE\x00\x00":
            return None

        section_count = struct.unpack_from("<H", coff_header, 6)[0]
        optional_header_size = struct.unpack_from("<H", coff_header, 20)[0]
        if optional_header_size < 64:
            return None
        optional_header = cls._read_executable_bytes(handle, pe_offset + 24, 64, file_size)
        if optional_header is None or struct.unpack_from("<H", optional_header, 0)[0] not in {0x10B, 0x20B}:
            return None
        size_of_headers = struct.unpack_from("<I", optional_header, 60)[0]
        section_table_offset = pe_offset + 24 + optional_header_size
        if (
            section_count == 0
            or section_count > 4096
            or section_table_offset > file_size
            or section_count > (file_size - section_table_offset) // 40
            or size_of_headers < section_table_offset + section_count * 40
            or size_of_headers > file_size
        ):
            return None

        mapped_end = size_of_headers
        for index in range(section_count):
            section = cls._read_executable_bytes(handle, section_table_offset + index * 40, 40, file_size)
            if section is None:
                return None
            raw_size = struct.unpack_from("<I", section, 16)[0]
            raw_offset = struct.unpack_from("<I", section, 20)[0]
            if raw_offset > file_size or raw_size > file_size - raw_offset:
                return None
            if raw_size > 0:
                mapped_end = max(mapped_end, raw_offset + raw_size)
        if not dos_header.startswith(b"MZqFpD"):
            return mapped_end
        embedded_search_start = mapped_end
        embedded_mapping_found = False
        search_end = file_size if max_scan_bytes is None else min(file_size, max(0, max_scan_bytes))
        if search_end < embedded_search_start:
            return None
        scanned = embedded_search_start
        carry = b""
        last_candidate = -1
        candidates = 0
        handle.seek(scanned)
        while scanned < search_end:
            chunk = handle.read(min(1024 * 1024, search_end - scanned))
            if not chunk:
                return None
            haystack = carry + chunk
            window_offset = scanned - len(carry)
            search_from = 0
            while True:
                relative_offset = haystack.find(ELF_MAGIC, search_from)
                if relative_offset == -1:
                    break
                search_from = relative_offset + len(ELF_MAGIC)
                candidate_offset = window_offset + relative_offset
                if candidate_offset <= last_candidate:
                    continue
                last_candidate = candidate_offset
                candidates += 1
                if candidates > LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES:
                    return None
                embedded_end = cls._elf_mapped_file_end(
                    handle,
                    file_size,
                    base_offset=candidate_offset,
                    require_nonempty_load_segment=True,
                    required_machine=183,
                )
                if embedded_end is not None:
                    embedded_mapping_found = True
                    mapped_end = max(mapped_end, embedded_end)
            carry = haystack[-(len(ELF_MAGIC) - 1) :]
            scanned += len(chunk)
            handle.seek(scanned)
        if search_end < file_size and not search_boundary_is_complete:
            return None
        return mapped_end if embedded_mapping_found else None

    @classmethod
    def _thin_macho_mapped_file_end(
        cls,
        handle: BinaryIO,
        file_size: int,
        *,
        base_offset: int = 0,
        slice_size: int | None = None,
    ) -> int | None:
        available = file_size - base_offset if slice_size is None else slice_size
        if base_offset < 0 or available < 0 or base_offset > file_size or available > file_size - base_offset:
            return None
        magic = cls._read_executable_bytes(handle, base_offset, 4, file_size)
        if magic is None:
            return None
        formats = {
            b"\xfe\xed\xfa\xce": (">", False),
            b"\xce\xfa\xed\xfe": ("<", False),
            b"\xfe\xed\xfa\xcf": (">", True),
            b"\xcf\xfa\xed\xfe": ("<", True),
        }
        format_info = formats.get(magic)
        if format_info is None:
            return None
        endian, is_64_bit = format_info
        header_size = 32 if is_64_bit else 28
        full_header = cls._read_executable_bytes(handle, base_offset, header_size, file_size)
        if full_header is None or header_size > available:
            return None
        command_count = struct.unpack_from(f"{endian}I", full_header, 16)[0]
        command_bytes = struct.unpack_from(f"{endian}I", full_header, 20)[0]
        if command_count == 0 or command_count > 4096 or command_bytes > available - header_size:
            return None

        command_offset = base_offset + header_size
        command_end = command_offset + command_bytes
        mapped_end = command_end
        for _ in range(command_count):
            command_header = cls._read_executable_bytes(handle, command_offset, 8, file_size)
            if command_header is None:
                return None
            command, command_size = struct.unpack(f"{endian}II", command_header)
            if command_size < 8 or command_size > command_end - command_offset:
                return None
            if command == 0x19 and command_size >= 72:  # LC_SEGMENT_64
                segment = cls._read_executable_bytes(handle, command_offset, 72, file_size)
                if segment is None:
                    return None
                segment_offset = struct.unpack_from(f"{endian}Q", segment, 40)[0]
                segment_size = struct.unpack_from(f"{endian}Q", segment, 48)[0]
            elif command == 0x1 and command_size >= 56:  # LC_SEGMENT
                segment = cls._read_executable_bytes(handle, command_offset, 56, file_size)
                if segment is None:
                    return None
                segment_offset = struct.unpack_from(f"{endian}I", segment, 32)[0]
                segment_size = struct.unpack_from(f"{endian}I", segment, 36)[0]
            else:
                command_offset += command_size
                continue
            if segment_offset > available or segment_size > available - segment_offset:
                return None
            if segment_size > 0:
                mapped_end = max(mapped_end, base_offset + segment_offset + segment_size)
            command_offset += command_size
        return mapped_end if command_offset == command_end else None

    @classmethod
    def _macho_mapped_file_end(cls, handle: BinaryIO, file_size: int) -> int | None:
        header = cls._read_executable_bytes(handle, 0, 8, file_size)
        if header is None:
            return None

        magic = header[:4]
        fat_32_magics = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
        fat_64_magics = {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
        if magic not in fat_32_magics | fat_64_magics:
            return cls._thin_macho_mapped_file_end(handle, file_size)

        endian = ">" if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "<"
        architecture_entry_size = 32 if magic in fat_64_magics else 20
        architecture_count = struct.unpack_from(f"{endian}I", header, 4)[0]
        if (
            architecture_count == 0
            or architecture_count > 64
            or architecture_count > (file_size - 8) // architecture_entry_size
        ):
            return None
        architecture_table_end = 8 + architecture_count * architecture_entry_size
        mapped_end = architecture_table_end
        slices: list[tuple[int, int]] = []
        for index in range(architecture_count):
            architecture = cls._read_executable_bytes(
                handle,
                8 + index * architecture_entry_size,
                architecture_entry_size,
                file_size,
            )
            if architecture is None:
                return None
            if magic in fat_64_magics:
                architecture_offset = struct.unpack_from(f"{endian}Q", architecture, 8)[0]
                architecture_size = struct.unpack_from(f"{endian}Q", architecture, 16)[0]
            else:
                architecture_offset = struct.unpack_from(f"{endian}I", architecture, 8)[0]
                architecture_size = struct.unpack_from(f"{endian}I", architecture, 12)[0]
            if (
                architecture_offset < architecture_table_end
                or architecture_size < 28
                or architecture_offset > file_size
                or architecture_size > file_size - architecture_offset
            ):
                return None
            slice_end = architecture_offset + architecture_size
            if any(
                architecture_offset < existing_end and existing_start < slice_end
                for existing_start, existing_end in slices
            ):
                return None
            slices.append((architecture_offset, slice_end))
            slice_mapped_end = cls._thin_macho_mapped_file_end(
                handle,
                file_size,
                base_offset=architecture_offset,
                slice_size=architecture_size,
            )
            if slice_mapped_end is None:
                return None
            mapped_end = max(mapped_end, slice_mapped_end)
        return mapped_end

    @classmethod
    def _mapped_executable_file_end(
        cls,
        path: Path,
        executable_format: str,
        *,
        max_scan_bytes: int | None = None,
        search_boundary_is_complete: bool = False,
    ) -> int | None:
        file_size = path.stat().st_size
        try:
            with path.open("rb") as handle:
                if executable_format == "elf":
                    return cls._elf_mapped_file_end(handle, file_size)
                if executable_format == "pe":
                    return cls._pe_mapped_file_end(
                        handle,
                        file_size,
                        max_scan_bytes=max_scan_bytes,
                        search_boundary_is_complete=search_boundary_is_complete,
                    )
                if executable_format == "mach-o":
                    return cls._macho_mapped_file_end(handle, file_size)
        except (OSError, struct.error, ValueError):
            return None
        return None

    @staticmethod
    def _is_ape_executable(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                return handle.read(8).startswith(b"MZqFpD")
        except OSError:
            return False

    @classmethod
    def _probe_gguf_header(cls, handle: BinaryIO, offset: int, file_size: int) -> tuple[bool, bool, bool]:
        if offset < 0 or offset > file_size or file_size - offset < 24:
            return False, False, True
        header = cls._read_executable_bytes(handle, offset, 24, file_size)
        if header is None or header[:4] != GGUF_MARKER:
            return False, False, False
        _, tensor_count, metadata_count = struct.unpack_from("<IQQ", header, 4)
        resource_limit_exceeded = tensor_count > 10_000_000 or metadata_count > 10_000_000
        return not resource_limit_exceeded, resource_limit_exceeded, False

    @classmethod
    def _find_zip_gguf_payload(
        cls,
        path: Path,
        config: dict[str, Any],
    ) -> tuple[int | None, int | None, int, bool] | None:
        from .zip_scanner import ZipPreflightRejected, open_preflighted_zip

        try:
            file_size = path.stat().st_size
            with open_preflighted_zip(path, config) as archive:
                candidates: list[tuple[int | None, int | None]] = []
                compressed_candidate_found = False
                members = archive.infolist()
                archive_start = min((member.header_offset for member in members), default=-1)
                if archive_start < 0 or archive_start > file_size:
                    return None
                for member in members:
                    if member.is_dir() or member.flag_bits & 0x1 or member.file_size < 24:
                        continue
                    with archive.open(member) as member_handle:
                        member_header = member_handle.read(24)
                    if len(member_header) != 24 or member_header[:4] != GGUF_MARKER:
                        continue
                    _, tensor_count, metadata_count = struct.unpack_from("<IQQ", member_header, 4)
                    if tensor_count > 10_000_000 or metadata_count > 10_000_000:
                        continue

                    if member.compress_type != zipfile.ZIP_STORED:
                        compressed_candidate_found = True
                        candidates.append((None, None))
                        continue

                    archive_handle = archive.fp
                    if archive_handle is None:
                        return None
                    archive_handle.seek(member.header_offset)
                    local_header = archive_handle.read(30)
                    if len(local_header) != 30 or local_header[:4] != b"PK\x03\x04":
                        continue
                    name_length, extra_length = struct.unpack_from("<HH", local_header, 26)
                    data_offset = member.header_offset + 30 + name_length + extra_length
                    if data_offset > file_size or member.file_size > file_size - data_offset:
                        continue
                    candidates.append((data_offset, member.file_size))
                if not candidates:
                    return None
                stored_candidates = [candidate for candidate in candidates if candidate[0] is not None]
                data_offset, payload_size = min(stored_candidates) if stored_candidates else (None, None)
                return data_offset, payload_size, archive_start, compressed_candidate_found
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, ZipPreflightRejected):
            return None

    def scan(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        self.current_file_path = path
        self.add_file_integrity_check(path, result)

        path_obj = Path(path)
        executable_format = self._detect_executable_format(path_obj)
        if executable_format is None:
            result.add_check(
                name="Llamafile Executable Header Check",
                passed=False,
                message="File is not a supported executable container (ELF/Mach-O/PE)",
                severity=IssueSeverity.INFO,
                location=path,
            )
            result.finish(success=False)
            return result

        result.metadata["executable_format"] = executable_format
        result.metadata["is_executable_permission"] = os.access(path, os.X_OK)

        result.add_check(
            name="Llamafile Executable Detection",
            passed=False,
            message="Llamafile executable artifact detected",
            severity=IssueSeverity.INFO,
            location=path,
            details={"executable_format": executable_format},
        )

        file_size = path_obj.stat().st_size
        runtime_blobs: list[tuple[int, bytes]] = []
        marker_probe = b""
        runtime_preview_bytes = 0
        try:
            head = self._read_prefix(path_obj, self.preview_bytes)
            runtime_blobs.append((0, head))
            runtime_preview_bytes += len(head)
            tail = self._read_suffix(path_obj, self.preview_bytes)
            runtime_blobs.append((max(0, file_size - len(tail)), tail))
            runtime_preview_bytes += len(tail)
            marker_offset, marker_probe = self._find_casefolded_marker_offset(
                path_obj,
                LLAMAFILE_MARKER,
                LLAMAFILE_ROUTE_SCAN_BYTES,
                self.preview_bytes,
            )
            if marker_offset is not None and not self._offset_is_in_preview_windows(
                marker_offset,
                file_size,
                self.preview_bytes,
            ):
                middle = self._read_window_around_offset(path_obj, marker_offset, self.preview_bytes)
                middle_start = self._preview_window_start(file_size, marker_offset, self.preview_bytes)
                runtime_blobs.append((middle_start, middle))
                runtime_preview_bytes += len(middle)
        except OSError as exc:
            if marker_probe:
                runtime_blobs.append((0, marker_probe))
                runtime_preview_bytes += len(marker_probe)
            result.bytes_scanned = runtime_preview_bytes
            if runtime_blobs:
                self._scan_runtime_strings(path, b"\n".join(blob for _, blob in runtime_blobs), result)
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_PREVIEW_READ_REASON)
            result.add_check(
                name="Llamafile Runtime Preview Read",
                passed=False,
                message=f"Failed reading runtime preview bytes: {exc!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_PREVIEW_READ_REASON,
                },
            )
            try:
                _, torch7_offset, _, _, _ = self._find_embedded_payload_offsets(
                    path_obj,
                    self.max_payload_scan_bytes,
                    stop_at_gguf=False,
                )
            except OSError:
                torch7_offset = None
            self._merge_polyglot_findings(path_obj, result, torch7_offset)
            result.finish(success=False)
            return result

        zip_payload = self._find_zip_gguf_payload(path_obj, self.config)
        raw_payload_probe: tuple[list[int], int | None, bool, bool, bool] | None = None
        is_ape_executable = self._is_ape_executable(path_obj)
        mapping_search_complete = zip_payload is not None
        if zip_payload is not None:
            mapping_scan_end = zip_payload[2]
        else:
            raw_payload_probe = self._find_embedded_payload_offsets(
                path_obj,
                self.max_payload_scan_bytes,
                stop_at_gguf=False,
            )
            raw_gguf_candidates = raw_payload_probe[0]
            if is_ape_executable and raw_gguf_candidates:
                mapping_scan_end = self.max_payload_scan_bytes
                mapping_search_complete = True
            else:
                mapping_scan_end = self.max_payload_scan_bytes
        mapped_executable_end = self._mapped_executable_file_end(
            path_obj,
            executable_format,
            max_scan_bytes=mapping_scan_end,
            search_boundary_is_complete=mapping_search_complete,
        )
        if mapped_executable_end is not None:
            result.metadata["mapped_executable_end"] = mapped_executable_end

        gguf_candidates: list[int]
        boundary_candidates: list[int]
        gguf_offset: int | None
        payload_size: int | None
        zip_runtime_end: int | None = None
        compressed_zip_gguf = False
        if zip_payload is not None:
            gguf_offset, payload_size, zip_runtime_end, compressed_zip_gguf = zip_payload
            zip_candidate_scan_end = (
                self.max_payload_scan_bytes
                if gguf_offset is not None
                else min(self.max_payload_scan_bytes, zip_runtime_end)
            )
            (
                runtime_candidates,
                torch7_offset,
                gguf_candidate_scan_limited,
                gguf_header_limit_exceeded,
                gguf_header_incomplete,
            ) = self._find_embedded_payload_offsets(
                path_obj,
                zip_candidate_scan_end,
                stop_at_gguf=False,
            )
            gguf_candidates = sorted({*runtime_candidates, *([gguf_offset] if gguf_offset is not None else [])})
            boundary_candidates = [gguf_offset] if gguf_offset is not None else []
        else:
            zip_payload = None
            payload_size = None
            assert raw_payload_probe is not None
            (
                gguf_candidates,
                torch7_offset,
                gguf_candidate_scan_limited,
                gguf_header_limit_exceeded,
                gguf_header_incomplete,
            ) = raw_payload_probe
            boundary_candidates = [
                offset for offset in gguf_candidates if mapped_executable_end is None or offset >= mapped_executable_end
            ]
            selected_candidates = boundary_candidates or gguf_candidates
            gguf_offset = selected_candidates[-1] if selected_candidates else None

        payload_bytes_scanned = 0
        recognized_offsets: set[int] = set()
        candidates_to_scan = gguf_candidates[:LLAMAFILE_GGUF_MAX_PAYLOAD_CANDIDATE_SCANS]
        if len(gguf_candidates) > len(candidates_to_scan):
            gguf_candidate_scan_limited = True

        remaining_carve_bytes = self.max_payload_carve_bytes
        for index, candidate_offset in enumerate(candidates_to_scan):
            if remaining_carve_bytes < 24:
                gguf_candidate_scan_limited = True
                break
            next_offset = gguf_candidates[index + 1] if index + 1 < len(gguf_candidates) else file_size
            candidate_size = (
                payload_size
                if zip_payload is not None and candidate_offset == gguf_offset and payload_size is not None
                else max(0, next_offset - candidate_offset)
            )
            candidate_size = min(candidate_size, remaining_carve_bytes)
            scanned_bytes, recognized_candidate = self._scan_embedded_payload(
                path_obj,
                result,
                candidate_offset,
                payload_size=candidate_size,
            )
            payload_bytes_scanned += scanned_bytes
            remaining_carve_bytes = max(0, remaining_carve_bytes - scanned_bytes)
            if recognized_candidate:
                recognized_offsets.add(candidate_offset)

        if not gguf_candidates and zip_payload is None:
            payload_bytes_scanned, _ = self._scan_embedded_payload(
                path_obj,
                result,
                None,
            )
        elif len(gguf_candidates) > 1:
            result.metadata["embedded_payload_candidate_offsets"] = gguf_candidates
        if len(boundary_candidates) > 1:
            result.metadata["embedded_payload_boundary_candidates"] = boundary_candidates
            self._mark_inconclusive(result, LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON)
            result.add_check(
                name="Llamafile Embedded Payload Disambiguation",
                passed=False,
                message="Multiple plausible embedded GGUF payload boundaries were found",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_GGUF_AMBIGUOUS_PAYLOAD_REASON,
                    "candidate_count": len(boundary_candidates),
                    "candidate_offsets": boundary_candidates[:LLAMAFILE_GGUF_MAX_PAYLOAD_CANDIDATE_SCANS],
                },
            )
        if gguf_header_limit_exceeded:
            self._mark_inconclusive(result, LLAMAFILE_GGUF_HEADER_LIMIT_REASON)
            result.add_check(
                name="Llamafile Embedded GGUF Header Resource Limits",
                passed=False,
                message="Embedded GGUF header declares resource counts above the structural probe limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_GGUF_HEADER_LIMIT_REASON,
                    "max_tensor_count": 10_000_000,
                    "max_metadata_count": 10_000_000,
                },
            )
        if gguf_header_incomplete and not gguf_candidates:
            self._mark_inconclusive(result, LLAMAFILE_GGUF_HEADER_INCOMPLETE_REASON)
            result.add_check(
                name="Llamafile Embedded GGUF Header Integrity",
                passed=False,
                message="Embedded GGUF marker is truncated before its complete header",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_GGUF_HEADER_INCOMPLETE_REASON,
                    "required_header_bytes": 24,
                },
            )
        zip_member_scan_incomplete = compressed_zip_gguf or (
            gguf_offset is not None
            and payload_size is not None
            and gguf_offset + payload_size > max(0, self.max_payload_scan_bytes)
        )
        if zip_member_scan_incomplete:
            self._mark_inconclusive(result, LLAMAFILE_GGUF_ZIP_MEMBER_INCOMPLETE_REASON)
            result.add_check(
                name="Llamafile Embedded ZIP GGUF Polyglot Coverage",
                passed=False,
                message="Embedded ZIP GGUF member could not be fully probed for trailing polyglot payloads",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_GGUF_ZIP_MEMBER_INCOMPLETE_REASON,
                    "compressed_member": compressed_zip_gguf,
                    "max_scan_bytes": self.max_payload_scan_bytes,
                },
            )
        if gguf_candidate_scan_limited:
            self._mark_inconclusive(result, LLAMAFILE_GGUF_CANDIDATE_SCAN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Embedded Payload Candidate Coverage",
                passed=False,
                message="Embedded GGUF candidate count exceeded the bounded structural probe limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_GGUF_CANDIDATE_SCAN_LIMIT_REASON,
                    "max_candidates": LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES,
                    "max_header_candidates": LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES,
                    "max_payload_candidate_scans": LLAMAFILE_GGUF_MAX_PAYLOAD_CANDIDATE_SCANS,
                },
            )
        trusted_zip_boundary = (
            zip_payload is not None
            and zip_runtime_end is not None
            and mapped_executable_end is not None
            and zip_runtime_end >= mapped_executable_end
        )
        trusted_mapped_boundary = (
            gguf_offset is not None
            and gguf_offset in recognized_offsets
            and len(boundary_candidates) == 1
            and mapped_executable_end is not None
            and gguf_offset >= mapped_executable_end
            and (not is_ape_executable or mapping_search_complete)
        )
        payload_discovery_end = min(file_size, max(0, self.max_payload_scan_bytes))
        if (
            payload_discovery_end < file_size
            and gguf_candidates
            and zip_payload is None
            and not trusted_mapped_boundary
        ):
            self._mark_inconclusive(result, LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Embedded Payload Coverage",
                passed=False,
                message="Embedded payload discovery stopped at the bounded scan window",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON,
                    "max_scan_bytes": self.max_payload_scan_bytes,
                    "payload_bytes_omitted": file_size - payload_discovery_end,
                },
            )
        if gguf_offset is not None and torch7_offset is None:
            torch7_offset = self._find_embedded_torch7_offset(
                path_obj,
                self.max_payload_scan_bytes,
                start_offset=gguf_offset + len(GGUF_MARKER),
            )

        trusted_gguf_boundary = trusted_zip_boundary or trusted_mapped_boundary
        if gguf_offset is not None or zip_payload is not None:
            result.metadata["embedded_payload_boundary_trusted"] = trusted_gguf_boundary
        if trusted_zip_boundary:
            result.metadata["embedded_payload_boundary_source"] = "zip_member"
        elif trusted_mapped_boundary:
            result.metadata["embedded_payload_boundary_source"] = "executable_mapping"

        if trusted_zip_boundary and zip_runtime_end is not None:
            runtime_end = zip_runtime_end
        elif trusted_mapped_boundary and gguf_offset is not None:
            runtime_end = gguf_offset
        elif (
            len(boundary_candidates) > 1
            and mapped_executable_end is not None
            and (not is_ape_executable or mapping_search_complete)
        ):
            runtime_end = mapped_executable_end
            result.metadata["runtime_boundary_source"] = "executable_mapping"
        else:
            runtime_end = file_size
        runtime_scan_end = min(runtime_end, max(0, self.max_payload_scan_bytes))
        runtime_preview_blobs = [
            blob[: runtime_end - start]
            for start, blob in runtime_blobs
            if start < runtime_end and runtime_end - start > 0
        ]
        (
            runtime_stream_bytes,
            runtime_stream_error,
            runtime_string_scan_limited,
            runtime_string_candidate_limited,
            runtime_transfer_token_limited,
            runtime_transfer_option_ambiguous,
            runtime_interpreter_token_limited,
            runtime_utf16_ambiguous,
        ) = self._scan_runtime_strings_streaming(
            path_obj,
            runtime_scan_end,
            runtime_preview_blobs,
            result,
            include_preview_fallback=runtime_scan_end < runtime_end,
        )

        result.bytes_scanned = min(file_size, runtime_preview_bytes + runtime_stream_bytes + payload_bytes_scanned)
        if runtime_stream_error is not None or runtime_stream_bytes < runtime_scan_end:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_STREAM_READ_REASON)
            details: dict[str, Any] = {
                "analysis_incomplete": True,
                "scan_outcome_reason": LLAMAFILE_RUNTIME_STREAM_READ_REASON,
                "expected_runtime_bytes": runtime_scan_end,
                "runtime_bytes_scanned": runtime_stream_bytes,
            }
            if runtime_stream_error is not None:
                details["exception"] = str(runtime_stream_error)
                details["exception_type"] = type(runtime_stream_error).__name__
            result.add_check(
                name="Llamafile Runtime Stream Read",
                passed=False,
                message=(
                    f"Failed reading runtime stream bytes: {runtime_stream_error!s}"
                    if runtime_stream_error is not None
                    else "Runtime stream ended before the expected executable boundary"
                ),
                severity=IssueSeverity.INFO,
                location=path,
                details=details,
            )

        if runtime_string_scan_limited:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_STRING_SCAN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Runtime String Coverage",
                passed=False,
                message="Runtime printable string exceeded the bounded cross-chunk analysis window",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_STRING_SCAN_LIMIT_REASON,
                    "max_string_bytes": LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES,
                },
            )

        if runtime_string_candidate_limited:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_STRING_CANDIDATE_LIMIT_REASON)
            result.add_check(
                name="Llamafile Runtime String Candidate Coverage",
                passed=False,
                message="Runtime printable-string candidate count exceeded the bounded analysis limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_STRING_CANDIDATE_LIMIT_REASON,
                    "max_candidates": LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES,
                },
            )

        if runtime_transfer_token_limited:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_TRANSFER_TOKEN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Runtime Transfer Command Coverage",
                passed=False,
                message="Runtime transfer command exceeded the bounded token analysis limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_TRANSFER_TOKEN_LIMIT_REASON,
                    "max_tokens": LLAMAFILE_RUNTIME_MAX_TRANSFER_TOKENS,
                },
            )

        if runtime_transfer_option_ambiguous:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_TRANSFER_OPTION_AMBIGUOUS_REASON)
            result.add_check(
                name="Llamafile Runtime Transfer Option Analysis",
                passed=False,
                message="Runtime transfer command used an option with ambiguous argument arity",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_TRANSFER_OPTION_AMBIGUOUS_REASON,
                },
            )

        if runtime_interpreter_token_limited:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Runtime Interpreter Command Coverage",
                passed=False,
                message="Runtime interpreter command exceeded the bounded argument analysis limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_INTERPRETER_TOKEN_LIMIT_REASON,
                    "max_tokens": LLAMAFILE_RUNTIME_MAX_INTERPRETER_TOKENS,
                },
            )

        if runtime_utf16_ambiguous:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_UTF16_AMBIGUOUS_REASON)
            result.add_check(
                name="Llamafile Runtime UTF-16 Analysis",
                passed=False,
                message="Runtime bytes had conflicting UTF-16 byte-order interpretations",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_UTF16_AMBIGUOUS_REASON,
                },
            )

        if runtime_scan_end < runtime_end:
            self._mark_inconclusive(result, LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON)
            result.add_check(
                name="Llamafile Runtime Coverage",
                passed=False,
                message="Executable runtime extends beyond the bounded streaming scan window",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "analysis_incomplete": True,
                    "scan_outcome_reason": LLAMAFILE_RUNTIME_SCAN_LIMIT_REASON,
                    "max_scan_bytes": self.max_payload_scan_bytes,
                    "runtime_bytes_scanned": runtime_stream_bytes,
                    "runtime_bytes_total": runtime_end,
                    "runtime_bytes_omitted": runtime_end - runtime_scan_end,
                },
            )

        self._merge_polyglot_findings(path_obj, result, torch7_offset)

        result.finish(
            success=not result.has_errors and result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME
        )
        return result

    @staticmethod
    def _is_known_runtime_string(text: str, *, command_signal: bool | None = None) -> bool:
        """Return True if the string matches a known-safe llamafile runtime pattern."""
        lowered = text.lower()
        if lowered in LLAMAFILE_RUNTIME_SAFE_EXACT_LOWER:
            return True
        if command_signal is None:
            command_signal = _has_command_indicator(text)
        if command_signal:
            return False

        normalized = _strip_local_urls(lowered)
        normalized = SAFE_JSON_SCHEMA_URL_RE.sub("json-schema.org", normalized)

        for fragment in LLAMAFILE_RUNTIME_SAFE_FRAGMENT_LOWER:
            if fragment not in normalized:
                continue
            if fragment in {"%'18t connect", "%'18t socket"} and _has_remote_runtime_fragment(normalized):
                continue
            candidate = normalized.replace(fragment, "", 1)
            (
                _,
                has_residual_network,
                token_scan_limited,
                option_ambiguous,
                interpreter_token_scan_limited,
            ) = _runtime_text_signals(candidate)
            has_residual_network |= token_scan_limited or option_ambiguous or interpreter_token_scan_limited
            if not has_residual_network:
                return True
        return False

    @staticmethod
    def _add_bounded_runtime_evidence(hits: set[str], evidence: str) -> None:
        if len(hits) < LLAMAFILE_RUNTIME_MAX_EVIDENCE:
            hits.add(evidence)

    def _runtime_string_hits(
        self,
        blob: bytes,
        *,
        max_string_bytes: int | None = None,
        command_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        network_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        candidate_budget: int = LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES,
    ) -> tuple[set[str], set[str], bool, bool, bool, bool, bool, int, int, int, bool]:
        command_hits: set[str] = set()
        network_hits: set[str] = set()
        string_scan_limited = bool(
            max_string_bytes == LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES and OVERSIZED_PRINTABLE_TEXT_RE.search(blob)
        )
        candidate_scan_limited = False
        transfer_token_scan_limited = False
        transfer_option_ambiguous = False
        interpreter_token_scan_limited = False
        command_evidence_attempts = 0
        network_evidence_attempts = 0
        candidates_scanned = 0
        correlated_signal_seen = False
        lowered_blob = blob.lower()
        runtime_text = blob.decode("latin-1")
        has_transfer_hint = TRANSFER_COMMAND_WORD_RE.search(runtime_text) is not None
        interpreter_start, interpreter_hint_limited = _interpreter_command_analysis(runtime_text)
        has_command_signal = any(hint in lowered_blob for hint in COMMAND_HINTS) and (
            COMMAND_INDICATOR_RE.search(runtime_text) is not None
            or interpreter_start is not None
            or QUOTED_WRAPPER_COMMAND_RE.search(runtime_text) is not None
            or has_transfer_hint
        )
        normalized_runtime_text = _strip_local_urls(runtime_text)
        normalized_runtime_text_lower = normalized_runtime_text.lower()
        has_network_signal = (
            any(token in normalized_runtime_text_lower for token in NETWORK_TOKENS)
            or NETWORK_CODE_RE.search(normalized_runtime_text_lower) is not None
            or has_transfer_hint
            or _has_remote_runtime_fragment(runtime_text)
        )
        if not has_command_signal:
            command_evidence_budget = 0
        if not has_network_signal:
            network_evidence_budget = 0
        if (
            command_evidence_budget <= 0
            and network_evidence_budget <= 0
            and not (has_command_signal and has_network_signal)
            and not interpreter_hint_limited
        ):
            return set(), set(), string_scan_limited, candidate_scan_limited, False, False, False, 0, 0, 0, False

        for match in PRINTABLE_TEXT_RE.finditer(blob):
            if candidates_scanned >= candidate_budget:
                candidate_scan_limited = True
                break
            candidates_scanned += 1
            raw_text = match.group()
            if max_string_bytes is not None and len(raw_text) > max_string_bytes:
                string_scan_limited = True
                raw_text = raw_text[:max_string_bytes]
            text = raw_text.decode("utf-8", errors="ignore").strip()
            (
                has_command_token,
                has_network_token,
                token_scan_limited,
                option_ambiguous,
                interpreter_tokens_limited,
            ) = _runtime_text_signals(text)
            transfer_token_scan_limited |= token_scan_limited
            transfer_option_ambiguous |= option_ambiguous
            interpreter_token_scan_limited |= interpreter_tokens_limited
            if self._is_known_runtime_string(text, command_signal=has_command_token):
                continue
            correlated_signal_seen |= has_command_token and has_network_token
            if not has_command_token and not has_network_token:
                continue

            retain_command = has_command_token and command_evidence_attempts < command_evidence_budget
            retain_network = has_network_token and network_evidence_attempts < network_evidence_budget
            if not retain_command and not retain_network:
                continue
            command_evidence_attempts += int(retain_command)
            network_evidence_attempts += int(retain_network)
            redacted_text = _redacted_runtime_evidence(text)
            if retain_command:
                self._add_bounded_runtime_evidence(command_hits, redacted_text)
            if retain_network:
                self._add_bounded_runtime_evidence(network_hits, redacted_text)

        return (
            command_hits,
            network_hits,
            string_scan_limited,
            candidate_scan_limited,
            transfer_token_scan_limited,
            transfer_option_ambiguous,
            interpreter_token_scan_limited,
            command_evidence_attempts,
            network_evidence_attempts,
            candidates_scanned,
            correlated_signal_seen,
        )

    def _merge_runtime_string_hits(
        self,
        blob: bytes,
        command_hits: set[str],
        network_hits: set[str],
        *,
        max_string_bytes: int | None = None,
        command_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        network_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        candidate_budget: int = LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES,
    ) -> tuple[bool, bool, bool, bool, bool, int, int, int, bool]:
        (
            new_command_hits,
            new_network_hits,
            string_scan_limited,
            candidate_scan_limited,
            transfer_token_scan_limited,
            transfer_option_ambiguous,
            interpreter_token_scan_limited,
            command_attempts,
            network_attempts,
            candidates_scanned,
            correlated_signal_seen,
        ) = self._runtime_string_hits(
            blob,
            max_string_bytes=max_string_bytes,
            command_evidence_budget=command_evidence_budget,
            network_evidence_budget=network_evidence_budget,
            candidate_budget=candidate_budget,
        )
        for evidence in new_command_hits:
            self._add_bounded_runtime_evidence(command_hits, evidence)
        for evidence in new_network_hits:
            self._add_bounded_runtime_evidence(network_hits, evidence)
        return (
            string_scan_limited,
            candidate_scan_limited,
            transfer_token_scan_limited,
            transfer_option_ambiguous,
            interpreter_token_scan_limited,
            command_attempts,
            network_attempts,
            candidates_scanned,
            correlated_signal_seen,
        )

    def _merge_utf16_runtime_string_hits(
        self,
        blob: bytes,
        command_hits: set[str],
        network_hits: set[str],
        *,
        little_endian: bool | None = None,
        command_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        network_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        candidate_budget: int = LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES,
    ) -> tuple[bool, bool, bool, bool, bool, bool, int, int, int, bool]:
        string_scan_limited = False
        candidate_scan_limited = False
        transfer_token_scan_limited = False
        transfer_option_ambiguous = False
        interpreter_token_scan_limited = False
        utf16_ambiguity_state = [False]
        command_attempts = 0
        network_attempts = 0
        candidates_scanned = 0
        correlated_signal_seen = False
        for decoded in _iter_utf16_runtime_strings(
            blob,
            little_endian=little_endian,
            max_candidates=candidate_budget,
            ambiguity_state=utf16_ambiguity_state,
        ):
            if candidates_scanned >= candidate_budget:
                candidate_scan_limited = True
                return (
                    string_scan_limited,
                    candidate_scan_limited,
                    transfer_token_scan_limited,
                    transfer_option_ambiguous,
                    interpreter_token_scan_limited,
                    utf16_ambiguity_state[0],
                    command_attempts,
                    network_attempts,
                    candidates_scanned,
                    correlated_signal_seen,
                )
            (
                limited,
                candidates_limited,
                tokens_limited,
                option_ambiguous,
                interpreter_tokens_limited,
                new_command_attempts,
                new_network_attempts,
                _,
                correlated,
            ) = self._merge_runtime_string_hits(
                decoded,
                command_hits,
                network_hits,
                max_string_bytes=LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES,
                command_evidence_budget=max(0, command_evidence_budget - command_attempts),
                network_evidence_budget=max(0, network_evidence_budget - network_attempts),
                candidate_budget=1,
            )
            string_scan_limited |= limited
            candidate_scan_limited |= candidates_limited
            transfer_token_scan_limited |= tokens_limited
            transfer_option_ambiguous |= option_ambiguous
            interpreter_token_scan_limited |= interpreter_tokens_limited
            command_attempts += new_command_attempts
            network_attempts += new_network_attempts
            candidates_scanned += 1
            correlated_signal_seen |= correlated
        return (
            string_scan_limited,
            candidate_scan_limited,
            transfer_token_scan_limited,
            transfer_option_ambiguous,
            interpreter_token_scan_limited,
            utf16_ambiguity_state[0],
            command_attempts,
            network_attempts,
            candidates_scanned,
            correlated_signal_seen,
        )

    def _merge_oversized_runtime_command_hits(
        self,
        blob: bytes,
        command_hits: set[str],
        network_hits: set[str],
        *,
        command_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
        network_evidence_budget: int = LLAMAFILE_RUNTIME_MAX_EVIDENCE,
    ) -> tuple[int, int, bool]:
        """Retain command evidence even when a printable run exceeds the bounded carry."""
        lowered_blob = blob.lower()
        if not any(hint in lowered_blob for hint in COMMAND_HINTS):
            return 0, 0, False
        command_evidence_attempts = 0
        network_evidence_attempts = 0
        correlated_signal_seen = False
        for match in PRINTABLE_TEXT_RE.finditer(blob):
            text = match.group().decode("utf-8", errors="ignore").strip()
            has_command_token, has_network_token, _, _, _ = _runtime_text_signals(text)
            if self._is_known_runtime_string(text, command_signal=has_command_token):
                continue
            if not has_command_token:
                continue

            retain_command = (
                len(command_hits) < LLAMAFILE_RUNTIME_MAX_EVIDENCE
                and command_evidence_attempts < command_evidence_budget
            )
            correlated_signal_seen |= has_network_token
            retain_network = (
                has_network_token
                and len(network_hits) < LLAMAFILE_RUNTIME_MAX_EVIDENCE
                and network_evidence_attempts < network_evidence_budget
            )
            if not retain_command and not retain_network:
                continue
            command_evidence_attempts += int(retain_command)
            network_evidence_attempts += int(retain_network)
            redacted_text = _redacted_runtime_evidence(text)
            if retain_command:
                self._add_bounded_runtime_evidence(command_hits, redacted_text)
            if retain_network:
                self._add_bounded_runtime_evidence(network_hits, redacted_text)
        return command_evidence_attempts, network_evidence_attempts, correlated_signal_seen

    @staticmethod
    def _add_runtime_string_analysis(
        path: str,
        result: ScanResult,
        command_hits: set[str],
        network_hits: set[str],
        correlated_signal_seen: bool,
    ) -> None:
        if not command_hits and not network_hits:
            return

        correlated_hits = command_hits.intersection(network_hits)
        if correlated_signal_seen:
            severity = IssueSeverity.CRITICAL
            message = "Executable runtime contains command execution and network indicators"
        elif command_hits:
            severity = IssueSeverity.WARNING
            message = "Executable runtime contains command execution indicators"
        else:
            severity = IssueSeverity.INFO
            message = "Executable runtime contains network indicators"

        result.add_check(
            name="Llamafile Runtime String Analysis",
            passed=False,
            message=message,
            severity=severity,
            location=path,
            details={
                "command_evidence": sorted(command_hits)[:5],
                "network_evidence": sorted(network_hits)[:5],
                "correlated_evidence": sorted(correlated_hits)[:5],
            },
        )

    def _scan_runtime_strings(self, path: str, blob: bytes, result: ScanResult) -> None:
        (
            command_hits,
            network_hits,
            _,
            _,
            _,
            _,
            _,
            command_attempts,
            network_attempts,
            candidates_scanned,
            correlated_signal_seen,
        ) = self._runtime_string_hits(blob)
        _, _, _, _, _, _, _, _, _, utf16_correlated = self._merge_utf16_runtime_string_hits(
            blob,
            command_hits,
            network_hits,
            command_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - command_attempts),
            network_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - network_attempts),
            candidate_budget=max(0, LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES - candidates_scanned),
        )
        correlated_signal_seen |= utf16_correlated
        self._add_runtime_string_analysis(path, result, command_hits, network_hits, correlated_signal_seen)

    def _scan_runtime_strings_streaming(
        self,
        path: Path,
        end_offset: int,
        preview_blobs: list[bytes],
        result: ScanResult,
        *,
        include_preview_fallback: bool,
    ) -> tuple[int, OSError | None, bool, bool, bool, bool, bool, bool]:
        command_hits: set[str] = set()
        network_hits: set[str] = set()
        scanned = 0
        carry = b""
        utf16_carry = b""
        utf16_context = b""
        read_error: OSError | None = None
        string_scan_limited = False
        candidate_scan_limited = False
        transfer_token_scan_limited = False
        transfer_option_ambiguous = False
        interpreter_token_scan_limited = False
        utf16_ambiguous = False
        command_evidence_attempts = 0
        network_evidence_attempts = 0
        runtime_string_candidates = 0
        correlated_signal_seen = False

        def merge_blob(blob: bytes) -> bool:
            nonlocal candidate_scan_limited
            nonlocal command_evidence_attempts
            nonlocal correlated_signal_seen
            nonlocal network_evidence_attempts
            nonlocal runtime_string_candidates
            nonlocal interpreter_token_scan_limited
            nonlocal transfer_option_ambiguous
            nonlocal transfer_token_scan_limited
            (
                limited,
                candidates_limited,
                tokens_limited,
                option_ambiguous,
                interpreter_tokens_limited,
                command_attempts,
                network_attempts,
                candidates_scanned,
                correlated,
            ) = self._merge_runtime_string_hits(
                blob,
                command_hits,
                network_hits,
                max_string_bytes=LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES,
                command_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - command_evidence_attempts),
                network_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - network_evidence_attempts),
                candidate_budget=max(
                    0,
                    LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES - runtime_string_candidates,
                ),
            )
            command_evidence_attempts += command_attempts
            network_evidence_attempts += network_attempts
            runtime_string_candidates += candidates_scanned
            correlated_signal_seen |= correlated
            candidate_scan_limited |= candidates_limited
            transfer_token_scan_limited |= tokens_limited
            transfer_option_ambiguous |= option_ambiguous
            interpreter_token_scan_limited |= interpreter_tokens_limited
            if limited and OVERSIZED_PRINTABLE_TEXT_RE.search(blob):
                command_attempts, network_attempts, correlated = self._merge_oversized_runtime_command_hits(
                    blob,
                    command_hits,
                    network_hits,
                    command_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - command_evidence_attempts),
                    network_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - network_evidence_attempts),
                )
                command_evidence_attempts += command_attempts
                network_evidence_attempts += network_attempts
                correlated_signal_seen |= correlated
            return limited

        def merge_utf16_blob(blob: bytes, *, continue_stream: bool = False) -> bool:
            nonlocal candidate_scan_limited
            nonlocal command_evidence_attempts
            nonlocal correlated_signal_seen
            nonlocal network_evidence_attempts
            nonlocal runtime_string_candidates
            nonlocal interpreter_token_scan_limited
            nonlocal transfer_option_ambiguous
            nonlocal transfer_token_scan_limited
            nonlocal utf16_ambiguous
            nonlocal utf16_context
            analysis_blob = utf16_context + blob if continue_stream else blob
            if continue_stream and blob:
                utf16_context = analysis_blob[-64:]
            (
                limited,
                candidates_limited,
                tokens_limited,
                option_ambiguous,
                interpreter_tokens_limited,
                decoded_ambiguous,
                command_attempts,
                network_attempts,
                candidates_scanned,
                correlated,
            ) = self._merge_utf16_runtime_string_hits(
                analysis_blob,
                command_hits,
                network_hits,
                command_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - command_evidence_attempts),
                network_evidence_budget=max(0, LLAMAFILE_RUNTIME_MAX_EVIDENCE - network_evidence_attempts),
                candidate_budget=max(
                    0,
                    LLAMAFILE_RUNTIME_MAX_STRING_CANDIDATES - runtime_string_candidates,
                ),
            )
            command_evidence_attempts += command_attempts
            network_evidence_attempts += network_attempts
            runtime_string_candidates += candidates_scanned
            correlated_signal_seen |= correlated
            candidate_scan_limited |= candidates_limited
            transfer_token_scan_limited |= tokens_limited
            transfer_option_ambiguous |= option_ambiguous
            interpreter_token_scan_limited |= interpreter_tokens_limited
            utf16_ambiguous |= decoded_ambiguous
            return limited

        try:
            with path.open("rb") as handle:
                while scanned < end_offset:
                    chunk = handle.read(min(LLAMAFILE_RUNTIME_STREAM_CHUNK_BYTES, end_offset - scanned))
                    if not chunk:
                        break

                    scanned += len(chunk)
                    combined = carry + chunk
                    if scanned >= end_offset:
                        complete = combined
                        carry = b""
                    else:
                        trailing_start = len(combined.rstrip(PRINTABLE_BYTES))
                        complete = combined[:trailing_start]
                        carry = combined[trailing_start:]

                    string_scan_limited |= merge_blob(complete)
                    utf16_combined = utf16_carry + chunk
                    if scanned >= end_offset:
                        utf16_complete = utf16_combined
                        utf16_carry = b""
                    else:
                        utf16_trailing_start = min(
                            _utf16_printable_suffix_start(utf16_combined, little_endian=True),
                            _utf16_printable_suffix_start(utf16_combined, little_endian=False),
                        )
                        utf16_complete = utf16_combined[:utf16_trailing_start]
                        utf16_carry = utf16_combined[utf16_trailing_start:]
                    string_scan_limited |= merge_utf16_blob(utf16_complete, continue_stream=True)
                    max_utf16_carry = 2 * LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES
                    if len(utf16_carry) > max_utf16_carry:
                        string_scan_limited = True
                        overflow = len(utf16_carry) - max_utf16_carry
                        probe_end = min(len(utf16_carry), overflow + 8192)
                        probe_end -= probe_end % 2
                        string_scan_limited |= merge_utf16_blob(utf16_carry[:probe_end])
                        retain_start = max(0, probe_end - 8192)
                        retain_start -= retain_start % 2
                        utf16_carry = utf16_carry[retain_start:]
                    if len(carry) > LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES:
                        string_scan_limited = True
                        overflow = len(carry) - LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES
                        probe_end = min(len(carry), overflow + 4096)
                        command_attempts, network_attempts, correlated = self._merge_oversized_runtime_command_hits(
                            carry[:probe_end],
                            command_hits,
                            network_hits,
                            command_evidence_budget=max(
                                0,
                                LLAMAFILE_RUNTIME_MAX_EVIDENCE - command_evidence_attempts,
                            ),
                            network_evidence_budget=max(
                                0,
                                LLAMAFILE_RUNTIME_MAX_EVIDENCE - network_evidence_attempts,
                            ),
                        )
                        command_evidence_attempts += command_attempts
                        network_evidence_attempts += network_attempts
                        correlated_signal_seen |= correlated
                        carry = carry[-LLAMAFILE_RUNTIME_STREAM_MAX_STRING_BYTES:]
        except OSError as exc:
            read_error = exc

        if carry:
            string_scan_limited |= merge_blob(carry)
        if utf16_carry:
            string_scan_limited |= merge_utf16_blob(utf16_carry, continue_stream=True)

        if include_preview_fallback or read_error is not None or scanned < end_offset:
            for blob in preview_blobs:
                string_scan_limited |= merge_blob(blob)
                string_scan_limited |= merge_utf16_blob(blob)

        self._add_runtime_string_analysis(
            str(path),
            result,
            command_hits,
            network_hits,
            correlated_signal_seen,
        )
        return (
            scanned,
            read_error,
            string_scan_limited,
            candidate_scan_limited,
            transfer_token_scan_limited,
            transfer_option_ambiguous,
            interpreter_token_scan_limited,
            utf16_ambiguous,
        )

    def _scan_embedded_payload(
        self,
        path: Path,
        result: ScanResult,
        gguf_offset: int | None,
        *,
        payload_size: int | None = None,
    ) -> tuple[int, bool]:
        if gguf_offset is None:
            file_size = self.get_file_size(str(path))
            details = {"max_scan_bytes": self.max_payload_scan_bytes}
            if file_size > self.max_payload_scan_bytes:
                self._mark_inconclusive(result, LLAMAFILE_PAYLOAD_SCAN_LIMIT_REASON)
                details["analysis_incomplete"] = True
                details["file_size"] = file_size
            result.add_check(
                name="Llamafile Embedded Payload Detection",
                passed=False,
                message=(
                    "No embedded GGUF payload marker found before bounded scan window ended"
                    if file_size > self.max_payload_scan_bytes
                    else "No embedded GGUF payload marker found within bounded scan window"
                ),
                severity=IssueSeverity.INFO,
                location=str(path),
                details=details,
            )
            return 0, False

        file_size = self.get_file_size(str(path))
        payload_available = max(0, file_size - gguf_offset)
        if payload_size is not None:
            payload_available = min(payload_available, payload_size)
        carve_size = min(payload_available, self.max_payload_carve_bytes)

        result.metadata["embedded_payload_offset"] = gguf_offset
        result.metadata["embedded_payload_size"] = carve_size

        result.add_check(
            name="Llamafile Embedded Payload Detection",
            passed=False,
            message="Embedded GGUF payload marker detected",
            severity=IssueSeverity.INFO,
            location=f"{path} (llamafile:{gguf_offset})",
            details={"offset": gguf_offset, "carve_size": carve_size},
        )

        # Large binaries should not place model payload immediately in the prologue.
        if gguf_offset < 4096 and file_size > 1024 * 1024:
            result.add_check(
                name="Llamafile Section Layout Check",
                passed=False,
                message="Embedded GGUF payload appears unusually early in binary layout",
                severity=IssueSeverity.WARNING,
                location=f"{path} (llamafile:{gguf_offset})",
                details={"offset": gguf_offset},
            )

        if carve_size < 24:
            result.add_check(
                name="Llamafile Embedded Payload Integrity",
                passed=False,
                message="Embedded GGUF payload pointer appears truncated",
                severity=IssueSeverity.WARNING,
                location=f"{path} (llamafile:{gguf_offset})",
                details={"offset": gguf_offset, "available_bytes": payload_available},
            )
            return 0, False

        carved_path = self._carve_payload(path, gguf_offset, carve_size)
        if carved_path is None:
            result.add_check(
                name="Llamafile Embedded Payload Carve",
                passed=False,
                message="Failed to carve embedded GGUF payload",
                severity=IssueSeverity.CRITICAL,
                location=f"{path} (llamafile:{gguf_offset})",
            )
            return 0, False

        try:
            from modelaudit.scanners.gguf_scanner import (
                GGUF_PARSE_INCONCLUSIVE_REASON,
                GGUF_STRUCTURE_INCONCLUSIVE_REASON,
                GgufScanner,
            )

            if not GgufScanner.can_handle(str(carved_path)):
                result.add_check(
                    name="Llamafile Embedded Payload Integrity",
                    passed=False,
                    message="Carved embedded payload did not validate as GGUF",
                    severity=IssueSeverity.WARNING,
                    location=f"{path} (llamafile:{gguf_offset})",
                )
                return carve_size, False

            embedded_result = GgufScanner(config=self.config).scan(str(carved_path))
            self._append_embedded_findings(result, embedded_result, gguf_offset)
            outcome_reasons = embedded_result.metadata.get("scan_outcome_reasons", [])
            invalid_structure_reasons = {GGUF_PARSE_INCONCLUSIVE_REASON, GGUF_STRUCTURE_INCONCLUSIVE_REASON}
            recognized = isinstance(outcome_reasons, list) and not invalid_structure_reasons.intersection(
                outcome_reasons
            )
            return carve_size, recognized
        finally:
            carved_path.unlink(missing_ok=True)

    def _append_embedded_findings(self, result: ScanResult, embedded: ScanResult, offset: int) -> None:
        for check in embedded.checks:
            prefixed_location = f"llamafile:{offset}"
            if check.location:
                prefixed_location = f"{prefixed_location} -> {check.location}"

            details = dict(check.details)
            details["embedded_offset"] = offset
            details["embedded_scanner"] = embedded.scanner_name

            result.add_check(
                name=f"Llamafile Embedded {check.name}",
                passed=check.status == CheckStatus.PASSED,
                message=check.message,
                severity=check.severity,
                location=prefixed_location,
                details=details,
                why=check.why,
            )

        result.metadata["embedded_gguf_metadata"] = dict(embedded.metadata)
        if embedded.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME or (
            not embedded.success and not embedded.has_errors
        ):
            self._mark_inconclusive(result, LLAMAFILE_GGUF_ANALYSIS_INCOMPLETE_REASON)

    @staticmethod
    def _mark_inconclusive(result: ScanResult, reason: str) -> None:
        """Mark Llamafile analysis coverage as explicitly incomplete."""
        result.metadata["analysis_incomplete"] = True
        result.metadata["scan_outcome"] = INCONCLUSIVE_SCAN_OUTCOME

        reasons = result.metadata.get("scan_outcome_reasons")
        if not isinstance(reasons, list):
            reasons = []
            result.metadata["scan_outcome_reasons"] = reasons
        if reason not in reasons:
            reasons.append(reason)

    def _merge_polyglot_findings(self, path: Path, result: ScanResult, torch7_offset: int | None) -> None:
        """Preserve trusted secondary-format coverage for executable polyglots."""
        if torch7_offset is not None:
            self._merge_torch7_findings(path, result, torch7_offset)

        merge_executable_zip_container_findings(
            str(path),
            result,
            self.config,
            context="embedded executable ZIP polyglot",
        )

    def _merge_torch7_findings(self, path: Path, result: ScanResult, offset: int) -> None:
        scanner_selection = policy_from_config(self.config)
        if not scanner_selection.allows("torch7"):
            add_scanner_selection_skip_check(
                result,
                str(path),
                "torch7",
                scanner_selection,
                context="embedded Llamafile/Torch7 polyglot analysis",
            )
            return

        from .torch7_scanner import Torch7Scanner

        scanner = Torch7Scanner(config=self.config)
        actionable_results: list[tuple[ScanResult, int, int, IssueSeverity]] = []
        actionable_keys: set[tuple[str, str, str, str, str]] = set()
        best_actionable_rank = 0
        deferred_incomplete: tuple[ScanResult, int, int] | None = None
        non_actionable_scans = 0
        actionable_scans = 0
        best_scanned_signal_rank = 0
        actionable_scan_limited = False

        for next_offset in self._iter_embedded_torch7_offsets(
            path,
            self.max_payload_scan_bytes,
            start_offset=offset,
            signal_scan_bytes=scanner.max_scan_bytes,
        ):
            structurally_credible = self._embedded_torch7_candidate_is_structural(path, next_offset)
            has_binary_payload = self._embedded_torch7_candidate_has_binary_payload_bytes(path, next_offset)
            actionable_signal_rank = self._embedded_torch7_candidate_actionable_signal_rank(
                path, next_offset, scanner.max_scan_bytes
            )
            has_actionable_signal = actionable_signal_rank > 0
            if not (structurally_credible or has_binary_payload or has_actionable_signal):
                continue
            if non_actionable_scans >= self.max_torch7_candidate_scans and not has_actionable_signal:
                continue
            if (
                has_actionable_signal
                and actionable_scans >= self.max_torch7_candidate_scans
                and actionable_signal_rank <= best_scanned_signal_rank
            ):
                actionable_scan_limited = True
                continue

            if has_actionable_signal:
                actionable_scans += 1
                best_scanned_signal_rank = max(best_scanned_signal_rank, actionable_signal_rank)

            embedded_result, carve_size = self._scan_embedded_torch7_candidate(path, scanner, result, next_offset)
            if embedded_result is not None:
                actionable_severity = self._torch7_result_actionable_severity(embedded_result)
                if actionable_severity is not None:
                    actionable_rank = self._torch7_severity_rank(actionable_severity)
                    if actionable_rank > best_actionable_rank:
                        actionable_results = []
                        actionable_keys.clear()
                        best_actionable_rank = actionable_rank
                    if actionable_rank == best_actionable_rank:
                        candidate_keys = self._torch7_actionable_finding_keys(embedded_result)
                        if not candidate_keys or not candidate_keys.issubset(actionable_keys):
                            actionable_results.append((embedded_result, next_offset, carve_size, actionable_severity))
                            actionable_keys.update(candidate_keys)
                else:
                    non_actionable_scans += 1
                if (
                    deferred_incomplete is None
                    and structurally_credible
                    and self._torch7_result_is_incomplete(embedded_result)
                ):
                    deferred_incomplete = (embedded_result, next_offset, carve_size)

        if actionable_results:
            _, actionable_offset, carve_size, _ = actionable_results[0]
            result.metadata["embedded_torch7_offset"] = actionable_offset
            result.metadata["embedded_torch7_size"] = carve_size
            result.metadata["embedded_torch7_candidates"] = [
                {"offset": candidate_offset, "size": candidate_size, "severity": severity.value}
                for _, candidate_offset, candidate_size, severity in actionable_results
            ]
            if actionable_scan_limited:
                result.metadata["embedded_torch7_candidate_scan_limited"] = True
                result.metadata["embedded_torch7_actionable_candidate_scans"] = actionable_scans
            for embedded_result, candidate_offset, _, _ in actionable_results:
                self._append_torch7_findings(result, embedded_result, candidate_offset)
            return

        if deferred_incomplete is not None:
            embedded_result, incomplete_offset, carve_size = deferred_incomplete
            result.metadata["embedded_torch7_offset"] = incomplete_offset
            result.metadata["embedded_torch7_size"] = carve_size
            if actionable_scan_limited:
                result.metadata["embedded_torch7_candidate_scan_limited"] = True
                result.metadata["embedded_torch7_actionable_candidate_scans"] = actionable_scans
            self._append_torch7_findings(result, embedded_result, incomplete_offset)
        elif actionable_scan_limited:
            result.metadata["embedded_torch7_candidate_scan_limited"] = True
            result.metadata["embedded_torch7_actionable_candidate_scans"] = actionable_scans

    @staticmethod
    def _embedded_torch7_candidate_is_structural(path: Path, offset: int) -> bool:
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                prefix = handle.read(TORCH7_SIGNATURE_WINDOW_BYTES)
        except OSError:
            return False
        return find_structural_torch7_offset(prefix) == 0

    @staticmethod
    def _embedded_torch7_candidate_has_binary_payload_bytes(path: Path, offset: int) -> bool:
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                prefix = handle.read(TORCH7_SIGNATURE_WINDOW_BYTES)
        except OSError:
            return False
        return LlamafileScanner._torch7_prefix_has_binary_payload_bytes(prefix)

    @staticmethod
    def _torch7_prefix_has_binary_payload_bytes(prefix: bytes) -> bool:
        if len(prefix) < 8 or not prefix.startswith(b"T7\x00\x00"):
            return False
        next_marker = prefix.find(TORCH7_BINARY_MARKER, len(TORCH7_BINARY_MARKER))
        window_end = 256 if next_marker == -1 else next_marker
        window = prefix[len(TORCH7_BINARY_MARKER) : window_end]
        return any(byte not in b"\t\n\r" + bytes(range(0x20, 0x7F)) for byte in window)

    @staticmethod
    def _torch7_has_suspicious_require(window: bytes) -> bool:
        for quoted_paren, _, long_paren, quoted_bare, _, long_bare in TORCH7_REQUIRE_BYTES_RE.findall(window):
            for module in (quoted_paren, long_paren, quoted_bare, long_bare):
                if not module:
                    continue
                normalized_module = module.strip().lower()
                if normalized_module not in TORCH7_SAFE_REQUIRE_MODULES and not normalized_module.startswith(b"torch."):
                    return True
        return False

    @classmethod
    def _torch7_actionable_signal_rank(cls, window: bytes) -> int:
        rank = 0
        strings = TORCH7_PRINTABLE_TEXT_RE.findall(window)
        for index, text in enumerate(strings):
            if TORCH7_EXEC_PRIMITIVE_BYTES_RE.search(text) is None:
                continue
            rank = 1
            window_start = max(0, index - 1)
            window_end = min(len(strings), index + 2)
            context_window = b" ".join(strings[window_start:window_end])
            if TORCH7_NETWORK_OR_SHELL_BYTES_RE.search(context_window) is not None:
                return 2
        if TORCH7_DYNAMIC_LOAD_BYTES_RE.search(window) is not None or cls._torch7_has_suspicious_require(window):
            rank = max(rank, 1)
        return rank

    @classmethod
    def _embedded_torch7_candidate_actionable_signal_rank(
        cls,
        path: Path,
        offset: int,
        max_scan_bytes: int,
        *,
        stop_at_any_marker: bool = False,
    ) -> int:
        best_rank = 0
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                remaining = max_scan_bytes
                carry = b""
                first_chunk = True
                while remaining > 0:
                    chunk = handle.read(min(TORCH7_ACTIONABLE_SIGNAL_CHUNK_BYTES, remaining))
                    if not chunk:
                        return best_rank

                    haystack = carry + chunk
                    marker_search_start = len(carry) + (len(TORCH7_BINARY_MARKER) if first_chunk else 0)
                    next_marker = (
                        haystack.find(TORCH7_BINARY_MARKER, marker_search_start)
                        if stop_at_any_marker
                        else cls._find_structural_torch7_boundary(haystack, marker_search_start)
                    )
                    signal_window = haystack if next_marker == -1 else haystack[:next_marker]
                    best_rank = max(best_rank, cls._torch7_actionable_signal_rank(signal_window))
                    if best_rank == 2:
                        return 2
                    if next_marker != -1:
                        return best_rank

                    carry = haystack[-TORCH7_ACTIONABLE_SIGNAL_CARRY_BYTES:]
                    remaining -= len(chunk)
                    first_chunk = False
        except OSError:
            return 0
        return best_rank

    @staticmethod
    def _torch7_ascii_candidate_is_structural(candidate_window: bytes) -> bool:
        fields: list[bytes] = []
        position = 0
        while len(fields) < 6 and position < len(candidate_window):
            line_limit = min(len(candidate_window), position + TORCH7_SIGNATURE_WINDOW_BYTES + 1)
            newline = candidate_window.find(b"\n", position, line_limit)
            carriage_return = candidate_window.find(b"\r", position, line_limit)
            line_end_candidates = [index for index in (newline, carriage_return) if index != -1]
            if not line_end_candidates:
                if line_limit < len(candidate_window):
                    return False
                fields.append(candidate_window[position:line_limit])
                break

            line_end = min(line_end_candidates)
            fields.append(candidate_window[position:line_end])
            position = line_end + 2 if candidate_window[line_end : line_end + 2] == b"\r\n" else line_end + 1

        if len(fields) < 6:
            return False
        try:
            object_index = int(fields[1])
            version_length = int(fields[2])
            class_name_length = int(fields[4])
        except ValueError:
            return False

        version = fields[3]
        class_name = fields[5]
        return (
            object_index > 0
            and version_length == len(version)
            and class_name_length == len(class_name)
            and re.fullmatch(rb"V [+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", version) is not None
            and class_name.startswith((b"torch.", b"nn.", b"cunn.", b"cutorch."))
        )

    @classmethod
    def _find_structural_torch7_boundary(cls, haystack: bytes, search_start: int) -> int:
        marker_offset = haystack.find(TORCH7_BINARY_MARKER, search_start)
        while marker_offset != -1:
            candidate_window = haystack[marker_offset : marker_offset + TORCH7_SIGNATURE_WINDOW_BYTES]
            if find_structural_torch7_offset(candidate_window) == 0:
                return marker_offset
            marker_offset = haystack.find(TORCH7_BINARY_MARKER, marker_offset + 1)

        ascii_window = haystack[search_start:]
        for match in re.finditer(rb"4(?:\r\n|[\r\n])", ascii_window):
            candidate_offset = search_start + match.start()
            candidate_window = haystack[candidate_offset : candidate_offset + TORCH7_SIGNATURE_WINDOW_BYTES]
            if cls._torch7_ascii_candidate_is_structural(candidate_window):
                return candidate_offset

        return -1

    @classmethod
    def _embedded_torch7_candidate_has_actionable_signal(cls, path: Path, offset: int, max_scan_bytes: int) -> bool:
        return cls._embedded_torch7_candidate_actionable_signal_rank(path, offset, max_scan_bytes) > 0

    def _scan_embedded_torch7_candidate(
        self,
        path: Path,
        scanner: Any,
        result: ScanResult,
        offset: int,
    ) -> tuple[ScanResult | None, int]:
        payload_available = max(0, self.get_file_size(str(path)) - offset)
        carve_size = min(payload_available, scanner.max_scan_bytes + 1)
        carved_path = self._carve_payload(path, offset, carve_size, suffix=".t7")
        if carved_path is None:
            result.metadata["embedded_torch7_offset"] = offset
            result.metadata["embedded_torch7_size"] = carve_size
            self._mark_inconclusive(result, LLAMAFILE_TORCH7_CARVE_FAILURE_REASON)
            result.add_check(
                name="Llamafile Embedded Torch7 Payload Carve",
                passed=False,
                message="Failed to carve embedded Torch7 payload",
                severity=IssueSeverity.CRITICAL,
                location=f"{path} (llamafile:{offset})",
            )
            return None, carve_size

        try:
            if not scanner.can_handle(str(carved_path)):
                return None, carve_size

            return scanner.scan(str(carved_path)), carve_size
        finally:
            carved_path.unlink(missing_ok=True)

    @staticmethod
    def _torch7_result_actionable_severity(result: ScanResult) -> IssueSeverity | None:
        severities = [
            check.severity
            for check in result.checks
            if check.status == CheckStatus.FAILED and check.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        ]
        severities.extend(
            issue.severity
            for issue in result.issues
            if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        )
        if IssueSeverity.CRITICAL in severities:
            return IssueSeverity.CRITICAL
        if IssueSeverity.WARNING in severities:
            return IssueSeverity.WARNING
        return None

    @staticmethod
    def _torch7_severity_rank(severity: IssueSeverity) -> int:
        return 2 if severity == IssueSeverity.CRITICAL else 1

    @staticmethod
    def _torch7_actionable_finding_keys(result: ScanResult) -> set[tuple[str, str, str, str, str]]:
        keys: set[tuple[str, str, str, str, str]] = set()
        for check in result.checks:
            if check.status == CheckStatus.FAILED and check.severity in {
                IssueSeverity.WARNING,
                IssueSeverity.CRITICAL,
            }:
                examples = check.details.get("examples", "")
                keys.add(
                    (
                        "check",
                        check.name,
                        check.severity.value,
                        str(check.details.get("signal", "")),
                        repr(examples),
                    )
                )
        for issue in result.issues:
            if issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL}:
                examples = issue.details.get("examples", "")
                keys.add(
                    (
                        "issue",
                        issue.message,
                        issue.severity.value,
                        str(issue.details.get("signal", "")),
                        repr(examples),
                    )
                )
        return keys

    @staticmethod
    def _torch7_result_is_incomplete(result: ScanResult) -> bool:
        return result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME or (
            not result.success and not result.has_errors
        )

    def _append_torch7_findings(self, result: ScanResult, embedded: ScanResult, offset: int) -> None:
        embedded_location = f"{self.current_file_path} (llamafile:{offset})"
        for check in embedded.checks:
            check.location = embedded_location
            check.details = {
                **check.details,
                "embedded_offset": offset,
                "embedded_scanner": embedded.scanner_name,
            }
        for issue in embedded.issues:
            issue.location = embedded_location
            issue.details = {
                **issue.details,
                "embedded_offset": offset,
                "embedded_scanner": embedded.scanner_name,
            }

        result.checks.extend(embedded.checks)
        result.issues.extend(embedded.issues)
        result.bytes_scanned += embedded.bytes_scanned
        result.metadata["embedded_torch7_metadata"] = dict(embedded.metadata)
        if embedded.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME or (
            not embedded.success and not embedded.has_errors
        ):
            self._mark_inconclusive(result, LLAMAFILE_TORCH7_ANALYSIS_INCOMPLETE_REASON)

    def _carve_payload(self, path: Path, offset: int, size: int, suffix: str = ".gguf") -> Path | None:
        try:
            with tempfile.NamedTemporaryFile(prefix="llamafile-payload-", suffix=suffix, delete=False) as handle:
                carved_path = Path(handle.name)
                with path.open("rb") as source:
                    source.seek(offset)
                    remaining = size
                    while remaining > 0:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        handle.write(chunk)
                        remaining -= len(chunk)
            return carved_path
        except OSError:
            return None

    @classmethod
    def _find_embedded_payload_offsets(
        cls,
        path: Path,
        max_scan_bytes: int,
        *,
        stop_at_gguf: bool = True,
        gguf_min_offset: int = 0,
    ) -> tuple[list[int], int | None, bool, bool, bool]:
        """Find GGUF and Torch7 payload signatures in one bounded pass."""
        file_size = path.stat().st_size
        search_limit = min(file_size, max_scan_bytes)
        overlap = max(len(GGUF_MARKER) - 1, TORCH7_SIGNATURE_WINDOW_BYTES - 1)
        scanned = 0
        carry = b""
        gguf_offsets: list[int] = []
        torch7_offset: int | None = None
        last_gguf_candidate = -1
        gguf_candidates_checked = 0
        gguf_header_limit_exceeded = False
        gguf_header_incomplete = False

        with path.open("rb") as handle:
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk
                window_offset = scanned - len(carry)
                gguf_relative_index = -1
                if not stop_at_gguf or not gguf_offsets:
                    search_from = max(0, gguf_min_offset - window_offset)
                    while gguf_candidates_checked < LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES:
                        candidate_index = haystack.find(GGUF_MARKER, search_from)
                        if candidate_index == -1:
                            break
                        search_from = candidate_index + len(GGUF_MARKER)
                        candidate_offset = window_offset + candidate_index
                        if candidate_offset <= last_gguf_candidate:
                            continue
                        last_gguf_candidate = candidate_offset
                        gguf_candidates_checked += 1
                        plausible, resource_limit_exceeded, header_incomplete = cls._probe_gguf_header(
                            handle,
                            candidate_offset,
                            file_size,
                        )
                        gguf_header_limit_exceeded |= resource_limit_exceeded
                        gguf_header_incomplete |= header_incomplete
                        if not plausible:
                            continue
                        gguf_offsets.append(candidate_offset)
                        gguf_relative_index = candidate_index
                        if stop_at_gguf:
                            break

                if torch7_offset is None:
                    torch7_relative_index = find_torch7_candidate_offset(haystack)
                    if torch7_relative_index is not None:
                        torch7_offset = window_offset + torch7_relative_index

                if stop_at_gguf and gguf_relative_index != -1:
                    return (
                        gguf_offsets,
                        torch7_offset,
                        False,
                        gguf_header_limit_exceeded,
                        gguf_header_incomplete,
                    )

                carry = haystack[-overlap:] if overlap > 0 else b""
                scanned += len(chunk)
                handle.seek(scanned)

        return (
            gguf_offsets,
            torch7_offset,
            gguf_candidates_checked >= LLAMAFILE_GGUF_MAX_HEADER_CANDIDATES,
            gguf_header_limit_exceeded,
            gguf_header_incomplete,
        )

    @classmethod
    def _iter_embedded_torch7_offsets(
        cls,
        path: Path,
        max_scan_bytes: int,
        *,
        start_offset: int = 0,
        signal_scan_bytes: int | None = None,
    ) -> Iterator[int]:
        """Yield Torch7 candidate offsets in one bounded pass."""
        file_size = path.stat().st_size
        search_limit = min(file_size, max_scan_bytes)
        if start_offset >= search_limit:
            return

        overlap = TORCH7_SIGNATURE_WINDOW_BYTES - 1
        scanned = start_offset
        carry = b""
        last_yielded = start_offset - 1

        with path.open("rb") as handle:
            handle.seek(start_offset)
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk
                window_offset = scanned - len(carry)
                relative_offsets: set[int] = set()

                marker_search_offset = 0
                while True:
                    marker_offset = haystack.find(TORCH7_BINARY_MARKER, marker_search_offset)
                    if marker_offset == -1:
                        break
                    absolute_offset = window_offset + marker_offset
                    candidate_window = haystack[marker_offset : marker_offset + TORCH7_SIGNATURE_WINDOW_BYTES]
                    if (
                        absolute_offset > last_yielded
                        and file_size - absolute_offset >= 8
                        and cls._torch7_marker_candidate_is_promising(
                            path,
                            absolute_offset,
                            haystack,
                            marker_offset,
                            candidate_window,
                            min(signal_scan_bytes or max_scan_bytes, max_scan_bytes - absolute_offset),
                        )
                    ):
                        relative_offsets.add(marker_offset)
                    marker_search_offset = marker_offset + 1

                for match in re.finditer(rb"4(?:\r\n|[\r\n])", haystack):
                    absolute_offset = window_offset + match.start()
                    if absolute_offset <= last_yielded:
                        continue
                    candidate_window = haystack[match.start() : match.start() + TORCH7_SIGNATURE_WINDOW_BYTES]
                    if cls._torch7_ascii_candidate_is_structural(candidate_window):
                        relative_offsets.add(match.start())

                for relative_offset in sorted(relative_offsets):
                    absolute_offset = window_offset + relative_offset
                    if absolute_offset <= last_yielded:
                        continue
                    yield absolute_offset
                    last_yielded = absolute_offset

                carry = haystack[-overlap:] if overlap > 0 else b""
                scanned += len(chunk)

    @classmethod
    def _torch7_marker_candidate_is_promising(
        cls,
        path: Path,
        absolute_offset: int,
        haystack: bytes,
        marker_offset: int,
        candidate_window: bytes,
        max_signal_scan_bytes: int,
    ) -> bool:
        if find_structural_torch7_offset(candidate_window) == 0:
            return True
        if cls._torch7_prefix_has_binary_payload_bytes(candidate_window):
            return True

        next_marker = haystack.find(TORCH7_BINARY_MARKER, marker_offset + len(TORCH7_BINARY_MARKER))
        signal_window = haystack[marker_offset:] if next_marker == -1 else haystack[marker_offset:next_marker]
        if cls._torch7_actionable_signal_rank(signal_window) > 0:
            return True
        return (
            cls._embedded_torch7_candidate_actionable_signal_rank(
                path,
                absolute_offset,
                max_signal_scan_bytes,
                stop_at_any_marker=True,
            )
            > 0
        )

    @classmethod
    def _find_embedded_torch7_offset(cls, path: Path, max_scan_bytes: int, *, start_offset: int = 0) -> int | None:
        """Find a Torch7 payload signature after a known payload boundary."""
        return next(cls._iter_embedded_torch7_offsets(path, max_scan_bytes, start_offset=start_offset), None)

    @staticmethod
    def _find_casefolded_marker_offset(
        path: Path,
        marker: bytes,
        max_scan_bytes: int,
        evidence_bytes: int,
    ) -> tuple[int | None, bytes]:
        marker_len = len(marker)
        search_limit = min(path.stat().st_size, max_scan_bytes)
        overlap = marker_len - 1
        scanned = 0
        carry = b""
        evidence_carry = b""
        normalized_marker = marker.lower()

        with path.open("rb") as handle:
            while scanned < search_limit:
                to_read = min(1024 * 1024, search_limit - scanned)
                chunk = handle.read(to_read)
                if not chunk:
                    break

                haystack = carry + chunk.lower()
                evidence_window = (evidence_carry + chunk)[-evidence_bytes:]
                relative_index = haystack.find(normalized_marker)
                if relative_index != -1:
                    return scanned - len(carry) + relative_index, evidence_window

                carry = haystack[-overlap:] if overlap > 0 else b""
                evidence_carry = evidence_window
                scanned += len(chunk)

        return None, b""

    @staticmethod
    def _read_prefix(path: Path, num_bytes: int) -> bytes:
        with path.open("rb") as handle:
            return handle.read(num_bytes)

    @staticmethod
    def _read_suffix(path: Path, num_bytes: int) -> bytes:
        file_size = path.stat().st_size
        if file_size <= num_bytes:
            return LlamafileScanner._read_prefix(path, num_bytes)
        with path.open("rb") as handle:
            handle.seek(file_size - num_bytes)
            return handle.read(num_bytes)

    @staticmethod
    def _offset_is_in_preview_windows(offset: int, file_size: int, preview_bytes: int) -> bool:
        """Return whether an offset is already covered by the head or tail preview."""
        return offset < preview_bytes or offset >= max(0, file_size - preview_bytes)

    @staticmethod
    def _preview_window_start(file_size: int, offset: int, num_bytes: int) -> int:
        window_start = max(0, offset - (num_bytes // 2))
        window_end = min(file_size, window_start + num_bytes)
        if window_end - window_start < num_bytes:
            window_start = max(0, window_end - num_bytes)
        return window_start

    @staticmethod
    def _read_window_around_offset(path: Path, offset: int, num_bytes: int) -> bytes:
        """Read a bounded preview window centered around a routed marker offset."""
        file_size = path.stat().st_size
        window_start = LlamafileScanner._preview_window_start(file_size, offset, num_bytes)
        window_end = min(file_size, window_start + num_bytes)
        with path.open("rb") as handle:
            handle.seek(window_start)
            return handle.read(window_end - window_start)
