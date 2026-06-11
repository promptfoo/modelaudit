"""Scanner for text-based ML files like README.md and vocab.txt."""

import ast
import io
import keyword
import os
import re
import token
import tokenize
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlsplit

from modelaudit.core_results import mark_operational_scan_error
from modelaudit.scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from modelaudit.scanners._evidence_redaction import redact_untrusted_error_message
from modelaudit.scanners.base import BaseScanner, CheckStatus, IssueSeverity, ScanResult

TEXT_CONTENT_SECURITY_SCAN_INCOMPLETE_REASON = "text_content_security_scan_incomplete"
TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON = "text_content_security_detector_failed"
TEXT_CONTENT_SECURITY_FINDING_LIMIT_REASON = "text_content_security_finding_limit"
TEXT_CONTENT_SECURITY_CLASSIFICATION_LIMIT_REASON = "text_content_security_classification_limit"
DEFAULT_TEXT_CONTENT_SECURITY_SCAN_BYTES = 100 * 1024 * 1024
DEFAULT_TEXT_CONTENT_SECURITY_MAX_FINDINGS = 1024
DETECTOR_FINDING_LIMIT_TYPE = "detector_finding_limit"
FSTRING_MIDDLE_TOKEN_TYPE = getattr(token, "FSTRING_MIDDLE", None)
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
DOCUMENTATION_FENCED_LOOPBACK_API_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DOCUMENTATION_FENCED_PASSIVE_MEDIA_URL_SUFFIXES = (".gif", ".jpeg", ".jpg", ".png", ".webp")
DOCUMENTATION_FENCED_PASSIVE_NETWORK_FINDING_TYPES = PASSIVE_NETWORK_FINDING_TYPES | {
    "network_function",
    "network_library",
    "suspicious_port",
}
PASSIVE_DATA_TEXT_FILENAMES = frozenset({"classes.txt"})
PASSIVE_DATA_TEXT_PREFIXES = ("label", "token", "vocab")
BARE_NETWORK_URL_TOKEN_PATTERN = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://\S+")
DOCUMENTATION_FENCED_BARE_URL_TOKEN_PATTERN = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"')\]}>,;]+")
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
MAX_DOCUMENTATION_FENCE_MARKERS = 4096
DOCUMENTATION_CODE_ASSIGNMENT_PATTERN = re.compile(
    rb"(?:^|[\r\n{[(,;])[ \t]*(?:(?:const|let|var)[ \t]+)?[A-Za-z_][A-Za-z0-9_.-]*[ \t]*="
    rb"[\s(\[{\\]{0,4096}[rubfRUBF]*[\"']?$"
)
DOCUMENTATION_PASSIVE_HTML_URL_ATTRIBUTE_PATTERN = re.compile(
    rb"<(?:a\b[^<>]{0,4096}\bhref|img\b[^<>]{0,4096}\bsrc)\s*=\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_EXECUTABLE_HTML_URL_ATTRIBUTE_PATTERN = re.compile(
    rb"<(?:iframe\b[^<>]{0,4096}\bsrc|link\b[^<>]{0,4096}\bhref|script\b[^<>]{0,4096}\bsrc)"
    rb"\s*=\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_HTML_URL_ATTRIBUTE_PATTERN = re.compile(rb"\b(?:href|src)\s*=\s*[\"']?$", re.IGNORECASE)
DOCUMENTATION_FENCE_LINE_PATTERN = re.compile(
    rb"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})(?P<suffix>[^\r\n]*)\r?$",
    re.MULTILINE,
)
DOCUMENTATION_CODE_CALL_PATTERN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()]{0,4096}[rubfRUBF]*[\"']$")
DOCUMENTATION_MARKDOWN_PREFIX_PATTERN = re.compile(rb"(?:(?:[-*+>]|[0-9]{1,9}[.)])\s+){1,8}")
DOCUMENTATION_CONFIG_NETWORK_KEY = rb"(?:endpoint|callback|webhook)(?:s|[_-][A-Za-z0-9_.-]{1,128}|(?:url|uri)s?)?"
DOCUMENTATION_CONFIG_MAPPING_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])(?:[\"']"
    + DOCUMENTATION_CONFIG_NETWORK_KEY
    + rb"[\"']|"
    + DOCUMENTATION_CONFIG_NETWORK_KEY
    + rb")\s*:\s*(?:\[\s*)?(?:(?:\r?\n|\r)[ \t]*(?:[-*+]\s+)?)?[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_NESTED_CONFIG_OBJECT_PATTERN = re.compile(
    rb"(?:^|[\s{[(,;])[\"']?" + DOCUMENTATION_CONFIG_NETWORK_KEY + rb"[\"']?\s*(?:=|:)\s*"
    rb"\{[^{}]{0,4096}[\"']?(?:url|uri)[\"']?\s*:\s*[\"']?$",
    re.IGNORECASE,
)
DOCUMENTATION_NESTED_CONFIG_PARENT_LINE_PATTERN = re.compile(
    rb"[ \t]*[\"']?" + DOCUMENTATION_CONFIG_NETWORK_KEY + rb"[\"']?\s*:\s*",
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
DOCUMENTATION_PRIVILEGE_OPTION_WITH_ARGUMENT = (
    rb"(?:-(?:C|D|g|h|p|R|T|u)|--(?:chdir|chroot|close-from|command-timeout|group|host|other-user|"
    rb"prompt|role|type|user))"
)
DOCUMENTATION_PRIVILEGE_OPTION = (
    rb"(?:"
    + DOCUMENTATION_PRIVILEGE_OPTION_WITH_ARGUMENT
    + rb"(?:=[^\s]+|\s+[^\s]+)|--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?)"
)
DOCUMENTATION_ENV_OPTION_ARGUMENT = rb"(?:[^\s\"']+|\"[^\"\r\n]{0,4096}\"|'[^'\r\n]{0,4096}')"
DOCUMENTATION_ENV_OPTION_WITH_ARGUMENT = rb"(?:-(?:C|u)|--(?:chdir|unset))"
DOCUMENTATION_ENV_OPTION_WITHOUT_ARGUMENT = (
    rb"(?:-[0iv]{1,3}|--(?:debug|ignore-environment|list-signal-handling|null)"
    rb"|--(?:block-signal|default-signal|ignore-signal)(?:=[^\s]+)?)"
)
DOCUMENTATION_ENV_OPTION = (
    rb"(?:"
    + DOCUMENTATION_ENV_OPTION_WITH_ARGUMENT
    + rb"(?:="
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb"|\s+"
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb")|"
    + DOCUMENTATION_ENV_OPTION_WITHOUT_ARGUMENT
    + rb")"
)
DOCUMENTATION_ENV_ASSIGNMENT = rb"[A-Za-z_][A-Za-z0-9_]{0,127}=(?:[^\s\"']+|\"[^\"\r\n]{0,4096}\"|'[^'\r\n]{0,4096}')"
DOCUMENTATION_ENV_SPLIT_STRING_WRAPPER = (
    rb"env(?:\s+" + DOCUMENTATION_ENV_OPTION + rb"){0,8}\s+(?:-S|--split-string)(?:=|\s+)[\"']?\s*"
)
DOCUMENTATION_ENV_WRAPPER = (
    rb"(?:(?:" + DOCUMENTATION_ENV_SPLIT_STRING_WRAPPER + rb")|(?:env(?:\s+" + DOCUMENTATION_ENV_OPTION + rb"){0,8}\s+"
    rb"(?:--\s+)?(?:" + DOCUMENTATION_ENV_ASSIGNMENT + rb"\s+){0,16})"
    rb"|(?:(?:" + DOCUMENTATION_ENV_ASSIGNMENT + rb"\s+){1,16}))?"
)
DOCUMENTATION_PRIVILEGE_WRAPPER = (
    rb"(?:(?:sudo|doas)(?:\s+"
    + DOCUMENTATION_PRIVILEGE_OPTION
    + rb"){0,8}\s+(?:--\s+)?"
    + DOCUMENTATION_ENV_WRAPPER
    + rb")?"
)
DOCUMENTATION_SHELL_WRAPPERS = DOCUMENTATION_ENV_WRAPPER + DOCUMENTATION_PRIVILEGE_WRAPPER
DOCUMENTATION_TIMEOUT_OPTION = (
    rb"(?:-(?:k|s)|--(?:kill-after|signal))(?:=[^\s]+|\s+[^\s]+)"
    rb"|--(?:foreground|preserve-status|verbose)"
)
DOCUMENTATION_POSIX_LAUNCHER_WRAPPER = (
    rb"(?:(?:"
    rb"(?:command|exec|nohup)(?:\s+--)?\s+"
    rb"|time(?:\s+-[pv]+){0,2}\s+"
    rb"|timeout(?:\s+(?:" + DOCUMENTATION_TIMEOUT_OPTION + rb")){0,4}\s+"
    rb"[0-9]+(?:\.[0-9]+)?[smhd]?\s+"
    rb"|nice(?:\s+(?:-n\s+[-+]?[0-9]+|--adjustment(?:=|\s+)[-+]?[0-9]+|[-+][0-9]+))?\s+"
    rb"|setsid(?:\s+--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?){0,4}\s+"
    rb")){0,2}"
)
DOCUMENTATION_SHELL_OPTION = rb"--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?"
DOCUMENTATION_SHELL_COMMAND_OPTION = rb"-[A-Za-z]*c[A-Za-z]*"
DOCUMENTATION_COMMAND_ARRAY_SEPARATOR = rb"[\"']?\s*,\s*[\"']?"
DOCUMENTATION_CMD_OPTION = rb"/[A-Za-z](?::[^\s]+)?"
DOCUMENTATION_SHELL_INTERPRETER_WRAPPER = (
    rb"(?:(?:(?:bash|sh|zsh)(?:\s+"
    + DOCUMENTATION_SHELL_OPTION
    + rb"){0,8}\s+"
    + DOCUMENTATION_SHELL_COMMAND_OPTION
    + rb"|cmd(?:\.exe)?(?:\s+"
    + DOCUMENTATION_CMD_OPTION
    + rb"){0,8}\s+/(?:c|k)|eval)\s+[\"']?\s*)?"
)
DOCUMENTATION_SHELL_WRAPPED_COMMAND = (
    DOCUMENTATION_SHELL_WRAPPERS
    + DOCUMENTATION_POSIX_LAUNCHER_WRAPPER
    + DOCUMENTATION_SHELL_INTERPRETER_WRAPPER
    + DOCUMENTATION_SHELL_WRAPPERS
    + DOCUMENTATION_POSIX_LAUNCHER_WRAPPER
)
DOCUMENTATION_SHELL_PROMPT = rb"(?:(?:[$>#]|[A-Za-z0-9._-]+[$#>])\s*)?"
DOCUMENTATION_ROOT_PROMPT_NON_SHELL_PREFIX_PATTERN = re.compile(
    rb"^(?:[A-Za-z][A-Za-z0-9 _-]{0,31}\s*:\s+|(?:ADD|CMD|ENTRYPOINT|RUN)\b)"
)
DOCUMENTATION_INLINE_CODE_OPEN = rb"(?:`{1,3}\s*)?"
DOCUMENTATION_COMMAND_LABEL = rb"(?:[A-Za-z][A-Za-z0-9 _-]{0,31}\s*:\s*)?"
DOCUMENTATION_DOCKER_RUN_OPTION = rb"--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?"
DOCUMENTATION_DOCKER_RUN = rb"(?:RUN(?:\s+" + DOCUMENTATION_DOCKER_RUN_OPTION + rb"){0,8}\s+)?"
DOCUMENTATION_COMMAND_CONTEXT = DOCUMENTATION_COMMAND_LABEL + DOCUMENTATION_DOCKER_RUN
DOCUMENTATION_SHELL_LINE_PREFIX = (
    rb"^\s*(?:(?:[-*+>]|[0-9]{1,9}[.)])\s+){0,8}"
    + DOCUMENTATION_INLINE_CODE_OPEN
    + DOCUMENTATION_SHELL_PROMPT
    + DOCUMENTATION_COMMAND_CONTEXT
)
DOCUMENTATION_COMMAND_PATH_PREFIX = rb"(?:/(?:usr/)?bin/)?(?:(?:busybox|toybox)(?:\.exe)?\s+)?"
DOCUMENTATION_DOWNLOADER_COMMAND = (
    DOCUMENTATION_COMMAND_PATH_PREFIX + rb"(?:curl|fetch|invoke-restmethod|invoke-webrequest|irm|iwr|wget)(?:\.exe)?"
)
DOCUMENTATION_COMMAND_ARRAY_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + rb"(?:RUN|CMD|ENTRYPOINT|command)\s*(?::|=)?\s*\[\s*[\"']?"
    + DOCUMENTATION_DOWNLOADER_COMMAND
    + rb"\b[\"']?\s*,\s*[\"']?"
    + rb"(?:$|--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\\])",
    re.IGNORECASE,
)
DOCUMENTATION_SHELL_COMMAND_ARRAY_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + rb"(?:RUN|CMD|ENTRYPOINT|command)\s*(?::|=)?\s*\[\s*[\"']?"
    + DOCUMENTATION_COMMAND_PATH_PREFIX
    + rb"(?:bash|sh|zsh)"
    + DOCUMENTATION_COMMAND_ARRAY_SEPARATOR
    + rb"(?:"
    + DOCUMENTATION_SHELL_OPTION
    + DOCUMENTATION_COMMAND_ARRAY_SEPARATOR
    + rb"){0,8}"
    + DOCUMENTATION_SHELL_COMMAND_OPTION
    + DOCUMENTATION_COMMAND_ARRAY_SEPARATOR
    + DOCUMENTATION_POSIX_LAUNCHER_WRAPPER
    + DOCUMENTATION_DOWNLOADER_COMMAND
    + rb"\b\s+",
    re.IGNORECASE,
)
DOCUMENTATION_XARGS_DOWNLOADER_PATTERN = re.compile(
    rb"(?:" + DOCUMENTATION_SHELL_LINE_PREFIX + rb"|[;&|]\s*)xargs"
    rb"(?:\s+--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?){0,8}\s+" + DOCUMENTATION_DOWNLOADER_COMMAND + rb"\b",
    re.IGNORECASE,
)
DOCUMENTATION_FIND_EXEC_DOWNLOADER_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + rb"find\b[^\r\n]{0,4096}?\s+-(?:exec|execdir)\s+"
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_DOWNLOADER_COMMAND
    + rb"\b\s+(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\])",
    re.IGNORECASE,
)
DOCUMENTATION_DOCKER_ADD_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + rb"ADD(?:\s+--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?){0,8}\s+"
    + rb"(?:$|[A-Za-z][A-Za-z0-9+.-]*://)",
)
DOCUMENTATION_DOCKER_ADD_CONTINUATION_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + rb"ADD(?:\s+--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?){0,8}\s+\\$"
)
DOCUMENTATION_CERTUTIL_OPTION = rb"-[A-Za-z][A-Za-z0-9_-]*"
DOCUMENTATION_CERTUTIL_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_COMMAND_PATH_PREFIX
    + rb"certutil(?:\.exe)?"
    + rb"(?:\s+"
    + DOCUMENTATION_CERTUTIL_OPTION
    + rb"){0,8}\s+-urlcache"
    + rb"(?:\s+"
    + DOCUMENTATION_CERTUTIL_OPTION
    + rb"){0,8}\s+"
    + rb"[\"']?(?:[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})",
    re.IGNORECASE,
)
DOCUMENTATION_NETCAT_OPTION_WITH_ARGUMENT = (
    rb"(?:-(?:e|i|p|q|s|w)|--(?:exec|interval|proxy|proxy-type|source|source-port|wait))"
    rb"(?:=[^\s]+|\s+[^\s]+)"
)
DOCUMENTATION_NETCAT_OPTION_WITHOUT_ARGUMENT = (
    rb"(?:-[46bCdDhklNnrStUuvz]+|--(?:close|listen|no-shutdown|recv-only|send-only|telnet|udp|verbose|zero))"
)
DOCUMENTATION_NETCAT_OPTION = (
    rb"(?:" + DOCUMENTATION_NETCAT_OPTION_WITH_ARGUMENT + rb"|" + DOCUMENTATION_NETCAT_OPTION_WITHOUT_ARGUMENT + rb")"
)
DOCUMENTATION_NETCAT_ENDPOINT = (
    rb"(?:\[[0-9A-Fa-f:]+\]|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|localhost)"
)
DOCUMENTATION_NETWORK_PORT = (
    rb"(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
)
DOCUMENTATION_NETCAT_COMMAND = (
    DOCUMENTATION_COMMAND_PATH_PREFIX
    + rb"(?:nc|ncat|netcat)(?:\.exe)?"
    + rb"(?:\s+"
    + DOCUMENTATION_NETCAT_OPTION
    + rb"){0,8}\s+"
    + DOCUMENTATION_NETCAT_ENDPOINT
    + rb"\s+"
    + DOCUMENTATION_NETWORK_PORT
    + rb"\b"
)
DOCUMENTATION_NETCAT_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + DOCUMENTATION_SHELL_WRAPPED_COMMAND + DOCUMENTATION_NETCAT_COMMAND,
    re.IGNORECASE,
)
DOCUMENTATION_GIT_CLONE_OPTION_WITH_ARGUMENT = (
    rb"(?:-(?:b|c|j|o|u)|--(?:branch|config|depth|filter|jobs|origin|reference|reference-if-able|"
    rb"separate-git-dir|shallow-exclude|shallow-since|template|upload-pack))(?:=|\s+)[^\s]{1,4096}"
)
DOCUMENTATION_GIT_CLONE_OPTION = (
    rb"(?:" + DOCUMENTATION_GIT_CLONE_OPTION_WITH_ARGUMENT + rb"|-[lnqsv]+|--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]{1,4096})?)"
)
DOCUMENTATION_GIT_CLONE_DESTINATION = (
    rb"(?:[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]{1,4096}|(?:[A-Za-z0-9._-]+@)?"
    + DOCUMENTATION_NETCAT_ENDPOINT
    + rb":[^\s\"'<>]{1,4096})"
)
DOCUMENTATION_NETWORK_COMMAND_LINE_LIMIT = rb"(?=[^\r\n]{1,8192}(?:\r?\n)?$)"
DOCUMENTATION_GIT_CLONE_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + DOCUMENTATION_NETWORK_COMMAND_LINE_LIMIT
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_COMMAND_PATH_PREFIX
    + rb"git(?:\.exe)?\s+clone"
    rb"(?:\s+"
    + DOCUMENTATION_GIT_CLONE_OPTION
    + rb"){0,8}\s+(?:--\s+)?"
    + DOCUMENTATION_GIT_CLONE_DESTINATION
    + rb"(?:\s+[^\s;&|#]{1,4096})?(?=\s*(?:$|[;&|#]))",
    re.IGNORECASE,
)
DOCUMENTATION_SSH_OPTION_WITH_ARGUMENT = rb"-(?:B|b|c|D|E|F|I|i|J|L|l|m|O|o|p|Q|R|S|W|w)(?:=|\s+)?[^\s]{1,4096}"
DOCUMENTATION_SSH_OPTION_WITHOUT_ARGUMENT = rb"-[46AaCfGgKkMNnqsTtVvXxYy]+"
DOCUMENTATION_SSH_OPTION = (
    rb"(?:" + DOCUMENTATION_SSH_OPTION_WITH_ARGUMENT + rb"|" + DOCUMENTATION_SSH_OPTION_WITHOUT_ARGUMENT + rb")"
)
DOCUMENTATION_SSH_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_COMMAND_PATH_PREFIX
    + rb"ssh(?:\.exe)?(?:\s+"
    + DOCUMENTATION_SSH_OPTION
    + rb"){0,8}\s+(?:[A-Za-z0-9._-]+@)?"
    + DOCUMENTATION_NETCAT_ENDPOINT
    + rb"(?=\s*(?:$|[;&|<>#]))",
    re.IGNORECASE,
)
DOCUMENTATION_DOCKER_PULL_OPTION_WITH_ARGUMENT = rb"--(?:disable-content-trust|platform)(?:=|\s+)[^\s]{1,4096}"
DOCUMENTATION_DOCKER_PULL_OPTION = (
    rb"(?:" + DOCUMENTATION_DOCKER_PULL_OPTION_WITH_ARGUMENT + rb"|-[aq]+|--[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]{1,4096})?)"
)
DOCUMENTATION_DOCKER_PULL_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + DOCUMENTATION_SHELL_WRAPPED_COMMAND + rb"docker(?:\.exe)?\s+(?:image\s+)?pull"
    rb"(?:\s+" + DOCUMENTATION_DOCKER_PULL_OPTION + rb"){0,8}\s+"
    rb"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::" + DOCUMENTATION_NETWORK_PORT + rb")?/[^\s\"'<>]{1,4096}"
    rb"(?=\s*(?:$|[;&|#]))",
    re.IGNORECASE,
)
DOCUMENTATION_INLINE_NETCAT_COMMAND_PATTERN = re.compile(
    rb"(?:^|[;&|]\s*)"
    + DOCUMENTATION_INLINE_CODE_OPEN
    + DOCUMENTATION_SHELL_PROMPT
    + DOCUMENTATION_COMMAND_CONTEXT
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_NETCAT_COMMAND,
    re.IGNORECASE,
)
DOCUMENTATION_POWERSHELL_OPTION_WITH_ARGUMENT = (
    rb"-(?:configurationname|executionpolicy|inputformat|outputformat|settingsfile|windowstyle|workingdirectory)"
    rb"(?:=[^\s]+|\s+[^\s]+)"
)
DOCUMENTATION_POWERSHELL_OPTION_WITHOUT_ARGUMENT = rb"-(?:login|mta|nologo|noexit|noninteractive|noprofile|sta)"
DOCUMENTATION_POWERSHELL_COMMAND = (
    rb"(?:powershell(?:\.exe)?|pwsh)\b"
    + rb"(?:\s+(?:"
    + DOCUMENTATION_POWERSHELL_OPTION_WITH_ARGUMENT
    + rb"|"
    + DOCUMENTATION_POWERSHELL_OPTION_WITHOUT_ARGUMENT
    + rb")){0,8}(?:\s+-(?:c|command|e|enc|encodedcommand)\b|\s+"
    + DOCUMENTATION_DOWNLOADER_COMMAND
    + rb"\b\s+)"
)
DOCUMENTATION_POWERSHELL_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + DOCUMENTATION_SHELL_WRAPPED_COMMAND + DOCUMENTATION_POWERSHELL_COMMAND,
    re.IGNORECASE,
)
DOCUMENTATION_INLINE_POWERSHELL_COMMAND_PATTERN = re.compile(
    rb"(?:^|[;&|]\s*)"
    + DOCUMENTATION_INLINE_CODE_OPEN
    + DOCUMENTATION_SHELL_PROMPT
    + DOCUMENTATION_COMMAND_CONTEXT
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + DOCUMENTATION_POWERSHELL_COMMAND,
    re.IGNORECASE,
)
DOCUMENTATION_SHELL_COMMAND_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + DOCUMENTATION_SHELL_WRAPPED_COMMAND + rb"(?:(?:\$\(|`)\s*)?"
    rb"(?:" + DOCUMENTATION_DOWNLOADER_COMMAND + rb"\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\])"
    rb")",
    re.IGNORECASE,
)
DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN = re.compile(
    rb"(?:^|[;&|]\s*)"
    + DOCUMENTATION_INLINE_CODE_OPEN
    + DOCUMENTATION_SHELL_PROMPT
    + DOCUMENTATION_COMMAND_CONTEXT
    + DOCUMENTATION_SHELL_WRAPPED_COMMAND
    + rb"(?:(?:\$\(|`)\s*)?(?:"
    + DOCUMENTATION_DOWNLOADER_COMMAND
    + rb"\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\]|$)"
    rb")",
    re.IGNORECASE,
)
DOCUMENTATION_SHELL_SUBSTITUTION_PATTERN = re.compile(
    rb"(?:\$\(|`)\s*" + DOCUMENTATION_SHELL_WRAPPED_COMMAND + DOCUMENTATION_DOWNLOADER_COMMAND + rb"\b\s+"
    rb"(?:--?[A-Za-z]|[A-Za-z][A-Za-z0-9+.-]*://|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|[$\"'\\]|$)",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_SHELL_EXECUTION_PATTERN = re.compile(
    rb"\|\s*(?:(?:/[A-Za-z0-9._-]+)*/)?(?:bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\b",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_ACTIONABLE_URL_TOKEN_PATTERN = re.compile(
    rb"(?:beacon|c2|cmd|download|evil|exec|exfil|payload|shell)",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_URL_ASSIGNMENT_PATTERN = re.compile(
    rb"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[rubfRUBF]*[\"'](?P<url>https?://[^\"'\s]+)[\"']",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_URL_REQUEST_ASSIGNMENT_PATTERN = re.compile(
    rb"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:urllib\.request\.)?Request\s*\(\s*"
    rb"[rubfRUBF]*[\"'](?P<url>https?://[^\"'\s)]+)[\"']",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_URL_VARIABLE_CALL_PATTERN = re.compile(
    rb"\b(?:requests\.(?:get|head)|urllib\.request\.urlopen|urlopen)\s*\(\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_DIRECT_URL_CALL_PATTERN = re.compile(
    rb"\b(?:requests\.(?:get|head)|urllib\.request\.urlopen|urlopen)\s*\(\s*[rubfRUBF]*[\"']"
    rb"(?P<url>https?://[^\"'\s)]+)",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_ALLOWED_NETWORK_CALL_PATTERN = re.compile(
    rb"\b(?:requests\.(?:get|head)|urllib\.request\.urlopen|urlopen)\s*\(",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_VARIABLE_ASSIGNMENT_PATTERN = re.compile(
    rb"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_REQUESTS_CALL_PATTERN = re.compile(
    rb"\brequests\.(?P<method>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
DOCUMENTATION_FENCED_NETWORK_FUNCTION_PATTERN = re.compile(
    rb"\b(?:urlopen|urlretrieve|socket\.connect|socket\.create_connection|requests\.(?:get|post|put|delete)|"
    rb"http\.request|ftp\.connect|ssh\.connect|telnet\.open|smtp\.connect|imap\.login|redis\.connect|"
    rb"mongo\.connect|getaddrinfo|gethostbyname|gethostbyaddr|dns\.resolver)\b",
    re.IGNORECASE,
)
DOCUMENTATION_PIP_OPTION_WITH_ARGUMENT = (
    rb"--(?:cache-dir|cert|client-cert|exists-action|keyring-provider|log|proxy|python|retries|"
    rb"resume-retries|root-user-action|timeout|trusted-host|use-deprecated|use-feature)"
)
DOCUMENTATION_PIP_OPTION_WITHOUT_ARGUMENT = (
    rb"(?:-[vq]{1,3}|--(?:debug|disable-pip-version-check|isolated|no-cache-dir|no-color|no-input|"
    rb"no-python-version-warning|quiet|require-virtualenv|verbose))"
)
DOCUMENTATION_PIP_OPTION = (
    rb"(?:"
    + DOCUMENTATION_PIP_OPTION_WITH_ARGUMENT
    + rb"(?:="
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb"|\s+"
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb")|"
    + DOCUMENTATION_PIP_OPTION_WITHOUT_ARGUMENT
    + rb")"
)
DOCUMENTATION_PYTHON_OPTION_WITH_ARGUMENT = (
    rb"(?:-[WX](?:=|\s+)?|--check-hash-based-pycs(?:=|\s+))" + DOCUMENTATION_ENV_OPTION_ARGUMENT
)
DOCUMENTATION_PYTHON_OPTION_WITHOUT_ARGUMENT = rb"(?:-[BbEhiIOPqRsSuvVx]+|--(?:help|version))"
DOCUMENTATION_PYTHON_OPTION = (
    rb"(?:" + DOCUMENTATION_PYTHON_OPTION_WITH_ARGUMENT + rb"|" + DOCUMENTATION_PYTHON_OPTION_WITHOUT_ARGUMENT + rb")"
)
DOCUMENTATION_PYTHON_LAUNCHER = rb"(?:python(?:[0-9.]+)?|py(?:\s+-[0-9.]+)?)"
DOCUMENTATION_JS_OPTION_WITH_ARGUMENT = rb"--(?:cache|cafile|https-proxy|prefix|proxy|registry|userconfig)"
DOCUMENTATION_JS_OPTION = (
    rb"(?:"
    + DOCUMENTATION_JS_OPTION_WITH_ARGUMENT
    + rb"(?:="
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb"|\s+"
    + DOCUMENTATION_ENV_OPTION_ARGUMENT
    + rb")|--?[A-Za-z][A-Za-z0-9_-]*(?:=[^\s]+)?)"
)
DOCUMENTATION_PACKAGE_INSTALL_PATTERN = re.compile(
    DOCUMENTATION_SHELL_LINE_PREFIX + DOCUMENTATION_SHELL_WRAPPED_COMMAND + rb"(?:"
    rb"(?:"
    + DOCUMENTATION_PYTHON_LAUNCHER
    + rb"(?:\s+"
    + DOCUMENTATION_PYTHON_OPTION
    + rb"){0,8}\s+-m\s+)?pip(?:[0-9.]+)?"
    rb"(?:\s+" + DOCUMENTATION_PIP_OPTION + rb"){0,8}\s+install"
    rb"|pipx\s+install"
    rb"|uv\s+(?:pip\s+install|add)"
    rb"|(?:conda|mamba|micromamba)\s+install"
    rb"|poetry\s+add"
    rb"|(?:npm|pnpm|bun)(?:\s+" + DOCUMENTATION_JS_OPTION + rb"){0,8}\s+"
    rb"(?:install|add|i|in|ins|inst|insta|instal|isnt|isnta|isntal|isntall)"
    rb"|yarn\s+add"
    rb"|cargo\s+install"
    rb"|gem\s+install"
    rb"|go\s+install"
    rb")\b",
    re.IGNORECASE,
)
DOCUMENTATION_PACKAGE_INSTALL_PROSE_TAIL_PATTERN = re.compile(
    rb"(?:\b(?:is|are|was|were)\s+(?:covered|described|documented|explained)\s+(?:at|in|on)"
    rb"|\b(?:docs?|documentation|guide|reference)\s+(?:at|in|on))\s*$",
    re.IGNORECASE,
)
DOCUMENTATION_COMPOUND_IMPORT_PREFIX_PATTERN = re.compile(
    rb"^\s*(?:(?:if|elif|else|for|while|with|try|except|finally|match|case|def|class)\b"
    rb"|async\s+(?:for|with|def)\b)[^#\n]{0,4096}:\s*$"
)
DOCUMENTATION_PYTHON_DEFINITION_BLOCK_PATTERN = re.compile(
    rb"(?:(?:async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^#\n]{0,2048}\)[^#\n]{0,512}"
    rb"|class\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^#\n]{0,2048}\))?)\s*:\s*(?:#.*)?$"
)
DOCUMENTATION_PYTHON_NESTED_BLOCK_PATTERN = re.compile(
    rb"(?:(?:async\s+)?(?:for|with)|if|elif|else|while|try|except|finally|match|case)\b"
    rb"[^#\n]{0,4096}:\s*(?:#.*)?$"
)
DOCUMENTATION_PYTHON_BLOCK_VALUE_PREFIX_PATTERN = re.compile(
    rb"(?:return|yield)(?:\s+from)?\b[\s(\[{\\]{1,4096}[rubfRUBF]*[\"']?$"
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
    rb"(?P<suffix>[^\n:]{0,32}):\s*$",
    re.IGNORECASE,
)
DOCUMENTATION_PASSIVE_NETWORK_LABEL_SUFFIX_PATTERN = re.compile(
    rb"\b(?:analysis|article|discussion|docs?|documentation|example|guide|overview|paper|reference|research)\b",
    re.IGNORECASE,
)
DOCUMENTATION_ACTIONABLE_NETWORK_LABEL_SUFFIX_PATTERN = re.compile(
    rb"\b(?:address|destination|endpoint|host|receiver|server|sink|target|uri|url)\b",
    re.IGNORECASE,
)
GENERIC_CC_BENIGN_TERM_PATTERN = rb"(?:malwares?|backdoors?|trojans?|botnets?|zombies?)"
BENIGN_DOCUMENTATION_CC_PATTERN = re.compile(
    rb"(?:"
    rb"\b(?:not|no|without)\s+(?:a\s+)?(?:known\s+)?" + GENERIC_CC_BENIGN_TERM_PATTERN + rb"\b"
    rb"|\b" + GENERIC_CC_BENIGN_TERM_PATTERN + rb"[ -]free\b"
    rb"|\b" + GENERIC_CC_BENIGN_TERM_PATTERN + rb"\s+"
    rb"(?:analysis|benchmark|classification|classifier|dataset|defen[cs]e|detection|indicators?|mitigation|research|resistance|robustness|testing)\b"
    rb"|\b(?:detect(?:ing|ion|s)?|mitigat(?:e|ing|ion)|resistan(?:ce|t)|robust(?:ness)?)\s+"
    + GENERIC_CC_BENIGN_TERM_PATTERN
    + rb"\b"
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
    def _is_model_card_documentation_filename(cls, filename: str) -> bool:
        return filename == "model_card" or (
            filename.startswith(("model_card.", "modelcard."))
            and os.path.splitext(filename)[1].lower() in cls.supported_extensions
        )

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given file."""
        filename = os.path.basename(path).lower()
        if cls._is_model_card_documentation_filename(filename) or cls._is_readme_documentation_filename(filename):
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
        return (
            filename in DOCUMENTATION_TEXT_FILENAMES
            or cls._is_readme_documentation_filename(filename)
            or cls._is_model_card_documentation_filename(filename)
        )

    @staticmethod
    def _documentation_fence_match_can_open_code(match: re.Match[bytes]) -> bool:
        marker = match.group("marker")
        suffix = match.group("suffix")
        return not (marker.startswith(b"`") and b"`" in suffix)

    @classmethod
    def _documentation_has_closed_bare_tilde_fence(cls, payload: bytes) -> bool:
        opening_marker: bytes | None = None
        opening_end: int | None = None
        for match in DOCUMENTATION_FENCE_LINE_PATTERN.finditer(payload):
            marker = match.group("marker")
            suffix = match.group("suffix")
            if not marker.startswith(b"~") or suffix.strip():
                continue
            if opening_marker is None:
                previous_line_end = match.start() - 1
                if previous_line_end >= 0:
                    previous_line_start = payload.rfind(b"\n", 0, previous_line_end) + 1
                    if payload[previous_line_start:previous_line_end].strip():
                        continue
                opening_marker = marker
                opening_end = match.end()
                continue
            if len(marker) >= len(opening_marker) and opening_end is not None and opening_end < match.start():
                return True
        return False

    @classmethod
    def _documentation_uses_markdown_fences(cls, path: str, payload: bytes) -> bool:
        filename = os.path.basename(path).lower()
        extension = os.path.splitext(filename)[1]
        if extension == ".rst":
            return False
        if extension in {".md", ".markdown"}:
            return True
        if cls._documentation_has_closed_bare_tilde_fence(payload):
            return True
        return any(
            cls._documentation_fence_match_can_open_code(match)
            and (match.group("marker").startswith(b"`") or bool(match.group("suffix").strip()))
            for match in DOCUMENTATION_FENCE_LINE_PATTERN.finditer(payload)
        )

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
    def _documentation_python_statements(line: bytes) -> list[ast.stmt]:
        source = line.strip()
        markdown_prefix = DOCUMENTATION_MARKDOWN_PREFIX_PATTERN.match(source)
        if markdown_prefix is not None:
            source = source[markdown_prefix.end() :].lstrip()
        for fence_length in (3, 2, 1):
            fence = b"`" * fence_length
            if len(source) > fence_length * 2 and source.startswith(fence) and source.endswith(fence):
                source = source[fence_length:-fence_length].strip()
                break
        if source.startswith((b">>>", b"...")):
            source = source[3:].lstrip()
        try:
            parsed = ast.parse(source.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError, ValueError):
            return []
        return parsed.body

    @classmethod
    def _documentation_line_has_import_statement(cls, line: bytes) -> bool:
        return any(
            isinstance(statement, (ast.Import, ast.ImportFrom))
            for statement in cls._documentation_python_statements(line)
        )

    @classmethod
    def _documentation_line_has_definition(cls, line: bytes) -> bool:
        return any(
            isinstance(statement, (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef))
            for statement in cls._documentation_python_statements(line)
        )

    @staticmethod
    def _documentation_prefix_has_enclosing_call(prefix: bytes) -> bool:
        """Return whether a bounded Python prefix leaves a function call open at the finding."""
        source = prefix.strip()
        markdown_prefix = DOCUMENTATION_MARKDOWN_PREFIX_PATTERN.match(source)
        if markdown_prefix is not None:
            source = source[markdown_prefix.end() :].lstrip()
        for fence_length in (3, 2, 1):
            fence = b"`" * fence_length
            if source.startswith(fence):
                source = source[fence_length:].lstrip()
                break
        if source.startswith((b">>>", b"...")):
            source = source[3:].lstrip()
        source = source.rstrip()
        if source.endswith((b"'", b'"')):
            source = source[:-1].rstrip()
        try:
            decoded = source.decode("utf-8")
        except UnicodeDecodeError:
            return False

        stack: list[tuple[str, bool]] = []
        previous: tokenize.TokenInfo | None = None
        before_previous: tokenize.TokenInfo | None = None
        previous_closed_subscript = False
        expression_keywords = {
            "and",
            "await",
            "elif",
            "if",
            "in",
            "is",
            "lambda",
            "not",
            "or",
            "return",
            "while",
            "yield",
        }
        ignored_token_types = {
            token.COMMENT,
            token.DEDENT,
            token.ENDMARKER,
            token.INDENT,
            token.NEWLINE,
            tokenize.ENCODING,
            tokenize.NL,
        }
        try:
            tokens = tokenize.generate_tokens(io.StringIO(decoded).readline)
            for current in tokens:
                if current.type in ignored_token_types:
                    continue
                current_closed_subscript = False
                if current.type == token.OP and current.string in "([{":
                    name_starts_call = (
                        previous is not None
                        and previous.type == token.NAME
                        and not keyword.iskeyword(previous.string)
                        and (
                            before_previous is None
                            or before_previous.type == token.OP
                            or (before_previous.type == token.NAME and before_previous.string in expression_keywords)
                        )
                    )
                    follows_callable_expression = (
                        previous is not None
                        and previous.type == token.OP
                        and (previous.string == ")" or (previous.string == "]" and previous_closed_subscript))
                    )
                    is_call = current.string == "(" and (name_starts_call or follows_callable_expression)
                    is_subscript = (
                        current.string == "["
                        and previous is not None
                        and previous.end == current.start
                        and (
                            (previous.type == token.NAME and not keyword.iskeyword(previous.string))
                            or (previous.type == token.OP and previous.string in {")", "]"})
                        )
                    )
                    stack.append((current.string, is_call or is_subscript))
                elif current.type == token.OP and current.string in ")]}":
                    expected = {")": "(", "]": "[", "}": "{"}[current.string]
                    if stack and stack[-1][0] == expected:
                        _, opens_callable_expression = stack.pop()
                        current_closed_subscript = current.string == "]" and opens_callable_expression
                before_previous = previous
                previous = current
                previous_closed_subscript = current_closed_subscript
        except (IndentationError, tokenize.TokenError):
            # Incomplete prefixes are expected; the partial stack still identifies an open call.
            return any(opening == "(" and is_call for opening, is_call in stack)
        return any(opening == "(" and is_call for opening, is_call in stack)

    @staticmethod
    def _documentation_comment_contains_position(payload: bytes, position: int) -> bool:
        """Return whether a bounded finding position is inside an HTML or C-style block comment."""
        context_start = max(0, position - MAX_TEXT_FINDING_CONTEXT_BYTES)
        if context_start > 0 and payload[context_start - 1 : context_start] not in {b"\n", b"\r"}:
            return False
        prefix = payload[context_start:position]
        comment_close: bytes | None = None
        quote: int | None = None
        escaped = False
        cursor = 0
        while cursor < len(prefix):
            if comment_close is not None:
                if prefix.startswith(comment_close, cursor):
                    cursor += len(comment_close)
                    comment_close = None
                else:
                    cursor += 1
                continue
            value = prefix[cursor]
            if escaped:
                escaped = False
                cursor += 1
                continue
            if quote is not None:
                if value == ord("\\") and quote != ord("'"):
                    escaped = True
                elif value == quote:
                    quote = None
                cursor += 1
                continue
            if value in {ord("'"), ord('"'), ord("`")}:
                quote = value
                cursor += 1
            elif prefix.startswith(b"<!--", cursor):
                comment_close = b"-->"
                cursor += 4
            elif prefix.startswith(b"/*", cursor):
                comment_close = b"*/"
                cursor += 2
            else:
                cursor += 1
        return comment_close is not None

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

    @staticmethod
    def _documentation_suspicious_label_is_actionable(prefix: bytes) -> bool:
        for match in DOCUMENTATION_SUSPICIOUS_NETWORK_LABEL_PATTERN.finditer(prefix):
            suffix = match.group("suffix")
            if DOCUMENTATION_ACTIONABLE_NETWORK_LABEL_SUFFIX_PATTERN.search(suffix) is not None:
                return True
            if DOCUMENTATION_PASSIVE_NETWORK_LABEL_SUFFIX_PATTERN.search(suffix) is None:
                return True
        return False

    @staticmethod
    def _documentation_package_install_is_actionable(line: bytes, position: int) -> bool:
        stripped = line.lstrip()
        leading_bytes = len(line) - len(stripped)
        match = DOCUMENTATION_PACKAGE_INSTALL_PATTERN.match(stripped)
        if match is None:
            return False
        for url_match in BARE_NETWORK_URL_TOKEN_PATTERN.finditer(line):
            if url_match.start() <= position < url_match.end():
                position = url_match.start()
                break
        relative_position = max(0, position - leading_bytes)
        if relative_position < match.end():
            return True
        return (
            DOCUMENTATION_PACKAGE_INSTALL_PROSE_TAIL_PATTERN.search(stripped[match.end() : relative_position]) is None
        )

    @staticmethod
    def _documentation_f_string_expression_contains_position(token_text: str, local_position: int) -> bool:
        prefix_match = re.match(r"(?i)(?:[rubf]*)('''|\"\"\"|'|\")", token_text)
        if prefix_match is None or "f" not in token_text[: prefix_match.start(1)].casefold():
            return False

        quote = prefix_match.group(1)
        content_start = prefix_match.end(1)
        content_end = len(token_text) - len(quote) if token_text.endswith(quote) else len(token_text)
        if local_position < content_start or local_position >= content_end:
            return False

        cursor = content_start
        while cursor < content_end:
            current = token_text[cursor]
            if current == "{" and token_text[cursor + 1 : cursor + 2] != "{":
                expression_start = cursor + 1
                cursor += 1
                depth = 1
                quote_char: str | None = None
                triple_quote = False
                escaped = False
                while cursor < content_end:
                    expression_char = token_text[cursor]
                    if escaped:
                        escaped = False
                    elif quote_char is not None:
                        if expression_char == "\\":
                            escaped = True
                        elif triple_quote and token_text.startswith(quote_char * 3, cursor):
                            cursor += 2
                            quote_char = None
                            triple_quote = False
                        elif not triple_quote and expression_char == quote_char:
                            quote_char = None
                    elif expression_char in {"'", '"'}:
                        quote_char = expression_char
                        triple_quote = token_text.startswith(expression_char * 3, cursor)
                        if triple_quote:
                            cursor += 2
                    elif expression_char == "{":
                        depth += 1
                    elif expression_char == "}":
                        depth -= 1
                        if depth == 0:
                            if expression_start <= local_position < cursor:
                                return True
                            break
                    cursor += 1
            elif current == "{" and token_text[cursor + 1 : cursor + 2] == "{":
                cursor += 1
            cursor += 1
        return False

    @staticmethod
    def _documentation_python_string_contains_position(line: bytes, position: int) -> bool:
        text = line.decode("utf-8", errors="replace")
        character_position = len(line[:position].decode("utf-8", errors="replace"))
        try:
            for current in tokenize.generate_tokens(io.StringIO(text).readline):
                if (
                    current.start[0] == 1
                    and current.end[0] == 1
                    and current.start[1] <= character_position < current.end[1]
                ):
                    if current.type == FSTRING_MIDDLE_TOKEN_TYPE:
                        return True
                    if current.type != token.STRING:
                        continue
                    local_position = character_position - current.start[1]
                    return not TextScanner._documentation_f_string_expression_contains_position(
                        current.string,
                        local_position,
                    )
        except (IndentationError, tokenize.TokenError):
            return False
        return False

    @staticmethod
    def _line_network_token_contains_position(line: bytes, start: int, end: int, position: int) -> bool:
        bounded_line = line[start:end]
        for pattern in BARE_NETWORK_TOKEN_PATTERNS:
            for match in pattern.finditer(bounded_line):
                token_start = start + match.start()
                token_end = start + match.end()
                if token_start <= position < token_end:
                    return True
        return False

    @classmethod
    def _documentation_xargs_downloader_is_actionable(cls, line: bytes, position: int) -> bool:
        for match in DOCUMENTATION_XARGS_DOWNLOADER_PATTERN.finditer(line):
            if position < match.start():
                if cls._line_network_token_contains_position(line, 0, match.start(), position):
                    return True
                continue

            cursor = match.end()
            while cursor < len(line) and line[cursor : cursor + 1] in {b" ", b"\t"}:
                cursor += 1
            if cursor >= len(line) or line[cursor : cursor + 1] in {b"`", b"'", b'"', b".", b",", b";", b"#"}:
                continue
            if cls._line_network_token_contains_position(line, cursor, len(line), position):
                return True
        return False

    @staticmethod
    def _documentation_anchored_network_command_is_actionable(line: bytes) -> bool:
        return any(
            pattern.match(line) is not None
            for pattern in (
                DOCUMENTATION_SHELL_COMMAND_PATTERN,
                DOCUMENTATION_COMMAND_ARRAY_PATTERN,
                DOCUMENTATION_SHELL_COMMAND_ARRAY_PATTERN,
                DOCUMENTATION_FIND_EXEC_DOWNLOADER_PATTERN,
                DOCUMENTATION_DOCKER_ADD_PATTERN,
                DOCUMENTATION_CERTUTIL_COMMAND_PATTERN,
                DOCUMENTATION_NETCAT_COMMAND_PATTERN,
                DOCUMENTATION_GIT_CLONE_COMMAND_PATTERN,
                DOCUMENTATION_SSH_COMMAND_PATTERN,
                DOCUMENTATION_DOCKER_PULL_COMMAND_PATTERN,
                DOCUMENTATION_POWERSHELL_COMMAND_PATTERN,
            )
        )

    @classmethod
    def _documentation_root_prompt_command_is_actionable(cls, line: bytes) -> bool:
        stripped = line.lstrip()
        if not stripped.startswith(b"#") or not cls._documentation_anchored_network_command_is_actionable(stripped):
            return False
        root_prompt_command = stripped[1:].lstrip()
        return DOCUMENTATION_ROOT_PROMPT_NON_SHELL_PREFIX_PATTERN.match(root_prompt_command) is None

    @classmethod
    def _documentation_line_is_code_shaped(cls, line: bytes, position: int) -> bool:
        prefix = line[:position]
        stripped = line.lstrip()
        shell_command_is_actionable = (
            cls._documentation_anchored_network_command_is_actionable(stripped)
            or cls._documentation_package_install_is_actionable(line, position)
            or DOCUMENTATION_INLINE_NETCAT_COMMAND_PATTERN.search(line) is not None
            or DOCUMENTATION_INLINE_POWERSHELL_COMMAND_PATTERN.search(line) is not None
            or DOCUMENTATION_INLINE_SHELL_COMMAND_PATTERN.search(prefix) is not None
            or DOCUMENTATION_SHELL_SUBSTITUTION_PATTERN.search(prefix) is not None
            or cls._documentation_xargs_downloader_is_actionable(line, position)
        )
        if cls._documentation_shell_comment_before_position(
            line, position
        ) and not cls._documentation_root_prompt_command_is_actionable(stripped):
            return False
        if (
            shell_command_is_actionable
            or DOCUMENTATION_EXECUTABLE_HTML_URL_ATTRIBUTE_PATTERN.search(prefix) is not None
            or cls._documentation_suspicious_label_is_actionable(prefix)
            or (
                DOCUMENTATION_HTML_URL_ATTRIBUTE_PATTERN.search(prefix) is None
                and cls._documentation_assignment_is_actionable(prefix)
            )
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or cls._documentation_prefix_has_enclosing_call(prefix)
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or cls._documentation_nested_config_is_actionable(prefix)
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
        ):
            return True

        statements = cls._documentation_python_statements(line)
        return any(
            isinstance(node, (ast.AnnAssign, ast.Assign, ast.AugAssign, ast.Call, ast.Lambda, ast.NamedExpr))
            for statement in statements
            for node in ast.walk(statement)
        ) or any(
            isinstance(statement, (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Import, ast.ImportFrom))
            for statement in statements
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
            stripped = previous_line.lstrip()
            if cls._documentation_shell_comment_before_position(previous_line, len(previous_line)) and not (
                cls._documentation_root_prompt_command_is_actionable(stripped)
            ):
                return False

            if (
                DOCUMENTATION_SHELL_COMMAND_PATTERN.match(stripped) is not None
                or DOCUMENTATION_PACKAGE_INSTALL_PATTERN.match(stripped) is not None
                or DOCUMENTATION_DOCKER_ADD_CONTINUATION_PATTERN.match(stripped) is not None
            ):
                return True
            if previous_line_start == context_start:
                return context_start > 0
            previous_line_end = previous_line_start - 1
        return False

    @staticmethod
    def _documentation_python_definition_contains_finding(payload: bytes, position: int) -> bool:
        line_start = payload.rfind(b"\n", 0, position) + 1
        current_line_prefix = payload[line_start:position]
        current_indent = len(current_line_prefix) - len(current_line_prefix.lstrip(b" \t"))
        if (
            current_indent == 0
            or DOCUMENTATION_PYTHON_BLOCK_VALUE_PREFIX_PATTERN.fullmatch(current_line_prefix.lstrip()) is None
        ):
            return False

        context_start = max(0, line_start - MAX_TEXT_FINDING_CONTEXT_BYTES)
        previous_line_end = line_start - 1
        target_indent = current_indent
        while previous_line_end >= context_start:
            previous_line_start = max(
                payload.rfind(b"\n", context_start, previous_line_end) + 1,
                context_start,
            )
            previous_line = payload[previous_line_start:previous_line_end]
            stripped = previous_line.strip()
            if stripped and not stripped.startswith(b"#"):
                indent = len(previous_line) - len(previous_line.lstrip(b" \t"))
                if indent < target_indent:
                    if DOCUMENTATION_PYTHON_DEFINITION_BLOCK_PATTERN.fullmatch(stripped) is not None:
                        return True
                    if DOCUMENTATION_PYTHON_NESTED_BLOCK_PATTERN.fullmatch(stripped) is None:
                        return False
                    target_indent = indent
            if previous_line_start == context_start:
                break
            previous_line_end = previous_line_start - 1
        return False

    @classmethod
    def _documentation_finding_is_actionable(cls, payload: bytes, finding: dict[str, Any]) -> bool:
        position = finding.get("position")
        if not isinstance(position, int) or position < 0 or position > len(payload):
            return False
        if cls._documentation_comment_contains_position(payload, position):
            return False
        if cls._finding_line_prefix_is_truncated(payload, finding):
            return True
        line_parts = cls._finding_line_parts(payload, finding)
        if line_parts is not None:
            line, line_position = line_parts
            if cls._documentation_line_is_code_shaped(line, line_position):
                return True
        if cls._documentation_previous_line_continues_command(payload, position):
            return True
        if cls._documentation_python_definition_contains_finding(payload, position):
            return True
        prefix = payload[max(0, position - MAX_TEXT_FINDING_CONTEXT_BYTES) : position]
        return (
            cls._documentation_assignment_is_actionable(prefix)
            or DOCUMENTATION_CODE_CALL_PATTERN.search(prefix) is not None
            or cls._documentation_prefix_has_enclosing_call(prefix)
            or DOCUMENTATION_CONFIG_MAPPING_PATTERN.search(prefix) is not None
            or cls._documentation_nested_config_is_actionable(prefix)
            or DOCUMENTATION_CONFIG_TAG_PATTERN.search(prefix) is not None
        )

    @classmethod
    def _documentation_fenced_code_ranges(cls, payload: bytes) -> tuple[tuple[tuple[int, int], ...], bool]:
        fenced_code_ranges: list[tuple[int, int]] = []
        opening_marker: bytes | None = None
        opening_end: int | None = None
        fence_markers_seen = 0
        for match in DOCUMENTATION_FENCE_LINE_PATTERN.finditer(payload):
            fence_markers_seen += 1
            if fence_markers_seen > MAX_DOCUMENTATION_FENCE_MARKERS:
                return (), True
            marker = match.group("marker")
            suffix = match.group("suffix")
            if opening_marker is None:
                if not cls._documentation_fence_match_can_open_code(match):
                    continue
                opening_marker = marker
                opening_end = match.end()
                continue
            if marker[:1] != opening_marker[:1] or len(marker) < len(opening_marker) or suffix.strip():
                continue
            if opening_end is not None and opening_end < match.start():
                fenced_code_ranges.append((opening_end, match.start()))
            opening_marker = None
            opening_end = None
        if opening_end is not None and opening_end < len(payload):
            fenced_code_ranges.append((opening_end, len(payload)))
        return tuple(fenced_code_ranges), False

    @staticmethod
    def _documentation_position_is_fenced_code(
        fenced_code_ranges: tuple[tuple[int, int], ...],
        position: int,
    ) -> bool:
        return any(range_start <= position < range_end for range_start, range_end in fenced_code_ranges)

    @classmethod
    def _documentation_fenced_passive_finding_is_informational(
        cls,
        payload: bytes,
        finding: dict[str, Any],
    ) -> bool:
        line_parts = cls._finding_line_parts(payload, finding)
        if line_parts is None:
            return True
        line, position = line_parts
        if cls._documentation_fenced_git_clone_reference_is_informational(line, finding):
            return True
        if cls._documentation_fenced_package_version_is_informational(line, position, finding):
            return True
        if cls._documentation_finding_is_actionable(payload, finding):
            return False
        if finding.get("type") in {
            "cloud_storage_url",
            "url_detected",
        } and cls._documentation_package_install_is_actionable(
            line,
            position,
        ):
            return False
        return not any(
            pattern.match(line) is not None
            for pattern in (
                DOCUMENTATION_SHELL_COMMAND_PATTERN,
                DOCUMENTATION_COMMAND_ARRAY_PATTERN,
                DOCUMENTATION_SHELL_COMMAND_ARRAY_PATTERN,
                DOCUMENTATION_FIND_EXEC_DOWNLOADER_PATTERN,
                DOCUMENTATION_DOCKER_ADD_PATTERN,
                DOCUMENTATION_CERTUTIL_COMMAND_PATTERN,
                DOCUMENTATION_NETCAT_COMMAND_PATTERN,
                DOCUMENTATION_SSH_COMMAND_PATTERN,
                DOCUMENTATION_POWERSHELL_COMMAND_PATTERN,
            )
        )

    @staticmethod
    def _documentation_fenced_git_clone_reference_is_informational(line: bytes, finding: dict[str, Any]) -> bool:
        if DOCUMENTATION_GIT_CLONE_COMMAND_PATTERN.match(line) is None:
            return False
        finding_type = finding.get("type")
        if finding_type in {"domain", "domain_name"}:
            domain = finding.get("domain")
            return isinstance(domain, str) and domain.casefold() == "github.com"
        if finding_type != "url_detected":
            return False
        url = finding.get("url")
        if not isinstance(url, str):
            return False
        try:
            parsed_url = urlsplit(url)
            raw_port = parsed_url.port
        except ValueError:
            return False
        hostname = parsed_url.hostname
        return (
            parsed_url.scheme.casefold() == "https"
            and isinstance(hostname, str)
            and hostname.casefold() == "github.com"
            and raw_port in {None, 443}
        )

    @staticmethod
    def _documentation_fenced_package_version_is_informational(
        line: bytes,
        position: int,
        finding: dict[str, Any],
    ) -> bool:
        if finding.get("type") != "ipv4_address" or DOCUMENTATION_PACKAGE_INSTALL_PATTERN.match(line.lstrip()) is None:
            return False
        ip = finding.get("ip")
        if not isinstance(ip, str):
            return False
        ip_bytes = ip.encode()
        return (
            b"://" not in line
            and line[position - 2 : position] == b"=="
            and line[position : position + len(ip_bytes)] == ip_bytes
        )

    @staticmethod
    def _documentation_loopback_api_url_is_informational(url: str) -> bool:
        try:
            parsed_url = urlsplit(url)
        except ValueError:
            return False
        hostname = parsed_url.hostname
        path = parsed_url.path.rstrip("/")
        return (
            parsed_url.scheme.casefold() in {"http", "https"}
            and isinstance(hostname, str)
            and hostname.casefold() in DOCUMENTATION_FENCED_LOOPBACK_API_HOSTS
            and (path == "/v1" or path.startswith("/v1/"))
        )

    @staticmethod
    def _documentation_fenced_passive_media_url_is_informational(url: str) -> bool:
        try:
            parsed_url = urlsplit(url)
        except ValueError:
            return False
        return (
            parsed_url.scheme.casefold() in {"http", "https"}
            and parsed_url.hostname is not None
            and DOCUMENTATION_FENCED_ACTIONABLE_URL_TOKEN_PATTERN.search(url.encode()) is None
            and parsed_url.path.casefold().endswith(DOCUMENTATION_FENCED_PASSIVE_MEDIA_URL_SUFFIXES)
        )

    @classmethod
    def _documentation_fenced_passive_assigned_url_is_informational(cls, url: str) -> bool:
        return cls._documentation_loopback_api_url_is_informational(
            url
        ) or cls._documentation_fenced_passive_media_url_is_informational(url)

    @classmethod
    def _documentation_fenced_bare_url_is_informational(cls, url: str) -> bool:
        try:
            parsed_url = urlsplit(url)
        except ValueError:
            return False
        if parsed_url.scheme.casefold() not in {"http", "https"}:
            return True
        return cls._documentation_fenced_passive_assigned_url_is_informational(url)

    @classmethod
    def _documentation_fenced_passive_network_example_is_informational(cls, fenced_code: bytes) -> bool:
        if DOCUMENTATION_FENCED_SHELL_EXECUTION_PATTERN.search(fenced_code):
            return False
        if any(
            match.group("method").lower() not in {b"get", b"head"}
            for match in DOCUMENTATION_FENCED_REQUESTS_CALL_PATTERN.finditer(fenced_code)
        ):
            return False
        direct_url_calls = tuple(DOCUMENTATION_FENCED_DIRECT_URL_CALL_PATTERN.finditer(fenced_code))
        direct_call_urls = [match.group("url").decode("utf-8", errors="ignore") for match in direct_url_calls]
        if any(not cls._documentation_fenced_passive_assigned_url_is_informational(url) for url in direct_call_urls):
            return False
        variable_call_matches = tuple(DOCUMENTATION_FENCED_URL_VARIABLE_CALL_PATTERN.finditer(fenced_code))
        allowed_call_positions = {match.start() for match in direct_url_calls} | {
            match.start() for match in variable_call_matches
        }
        if any(
            match.start() not in allowed_call_positions
            for match in DOCUMENTATION_FENCED_ALLOWED_NETWORK_CALL_PATTERN.finditer(fenced_code)
        ):
            return False
        if any(
            match.group().lower() not in {b"requests.get", b"urlopen"}
            for match in DOCUMENTATION_FENCED_NETWORK_FUNCTION_PATTERN.finditer(fenced_code)
        ):
            return False
        safe_assigned_urls = {
            (match.group("target"), match.start()): match.group("url").decode("utf-8", errors="ignore")
            for pattern in (
                DOCUMENTATION_FENCED_URL_ASSIGNMENT_PATTERN,
                DOCUMENTATION_FENCED_URL_REQUEST_ASSIGNMENT_PATTERN,
            )
            for match in pattern.finditer(fenced_code)
        }
        assignment_positions: dict[bytes, list[int]] = {}
        for match in DOCUMENTATION_FENCED_VARIABLE_ASSIGNMENT_PATTERN.finditer(fenced_code):
            assignment_positions.setdefault(match.group("target"), []).append(match.start())
        call_target_urls: list[str] = []
        for match in variable_call_matches:
            target = match.group("target")
            preceding_assignments = [
                position for position in assignment_positions.get(target, []) if position < match.start()
            ]
            if not preceding_assignments:
                return False
            assigned_url = safe_assigned_urls.get((target, preceding_assignments[-1]))
            if assigned_url is None or not cls._documentation_fenced_passive_assigned_url_is_informational(
                assigned_url
            ):
                return False
            call_target_urls.append(assigned_url)
        bare_urls = [
            match.group().decode("utf-8", errors="ignore").rstrip("`.")
            for match in DOCUMENTATION_FENCED_BARE_URL_TOKEN_PATTERN.finditer(fenced_code)
        ]
        if any(not cls._documentation_fenced_bare_url_is_informational(url) for url in bare_urls):
            return False
        if any(cls._documentation_loopback_api_url_is_informational(url) for url in bare_urls):
            return True
        return bool(call_target_urls or direct_call_urls) and all(
            cls._documentation_fenced_passive_media_url_is_informational(url)
            for url in (*call_target_urls, *direct_call_urls)
        )

    @classmethod
    def _documentation_fenced_passive_network_example_ranges(
        cls,
        payload: bytes,
        fenced_code_ranges: tuple[tuple[int, int], ...],
    ) -> tuple[tuple[int, int], ...]:
        return tuple(
            (range_start, range_end)
            for range_start, range_end in fenced_code_ranges
            if cls._documentation_fenced_passive_network_example_is_informational(payload[range_start:range_end])
        )

    @classmethod
    def _documentation_fenced_passive_network_example_contains_finding(
        cls,
        finding: dict[str, Any],
        fenced_passive_network_example_ranges: tuple[tuple[int, int], ...],
    ) -> bool:
        finding_position = finding.get("position")
        return (
            finding.get("type") in DOCUMENTATION_FENCED_PASSIVE_NETWORK_FINDING_TYPES
            and isinstance(finding_position, int)
            and cls._documentation_position_is_fenced_code(fenced_passive_network_example_ranges, finding_position)
        )

    @staticmethod
    def _documentation_fenced_network_command_is_informational(finding: dict[str, Any]) -> bool:
        if finding.get("command_type") != "git_clone":
            return False
        destination = finding.get("destination")
        return isinstance(destination, str) and destination.casefold().startswith(
            ("git@github.com:", "https://github.com/")
        )

    @classmethod
    def _documentation_fenced_finding_is_informational(
        cls,
        payload: bytes,
        finding: dict[str, Any],
        fenced_passive_network_example_ranges: tuple[tuple[int, int], ...],
    ) -> bool:
        if cls._documentation_fenced_passive_network_example_contains_finding(
            finding,
            fenced_passive_network_example_ranges,
        ):
            return True
        finding_type = finding.get("type")
        if finding_type == "network_command":
            return cls._documentation_fenced_network_command_is_informational(finding)
        if finding_type in PASSIVE_NETWORK_FINDING_TYPES:
            return cls._documentation_fenced_passive_finding_is_informational(payload, finding)
        return finding_type in {
            "cc_pattern",
            "suspicious_port",
        } and not cls._documentation_finding_is_actionable(
            payload,
            finding,
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

    @staticmethod
    def _find_documentation_token(payload: bytes, token_bytes: bytes, start: int) -> int:
        return payload.find(token_bytes, start)

    @classmethod
    def _retarget_documentation_finding(
        cls,
        payload: bytes,
        lowered_payload: bytes,
        finding: dict[str, Any],
        fenced_code_ranges: tuple[tuple[int, int], ...],
        fenced_passive_network_example_ranges: tuple[tuple[int, int], ...],
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
        next_positions = {
            token_bytes: cls._find_documentation_token(lowered_payload, token_bytes, search_start)
            for token_bytes in token_bytes_options
        }
        while True:
            if remaining_occurrences <= 0:
                return {**finding, "position": None, "severity": "INFO"}, True, 0
            matches = (
                (position, token_bytes) for token_bytes, position in next_positions.items() if position >= search_start
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
            if cls._documentation_comment_contains_position(payload, position) or (
                fenced_code_ranges
                and cls._documentation_position_is_fenced_code(fenced_code_ranges, position)
                and cls._documentation_fenced_finding_is_informational(
                    payload,
                    candidate,
                    fenced_passive_network_example_ranges,
                )
            ):
                actionable = False
            elif finding_type == "network_function":
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
            for option, next_position in next_positions.items():
                if 0 <= next_position < search_start:
                    next_positions[option] = cls._find_documentation_token(lowered_payload, option, search_start)
            if remaining_occurrences <= 0:
                if allow_exhaustion_probe and not any(position >= search_start for position in next_positions.values()):
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
        if cls._documentation_shell_comment_before_position(line, position):
            return True
        if cls._documentation_python_string_contains_position(line, position):
            return True
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
            and not cls._documentation_prefix_has_enclosing_call(line[:position])
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
        if cls._documentation_shell_comment_before_position(line, position):
            return True
        if cls._documentation_python_string_contains_position(line, position):
            return True
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
            and not cls._documentation_prefix_has_enclosing_call(prefix)
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
        if cls._documentation_shell_comment_before_position(line, position):
            return True
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
        fenced_code_ranges: tuple[tuple[int, int], ...] = (),
        fenced_passive_network_example_ranges: tuple[tuple[int, int], ...] = (),
    ) -> bool:
        if cls._is_documentation_sidecar(path):
            finding_type = finding.get("type")
            position = finding.get("position")
            if isinstance(position, int) and cls._documentation_comment_contains_position(payload, position):
                return True
            if (
                isinstance(position, int)
                and fenced_code_ranges
                and cls._documentation_position_is_fenced_code(fenced_code_ranges, position)
                and cls._documentation_fenced_finding_is_informational(
                    payload,
                    finding,
                    fenced_passive_network_example_ranges,
                )
            ):
                return True
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
        if not findings:
            return findings, False

        classified_findings: list[dict[str, Any]] = []
        classification_incomplete = False
        remaining_occurrences = MAX_DOCUMENTATION_FINDING_RETARGET_OCCURRENCES
        documentation_sidecar = cls._is_documentation_sidecar(path)
        lowered_payload = payload.lower() if documentation_sidecar else b""
        markdown_fences = documentation_sidecar and cls._documentation_uses_markdown_fences(path, payload)
        fenced_code_ranges: tuple[tuple[int, int], ...] = ()
        fenced_passive_network_example_ranges: tuple[tuple[int, int], ...] = ()
        if markdown_fences:
            fenced_code_ranges, fence_classification_incomplete = cls._documentation_fenced_code_ranges(payload)
            classification_incomplete = classification_incomplete or fence_classification_incomplete
            fenced_passive_network_example_ranges = cls._documentation_fenced_passive_network_example_ranges(
                payload,
                fenced_code_ranges,
            )
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
                    fenced_code_ranges,
                    fenced_passive_network_example_ranges,
                    remaining_occurrences,
                    index == last_retargetable_index,
                )
                classification_incomplete = classification_incomplete or retarget_incomplete
            if not retarget_incomplete and cls._sidecar_network_finding_is_informational(
                path,
                payload,
                finding,
                fenced_code_ranges,
                fenced_passive_network_example_ranges,
            ):
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
                redacted_error = redact_untrusted_error_message(error)
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Embedded secret detector failed for text content: {redacted_error}",
                    details={
                        "detector": "secrets",
                        "exception": redacted_error,
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
                redacted_error = redact_untrusted_error_message(error)
                self._mark_content_security_scan_incomplete(
                    result,
                    path,
                    reason=TEXT_CONTENT_SECURITY_DETECTOR_FAILED_REASON,
                    message=f"Network communication detector failed for text content: {redacted_error}",
                    details={
                        "detector": "network_communication",
                        "exception": redacted_error,
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
