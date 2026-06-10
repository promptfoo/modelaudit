"""Helpers for storing scanner evidence without embedded secrets."""

from __future__ import annotations

import ast
import io
import re
import shlex
import string
import tokenize
import unicodedata
from typing import Final, TypeAlias
from urllib.parse import SplitResult, parse_qsl, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

from ._evidence_redaction import (
    AUTHORIZATION_ALIAS_ASSIGNMENT_KEY as SHARED_AUTHORIZATION_ALIAS_ASSIGNMENT_KEY,
)
from ._evidence_redaction import (
    CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY as SHARED_CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY,
)
from ._evidence_redaction import (
    STANDALONE_SECRET_RE as SHARED_STANDALONE_SECRET_RE,
)

REDACTED_EVIDENCE_VALUE: Final[str] = "<redacted>"
REDACTED_URL_CREDENTIALS: Final[str] = "<credentials-redacted>"
EVIDENCE_REDACTION_LOOKAHEAD_CHARS: Final[int] = 4096
EVIDENCE_URL_LOOKAHEAD_CHARS: Final[int] = 64 * 1024
CURL_COMMAND_SCAN_CHARS: Final[int] = EVIDENCE_URL_LOOKAHEAD_CHARS
MAX_CURL_EXECUTABLE_CANDIDATES: Final[int] = 64
MAX_SUBPROCESS_CALL_CANDIDATES: Final[int] = 64
MAX_COMPARISON_CANDIDATES: Final[int] = 64
MAX_URL_QUERY_DECODE_PASSES: Final[int] = 8
MAX_NESTED_URL_QUERY_DEPTH: Final[int] = 8
MAX_EVALUATED_KEY_CHARS: Final[int] = 256
MAX_KEY_EXPRESSION_CHARS: Final[int] = 300
MAX_KEY_EXPRESSION_PARSE_ATTEMPTS: Final[int] = 64
MAX_KEY_EXPRESSION_CANDIDATES: Final[int] = 8
SENSITIVE_KEYWORD_SIGNALS: Final[tuple[str, ...]] = (
    "access",
    "api",
    "auth",
    "cookie",
    "credential",
    "jwt",
    "pass",
    "private",
    "pwd",
    "sas",
    "secret",
    "session",
    "sig",
    "storage",
    "token",
)
DICT_LOOKUP_MISSING: Final[object] = object()
DICT_LOOKUP_UNKNOWN: Final[object] = object()
NONE_COMPARABLE: Final[object] = object()
EvaluatedStringSequence: TypeAlias = list[str] | tuple[str, ...] | frozenset[str]
EvaluatedStringValue: TypeAlias = str | EvaluatedStringSequence
ComparableLiteral: TypeAlias = bool | int | EvaluatedStringValue
MembershipContainer: TypeAlias = str | list[object] | tuple[object, ...] | frozenset[object]

URL_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+")
COMMAND_URL_CONTEXT_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"']+")
PYTHON_STRING_PREFIX_RE: Final[str] = r"[rubf]{0,3}"
PYTHON_LITERAL_OPEN_RE: Final[str] = r"(?:\s*\(\s*)*"
PYTHON_STRING_LITERAL_FRAGMENT_RE: Final[str] = (
    rf"(?:{PYTHON_STRING_PREFIX_RE})(?:(?:\\*[\"']){{3}}[\s\S]*?(?:\\*[\"']){{3}}|"
    r"(?:\\*[\"'])[\s\S]*?(?:\\*[\"']))"
)
PYTHON_STRING_LITERAL_DETECT_RE: Final[re.Pattern[str]] = re.compile(PYTHON_STRING_LITERAL_FRAGMENT_RE, re.IGNORECASE)
PYTHON_LITERAL_JOINED_FRAGMENT_RE: Final[str] = (
    rf"(?:(?:\s+|\s*\+\s*|\s*%\s*\(?\s*){PYTHON_STRING_LITERAL_FRAGMENT_RE}\s*\)?)"
)
PYTHON_RESIDUAL_LITERAL_OPERATOR_RE: Final[str] = r"(?:[\(\.,+*/%]|\b(?:or|and|if|else)\b)"
QUOTED_KEY_CONTENT_PATTERN: Final[str] = rf"(?:[^\\\"']|\\[\s\S]){{0,{MAX_KEY_EXPRESSION_CHARS}}}?"
SERIALIZED_BACKSLASH_ESCAPE_TOKEN: Final[str] = (
    r"\\+(?:u+005c|x5c|134|U0000005c|u\{0*5c\}|N\{(?:reverse solidus|backslash)\})"
)
SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:u+005c|x5c|134|U0000005c|u\{0*5c\}|N\{(?:reverse solidus|backslash)\})"
)
SERIALIZED_QUOTE_ESCAPE_TOKEN: Final[str] = (
    r"(?:u+0022|u+0027|x22|x27|0?42|0?47|U00000022|U00000027|u\{0*22\}|u\{0*27\}|"
    r"N\{(?:quotation mark|double quote|apostrophe|single quote)\})"
)
SERIALIZED_QUOTE_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{SERIALIZED_BACKSLASH_ESCAPE_TOKEN})*)\\+({SERIALIZED_QUOTE_ESCAPE_TOKEN})"
)
SERIALIZED_BACKSLASH_ESCAPED_QUOTE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{SERIALIZED_BACKSLASH_ESCAPE_TOKEN})+)(\\+)([\"'])"
)
SERIALIZED_SLASH_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\\(?:x2f|u+002f|U0000002f|u\{0*2f\}|0?57|N\{solidus\})"
)
SERIALIZED_ASSIGNMENT_SEPARATOR_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\\+(?:x(?:3a|3d)|u+(?:003a|003d)|U000000(?:3a|3d)|u\{0*(?:3a|3d)\}|0?(?:72|75)|"
    r"N\{(?:colon|equals sign)\})"
)
SENSITIVE_QUERY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_key",
        "access-key",
        "access_key_id",
        "access-key-id",
        "access_token",
        "access-token",
        "api_key",
        "api-key",
        "apikey",
        "auth",
        "aws_access_key_id",
        "aws-secret-access-key",
        "aws_secret_access_key",
        "aws-session-token",
        "aws_session_token",
        "awsaccesskeyid",
        "awssecretaccesskey",
        "awssessiontoken",
        "auth_token",
        "auth-token",
        "basic_auth",
        "basic-auth",
        "client_secret",
        "client-secret",
        "cookie",
        "credential",
        "jwt",
        "passphrase",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "private-key",
        "proxy-authorization",
        "proxy_authorization",
        "proxyauthorization",
        "refresh_token",
        "refresh-token",
        "sas",
        "secret",
        "secret_key",
        "secret-key",
        "session_id",
        "session-id",
        "session_token",
        "session-token",
        "sessionid",
        "sig",
        "signature",
        "token",
        "x-amz-credential",
        "x-amz-security-token",
        "x-amz-signature",
    }
)
COMPACT_SENSITIVE_QUERY_KEYS: Final[frozenset[str]] = frozenset(
    re.sub(r"[._-]", "", key.lower()) for key in SENSITIVE_QUERY_KEYS
)
COMPACT_SENSITIVE_KEY_PREFIX: Final[str] = (
    r"(?:db|database|pg|postgres(?:ql)?|mysql|mariadb|mongo(?:db)?|redis|github|gitlab|bitbucket|slack|stripe|"
    r"npm|pypi|docker|registry|huggingface|hf|openai|anthropic|azure|gcp|google)"
)
COMPACT_PREFIXED_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{COMPACT_SENSITIVE_KEY_PREFIX}(?:password|token|secret)|"
    r"azurestoragekey|"
    r"(?-i:[A-Z0-9]+(?:PASSWORD|TOKEN|SECRET)))"
)
SEPARATED_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    r"(?:[a-z0-9]+[_.-])*"
    rf"(?:{COMPACT_PREFIXED_SENSITIVE_ASSIGNMENT_KEY}|"
    r"access[_.-]?key(?:[_.-]?id)?|access[_.-]?token|api[_.-]?key|apikey|"
    r"aws(?:accesskeyid|secretaccesskey|sessiontoken)|auth[_.-]?token|client[_.-]?secret|"
    r"auth|basic[_.-]?auth|cookie|credential|google[_.-]?access[_.-]?id|jwt|passphrase|password|passwd|"
    r"private[_.-]?key|pwd|"
    r"refresh[_.-]?token|sas|secret|"
    r"secret[_.-]?key|session[_.-]?(?:id|token)|sessionid|signature|sig|storage[_.-]?key|token)"
    r"(?:s|[0-9]+|[_.-]?values?)?"
)
CAMEL_CASE_SENSITIVE_NEAR_MATCH_SUFFIX: Final[str] = r"(?:Algorithm|Cache|Count|Format|Hint|Ingredient|Policy)"
CATBOOST_CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?![A-Za-z0-9]*{CAMEL_CASE_SENSITIVE_NEAR_MATCH_SUFFIX}\b)"
    rf"{SHARED_CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY}"
)
SENSITIVE_ASSIGNMENT_KEY: Final[str] = (
    rf"(?:{SEPARATED_SENSITIVE_ASSIGNMENT_KEY}|(?-i:{CATBOOST_CAMEL_CASE_SENSITIVE_ASSIGNMENT_KEY}))"
)
AUTHORIZATION_KEY_PATTERN: Final[str] = SHARED_AUTHORIZATION_ALIAS_ASSIGNMENT_KEY
ASSIGNMENT_SEPARATOR: Final[str] = r"(?::=|\*\*=|//=|<<=|>>=|[+\-*/%@&|^]=|[:=](?!=))"
ASSIGNMENT_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)\s*{ASSIGNMENT_SEPARATOR}\s*")
KNOWN_AUTHORIZATION_SCHEME_PATTERN: Final[str] = (
    r"(?:bearer|basic|digest|token|negotiate|ntlm|aws4-hmac-sha256|foo\.bar)"
)
COMPOUND_AUTHORIZATION_SCHEME_PATTERN: Final[str] = r"(?:digest|aws4-hmac-sha256)"
AUTHORIZATION_SCHEME_PATTERN: Final[str] = rf"(?:{KNOWN_AUTHORIZATION_SCHEME_PATTERN}\s+)?"
SENSITIVE_ASSIGNMENT_KEY_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)^{SENSITIVE_ASSIGNMENT_KEY}$")
COMPARISON_OPERATOR_PATTERN: Final[str] = (
    r"(?:===|!==|==|!=|>=|<=|<>|"
    r"(?<![<>])<(?![<=>]|redacted>|credentials-redacted>)|"
    r"(?<![<>])(?<!<redacted)(?<!<credentials-redacted)>(?![=>])|"
    r"(?<!\w)is(?:\s+not)?(?!\w)|(?<!\w)(?:not\s+)?in(?!\w))"
)
COMPARISON_OPERATOR_RE: Final[re.Pattern[str]] = re.compile(COMPARISON_OPERATOR_PATTERN, re.IGNORECASE)
AUTHORIZATION_KEY_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)^{AUTHORIZATION_KEY_PATTERN}$")
QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\\*)([\"'])({QUOTED_KEY_CONTENT_PATTERN})\1\2\s*{ASSIGNMENT_SEPARATOR}\s*"
)
KEY_LITERAL_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)(\\*)([\"'])({QUOTED_KEY_CONTENT_PATTERN})\1\2")
KEY_ESCAPE_PATTERN: Final[str] = (
    r"\\+(?:u\{([0-9a-f]+)\}|U([0-9a-f]{8})|u([0-9a-f]{4})|x([0-9a-f]{2})|([0-7]{1,3})|N\{([^}]+)\})"
)
KEY_ESCAPE_TOKEN_PATTERN: Final[str] = (
    r"\\+(?:u\{[0-9a-f]+\}|U[0-9a-f]{8}|u[0-9a-f]{4}|x[0-9a-f]{2}|[0-7]{1,3}|N\{[^}]+\})"
)
KEY_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    KEY_ESCAPE_PATTERN,
    re.IGNORECASE,
)
UNQUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?<![a-z0-9_])((?:[a-z0-9_-]|{KEY_ESCAPE_TOKEN_PATTERN})+)(\s*{ASSIGNMENT_SEPARATOR}\s*)"
)
SENSITIVE_EVIDENCE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*|"
    rf"\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}|\bbearer\s+)"
)
CURL_EXECUTABLE_NAME_PATTERN: Final[str] = r"curl(?:\.exe)?"
SHELL_COMMAND_EXECUTABLE_PATTERN: Final[str] = r"(?:bash|csh|dash|fish|ksh|mksh|sh|tcsh|zsh)"
COMMAND_EVIDENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:(?:os\.system|subprocess\.(?:popen|run|call|check_output|check_call)|eval|exec|__import__)\s*\(|"
    rf"{SHELL_COMMAND_EXECUTABLE_PATTERN}\s+-c\b|cmd\.exe\s*/c\b|powershell(?:\.exe)?\b|"
    rf"(?:{CURL_EXECUTABLE_NAME_PATTERN}|wget|nc|netcat|sshpass|redis-cli)(?=\s|$))"
    r"|(?:docker\s+login|aws\s+configure\s+set|az\s+(?:login|storage)|openssl\s+enc|poetry\s+config)\b"
)
COMMAND_CONTEXT_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:os\.system|subprocess|__import__|{SHELL_COMMAND_EXECUTABLE_PATTERN}\s+-c|cmd\.exe|powershell|"
    rf"{CURL_EXECUTABLE_NAME_PATTERN}|wget|nc\s+|netcat|"
    r"sshpass|redis-cli|docker\s+login|aws\s+configure\s+set|az\s+(?:login|storage)|openssl\s+enc|"
    r"poetry\s+config|\b(?:cat|id|touch)\b|/[A-Za-z0-9_./-]+)"
)
COMMAND_BARE_SENSITIVE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?<![-/\w.])(?!pwd(?![/\w.-])){SENSITIVE_ASSIGNMENT_KEY}(?![/\w.-])"
)
COMMAND_LITERAL_SENSITIVE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?<![-/\w.])(?!pwd(?![/\w.-])){SENSITIVE_ASSIGNMENT_KEY}(?![/\w.-])"
    rf"(?![\"']?(?:\s*[:=]\s*|\s+)[\"']?{re.escape(REDACTED_EVIDENCE_VALUE)})"
)
COMMAND_SENSITIVE_VALUE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![<\w.])[A-Za-z0-9][A-Za-z0-9_@./:=+-]{2,}(?![>\w.])"
)
COMMAND_SECRET_LONG_OPTION_NAME_PATTERN: Final[str] = (
    r"(?:account[_-]?key|storage[_-]?key|federated[_-]?token|cookie|password|passwd|passphrase|pass|"
    r"proxy-password|proxy-passphrase|proxy-pass|"
    r"proxy-tls-?password|tls-?password|ftp-account|ftp-password|http-password|oauth2-bearer|"
    r"client[_-]?secret|api[_-]?key|token|secret)"
)
COMMAND_SECRET_LONG_OPTION_PATTERN: Final[str] = rf"--{COMMAND_SECRET_LONG_OPTION_NAME_PATTERN}"
COMMAND_SECRET_OPTION_PREFIX_PATTERN: Final[str] = (
    rf"(?:(?<!\w){COMMAND_SECRET_LONG_OPTION_PATTERN}|(?<!\w)-b)(?:=|\s+)"
)
COMMAND_SECRET_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)({COMMAND_SECRET_OPTION_PREFIX_PATTERN})"
    r"(?!<\()(?:\$?\"(?:\\.|[^\"\\])*\"|\$?'(?:\\.|[^'\\])*'|[^\s\"';&|)]+)"
)
CURL_COMMAND_TRANSITION_PATTERN: Final[str] = (
    rf"(?<![-/\w.])(?:{SHELL_COMMAND_EXECUTABLE_PATTERN}|cmd\.exe|powershell(?:\.exe)?|wget|nc|netcat|"
    rf"sshpass|redis-cli|docker|aws|"
    rf"{CURL_EXECUTABLE_NAME_PATTERN})"
    r"(?=\s+-)"
)
CURL_ATTACHED_COOKIE_OPTION_PREFIX_PATTERN: Final[str] = (
    rf"\b{CURL_EXECUTABLE_NAME_PATTERN}\b"
    rf"(?:(?![;&|\n]|{CURL_COMMAND_TRANSITION_PATTERN}(?=\s|$)).){{0,{CURL_COMMAND_SCAN_CHARS}}}?"
    r"(?<=[\s\"'])-[A-Za-z]*?b"
)
CURL_ATTACHED_COOKIE_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)({CURL_ATTACHED_COOKIE_OPTION_PREFIX_PATTERN})"
    r"(?:\$?\"(?:\\.|[^\"\\,])*\"|\$?'(?:\\.|[^'\\,])*'|[^\s\"';&|)]+)"
)
COMMAND_BODY_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(?P<option>(?<!\w)(?:(?:-d|-F)(?:=|\s*)|"
    r"(?:--data(?:-ascii|-binary|-raw|-urlencode)?|--form(?:-string)?|--url-query|--post-data|--body-data)"
    r"(?:=|\s+)))"
    r"(?P<argument>\$?\"(?:\\.|[^\"\\])*\"|\$?'(?:\\.|[^'\\])*'|[^\s;&|)]+)"
)
COMMAND_SHELL_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b(?:{SENSITIVE_ASSIGNMENT_KEY})\s*=\s*)"
    r"(?P<value>\$?\"(?:\\.|[^\"\\])*\"|\$?'(?:\\.|[^'\\])*'|(?!\\+[\"'])[^\s\"';&|)]+)"
)
COMMAND_SECRET_OPTION_SERIALIZED_QUOTED_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>{COMMAND_SECRET_OPTION_PREFIX_PATTERN})"
    r"(?P<prefix>\$?)(?P<slashes>\\+)(?P<quote>[\"'])(?:(?!(?<!\\)(?P=slashes)(?P=quote))[\s\S])*?"
    r"(?<!\\)(?P=slashes)(?P=quote)"
)
CURL_ATTACHED_COOKIE_SERIALIZED_QUOTED_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>{CURL_ATTACHED_COOKIE_OPTION_PREFIX_PATTERN})"
    r"(?P<prefix>\$?)(?P<slashes>\\+)(?P<quote>[\"'])(?:(?!(?<!\\)(?P=slashes)(?P=quote)|,)[\s\S])*?"
    r"(?<!\\)(?P=slashes)(?P=quote)"
)
COMMAND_QUOTED_CREDENTIAL_CHAR_PATTERN: Final[str] = r"(?:\\.|\\\Z|(?!\\)(?!(?P=quote)).)"
COMMAND_QUOTED_CREDENTIAL_NAME_CHAR_PATTERN: Final[str] = r"(?:\\.|(?!\\)(?!:)(?!(?P=quote)).)"
COMMAND_UNQUOTED_CREDENTIAL_PASSWORD_PATTERN: Final[str] = r"(?:\\[\s\S]|(?!\\)[^\s\"';&|)])+"
COMMAND_CERT_OPTION_BOUNDARY_PATTERN: Final[str] = r"(?<![^\s\"'])"
COMMAND_CERT_OPTION_ESCAPE_PATTERN: Final[str] = r"(?:\\)?"
CURL_CERT_BUNDLE_FLAG_PATTERN: Final[str] = r"[#012346:BGIJLMNORSVZafgijklnpqsv]*"
CURL_CONFIG_SHORT_OPTION_PATTERN: Final[str] = rf"-(?-i:{CURL_CERT_BUNDLE_FLAG_PATTERN}K)"
CURL_USER_SHORT_OPTION_PATTERN: Final[str] = rf"-(?-i:{CURL_CERT_BUNDLE_FLAG_PATTERN}u)"
COMMAND_USER_OPTION_PATTERN: Final[str] = (
    rf"(?:(?<![-\w])--(?:user|proxy-user)(?![\w-])|(?<![-\w]){CURL_USER_SHORT_OPTION_PATTERN})"
)
COMMAND_CERT_OPTION_PATTERN: Final[str] = (
    rf"(?:{COMMAND_CERT_OPTION_BOUNDARY_PATTERN}{COMMAND_CERT_OPTION_ESCAPE_PATTERN}"
    rf"--(?:proxy-)?cert(?:=|\s+)|{COMMAND_CERT_OPTION_BOUNDARY_PATTERN}{COMMAND_CERT_OPTION_ESCAPE_PATTERN}"
    rf"-(?-i:{CURL_CERT_BUNDLE_FLAG_PATTERN}E)(?:=|\s*))"
)
COMMAND_CERT_PASSWORD_QUOTED_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>{COMMAND_CERT_OPTION_PATTERN})"
    rf"(?P<prefix>\$?)(?P<quote>[\"'])(?P<certificate>{COMMAND_QUOTED_CREDENTIAL_NAME_CHAR_PATTERN}*:)"
    rf"(?P<password>{COMMAND_QUOTED_CREDENTIAL_CHAR_PATTERN}+)(?P<closing>(?P=quote)|\Z)"
)
COMMAND_UNQUOTED_CERTIFICATE_NAME_CHAR_PATTERN: Final[str] = r"(?:\\[^:\r\n]|(?!\\)(?!:)[^\s\"';&|)])"
COMMAND_CERT_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?P<option>{COMMAND_CERT_OPTION_PATTERN})"
    rf"(?P<certificate>{COMMAND_UNQUOTED_CERTIFICATE_NAME_CHAR_PATTERN}*(?:\\)?:)"
    rf"(?P<password>{COMMAND_UNQUOTED_CREDENTIAL_PASSWORD_PATTERN})"
)
COMMAND_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)((?:{COMMAND_USER_OPTION_PATTERN})(?:=|\s+)?)(\$?[\"']?)([^:\s\"';&|]*:)"
    rf"({COMMAND_UNQUOTED_CREDENTIAL_PASSWORD_PATTERN})([\"']?)"
)
COMMAND_QUOTED_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?:{COMMAND_USER_OPTION_PATTERN})(?:=|\s+)?)"
    rf"(?P<prefix>\$?)(?P<quote>[\"'])(?P<username>{COMMAND_QUOTED_CREDENTIAL_NAME_CHAR_PATTERN}*:)"
    rf"(?P<password>{COMMAND_QUOTED_CREDENTIAL_CHAR_PATTERN}+)(?P<closing>(?P=quote)|\Z)"
)
COMMAND_SUBSTITUTION_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?:{COMMAND_USER_OPTION_PATTERN})(?:=|\s+)?)"
    r"(?P<username>[^:\s\"';&|]*:)(?P<password>\$\((?:\\.|[^\\)])*\))"
)
COMMAND_USER_SHELL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?:{COMMAND_USER_OPTION_PATTERN})(?:=|\s+)?)"
    r"(?P<argument>(?:\\[\s\S]|[^\s;&|)])+)"
)
COMMAND_CERT_SHELL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>{COMMAND_CERT_OPTION_PATTERN})"
    r"(?P<argument>(?:\\[\s\S]|[^\s;&|)])+)"
)
COMMAND_SEPARATELY_QUOTED_USER_SHELL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?P<option_quote>[\"'])(?:--(?:user|proxy-user)|{CURL_USER_SHORT_OPTION_PATTERN})"
    r"(?P=option_quote)\s+)"
    r"(?P<argument>(?:\\[\s\S]|[^\s;&|)])+)"
)
COMMAND_SEPARATELY_QUOTED_CERT_SHELL_WORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?P<option_quote>[\"'])(?:--(?:proxy-)?cert|-(?-i:{CURL_CERT_BUNDLE_FLAG_PATTERN}E))"
    r"(?P=option_quote)\s+)"
    r"(?P<argument>(?:\\[\s\S]|[^\s;&|)])+)"
)
COMMAND_CONFIG_QUOTED_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(?<![?&/\w-])(?P<option>(?:--)?(?:proxy-)?user\s*(?:=|:|\s+)\s*)"
    rf"(?P<prefix>\$?)(?P<quote>[\"'])(?P<username>{COMMAND_QUOTED_CREDENTIAL_NAME_CHAR_PATTERN}*:)"
    rf"(?P<password>{COMMAND_QUOTED_CREDENTIAL_CHAR_PATTERN}+)(?P<closing>(?P=quote)|\Z)"
)
COMMAND_CONFIG_USER_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?<![?&/\w-])((?:--)?(?:proxy-)?user\s*(?:=|:|\s+)\s*)(\$?[\"']?)([^:\s\"';&|]*:)"
    r"([^\"'\r\n]+)([\"']?)"
)
CURL_CONFIG_SOURCE_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<option>(?<!\w)(?:(?P<config>--config)(?:=|\s+)|"
    rf"(?P<short_config>{CURL_CONFIG_SHORT_OPTION_PATTERN})\s*|"
    r"(?P<netrc>--netrc-file)(?:=|\s+)))"
    r"(?P<source><\(|-)"
)
COMMAND_CONFIG_CERT_PASSWORD_QUOTED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(?P<option>(?<![?&/\w-])(?:--)?(?:proxy-)?cert\s*(?:=|:|\s+)\s*)"
    rf"(?P<prefix>\$?)(?P<quote>[\"'])(?P<certificate>{COMMAND_QUOTED_CREDENTIAL_NAME_CHAR_PATTERN}*:)"
    rf"(?P<password>{COMMAND_QUOTED_CREDENTIAL_CHAR_PATTERN}+)(?P<closing>(?P=quote)|\Z)"
)
COMMAND_CONFIG_UNQUOTED_CERTIFICATE_NAME_CHAR_PATTERN: Final[str] = r"(?:\\.|(?!\\)(?!:)[^\s\"';&|)])"
COMMAND_CONFIG_CERT_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?P<option>(?<![?&/\w-])(?:--)?(?:proxy-)?cert\s*(?:=|:|\s+)\s*)"
    rf"(?P<certificate>{COMMAND_CONFIG_UNQUOTED_CERTIFICATE_NAME_CHAR_PATTERN}*:)"
    rf"(?P<password>{COMMAND_UNQUOTED_CREDENTIAL_PASSWORD_PATTERN})"
)
COMMAND_NETRC_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(?<![\w-])(?P<prefix>password\s+)"
    r"(?P<value>\$?\"(?:\\.|[^\"\\])*\"|\$?'(?:\\.|[^'\\])*'|[^\s\"';&|)]+)"
)
COMMAND_TOKEN_SEPARATOR: Final[str] = r"(?:[\"']?\s*,\s*[\"']?|\s+)"
COMMAND_POSITIONAL_VALUE_SEPARATOR: Final[str] = r"(?:\s*=|\s+|[\"']?\s*,\s*)"
COMMAND_POSITIONAL_SECRET_VALUE: Final[str] = r"(?:\$?\"(?:\\.|[^\"\\])*\"|\$?'(?:\\.|[^'\\])*'|[^\s\"';&|),\]]+)"
POETRY_CONFIG_PREFIX_OPTIONS: Final[str] = rf"(?:(?:--local|--){COMMAND_TOKEN_SEPARATOR}){{0,2}}"
COMMAND_CONFIG_SECRET_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?<![?&/\w-]){COMMAND_SECRET_LONG_OPTION_NAME_PATTERN}(?![\w-])"
    rf"\s*(?:=|:|\s+)\s*)(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
NPMRC_SCOPED_AUTH_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?:^|[\s\"'])//[^\s\"';&|)=]+/:"
    rf"(?:(?:_auth(?:token)?|_password)|username)\s*=\s*)(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
NPM_CONFIG_SCOPED_AUTH_ARGUMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\bnpm{COMMAND_TOKEN_SEPARATOR}config{COMMAND_TOKEN_SEPARATOR}set"
    rf"{COMMAND_TOKEN_SEPARATOR}//[^\s\"';&|)=]+/:"
    rf"(?:(?:_auth(?:token)?|_password)|username)(?![\w-]){COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
POETRY_CONFIG_PYPI_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\bpoetry{COMMAND_TOKEN_SEPARATOR}config{COMMAND_TOKEN_SEPARATOR}"
    rf"{POETRY_CONFIG_PREFIX_OPTIONS}pypi-token\.[A-Za-z0-9_.-]+{COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
POETRY_CONFIG_HTTP_BASIC_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\bpoetry{COMMAND_TOKEN_SEPARATOR}config{COMMAND_TOKEN_SEPARATOR}"
    rf"{POETRY_CONFIG_PREFIX_OPTIONS}http-basic\.[A-Za-z0-9_.-]+{COMMAND_POSITIONAL_VALUE_SEPARATOR}"
    rf"{COMMAND_POSITIONAL_SECRET_VALUE}{COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
MYSQL_ATTACHED_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?s)(?P<prefix>(?i:\bmysql\b)(?:(?![;&|\n]).){0,1024}?(?<![\w-])-p)"
    r"(?P<value>[^\s\"';&|),\]]+)"
)
MYSQL_SEPARATED_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?s)(?P<prefix>(?i:\bmysql\b)(?:(?![;&|\n]).){{0,1024}}?(?<![\w-])-p(?![\w-])"
    rf"{COMMAND_POSITIONAL_VALUE_SEPARATOR})(?P<value>(?!\$?[\"']?-){COMMAND_POSITIONAL_SECRET_VALUE})"
)
DOCKER_LOGIN_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\bdocker{COMMAND_TOKEN_SEPARATOR}login\b"
    rf"[^;&|\n]{{0,1024}}?(?<!\w)-p(?![\w-]){COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
DOCKER_LOGIN_PASSWORD_STDIN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\bdocker{COMMAND_TOKEN_SEPARATOR}login\b"
    r"(?:(?![;&|\n]).){0,1024}?(?<!\w)--password-stdin(?![\w-])"
)
GH_AUTH_LOGIN_TOKEN_STDIN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\bgh{COMMAND_TOKEN_SEPARATOR}auth{COMMAND_TOKEN_SEPARATOR}login\b"
    r"(?:(?![;&|\n]).){0,1024}?(?<!\w)--with-token(?![\w-])"
)
SSHPASS_DEFAULT_ENV_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?s)(?P<prefix>(?<!\w)SSHPASS\s*=\s*)(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
    r"(?=(?:(?![;&|\n]).){0,1024}\bsshpass\b(?:(?![;&|\n]).){0,1024}?(?<!\w)-e(?![\w-]))"
)
SSHPASS_NAMED_ENV_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?s)(?P<prefix>(?<!\w)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
    r"(?=(?:(?![;&|\n]).){0,1024}\bsshpass\b(?:(?![;&|\n]).){0,1024}?(?<!\w)-e(?P=name)(?![A-Za-z0-9_]))"
)
SSHPASS_INLINE_FILE_SOURCE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)\bsshpass\b(?:(?![;&|\n]).){0,1024}?(?<!\w)-f(?![\w-])(?:=|\s+)\s*<\("
)
SSHPASS_FILE_DESCRIPTOR_SOURCE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)\bsshpass\b(?:(?![;&|\n]).){0,1024}?(?<!\w)-d(?:=|\s*)(?P<fd>[0-9]+)(?![0-9])"
)
COMMAND_INLINE_SECRET_SOURCE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?:(?<!\w){COMMAND_SECRET_LONG_OPTION_PATTERN}(?:=|\s+)|"
    rf"\b{CURL_EXECUTABLE_NAME_PATTERN}\b"
    rf"(?:(?![;&|\n]|{CURL_COMMAND_TRANSITION_PATTERN}(?=\s|$)).){{0,{CURL_COMMAND_SCAN_CHARS}}}?"
    r"(?<!\w)-[A-Za-z]*b(?![A-Za-z])(?:=|\s+))\s*<\("
)
CURL_INLINE_COOKIE_SOURCE_OPTION_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(?<!\w)-[A-Za-z]*b(?![A-Za-z])(?:=|\s+)\s*<\("
)
SHELL_HERE_STRING_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)<<<\s*(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
SHELL_HEREDOC_OPERATOR_RE: Final[re.Pattern[str]] = re.compile(
    r"<<(?!<)(?P<strip_tabs>-)?\s*(?P<quote>['\"]?)(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
)
STDIN_PROCESS_SUBSTITUTION_RE: Final[re.Pattern[str]] = re.compile(r"(?is)<\s*<\(")
AWS_CONFIGURE_SET_SECRET_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\baws{COMMAND_TOKEN_SEPARATOR}configure{COMMAND_TOKEN_SEPARATOR}set"
    rf"{COMMAND_TOKEN_SEPARATOR}(?:{SENSITIVE_ASSIGNMENT_KEY}){COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
COMMAND_PROGRAM_SHORT_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b(?:(?:sshpass\b[^;&|\n]{{0,1024}}?(?<!\w)-p)|"
    rf"(?:redis-cli\b[^;&|\n]{{0,1024}}?(?<!\w)-a)|"
    rf"(?:az{COMMAND_TOKEN_SEPARATOR}login\b[^;&|\n]{{0,1024}}?(?<!\w)-p)|"
    rf"(?:twine{COMMAND_TOKEN_SEPARATOR}upload\b[^;&|\n]{{0,1024}}?(?<!\w)-(?-i:p)))"
    rf"(?![\w-]){COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
OPENSSL_ENC_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\bopenssl{COMMAND_TOKEN_SEPARATOR}enc\b[^;&|\n]{{0,1024}}?"
    rf"(?<!\w)-(?P<option>k|K|pass)(?![\w-]){COMMAND_POSITIONAL_VALUE_SEPARATOR})"
    rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})"
)
SENSITIVE_FUNCTION_ARGUMENT_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\(\s*(?:{PYTHON_STRING_PREFIX_RE})"
    rf"(?P<key_quote>[\"'])(?P<key>{QUOTED_KEY_CONTENT_PATTERN})(?P=key_quote)\s*,\s*)"
)
COMPOSED_SENSITIVE_FUNCTION_ARGUMENT_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>\b(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\(\s*"
    rf"(?P<key>(?:{PYTHON_STRING_LITERAL_FRAGMENT_RE}(?:\s*[+%]\s*|\s+))+"
    rf"{PYTHON_STRING_LITERAL_FRAGMENT_RE})\s*,\s*)"
)
CAMEL_CASE_SENSITIVE_SETTER_KEY: Final[str] = (
    r"(?:[A-Z][A-Za-z0-9]*?)?"
    r"(?:AccessKey(?:Id)?|AccessToken|APIKey|ApiKey|Auth|AuthToken|Authorization|BasicAuth|ClientSecret|Cookie|"
    r"Credentials?|GoogleAccessId|JWT|Jwt|Passphrase|Password|Passwd|PrivateKey|ProxyAuthorization|Pwd|"
    r"RefreshToken|SAS|Secret|SecretKey|SessionId|SessionToken|Signature|Sig|Token)"
)
SENSITIVE_SETTER_CALL_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<callee>(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:"
    rf"set_(?P<key>{SENSITIVE_ASSIGNMENT_KEY})|"
    rf"set(?P<camel_key>(?-i:{CAMEL_CASE_SENSITIVE_SETTER_KEY}))))\s*\(\s*"
)
SENSITIVE_ARGV_PAIR_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?P<collection_prefix>[\[(,])\s*(?:{PYTHON_STRING_PREFIX_RE})?(?P<key_quote>[\"'])"
    rf"(?P<key>{QUOTED_KEY_CONTENT_PATTERN})(?P=key_quote)\s*,\s*)"
    rf"(?P<value_prefix>{PYTHON_STRING_PREFIX_RE})(?P<value_quote>[\"'])"
    rf"(?P<value>(?:\\.|(?!\\)(?!(?P=value_quote))[\s\S]){{0,{EVIDENCE_REDACTION_LOOKAHEAD_CHARS}}})"
    rf"(?P=value_quote)"
)
CURL_SHORT_COOKIE_OPTION_RE: Final[re.Pattern[str]] = re.compile(r"(?i)^-[a-z]*b$")
PYTHON_CURL_ARGV_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)^\s*(?:{PYTHON_STRING_PREFIX_RE})?(?P<quote>[\"'])"
    rf"(?:[^\"']*[\\/])?{CURL_EXECUTABLE_NAME_PATTERN}(?P=quote)(?:\s*,|\s*$)"
)
CURL_EXECUTABLE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?<![-\w.])(?P<executable>{CURL_EXECUTABLE_NAME_PATTERN})(?=$|[\s\"',)\]])"
)
CURL_SCAN_PREFIX_RE: Final[re.Pattern[str]] = re.compile(rf"(?i)\b{CURL_EXECUTABLE_NAME_PATTERN}\b")
CURL_STATIC_SHELL_EXECUTABLE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?<![-\w.])(?P<executable>"
    r"(?=[^\s;&|(),\[\]{}]*[\"'\\])"
    r"[\"'\\]*c[\"'\\]*u[\"'\\]*r[\"'\\]*l"
    r"(?:[\"'\\]*\.[\"'\\]*e[\"'\\]*x[\"'\\]*e)?[\"'\\]*)"
    r"(?=$|[\s\"',)\]])"
)
SERIALIZED_STRUCTURED_QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<prefix>(?:^|[{{,])\s*)(?P<slashes>\\+)(?P<quote>[\"'])"
    rf"(?P<key>{QUOTED_KEY_CONTENT_PATTERN})(?P=slashes)(?P=quote)\s*:\s*"
)
FUNCTION_KEYWORD_ARGUMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*"
)
SUBPROCESS_CALL_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)\bsubprocess\.(?:popen|run|call|check_output|check_call)\s*\(\s*"
)
FUNCTION_CALL_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"(?i)\b(?P<callee>[A-Za-z_][A-Za-z0-9_.]*)\s*\(\s*")
STANDALONE_SECRET_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|[A-Za-z0-9_+/=-]{32,})\b"
)
HIGH_ENTROPY_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|[A-Za-z0-9_+/=-]{24,})\b")
COMMAND_SENSITIVE_HEADER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*:\s*)"
    r"(?:\$?\"[^\"]*\"|\$?'[^']*'|[^\s\"';&|)]+)"
)
COMMAND_QUOTED_COOKIE_HEADER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(\$?(?P<cookie_quote>[\"'])cookie\s*:\s*)"
    r"(?:\\.|(?!\\)(?!(?P=cookie_quote)).)*(?P=cookie_quote)"
)
COMMAND_STRUCTURED_SENSITIVE_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)((?P<key_quote>[\"'])(?:{SENSITIVE_ASSIGNMENT_KEY}|{AUTHORIZATION_KEY_PATTERN})"
    rf"(?P=key_quote)\s*:\s*)(?P<value_quote>[\"'])(?:\\.|(?!\\)(?!(?P=value_quote)).)*(?P=value_quote)"
)
EMBEDDED_CONTROL_QUOTED_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<quote>[\"'])(?P<key>(?:\\.|(?!\\)(?!(?P=quote))[\s\S]){{1,128}})(?P=quote)"
    rf"(?P<separator>\s*{ASSIGNMENT_SEPARATOR}\s*)"
)
STRUCTURED_SENSITIVE_KEY_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(?:^|[{{,])\s*[\"'](?:{SENSITIVE_ASSIGNMENT_KEY}|{AUTHORIZATION_KEY_PATTERN})[\"']\s*:"
)
REDACTED_STRUCTURED_VALUE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"^\s*(?P<slashes>\\*)(?P<quote>[\"']){re.escape(REDACTED_EVIDENCE_VALUE)}"
    rf"(?P=slashes)(?P=quote)\s*(?=[,\]}})]|$)"
)
REDACTED_VALUE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    rf"^\s*{re.escape(REDACTED_EVIDENCE_VALUE)}(?=\s|[\"',;\])}}]|$)"
)
AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{KNOWN_AUTHORIZATION_SCHEME_PATTERN}\s+)"
    r"([^\"'\s;&|]+)"
)
COMPOUND_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{COMPOUND_AUTHORIZATION_SCHEME_PATTERN}\s+)"
    rf"((?:(?!\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}).)*?)"
    rf"(?=[\"';&|\n]|$|\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}|\bbearer\s+)"
)
BARE_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*)"
    rf"(?!{KNOWN_AUTHORIZATION_SCHEME_PATTERN}\s+)[^\"'\s;&|]+"
)
UNKNOWN_AUTHORIZATION_SCHEME_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*)"
    rf"(?!{KNOWN_AUTHORIZATION_SCHEME_PATTERN}\s+)"
    rf"([^\"'\s;&|]+)(\s+)(?!{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR})([^\"'\s;&|]+)"
)
TRIPLE_QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3[\s\S]*?\2\3\2\3\2\3"
)
TRIPLE_QUOTED_AUTHORIZATION_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3"
)
QUOTED_AUTHORIZATION_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\2\3"
)
QUOTED_AUTHORIZATION_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN}){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"(?i)(\bbearer\s+)[^\"'\s;&|]+")
TRIPLE_QUOTED_BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3[\s\S]*?\2\3\2\3\2\3"
)
TRIPLE_QUOTED_BEARER_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\2\3\2\3"
)
QUOTED_BEARER_VALUE_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\2\3"
)
QUOTED_BEARER_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)"
    rf"((?:(?!\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}).)*?)"
    rf"(?=,|;|}}|\]|&|\||\n|$|\b{SENSITIVE_ASSIGNMENT_KEY}\s*{ASSIGNMENT_SEPARATOR}|\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}|\bbearer\s+)"
)
URL_PATH_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)\b(?P<prefix>(?:{SENSITIVE_ASSIGNMENT_KEY}|{AUTHORIZATION_KEY_PATTERN})\s*[:=]\s*)"
)
TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\3\4\3\4[\s\S]*?\3\4\3\4\3\4"
)
TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])\3\4\3\4"
)
QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"']).*?\3\4"
)
STRUCTURED_QUOTED_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?is)(?P<container_prefix>(?:^|[{{,])\s*)\b"
    rf"(?P<prefix>({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)"
    rf"(?P<slashes>\\*)(?P<quote>[\"'])(?P<value>.*?)(?P=slashes)(?P=quote)(?=\s*[,}}])"
)
QUOTED_SENSITIVE_ASSIGNMENT_START_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*){PYTHON_LITERAL_OPEN_RE}(?:{PYTHON_STRING_PREFIX_RE})(\\*)([\"'])"
)
ADJACENT_LITERAL_AUTHORIZATION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN})[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
ADJACENT_LITERAL_BEARER_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+)[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
ADJACENT_LITERAL_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)[^\s;&|]*{re.escape(REDACTED_EVIDENCE_VALUE)}[^\s;&|]*(?:{PYTHON_LITERAL_JOINED_FRAGMENT_RE})+"
)
RESIDUAL_LITERAL_AUTHORIZATION_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\b{AUTHORIZATION_KEY_PATTERN}\s*{ASSIGNMENT_SEPARATOR}\s*{AUTHORIZATION_SCHEME_PATTERN})[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
)
RESIDUAL_LITERAL_BEARER_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)(\bbearer\s+)[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
)
RESIDUAL_LITERAL_SENSITIVE_ASSIGNMENT_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?i)\b(({SENSITIVE_ASSIGNMENT_KEY})\s*{ASSIGNMENT_SEPARATOR}\s*)[^;&|\n]*?{re.escape(REDACTED_EVIDENCE_VALUE)}[^;&|\n]*{PYTHON_RESIDUAL_LITERAL_OPERATOR_RE}[^;&|\n]*{PYTHON_STRING_LITERAL_FRAGMENT_RE}[^;&|\n]*"
)


def _redact_malformed_url(raw_url: str) -> str:
    """Fail closed for URL-like strings that the parser rejects."""
    scheme_match = re.match(r"(?i)^([a-z][a-z0-9+.-]*://)(.*)$", raw_url)
    if scheme_match is None:
        return REDACTED_EVIDENCE_VALUE

    scheme, rest = scheme_match.groups()
    rest = re.split(r"[?#]", rest, maxsplit=1)[0]
    if "@" not in rest:
        return f"{scheme}{REDACTED_EVIDENCE_VALUE}"

    return f"{scheme}{REDACTED_URL_CREDENTIALS}@{rest.rsplit('@', 1)[1]}"


def _decode_query_component(value: str) -> tuple[str, bool]:
    decoded = value
    for _ in range(MAX_URL_QUERY_DECODE_PASSES):
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            return decoded, True
        decoded = next_decoded
    return decoded, unquote_plus(decoded) == decoded


def _decode_path_component(value: str) -> tuple[str, bool]:
    decoded = value
    for _ in range(MAX_URL_QUERY_DECODE_PASSES):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            return decoded, True
        decoded = next_decoded
    return decoded, unquote(decoded) == decoded


def _redact_sensitive_url_path(path: str) -> str:
    decoded_path, decoding_complete = _decode_path_component(path)
    if not decoding_complete:
        return REDACTED_EVIDENCE_VALUE

    provider_redacted_path = _redact_standalone_secret_tokens(decoded_path)
    if provider_redacted_path != decoded_path:
        return provider_redacted_path

    match = URL_PATH_SENSITIVE_ASSIGNMENT_RE.search(decoded_path)
    if match is None:
        return path
    return f"{decoded_path[: match.end()]}{REDACTED_EVIDENCE_VALUE}"


def _redacted_sensitive_query_key(key: str) -> str | None:
    decoded_key, decoding_complete = _decode_query_component(key)
    if not decoding_complete:
        return "credential"

    assignment_match = re.search(
        rf"(?is)(?:^|[?&;])(?:amp;)?\s*"
        rf"(?P<key>{SENSITIVE_ASSIGNMENT_KEY}|{AUTHORIZATION_KEY_PATTERN})\s*[:=]",
        decoded_key,
    )
    if assignment_match is not None:
        return _normalize_sensitive_key(assignment_match.group("key")) or "credential"
    if STRUCTURED_SENSITIVE_KEY_RE.search(decoded_key):
        return "credential"

    normalized_key = re.sub(r"(?:\[[^\]]*\])+$", "", decoded_key)
    compact_key = re.sub(r"[._-]", "", normalized_key.lower())
    if (
        normalized_key.lower() in SENSITIVE_QUERY_KEYS
        or compact_key in COMPACT_SENSITIVE_QUERY_KEYS
        or _normalize_sensitive_key(normalized_key) is not None
    ):
        return decoded_key
    return None


def _is_sensitive_query_key(key: str) -> bool:
    return _redacted_sensitive_query_key(key) is not None


def _url_authority_contains_secret(parsed: SplitResult) -> bool:
    if "@" in parsed.netloc:
        return True
    if ":" not in parsed.netloc:
        return False
    try:
        _ = parsed.port
    except ValueError:
        return True
    return False


def _query_contains_secret(query: str, *, nested_depth: int) -> bool:
    for part in re.split(r"[&;]", query):
        for key, nested_value in parse_qsl(part, keep_blank_values=True):
            if _is_sensitive_query_key(key):
                return True
            if nested_depth >= MAX_NESTED_URL_QUERY_DEPTH:
                return True
            if _query_value_contains_secret(nested_value, nested_depth=nested_depth + 1):
                return True
    return False


def _query_value_contains_secret(value: str, *, nested_depth: int = 0) -> bool:
    decoded, decoding_complete = _decode_query_component(value)
    if not decoding_complete:
        return True

    if re.search(
        rf"(?i)(?:^|[?&;])\s*(?:{SENSITIVE_ASSIGNMENT_KEY}|{AUTHORIZATION_KEY_PATTERN})\s*[:=]",
        decoded,
    ):
        return True
    if BEARER_VALUE_RE.search(decoded):
        return True
    if STRUCTURED_SENSITIVE_KEY_RE.search(decoded):
        return True

    try:
        parsed_reference = urlsplit(decoded)
    except ValueError:
        return True
    if parsed_reference is not None:
        if _url_authority_contains_secret(parsed_reference):
            return True
        if _redact_sensitive_url_path(parsed_reference.path) != parsed_reference.path:
            return True
        if parsed_reference.query and _query_contains_secret(
            parsed_reference.query,
            nested_depth=nested_depth,
        ):
            return True
        if parsed_reference.fragment:
            if nested_depth >= MAX_NESTED_URL_QUERY_DEPTH:
                return True
            if _query_value_contains_secret(
                parsed_reference.fragment,
                nested_depth=nested_depth + 1,
            ):
                return True

    for nested_url in URL_RE.finditer(decoded):
        try:
            parsed = urlsplit(nested_url.group(0))
        except ValueError:
            return True
        if _url_authority_contains_secret(parsed):
            return True
        if _redact_sensitive_url_path(parsed.path) != parsed.path:
            return True
        if _query_contains_secret(parsed.query, nested_depth=nested_depth):
            return True
        if parsed.fragment:
            if nested_depth >= MAX_NESTED_URL_QUERY_DEPTH:
                return True
            if _query_value_contains_secret(parsed.fragment, nested_depth=nested_depth + 1):
                return True
    return False


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return _redact_malformed_url(raw_url)

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = f"{REDACTED_URL_CREDENTIALS}@{netloc.rsplit('@', 1)[1]}"
    elif ":" in netloc:
        try:
            _ = parsed.port
        except ValueError:
            netloc = REDACTED_URL_CREDENTIALS

    query_parts: list[str] = []
    for part in re.split(r"([&;])", parsed.query):
        if part in {"&", ";"}:
            query_parts.append(part)
            continue

        query_items = []
        for key, value in parse_qsl(part, keep_blank_values=True):
            redacted_key = _redacted_sensitive_query_key(key)
            is_sensitive = redacted_key is not None or _query_value_contains_secret(value)
            query_items.append((redacted_key or key, REDACTED_EVIDENCE_VALUE if is_sensitive else value))
        query_parts.append(urlencode(query_items, doseq=True, safe="<>") if query_items else part)

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            _redact_sensitive_url_path(parsed.path),
            "".join(query_parts),
            "",
        )
    )


def _normalize_serialized_quote_escapes(text: str) -> str:
    def is_single_quote_escape(token: str) -> bool:
        quote_token = token.lower()
        return (
            quote_token in {"x27", "47", "047", "u00000027"}
            or re.fullmatch(r"u+0027", quote_token) is not None
            or re.fullmatch(r"u\{0*27\}", quote_token) is not None
            or "apostrophe" in quote_token
            or "single" in quote_token
        )

    def replace_backslash_quote(match: re.Match[str]) -> str:
        encoded_backslashes = len(SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE.findall(match.group(1)))
        quote_backslashes = len(match.group(2))
        return "\\" * (encoded_backslashes + quote_backslashes) + match.group(3)

    def replace_escape(match: re.Match[str]) -> str:
        encoded_backslashes = len(SERIALIZED_BACKSLASH_ESCAPE_VALUE_RE.findall(match.group(1)))
        quote = "'" if is_single_quote_escape(match.group(2)) else '"'
        return "\\" * (encoded_backslashes + 1) + quote

    text = SERIALIZED_BACKSLASH_ESCAPED_QUOTE_RE.sub(replace_backslash_quote, text)
    return SERIALIZED_QUOTE_ESCAPE_RE.sub(replace_escape, text)


def _normalize_serialized_url_slashes(text: str) -> str:
    """Restore serialized slash escapes so URL credentials cannot evade parsing."""
    for _ in range(3):
        normalized = SERIALIZED_SLASH_ESCAPE_RE.sub("/", text.replace(r"\/", "/"))
        if normalized == text:
            break
        text = normalized
    return text


def _normalize_serialized_assignment_separators(text: str) -> str:
    """Restore escaped ':' and '=' separators before sensitive-key matching."""

    def replace_separator(match: re.Match[str]) -> str:
        token = match.group(0).lower()
        return ":" if "3a" in token or "72" in token or "colon" in token else "="

    return SERIALIZED_ASSIGNMENT_SEPARATOR_ESCAPE_RE.sub(replace_separator, text)


def _escape_evidence_controls(text: str) -> str:
    """Render control and format characters inert before evidence is persisted."""
    escaped: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char == "\n":
            escaped.append(r"\n")
        elif char == "\r":
            escaped.append(r"\r")
        elif char == "\t":
            escaped.append(r"\t")
        elif category in {"Cc", "Cf", "Cs"} or not char.isprintable():
            codepoint = ord(char)
            escaped.append(f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _normalize_embedded_control_sensitive_keys(text: str) -> str:
    """Remove invisible separators only when they conceal a sensitive assignment key."""

    def normalize_key(raw_key: str) -> str | None:
        normalized = "".join(char for char in raw_key if unicodedata.category(char) not in {"Cc", "Cf", "Cs"})
        if normalized == raw_key:
            return None
        return _normalize_sensitive_key(normalized)

    def replace_quoted(match: re.Match[str]) -> str:
        normalized = normalize_key(match.group("key"))
        if normalized is None:
            return match.group(0)
        quote = match.group("quote")
        return f"{quote}{normalized}{quote}{match.group('separator')}"

    text = EMBEDDED_CONTROL_QUOTED_KEY_RE.sub(replace_quoted, text)
    unquoted_pattern = re.compile(
        rf"(?is)(?<![\w.-])(?P<key>[^\s\"'=:;,\[\](){{}}]{{1,128}})"
        rf"(?P<separator>\s*{ASSIGNMENT_SEPARATOR}\s*)"
    )

    def replace_unquoted(match: re.Match[str]) -> str:
        normalized = normalize_key(match.group("key"))
        if normalized is None:
            return match.group(0)
        return f"{normalized}{match.group('separator')}"

    return unquoted_pattern.sub(replace_unquoted, text)


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    slash = match.group(3)
    quote = match.group(4)
    return f"{match.group(1)}{slash}{quote}{REDACTED_EVIDENCE_VALUE}{slash}{quote}"


def _redact_structured_quoted_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    safe_value = (
        _redact_sensitive_command_value(value) if COMMAND_EVIDENCE_RE.search(value) else REDACTED_EVIDENCE_VALUE
    )
    return (
        f"{match.group('container_prefix')}{match.group('prefix')}{match.group('slashes')}{match.group('quote')}"
        f"{safe_value}{match.group('slashes')}{match.group('quote')}"
    )


def _redact_quoted_authorization(match: re.Match[str]) -> str:
    slash = match.group(2)
    quote = match.group(3)
    return f"{match.group(1)}{slash}{quote}{REDACTED_EVIDENCE_VALUE}{slash}{quote}"


def _redact_prefixed_quoted_value(match: re.Match[str]) -> str:
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}"


def _decode_key_escapes(key: str) -> str:
    def replace_escape(match: re.Match[str]) -> str:
        if match.group(6) is not None:
            try:
                return unicodedata.lookup(match.group(6))
            except KeyError:
                return match.group(0)

        raw_value = next(group for group in match.groups()[:5] if group is not None)
        codepoint = int(raw_value, 8 if match.group(5) is not None else 16)
        if codepoint > 0x10FFFF:
            return match.group(0)
        return chr(codepoint)

    return KEY_ESCAPE_RE.sub(replace_escape, key)


def _normalize_quoted_sensitive_keys(text: str) -> str:
    def replace_key(match: re.Match[str]) -> str:
        if _is_composed_key_fragment(text, match.start()):
            return match.group(0)
        decoded_key = _decode_key_escapes(match.group(3))
        normalized_key = _normalize_sensitive_key(decoded_key)
        if normalized_key is not None:
            return f"{normalized_key}="
        return match.group(0)

    text = _normalize_composed_quoted_sensitive_keys(text)
    return QUOTED_KEY_RE.sub(replace_key, text)


def _sensitive_key_from_composed_literal_expression(expression: str) -> str | None:
    if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
        return None
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(expression).readline))
    except (IndentationError, tokenize.TokenError):
        return None

    literal_count = 0
    for token in tokens:
        if token.type == tokenize.STRING:
            literal_count += 1
        elif token.type == tokenize.OP and token.string in {"+", "(", ")"}:
            continue
        elif token.type not in {tokenize.NEWLINE, tokenize.NL, tokenize.ENDMARKER}:
            return None
    if literal_count < 2:
        return None
    return _sensitive_key_from_safe_expression(expression)


def _normalize_composed_quoted_sensitive_keys(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    parse_attempts = 0
    for separator in ASSIGNMENT_SEPARATOR_RE.finditer(text):
        separator_text = separator.group(0)
        operator = separator_text.strip()
        operator_start = separator.start() + len(separator_text) - len(separator_text.lstrip())
        if operator == "=" and operator_start > 0 and text[operator_start - 1] in "=!<>":
            continue
        if _is_inside_quoted_literal(text, 0, separator.start()):
            continue

        window_start = max(0, separator.start() - MAX_KEY_EXPRESSION_CHARS)
        window_start = _last_unquoted_statement_boundary(text, window_start, separator.start())
        for expression_start in _candidate_expression_starts(text, window_start, separator.start()):
            if parse_attempts >= MAX_KEY_EXPRESSION_PARSE_ATTEMPTS:
                break
            raw_expression = text[expression_start : separator.start()]
            expression = raw_expression.strip()
            if KEY_LITERAL_RE.search(expression) is None:
                continue
            parse_attempts += 1
            normalized_key = _sensitive_key_from_composed_literal_expression(expression)
            if normalized_key is None:
                continue
            leading = raw_expression[: len(raw_expression) - len(raw_expression.lstrip())]
            replacements.append((expression_start, separator.end(), f"{leading}{normalized_key}="))
            break

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _normalize_serialized_structured_sensitive_keys(text: str) -> str:
    """Normalize escaped quoted keys that follow JSON/object delimiters."""

    def replace_key(match: re.Match[str]) -> str:
        normalized_key = _normalize_sensitive_key(_decode_key_escapes(match.group("key")))
        if normalized_key is None:
            return match.group(0)
        return f"{match.group('prefix')}{normalized_key}="

    return SERIALIZED_STRUCTURED_QUOTED_KEY_RE.sub(replace_key, text)


def _normalize_unquoted_sensitive_keys(text: str) -> str:
    if "=" not in text and ":" not in text:
        return text

    def replace_key(match: re.Match[str]) -> str:
        decoded_key = _decode_key_escapes(match.group(1))
        normalized_key = _normalize_sensitive_key(decoded_key)
        if normalized_key is not None:
            return f"{normalized_key}{match.group(2)}"
        return match.group(0)

    return UNQUOTED_KEY_RE.sub(replace_key, text)


def _normalize_subscript_sensitive_keys(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        if text[index] != "[" or _is_inside_quoted_literal(text, 0, index):
            index += 1
            continue
        expression_end = _find_subscript_expression_end(text, index)
        if expression_end is None:
            index += 1
            continue
        separator_match = ASSIGNMENT_SEPARATOR_RE.match(text, expression_end + 1)
        if separator_match is None:
            index = expression_end + 1
            continue

        expression = text[index + 1 : expression_end].strip()
        normalized_key = _sensitive_key_from_safe_expression(expression)
        if normalized_key is not None:
            replacement_start = _subscript_target_start(text, index)
            replacements.append(
                (
                    replacement_start,
                    separator_match.end(),
                    f"{normalized_key}{separator_match.group(0)}",
                )
            )
        index = expression_end + 1

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _sensitive_key_from_safe_expression(expression: str) -> str | None:
    if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
        return None
    if not _has_sensitive_literal_signal(expression):
        return None
    try:
        value = _safe_eval_string_expr(ast.parse(expression, mode="eval"))
    except SyntaxError:
        value = None
    return _normalize_sensitive_key(value) if isinstance(value, str) else None


def _sensitive_function_key_from_safe_expression(expression: str) -> str | None:
    if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS or not _has_sensitive_literal_signal(expression):
        return None
    try:
        value = _safe_eval_string_expr(ast.parse(expression, mode="eval"))
    except SyntaxError:
        return None
    values = (value,) if isinstance(value, str) else value
    if not isinstance(values, (list, tuple, frozenset)):
        return None
    for candidate in values:
        normalized_key = _normalize_sensitive_function_key(candidate)
        if normalized_key is not None:
            return normalized_key
    return None


def _subscript_target_start(text: str, bracket_start: int) -> int:
    index = bracket_start - 1
    while index >= 0 and text[index].isspace():
        index -= 1
    target_end = index + 1
    while index >= 0 and (text[index].isalnum() or text[index] in {"_", "."}):
        index -= 1
    target_start = index + 1
    target = text[target_start:target_end]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", target):
        return target_start
    return bracket_start


def _find_subscript_expression_end(text: str, start: int) -> int | None:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start + 1
    while index < len(text):
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char == "[":
            bracket_depth += 1
        elif char == "]":
            if bracket_depth == 0:
                return index
            bracket_depth -= 1
        elif char in {";", "\n"}:
            return None
        index += 1
    return None


def _normalize_sensitive_key(decoded_key: str) -> str | None:
    if SENSITIVE_ASSIGNMENT_KEY_RE.fullmatch(decoded_key):
        return decoded_key
    if AUTHORIZATION_KEY_RE.fullmatch(decoded_key):
        return "Authorization"
    return None


def _redact_standalone_secret_tokens(text: str) -> str:
    """Redact shared provider tokens plus CatBoost's generic opaque-token forms."""
    return STANDALONE_SECRET_TOKEN_RE.sub(
        REDACTED_EVIDENCE_VALUE,
        _redact_shared_provider_tokens(text),
    )


def _redact_shared_provider_tokens(text: str) -> str:
    return SHARED_STANDALONE_SECRET_RE.sub(REDACTED_EVIDENCE_VALUE, text)


def _is_composed_key_fragment(text: str, start: int) -> bool:
    prefix = text[:start].rstrip()
    return bool(prefix) and (prefix[-1] in {"+", "%", "'", '"'})


def _safe_eval_string_expr(node: ast.AST) -> EvaluatedStringValue | None:
    if isinstance(node, ast.Expression):
        return _safe_eval_string_expr(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if len(node.value) <= MAX_EVALUATED_KEY_CHARS else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for joined_value in node.values:
            if isinstance(joined_value, ast.Constant) and isinstance(joined_value.value, str):
                parts.append(joined_value.value)
                continue
            if (
                isinstance(joined_value, ast.FormattedValue)
                and joined_value.conversion in {-1, ord("s")}
                and _safe_eval_format_spec(joined_value.format_spec) in {None, "", "s"}
            ):
                formatted_value = _safe_eval_string_expr(joined_value.value)
                if isinstance(formatted_value, str):
                    parts.append(formatted_value)
                    continue
            return None
        return _join_bounded(parts)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for element in node.elts:  # type: ignore[attr-defined]
            element_value = _safe_eval_string_expr(element)
            if not isinstance(element_value, str):
                return None
            values.append(element_value)
        if isinstance(node, ast.List):
            return _list_bounded(values)
        if isinstance(node, ast.Set):
            return _frozenset_bounded(values)
        return _tuple_bounded(values)
    if isinstance(node, ast.IfExp):
        condition = _safe_eval_truthy_literal(node.test)
        if condition is not None:
            return _safe_eval_string_expr(node.body if condition else node.orelse)
    if isinstance(node, ast.BoolOp):
        last_value: str | None = None
        for value_node in node.values:
            value = _safe_eval_string_expr(value_node)
            if not isinstance(value, str):
                return None
            last_value = value
            if isinstance(node.op, ast.Or) and value:
                return value
            if isinstance(node.op, ast.And) and not value:
                return value
        if last_value is None:
            return None
        if isinstance(node.op, (ast.Or, ast.And)):
            return last_value
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Dict):
            key = _safe_eval_string_expr(node.slice)
            if isinstance(key, str):
                return _safe_eval_string_dict_lookup(node.value, key)
        base = _safe_eval_string_expr(node.value)
        if isinstance(base, str):
            value_slice = _safe_eval_slice(node.slice)
            if value_slice is not None:
                sliced = base[value_slice]
                return sliced if len(sliced) <= MAX_EVALUATED_KEY_CHARS else None
        index = _safe_eval_int_literal(node.slice)
        if isinstance(base, (tuple, list)) and index is not None and -len(base) <= index < len(base):
            return base[index]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str) and isinstance(right, str):
            return _join_bounded([left, right])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str):
            multiplier = _safe_eval_int_literal(node.right)
            if multiplier is not None:
                return _repeat_bounded(left, multiplier)
        if isinstance(right, str):
            multiplier = _safe_eval_int_literal(node.left)
            if multiplier is not None:
                return _repeat_bounded(right, multiplier)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = _safe_eval_string_expr(node.left)
        right = _safe_eval_string_expr(node.right)
        if isinstance(left, str) and isinstance(right, (str, tuple)):
            return _safe_percent_literal(left, right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "chr"
        and len(node.args) == 1
        and not node.keywords
    ):
        codepoint = _safe_eval_int_literal(node.args[0])
        if codepoint is not None and 0 <= codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF:
            return chr(codepoint)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decode"
        and len(node.args) <= 1
        and not node.keywords
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id in {"bytes", "bytearray"}
        and len(node.func.value.args) == 1
        and not node.func.value.keywords
        and isinstance(node.func.value.args[0], (ast.List, ast.Tuple))
    ):
        encoding = _safe_eval_string_expr(node.args[0]) if node.args else "utf-8"
        if isinstance(encoding, str) and encoding.lower().replace("_", "-") in {"ascii", "utf-8", "utf8"}:
            byte_values: list[int] = []
            for element in node.func.value.args[0].elts:
                int_value = _safe_eval_int_literal(element)
                if int_value is None or not 0 <= int_value <= 255:
                    return None
                byte_values.append(int_value)
            if len(byte_values) <= MAX_EVALUATED_KEY_CHARS:
                try:
                    decoded = bytes(byte_values).decode(encoding)
                except (LookupError, UnicodeDecodeError):
                    return None
                return decoded if len(decoded) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decode"
        and not node.keywords
        and len(node.args) <= 1
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Attribute)
        and node.func.value.func.attr == "encode"
        and not node.func.value.keywords
        and len(node.func.value.args) <= 1
    ):
        base = _safe_eval_string_expr(node.func.value.func.value)
        encode_arg = _safe_eval_string_expr(node.func.value.args[0]) if node.func.value.args else "utf-8"
        decode_arg = _safe_eval_string_expr(node.args[0]) if node.args else "utf-8"
        if isinstance(base, str) and encode_arg == decode_arg and isinstance(encode_arg, str):
            return base
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        base = _safe_eval_string_expr(node.func.value)
        args = tuple(_safe_eval_string_expr(arg) for arg in node.args)
        kwargs = {
            keyword.arg: _safe_eval_string_expr(keyword.value) for keyword in node.keywords if keyword.arg is not None
        }
        if (
            isinstance(base, str)
            and all(isinstance(arg, str) for arg in args)
            and len(kwargs) == len(node.keywords)
            and all(isinstance(value, str) for value in kwargs.values())
        ):
            return _safe_format_literal(base, args, kwargs)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"strip", "lstrip", "rstrip"}
    ):
        base = _safe_eval_string_expr(node.func.value)
        if isinstance(base, str) and len(node.args) <= 1 and not node.keywords:
            chars = _safe_eval_string_expr(node.args[0]) if node.args else None
            if node.args and not isinstance(chars, str):
                return None
            if chars == "":
                return None
            result = getattr(base, node.func.attr)(chars)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"capitalize", "casefold", "lower", "swapcase", "title", "upper"}
        and not node.args
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        if isinstance(base, str):
            result = getattr(base, node.func.attr)()
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"removeprefix", "removesuffix"}
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        affix = _safe_eval_string_expr(node.args[0])
        if isinstance(base, str) and isinstance(affix, str):
            result = getattr(base, node.func.attr)(affix)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"split", "rsplit"}
        and len(node.args) <= 2
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        separator = _safe_eval_string_expr(node.args[0]) if node.args else None
        maxsplit = _safe_eval_int_literal(node.args[1]) if len(node.args) == 2 else -1
        if (
            isinstance(base, str)
            and (not node.args or isinstance(separator, str))
            and (len(node.args) < 2 or maxsplit is not None)
            and separator != ""
        ):
            parts = getattr(base, node.func.attr)(separator, maxsplit)
            return _tuple_bounded(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"partition", "rpartition"}
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        separator = _safe_eval_string_expr(node.args[0])
        if isinstance(base, str) and isinstance(separator, str) and separator:
            return _tuple_bounded(list(getattr(base, node.func.attr)(separator)))
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "zfill"
        and len(node.args) == 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        width = _safe_eval_int_literal(node.args[0])
        if isinstance(base, str) and width is not None:
            result = base.zfill(width)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"center", "ljust", "rjust"}
        and len(node.args) in {1, 2}
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        width = _safe_eval_int_literal(node.args[0])
        fillchar = _safe_eval_string_expr(node.args[1]) if len(node.args) == 2 else " "
        if isinstance(base, str) and width is not None and isinstance(fillchar, str) and len(fillchar) == 1:
            result = getattr(base, node.func.attr)(width, fillchar)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "expandtabs"
        and len(node.args) <= 1
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        tabsize = _safe_eval_int_literal(node.args[0]) if node.args else 8
        if isinstance(base, str) and tabsize is not None:
            result = base.expandtabs(tabsize)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and len(node.args) in {2, 3}
        and not node.keywords
    ):
        base = _safe_eval_string_expr(node.func.value)
        old = _safe_eval_string_expr(node.args[0])
        new = _safe_eval_string_expr(node.args[1])
        count = _safe_eval_int_literal(node.args[2]) if len(node.args) == 3 else None
        if (
            isinstance(base, str)
            and isinstance(old, str)
            and isinstance(new, str)
            and (len(node.args) == 2 or count is not None)
        ):
            if old == "":
                return base if new == "" else None
            result = base.replace(old, new) if count is None else base.replace(old, new, count)
            return result if len(result) <= MAX_EVALUATED_KEY_CHARS else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
    ):
        separator = _safe_eval_string_expr(node.func.value)
        join_values = _safe_eval_string_expr(node.args[0])
        if isinstance(separator, str) and isinstance(join_values, (tuple, list)) and not node.keywords:
            join_parts: list[str] = []
            for index, value in enumerate(join_values):
                if index:
                    join_parts.append(separator)
                join_parts.append(value)
            return _join_bounded(join_parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "str"
        and len(node.args) == 1
        and not node.keywords
    ):
        str_value = _safe_eval_string_expr(node.args[0])
        if isinstance(str_value, str):
            return str_value
    return None


def _safe_eval_int_literal(node: ast.AST) -> int | None:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
        and abs(node.value) <= MAX_EVALUATED_KEY_CHARS
    ):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _safe_eval_int_literal(node.operand)
        return -value if value is not None else None
    return None


def _safe_eval_bool_literal(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _safe_eval_truthy_literal(node: ast.AST) -> bool | None:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _safe_eval_truthy_literal(node.operand)
        return not value if value is not None else None
    if isinstance(node, ast.Constant) and node.value is None:
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, (float, complex)):
        return bool(node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return bool(node.value) if len(node.value) <= MAX_EVALUATED_KEY_CHARS else None
    if isinstance(node, ast.Dict) and not node.keys:
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"dict", "frozenset", "list", "set", "tuple"}
        and not node.keywords
    ):
        if not node.args:
            return False
        if len(node.args) == 1:
            argument_truth = _safe_eval_truthy_literal(node.args[0])
            if argument_truth is False:
                return False
            if argument_truth is True and node.func.id in {"frozenset", "list", "set", "tuple"}:
                return True
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            saw_value = False
            for value_node in node.values:
                value = _safe_eval_truthy_literal(value_node)
                if value is None:
                    return None
                saw_value = True
                if value:
                    return True
            return False if saw_value else None
        if isinstance(node.op, ast.And):
            saw_value = False
            for value_node in node.values:
                value = _safe_eval_truthy_literal(value_node)
                if value is None:
                    return None
                saw_value = True
                if not value:
                    return False
            return True if saw_value else None
    bool_value = _safe_eval_bool_literal(node)
    if bool_value is not None:
        return bool_value
    compare_value = _safe_eval_compare_literal(node)
    if compare_value is not None:
        return compare_value
    int_value = _safe_eval_int_literal(node)
    if int_value is not None:
        return bool(int_value)
    string_value = _safe_eval_string_expr(node)
    if isinstance(string_value, (str, tuple, list, frozenset)):
        return bool(string_value)
    return None


def _safe_eval_compare_literal(node: ast.AST) -> bool | None:
    if not isinstance(node, ast.Compare):
        return None
    left_value = _safe_eval_comparable_or_none_literal(node.left)
    if left_value is None:
        return None
    left: object = left_value
    for operator, comparator in zip(node.ops, node.comparators, strict=True):
        if isinstance(operator, (ast.In, ast.NotIn)):
            container = _safe_eval_membership_container(comparator)
            if container is None:
                return None
            result = _safe_eval_membership_literal(left, container)
            if result is None:
                return None
            if isinstance(operator, ast.NotIn):
                result = not result
            if not result:
                return False
            left = container
            continue
        else:
            right = _safe_eval_comparable_or_none_literal(comparator)
            if right is None:
                return None
        if isinstance(operator, ast.Eq):
            result = left == right
        elif isinstance(operator, ast.NotEq):
            result = left != right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.Lt):
            result = left < right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.LtE):
            result = left <= right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.Gt):
            result = left > right
        elif isinstance(left, int) and isinstance(right, int) and isinstance(operator, ast.GtE):
            result = left >= right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.Lt):
            result = left < right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.LtE):
            result = left <= right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.Gt):
            result = left > right
        elif isinstance(left, str) and isinstance(right, str) and isinstance(operator, ast.GtE):
            result = left >= right
        else:
            identity_result = _safe_eval_identity_compare(left, right, operator)
            if identity_result is not None:
                result = identity_result
                if not result:
                    return False
                left = right
                continue
            container_result = _safe_eval_container_compare(left, right, operator)
            if container_result is None:
                return None
            result = container_result
        if not result:
            return False
        left = right
    return True


def _safe_eval_membership_literal(left: object, container: MembershipContainer) -> bool | None:
    if isinstance(container, str):
        if not isinstance(left, str):
            return None
        return left in container
    try:
        return left in container
    except TypeError:
        return None


def _safe_eval_identity_compare(left: object, right: object, operator: ast.cmpop) -> bool | None:
    if not isinstance(operator, (ast.Is, ast.IsNot)):
        return None
    if not (
        left is NONE_COMPARABLE or right is NONE_COMPARABLE or (isinstance(left, bool) and isinstance(right, bool))
    ):
        return None
    result = left is right
    return not result if isinstance(operator, ast.IsNot) else result


def _safe_eval_container_compare(left: object, right: object, operator: ast.cmpop) -> bool | None:
    if isinstance(left, list) and isinstance(right, list):
        return _safe_eval_list_compare(left, right, operator)
    if isinstance(left, tuple) and isinstance(right, tuple):
        return _safe_eval_tuple_compare(left, right, operator)
    if isinstance(left, frozenset) and isinstance(right, frozenset):
        return _safe_eval_set_compare(left, right, operator)
    return None


def _safe_eval_list_compare(left: list[str], right: list[str], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_tuple_compare(left: tuple[str, ...], right: tuple[str, ...], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_set_compare(left: frozenset[str], right: frozenset[str], operator: ast.cmpop) -> bool | None:
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    return None


def _safe_eval_comparable_literal(node: ast.AST) -> ComparableLiteral | None:
    bool_value = _safe_eval_bool_literal(node)
    if bool_value is not None:
        return bool_value
    int_value = _safe_eval_int_literal(node)
    if int_value is not None:
        return int_value
    string_value = _safe_eval_string_expr(node)
    return string_value if isinstance(string_value, (str, tuple, list, frozenset)) else None


def _safe_eval_comparable_or_none_literal(node: ast.AST) -> object | None:
    value = _safe_eval_comparable_literal(node)
    if value is not None:
        return value
    if isinstance(node, ast.Constant) and node.value is None:
        return NONE_COMPARABLE
    return None


def _safe_eval_membership_container(node: ast.AST) -> MembershipContainer | None:
    value = _safe_eval_string_expr(node)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        members: list[object] = list(value)
        return members
    if isinstance(value, (tuple, frozenset)):
        return value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[object] = []
        total = 0
        for element in node.elts:  # type: ignore[attr-defined]
            element_value = _safe_eval_comparable_literal(element)
            if element_value is None:
                return None
            total += _safe_eval_literal_size(element_value)
            if total > MAX_EVALUATED_KEY_CHARS:
                return None
            values.append(element_value)
        if isinstance(node, ast.List):
            return values
        if isinstance(node, ast.Set):
            try:
                return frozenset(values)
            except TypeError:
                return None
        return tuple(values)
    return None


def _safe_eval_literal_size(value: object) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (bool, int)):
        return 1
    if isinstance(value, (tuple, list, frozenset)):
        return sum(_safe_eval_literal_size(item) for item in value)
    return MAX_EVALUATED_KEY_CHARS + 1


def _safe_eval_string_dict_lookup(node: ast.Dict, lookup_key: str) -> str | None:
    result = _safe_eval_string_dict_lookup_result(node, lookup_key)
    return result if isinstance(result, str) else None


def _safe_eval_string_dict_lookup_result(node: ast.Dict, lookup_key: str) -> str | None | object:
    total = 0
    selected_value: str | None | object = DICT_LOOKUP_MISSING
    unknown_before_selection = False
    unknown_after_selection = False
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if key_node is None:
            if not isinstance(value_node, ast.Dict):
                return DICT_LOOKUP_UNKNOWN
            unpacked_value = _safe_eval_string_dict_lookup_result(value_node, lookup_key)
            if unpacked_value is DICT_LOOKUP_UNKNOWN:
                if selected_value is DICT_LOOKUP_MISSING:
                    unknown_before_selection = True
                else:
                    unknown_after_selection = True
                continue
            if unpacked_value is not DICT_LOOKUP_MISSING:
                selected_value = unpacked_value
            continue
        key = _safe_eval_string_expr(key_node)
        if not isinstance(key, str):
            if isinstance(key_node, ast.Constant):
                continue
            if selected_value is not DICT_LOOKUP_MISSING:
                unknown_after_selection = True
            else:
                unknown_before_selection = True
            continue
        total += len(key)
        if total > MAX_EVALUATED_KEY_CHARS:
            return DICT_LOOKUP_UNKNOWN
        if key != lookup_key:
            continue
        value = _safe_eval_string_expr(value_node)
        selected_value = value if isinstance(value, str) else None
        unknown_before_selection = False
        unknown_after_selection = False
    if unknown_after_selection:
        return DICT_LOOKUP_UNKNOWN
    if selected_value is DICT_LOOKUP_MISSING and unknown_before_selection:
        return DICT_LOOKUP_UNKNOWN
    return selected_value


def _safe_eval_slice(node: ast.AST) -> slice | None:
    if not isinstance(node, ast.Slice):
        return None
    lower = _safe_eval_int_literal(node.lower) if node.lower is not None else None
    upper = _safe_eval_int_literal(node.upper) if node.upper is not None else None
    step = _safe_eval_int_literal(node.step) if node.step is not None else None
    if (
        (node.lower is not None and lower is None)
        or (node.upper is not None and upper is None)
        or (node.step is not None and step is None)
    ):
        return None
    if step == 0:
        return None
    return slice(lower, upper, step)


def _safe_eval_format_spec(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    value = _safe_eval_string_expr(node)
    return value if isinstance(value, str) else None


def _join_bounded(parts: list[str]) -> str | None:
    total = 0
    for part in parts:
        total += len(part)
        if total > MAX_EVALUATED_KEY_CHARS:
            return None
    return "".join(parts)


def _tuple_bounded(parts: list[str]) -> tuple[str, ...] | None:
    if not _strings_within_bound(parts):
        return None
    return tuple(parts)


def _list_bounded(parts: list[str]) -> list[str] | None:
    if not _strings_within_bound(parts):
        return None
    return list(parts)


def _frozenset_bounded(parts: list[str]) -> frozenset[str] | None:
    if not _strings_within_bound(parts):
        return None
    return frozenset(parts)


def _strings_within_bound(parts: list[str]) -> bool:
    total = 0
    for part in parts:
        total += len(part)
        if total > MAX_EVALUATED_KEY_CHARS:
            return False
    return True


def _repeat_bounded(value: str, multiplier: int) -> str | None:
    if multiplier < 0:
        return None
    if len(value) * multiplier > MAX_EVALUATED_KEY_CHARS:
        return None
    return value * multiplier


def _safe_percent_literal(format_string: str, values: str | tuple[str, ...]) -> str | None:
    value_tuple = (values,) if isinstance(values, str) else values
    value_index = 0
    parts: list[str] = []
    index = 0
    while index < len(format_string):
        char = format_string[index]
        if char != "%":
            parts.append(char)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            index += 1
            continue
        if index + 1 >= len(format_string):
            return None
        marker = format_string[index + 1]
        if marker == "%":
            parts.append("%")
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            index += 2
            continue
        if marker != "s" or value_index >= len(value_tuple):
            return None
        parts.append(value_tuple[value_index])
        if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
            return None
        value_index += 1
        index += 2

    if value_index != len(value_tuple):
        return None
    return "".join(parts)


def _safe_format_literal(
    base: str, args: tuple[EvaluatedStringValue | None, ...], kwargs: dict[str, EvaluatedStringValue | None]
) -> str | None:
    formatter = string.Formatter()
    parts: list[str] = []
    automatic_index = 0
    try:
        parsed = list(formatter.parse(base))
    except ValueError:
        return None

    for literal_text, field_name, format_spec, conversion in parsed:
        parts.append(literal_text)
        if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
            return None
        if field_name is None:
            continue
        if format_spec or conversion:
            return None
        if field_name == "":
            if automatic_index >= len(args):
                return None
            arg_value = args[automatic_index]
            if not isinstance(arg_value, str):
                return None
            parts.append(arg_value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
            automatic_index += 1
        elif field_name.isdecimal():
            index = int(field_name)
            if index >= len(args):
                return None
            arg_value = args[index]
            if not isinstance(arg_value, str):
                return None
            parts.append(arg_value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
        elif field_name.isidentifier():
            value = kwargs.get(field_name)
            if not isinstance(value, str):
                return None
            parts.append(value)
            if sum(len(part) for part in parts) > MAX_EVALUATED_KEY_CHARS:
                return None
        else:
            return None

    return "".join(parts)


def _normalize_expression_sensitive_keys(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    parse_attempts = 0
    for separator in re.finditer(r":\s*", text):
        quoted_key_start = max(0, separator.start() - MAX_KEY_EXPRESSION_CHARS - 8)
        quoted_key_match = next(
            (
                match
                for match in QUOTED_KEY_RE.finditer(text, quoted_key_start, separator.end())
                if match.end() == separator.end() and not _is_composed_key_fragment(text, match.start())
            ),
            None,
        )
        if quoted_key_match is not None:
            continue
        window_start = max(0, separator.start() - MAX_KEY_EXPRESSION_CHARS)
        window_start = _last_unquoted_statement_boundary(text, window_start, separator.start())
        expression_window = text[window_start : separator.start()]
        if not (_has_sensitive_literal_signal(expression_window) or _has_bounded_numeric_key_signal(expression_window)):
            continue
        following = text[separator.end() :].lstrip()
        if not following or following[0] not in {"'", '"', "{", "[", "("}:
            continue
        if _is_inside_quoted_literal(text, 0, separator.start()):
            continue
        for expression_start in _candidate_expression_starts(text, window_start, separator.start()):
            if parse_attempts >= MAX_KEY_EXPRESSION_PARSE_ATTEMPTS:
                break
            if _is_inside_quoted_literal(text, 0, expression_start):
                continue
            raw_expression = text[expression_start : separator.start()]
            expression = raw_expression.strip()
            if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
                continue
            has_literal_signal = KEY_LITERAL_RE.search(expression) is not None and _has_sensitive_literal_signal(
                expression
            )
            if not (has_literal_signal or _has_bounded_numeric_key_signal(expression)):
                continue
            parse_attempts += 1
            parse_failed = False
            try:
                value = _safe_eval_string_expr(ast.parse(expression, mode="eval"))
            except SyntaxError:
                parse_failed = True
                value = None
            fallback_key = _sensitive_key_from_expression_literals(expression) if parse_failed else None
            normalized_key = _normalize_sensitive_key(value) if isinstance(value, str) else None
            if normalized_key is not None:
                leading = raw_expression[: len(raw_expression) - len(raw_expression.lstrip())]
                replacements.append((expression_start, separator.end(), f"{leading}{normalized_key}="))
                break
            if fallback_key is not None:
                leading = raw_expression[: len(raw_expression) - len(raw_expression.lstrip())]
                replacements.append((expression_start, separator.end(), f"{leading}{fallback_key}="))
                break
            if isinstance(value, str) or not parse_failed:
                break

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _candidate_expression_starts(text: str, start: int, end: int) -> list[int]:
    starts = [start]
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            previous = text[:index].rstrip()
            if char == "{" and bracket_depth == 0 and not previous.endswith("{"):
                starts.append(index + 1)
            bracket_depth += 1
        elif char in ")]}":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "," and bracket_depth <= 1:
            starts.append(index + 1)
        index += 1
    return list(reversed(starts))[:MAX_KEY_EXPRESSION_CANDIDATES]


def _last_unquoted_statement_boundary(text: str, start: int, end: int) -> int:
    boundary = start
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}":
            if bracket_depth > 0:
                bracket_depth -= 1
            if char == "}" and bracket_depth == 0:
                whitespace_end = index + 1
                while whitespace_end < end and text[whitespace_end].isspace():
                    whitespace_end += 1
                if whitespace_end > index + 1:
                    boundary = whitespace_end
                    index = whitespace_end
                    continue
        elif char in {";", "\n"} and bracket_depth == 0:
            boundary = index + 1
        index += 1
    return boundary


def _sensitive_key_from_expression_literals(expression: str) -> str | None:
    literal_parts = [_decode_key_escapes(match.group(3)).lower() for match in KEY_LITERAL_RE.finditer(expression)]
    if not literal_parts:
        return None
    compact = re.sub(r"[^a-z0-9]+", "", "".join(literal_parts))
    reversed_compact = compact[::-1]
    for candidate in (compact, reversed_compact):
        sensitive_key = _sensitive_key_from_compact(candidate)
        if sensitive_key is not None:
            return sensitive_key
    return None


def _has_sensitive_literal_signal(expression: str) -> bool:
    if _sensitive_key_from_expression_literals(expression) is not None:
        return True
    compact = re.sub(r"[^a-z0-9]+", "", expression.lower())
    return _sensitive_key_from_compact(compact) is not None or _sensitive_key_from_compact(compact[::-1]) is not None


def _has_bounded_numeric_key_signal(expression: str) -> bool:
    if len(expression) > MAX_KEY_EXPRESSION_CHARS:
        return False
    return bool(
        re.search(r"\bchr\s*\(\s*\d{1,3}\s*\)", expression)
        or re.search(r"\b(?:bytes|bytearray)\s*\(\s*[\[(]\s*\d{1,3}", expression)
    )


def _sensitive_key_from_compact(compact: str) -> str | None:
    if "authorization" in compact:
        return "Authorization"
    if compact in {"auth", "basicauth"}:
        return "basic_auth" if compact == "basicauth" else "auth"
    if "accesskeyid" in compact:
        return "access_key_id"
    if "client" in compact and "secret" in compact:
        return "client_secret"
    if "api" in compact and "key" in compact:
        return "api_key"
    if "private" in compact and "key" in compact:
        return "private_key"
    for key in (
        "refresh_token",
        "access_token",
        "auth_token",
        "session_token",
        "session_id",
        "sessionid",
        "passphrase",
        "password",
        "passwd",
        "cookie",
        "credential",
        "jwt",
        "pwd",
        "signature",
        "secret",
        "sig",
        "sas",
        "token",
    ):
        if key.replace("_", "") in compact:
            return key
    return None


def _is_inside_quoted_literal(text: str, start: int, position: int) -> bool:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    index = start
    while index < position:
        char = text[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                quote_slashes = _count_preceding_backslashes(text, index)
                triple = text.startswith(char * 3, index)
                index += 3 if triple else 1
            else:
                index += 1
            continue

        current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
        closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
        closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
        if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
            quote = None
            quote_slashes = 0
            triple = False
            index += 3
        elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
            quote = None
            quote_slashes = 0
            index += 1
        else:
            index += 1

    return quote is not None


def _find_value_expression_end(text: str, start: int, default_end: int) -> int:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < default_end:
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}":
            if bracket_depth == 0:
                return index
            bracket_depth -= 1
        elif char in {";", "\n"} and bracket_depth == 0:
            return index
        index += 1
    return default_end


def _sensitive_comparison_key_from_expression(
    expression: str,
    *,
    allow_literal: bool,
) -> str | None:
    expression = expression.strip()
    if not expression or len(expression) > MAX_KEY_EXPRESSION_CHARS:
        return None
    folded = expression.casefold()
    if not any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS):
        return None
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError:
        return None

    value: str | None = None
    if isinstance(node, ast.Name):
        value = node.id
    elif isinstance(node, ast.Attribute):
        value = node.attr
    elif isinstance(node, ast.Subscript):
        subscript_value = _safe_eval_string_expr(node.slice)
        value = subscript_value if isinstance(subscript_value, str) else None
    elif allow_literal:
        evaluated = _safe_eval_string_expr(node)
        value = evaluated if isinstance(evaluated, str) else None
    return _normalize_sensitive_key(value) if value is not None else None


def _left_comparison_operand_has_sensitive_key(text: str, statement_start: int, operator_start: int) -> bool:
    window_start = max(statement_start, operator_start - MAX_KEY_EXPRESSION_CHARS)
    segment = text[window_start:operator_start].rstrip()
    starts = {0}
    for index, char in enumerate(segment):
        if char.isspace() or char in ";,&|?:=<>!":
            starts.add(index + 1)
    attempts = 0
    for start in sorted(starts, reverse=True):
        candidate = segment[start:].strip()
        if not candidate:
            continue
        attempts += 1
        if _sensitive_comparison_key_from_expression(candidate, allow_literal=True) is not None:
            return True
        if attempts >= MAX_KEY_EXPRESSION_PARSE_ATTEMPTS:
            break
    return False


def _right_comparison_operand_has_sensitive_key(
    text: str,
    operator_end: int,
    statement_end: int,
    *,
    allow_literal: bool = False,
) -> bool:
    segment = text[operator_end : min(statement_end, operator_end + MAX_KEY_EXPRESSION_CHARS)].lstrip()
    ends = {len(segment)}
    for index, char in enumerate(segment):
        if char.isspace() or char in ";,&|?:=<>!":
            ends.add(index)
    attempts = 0
    for end in sorted(ends):
        candidate = segment[:end].strip()
        if not candidate:
            continue
        attempts += 1
        if _sensitive_comparison_key_from_expression(candidate, allow_literal=allow_literal) is not None:
            return True
        if attempts >= MAX_KEY_EXPRESSION_PARSE_ATTEMPTS:
            break
    return False


def _comparison_left_operand_is_string_literal(text: str, statement_start: int, operator_start: int) -> bool:
    return text[statement_start:operator_start].rstrip().endswith(('"', "'"))


def _redact_sensitive_comparison_statements(text: str) -> str:
    spans: list[tuple[int, int]] = []
    candidate_count = 0
    for match in COMPARISON_OPERATOR_RE.finditer(text):
        if _is_inside_quoted_literal(text, 0, match.start()):
            continue
        start = _last_unquoted_statement_boundary(text, 0, match.start())
        end = _find_value_expression_end(text, match.end(), len(text))
        if start >= end or not (
            _left_comparison_operand_has_sensitive_key(text, start, match.start())
            or _right_comparison_operand_has_sensitive_key(
                text,
                match.end(),
                end,
                # A literal sensitive key on the right only marks the statement
                # when the left operand is itself a literal candidate value;
                # identifier-vs-key-name dispatches stay untouched.
                allow_literal=_comparison_left_operand_is_string_literal(text, start, match.start()),
            )
        ):
            continue
        candidate_count += 1
        if candidate_count > MAX_COMPARISON_CANDIDATES:
            return REDACTED_EVIDENCE_VALUE
        spans.append((start, end))

    if not spans:
        return text

    merged_spans: list[tuple[int, int]] = []
    for start, end in spans:
        if merged_spans and start <= merged_spans[-1][1]:
            merged_spans[-1] = (merged_spans[-1][0], max(merged_spans[-1][1], end))
        else:
            merged_spans.append((start, end))

    pieces: list[str] = []
    cursor = 0
    for start, end in merged_spans:
        pieces.append(text[cursor:start])
        pieces.append(_redact_sensitive_command_value(text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _count_preceding_backslashes(text: str, position: int) -> int:
    count = 0
    index = position - 1
    while index >= 0 and text[index] == "\\":
        count += 1
        index -= 1
    return count


def _redact_sensitive_literal_expressions(text: str) -> str:
    folded = text.casefold()
    if not any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS) and "bearer" not in folded:
        return text
    if "=" not in text and ":" not in text and "bearer" not in folded:
        return text
    matches = list(SENSITIVE_EVIDENCE_PREFIX_RE.finditer(text))
    if not matches:
        return text

    pieces: list[str] = []
    cursor = 0
    for index, match in enumerate(matches):
        if match.start() < cursor:
            continue
        segment_end = len(text)
        for next_match in matches[index + 1 :]:
            if not _is_inside_quoted_literal(text, match.end(), next_match.start()):
                segment_end = next_match.start()
                break
        segment_end = _find_value_expression_end(text, match.end(), segment_end)
        segment = text[match.end() : segment_end]
        pieces.append(text[cursor : match.start()])
        if REDACTED_STRUCTURED_VALUE_PREFIX_RE.match(segment) or REDACTED_VALUE_PREFIX_RE.match(segment):
            pieces.append(text[match.start() : segment_end])
        elif COMMAND_EVIDENCE_RE.search(segment):
            pieces.append(f"{text[match.start() : match.end()]}{_redact_sensitive_command_value(segment)}")
        elif PYTHON_STRING_LITERAL_DETECT_RE.search(segment):
            trailing_whitespace = re.search(r"\s*$", segment)
            suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
            pieces.append(f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}")
        else:
            pieces.append(text[match.start() : segment_end])
        cursor = segment_end

    pieces.append(text[cursor:])
    return "".join(pieces)


def _redact_unclosed_quoted_values(text: str) -> str:
    folded = text.casefold()
    if not any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS) and "bearer" not in folded:
        return text
    if ('"' not in text and "'" not in text) or ("=" not in text and ":" not in text and "bearer" not in folded):
        return text
    starts: list[tuple[int, str]] = []
    for pattern, slash_group, quote_group in (
        (TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_START_RE, 3, 4),
        (TRIPLE_QUOTED_AUTHORIZATION_START_RE, 2, 3),
        (TRIPLE_QUOTED_BEARER_START_RE, 2, 3),
    ):
        for match in pattern.finditer(text):
            closing_marker = f"{match.group(slash_group)}{match.group(quote_group)}" * 3
            if text.find(closing_marker, match.end()) == -1:
                starts.append((match.start(), match.group(1)))

    for pattern, slash_group, quote_group in (
        (QUOTED_SENSITIVE_ASSIGNMENT_START_RE, 3, 4),
        (QUOTED_AUTHORIZATION_START_RE, 2, 3),
        (QUOTED_BEARER_START_RE, 2, 3),
    ):
        for match in pattern.finditer(text):
            closing_marker = f"{match.group(slash_group)}{match.group(quote_group)}"
            if text.find(closing_marker, match.end()) == -1:
                starts.append((match.start(), match.group(1)))

    if not starts:
        return text

    start, prefix = min(starts, key=lambda item: item[0])
    return f"{text[:start]}{prefix}{REDACTED_EVIDENCE_VALUE}"


def _redact_adjacent_string_literals(text: str) -> str:
    folded = text.casefold()
    if not any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS) and "bearer" not in folded:
        return text
    if ('"' not in text and "'" not in text) or ("=" not in text and ":" not in text and "bearer" not in folded):
        return text
    for pattern in (
        ADJACENT_LITERAL_SENSITIVE_ASSIGNMENT_RE,
        ADJACENT_LITERAL_AUTHORIZATION_RE,
        ADJACENT_LITERAL_BEARER_RE,
    ):
        text = pattern.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", text)
    return text


def _redact_residual_expression_literals(text: str) -> str:
    if REDACTED_EVIDENCE_VALUE not in text or ('"' not in text and "'" not in text):
        return text

    def replace_residual(match: re.Match[str]) -> str:
        value = match.group(0)[len(match.group(1)) :]
        if REDACTED_STRUCTURED_VALUE_PREFIX_RE.match(value) or REDACTED_VALUE_PREFIX_RE.match(value):
            return match.group(0)
        if COMMAND_EVIDENCE_RE.search(match.group(0)):
            return match.group(0)
        return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}"

    for pattern in (
        RESIDUAL_LITERAL_SENSITIVE_ASSIGNMENT_RE,
        RESIDUAL_LITERAL_AUTHORIZATION_RE,
        RESIDUAL_LITERAL_BEARER_RE,
    ):
        text = pattern.sub(replace_residual, text)
    return text


def _redact_unquoted_sensitive_assignment(match: re.Match[str]) -> str:
    value = match.group(3)
    stripped_value = value.lstrip()
    structured_value = REDACTED_STRUCTURED_VALUE_PREFIX_RE.match(stripped_value)
    if structured_value is not None and structured_value.group("slashes"):
        leading_whitespace = value[: len(value) - len(stripped_value)]
        return f"{match.group(1)}{leading_whitespace}{REDACTED_EVIDENCE_VALUE}"
    if structured_value is not None:
        return match.group(0)
    if stripped_value.startswith(REDACTED_EVIDENCE_VALUE):
        command_tail = stripped_value[len(REDACTED_EVIDENCE_VALUE) :]
        if COMMAND_CONTEXT_LITERAL_RE.search(command_tail):
            leading_whitespace = value[: len(value) - len(stripped_value)]
            return f"{match.group(1)}{leading_whitespace}{REDACTED_EVIDENCE_VALUE}{command_tail}"
        if re.fullmatch(r"[\s'\"`)\]}]*", command_tail):
            return match.group(0)
    if COMMAND_EVIDENCE_RE.search(value):
        return f"{match.group(1)}{_redact_sensitive_command_value(value)}"
    trailing_whitespace = re.search(r"\s*$", value)
    suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _redact_authorization_value(match: re.Match[str]) -> str:
    value = match.group(2)
    trailing_whitespace = re.search(r"\s*$", value)
    suffix = trailing_whitespace.group(0) if trailing_whitespace else ""
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _redact_bare_authorization_value(match: re.Match[str]) -> str:
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}"


def _redact_unknown_authorization_scheme_value(match: re.Match[str]) -> str:
    trailing_token = match.group(4)
    if COMMAND_CONTEXT_LITERAL_RE.fullmatch(trailing_token):
        return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}{match.group(3)}{trailing_token}"
    return f"{match.group(1)}{REDACTED_EVIDENCE_VALUE}"


def _redact_command_user_password(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED_EVIDENCE_VALUE}{match.group(5)}"


def _redact_quoted_command_user_password(match: re.Match[str]) -> str:
    if (
        match.start("quote") == match.end("option")
        and match.start() > 0
        and match.string[match.start() - 1] == match.group("quote")
    ):
        return match.group(0)
    return (
        f"{match.group('option')}{match.group('prefix')}{match.group('quote')}"
        f"{match.group('username')}{REDACTED_EVIDENCE_VALUE}{match.group('closing')}"
    )


def _redact_substitution_command_user_password(match: re.Match[str]) -> str:
    return f"{match.group('option')}{match.group('username')}{REDACTED_EVIDENCE_VALUE}"


def _redact_command_positional_secret(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{_redact_positional_secret_value(match.group('value'))}"


def _redact_positional_secret_value(value: str) -> str:
    prefix = ""
    suffix = ""
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        prefix = suffix = value[0]
    elif len(value) >= 3 and value[0] == "$" and value[1] in {"'", '"'} and value[-1] == value[1]:
        prefix = value[:2]
        suffix = value[1]
    return f"{prefix}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _redact_netrc_password(match: re.Match[str]) -> str:
    value = match.group("value")
    prefix = ""
    suffix = ""
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        prefix = suffix = value[0]
    return f"{match.group('prefix')}{prefix}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _find_shell_group_end(text: str, start: int) -> int:
    depth = 1
    quote: str | None = None
    index = start
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == quote and _count_preceding_backslashes(text, index) % 2 == 0:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(" and _count_preceding_backslashes(text, index) % 2 == 0:
            depth += 1
        elif char == ")" and _count_preceding_backslashes(text, index) % 2 == 0:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(text)


def _search_unquoted_shell_pattern(
    pattern: re.Pattern[str],
    text: str,
    start: int,
    end: int,
) -> re.Match[str] | None:
    quote: str | None = None
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            if char == quote and _count_preceding_backslashes(text, index) % 2 == 0:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "\\":
            index += 1
        else:
            match = pattern.match(text, index, end)
            if match is not None:
                return match
        index += 1
    return None


def _find_shell_heredoc_body_range(text: str, start: int) -> tuple[int, int] | None:
    line_end = text.find("\n", start)
    if line_end < 0:
        return None
    operator = _search_unquoted_shell_pattern(SHELL_HEREDOC_OPERATOR_RE, text, start, line_end)
    if operator is None:
        return None

    body_start = line_end + 1
    indentation = r"\t*" if operator.group("strip_tabs") else ""
    terminator = re.search(
        rf"(?m)^{indentation}{re.escape(operator.group('delimiter'))}\r?$",
        text[body_start:],
    )
    body_end = len(text) if terminator is None else body_start + terminator.start()
    return body_start, body_end


def _redact_inline_stdin_emitter(fragment: str) -> str:
    emitter = re.search(
        r"(?is)(?P<prefix>\b(?:echo|printf)\b(?:\s+(?:--|-[A-Za-z]+))*\s+)"
        r"(?P<value>.+?)(?P<suffix>\s*)$",
        fragment,
    )
    if emitter is None:
        python_emitter = re.search(
            r"(?is)(?P<prefix>\bpython(?:3(?:\.\d+)?)?\s+-c\s+(?P<outer_quote>[\"']))"
            r"\s*print\s*\(\s*(?P<inner_quote>[\"'])(?P<value>.*?)"
            r"(?P=inner_quote)\s*\)\s*(?P=outer_quote)(?P<suffix>\s*)$",
            fragment,
        )
        if python_emitter is None:
            return fragment
        return (
            f"{fragment[: python_emitter.start()]}{python_emitter.group('prefix')}"
            f"print({python_emitter.group('inner_quote')}{REDACTED_EVIDENCE_VALUE}"
            f"{python_emitter.group('inner_quote')}){python_emitter.group('outer_quote')}"
            f"{python_emitter.group('suffix')}"
        )
    return f"{fragment[: emitter.start()]}{emitter.group('prefix')}{REDACTED_EVIDENCE_VALUE}{emitter.group('suffix')}"


def _redact_inline_secret_source(fragment: str) -> str:
    redacted = _redact_inline_stdin_emitter(fragment)
    if redacted != fragment:
        return redacted

    here_string = SHELL_HERE_STRING_VALUE_RE.search(fragment)
    if here_string is not None:
        return (
            f"{fragment[: here_string.start('value')]}"
            f"{_redact_positional_secret_value(here_string.group('value'))}"
            f"{fragment[here_string.end('value') :]}"
        )

    heredoc_range = _find_shell_heredoc_body_range(fragment, 0)
    if heredoc_range is None:
        return fragment
    body_start, body_end = heredoc_range
    trailing_newline = "\n" if fragment[body_start:body_end].endswith("\n") else ""
    return f"{fragment[:body_start]}{REDACTED_EVIDENCE_VALUE}{trailing_newline}{fragment[body_end:]}"


def _redact_inline_password_sources(text: str) -> str:
    """Redact inline values consumed by password-specific command inputs."""
    text = SSHPASS_DEFAULT_ENV_PASSWORD_RE.sub(_redact_command_positional_secret, text)
    text = SSHPASS_NAMED_ENV_PASSWORD_RE.sub(_redact_command_positional_secret, text)

    for match in reversed(list(SSHPASS_INLINE_FILE_SOURCE_RE.finditer(text))):
        source_end = _find_shell_group_end(text, match.end())
        source = text[match.end() : source_end]
        redacted_source = _redact_inline_secret_source(source)
        if redacted_source != source:
            text = f"{text[: match.end()]}{redacted_source}{text[source_end:]}"

    for match in reversed(list(SSHPASS_FILE_DESCRIPTOR_SOURCE_RE.finditer(text))):
        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        descriptor_here_string = re.search(
            rf"(?is)(?<![0-9]){re.escape(match.group('fd'))}\s*<<<\s*"
            rf"(?P<value>{COMMAND_POSITIONAL_SECRET_VALUE})",
            text[match.end() : line_end],
        )
        if descriptor_here_string is None:
            continue
        value_start = match.end() + descriptor_here_string.start("value")
        value_end = match.end() + descriptor_here_string.end("value")
        text = (
            f"{text[:value_start]}"
            f"{_redact_positional_secret_value(descriptor_here_string.group('value'))}"
            f"{text[value_end:]}"
        )

    stdin_secret_matches = [
        *DOCKER_LOGIN_PASSWORD_STDIN_RE.finditer(text),
        *GH_AUTH_LOGIN_TOKEN_STDIN_RE.finditer(text),
    ]
    for match in sorted(
        stdin_secret_matches,
        key=lambda candidate: candidate.start(),
        reverse=True,
    ):
        replacements: list[tuple[int, int, str]] = []
        line_start = text.rfind("\n", 0, match.start()) + 1
        pipe = text.rfind("|", line_start, match.start())
        if pipe >= 0:
            input_start = text.rfind(";", line_start, pipe) + 1
            source = text[input_start:pipe]
            redacted_source = _redact_inline_stdin_emitter(source)
            if redacted_source != source:
                replacements.append((input_start, pipe, redacted_source))
            piped_heredoc_range = _find_shell_heredoc_body_range(text, input_start)
            if piped_heredoc_range is not None:
                body_start, body_end = piped_heredoc_range
                trailing_newline = "\n" if text[body_start:body_end].endswith("\n") else ""
                replacements.append((body_start, body_end, f"{REDACTED_EVIDENCE_VALUE}{trailing_newline}"))

        line_end = text.find("\n", match.end())
        if line_end < 0:
            line_end = len(text)
        process_substitution = STDIN_PROCESS_SUBSTITUTION_RE.search(text, match.end(), line_end)
        if process_substitution is not None:
            source_end = _find_shell_group_end(text, process_substitution.end())
            source = text[process_substitution.end() : source_end]
            redacted_source = _redact_inline_secret_source(source)
            if redacted_source != source:
                replacements.append((process_substitution.end(), source_end, redacted_source))

        here_string = SHELL_HERE_STRING_VALUE_RE.search(text, match.end(), line_end)
        if here_string is not None:
            replacements.append(
                (
                    here_string.start("value"),
                    here_string.end("value"),
                    _redact_positional_secret_value(here_string.group("value")),
                )
            )

        heredoc_range = _find_shell_heredoc_body_range(text, match.end())
        if heredoc_range is not None:
            body_start, body_end = heredoc_range
            trailing_newline = "\n" if text[body_start:body_end].endswith("\n") else ""
            replacements.append((body_start, body_end, f"{REDACTED_EVIDENCE_VALUE}{trailing_newline}"))

        for start, end, replacement in reversed(replacements):
            text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_openssl_password_source(match: re.Match[str]) -> str:
    value = match.group("value")
    normalized = value.removeprefix("$")
    if len(normalized) >= 2 and normalized[0] in {"'", '"'} and normalized[-1] == normalized[0]:
        normalized = normalized[1:-1]
    if match.group("option").casefold() == "pass" and (
        normalized.casefold() == "stdin" or re.match(r"(?i)^(?:env|fd|file):", normalized) is not None
    ):
        return match.group(0)
    return _redact_command_positional_secret(match)


def _redact_process_substitution_sources(text: str, source_starts: set[int]) -> str:
    for source_start in sorted(source_starts, reverse=True):
        source_end = _find_shell_group_end(text, source_start)
        source = text[source_start:source_end]
        redacted_source = _redact_inline_secret_source(source)
        if redacted_source != source:
            text = f"{text[:source_start]}{redacted_source}{text[source_end:]}"
    return text


def _redact_inline_curl_cookie_sources(text: str) -> str:
    source_starts: set[int] = set()
    for command_start, command_end in _curl_command_ranges(text):
        source_starts.update(
            match.end() for match in CURL_INLINE_COOKIE_SOURCE_OPTION_RE.finditer(text, command_start, command_end)
        )
    return _redact_process_substitution_sources(text, source_starts)


def _redact_inline_command_secret_sources(text: str) -> str:
    source_starts = {match.end() for match in COMMAND_INLINE_SECRET_SOURCE_RE.finditer(text)}
    for command_start, command_end in _curl_command_ranges(text):
        source_starts.update(
            match.end() for match in CURL_INLINE_COOKIE_SOURCE_OPTION_RE.finditer(text, command_start, command_end)
        )
    return _redact_process_substitution_sources(text, source_starts)


def _curl_executable_token_start(text: str, curl_name_start: int) -> int | None:
    token_start = curl_name_start
    while token_start > 0 and text[token_start - 1] not in " \t\r\n\"';&|(),[]{}":
        token_start -= 1
    candidate = text[token_start:curl_name_start]
    if "://" in candidate or candidate.startswith("//") or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", candidate) is not None:
        return None
    return token_start if candidate.endswith(("/", "\\")) else curl_name_start


def _curl_executable_spans(text: str) -> list[tuple[int, int]]:
    spans = [(match.start(), match.end()) for match in CURL_EXECUTABLE_RE.finditer(text)]
    for match in CURL_STATIC_SHELL_EXECUTABLE_RE.finditer(text):
        raw_executable = match.group("executable")
        if CURL_EXECUTABLE_RE.search(raw_executable) is not None:
            continue
        try:
            decoded = shlex.split(raw_executable)
        except ValueError:
            continue
        if len(decoded) != 1 or re.fullmatch(CURL_EXECUTABLE_NAME_PATTERN, decoded[0], re.IGNORECASE) is None:
            continue
        spans.append((match.start(), match.end()))
    return sorted(spans)


def _shell_segment_context(text: str, end: int) -> tuple[int, str | None, int]:
    window_start = max(0, end - 2048)
    segment_start = window_start
    quote: str | None = None
    quote_start = -1
    index = window_start
    while index < end:
        char = text[index]
        if quote is not None:
            if char == quote and _count_preceding_backslashes(text, index) % 2 == 0:
                quote = None
                quote_start = -1
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            quote_start = index
        elif char == "\\":
            index += 1
        elif char in {";", "&", "|", "\n"}:
            segment_start = index + 1
        index += 1
    return segment_start, quote, quote_start


def _shell_wrapper_prefix_allows_command(prefix: str) -> bool:
    try:
        tokens = shlex.split(prefix)
    except ValueError:
        return False

    if tokens and tokens[0].replace("\\", "/").rsplit("/", 1)[-1] == "find":
        exec_indexes = [index for index, token in enumerate(tokens) if token in {"-exec", "-execdir"}]
        if not exec_indexes:
            return False
        nested_prefix = tokens[exec_indexes[-1] + 1 :]
        return not nested_prefix or _shell_wrapper_prefix_allows_command(shlex.join(nested_prefix))

    index = 0
    while index < len(tokens) and tokens[index] in {"!", "do", "elif", "if", "then", "until", "while"}:
        index += 1
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index], re.DOTALL):
        index += 1
    while index < len(tokens):
        wrapper = tokens[index]
        index += 1
        if wrapper == "env":
            options_with_values = {"-C", "-S", "-u", "--chdir", "--split-string", "--unset"}
            while index < len(tokens):
                token = tokens[index]
                if token == "--":
                    index += 1
                    break
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token, re.DOTALL):
                    index += 1
                    continue
                if not token.startswith("-"):
                    break
                option = token.split("=", 1)[0]
                index += 1
                if option in options_with_values and "=" not in token:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        if wrapper == "sudo":
            options_with_values = {
                "-C",
                "-g",
                "-h",
                "-p",
                "-r",
                "-t",
                "-T",
                "-u",
                "--chdir",
                "--group",
                "--host",
                "--prompt",
                "--role",
                "--type",
                "--user",
            }
            while index < len(tokens) and tokens[index].startswith("-"):
                option = tokens[index].split("=", 1)[0]
                index += 1
                if option in options_with_values and "=" not in tokens[index - 1]:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        if wrapper in {"command", "nohup"}:
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            continue
        if wrapper == "busybox":
            return index == len(tokens)
        if wrapper == "setsid":
            while index < len(tokens) and tokens[index].startswith("-"):
                if tokens[index] not in {"-c", "-f", "-w", "--ctty", "--fork", "--wait"}:
                    return False
                index += 1
            continue
        if wrapper in {"exec", "time"}:
            options_with_values = {"-a"} if wrapper == "exec" else {"-f", "-o", "--format", "--output"}
            while index < len(tokens) and tokens[index].startswith("-"):
                option = tokens[index].split("=", 1)[0]
                index += 1
                if option in options_with_values and "=" not in tokens[index - 1]:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        if wrapper == "nice":
            while index < len(tokens) and tokens[index].startswith("-"):
                option = tokens[index]
                index += 1
                if option in {"-n", "--adjustment"} and "=" not in option:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        if wrapper == "xargs":
            while index < len(tokens) and tokens[index].startswith("-"):
                option = tokens[index]
                index += 1
                if option in {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"}:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        if wrapper == "timeout":
            options_with_values = {"-k", "-s", "--kill-after", "--signal"}
            while index < len(tokens) and tokens[index].startswith("-"):
                token = tokens[index]
                if token == "--":
                    index += 1
                    break
                option = token.split("=", 1)[0]
                index += 1
                if option in options_with_values and "=" not in token:
                    if index >= len(tokens):
                        return False
                    index += 1
            if index >= len(tokens):
                return False
            index += 1
            continue
        if wrapper == "stdbuf":
            options_with_values = {"-e", "-i", "-o", "--error", "--input", "--output"}
            while index < len(tokens) and tokens[index].startswith("-"):
                token = tokens[index]
                if token == "--":
                    index += 1
                    break
                option = token.split("=", 1)[0]
                index += 1
                if option in options_with_values and "=" not in token:
                    if index >= len(tokens):
                        return False
                    index += 1
            continue
        return False
    return True


def _curl_executable_is_command(text: str, executable_start: int) -> bool:
    segment_start, quote, quote_start = _shell_segment_context(text, executable_start)
    if quote is not None:
        before_quote = text[segment_start:quote_start].rstrip()
        if quote == "`":
            return True
        if not before_quote or before_quote.endswith(("(", "[", "{", ",", "=", ":")):
            return True
        return (
            re.search(
                rf"(?is)(?:\b{SHELL_COMMAND_EXECUTABLE_PATTERN}\s+-c|\bcmd(?:\.exe)?\s+/c|"
                r"\bpowershell(?:\.exe)?\s+-c)$",
                before_quote,
            )
            is not None
        )

    prefix = text[segment_start:executable_start].rstrip()
    if not prefix:
        return True
    if re.fullmatch(
        rf"(?is)(?:\b{SHELL_COMMAND_EXECUTABLE_PATTERN}\s+-c|\bcmd(?:\.exe)?\s+/c|"
        r"\bpowershell(?:\.exe)?\s+-c)",
        prefix,
    ):
        return True
    if prefix.endswith(("(", "[", "{", ",", "=", ":")):
        return True
    return _shell_wrapper_prefix_allows_command(prefix)


def _curl_command_ranges(text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    covered_until = -1
    for candidate_start, candidate_end in _curl_executable_spans(text):
        if candidate_start < covered_until:
            continue
        executable_start = _curl_executable_token_start(text, candidate_start)
        if executable_start is None or not _curl_executable_is_command(text, executable_start):
            continue
        _, enclosing_quote, _ = _shell_segment_context(text, executable_start)
        segment_end = len(text)
        quote = enclosing_quote if enclosing_quote in {"'", '"'} else None
        bracket_depth = 0
        index = candidate_end
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote and _count_preceding_backslashes(text, index) % 2 == 0:
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "`" and enclosing_quote == "`" and bracket_depth == 0:
                segment_end = index
                break
            elif char == "(" and _count_preceding_backslashes(text, index) % 2 == 0:
                bracket_depth += 1
            elif char == ")" and _count_preceding_backslashes(text, index) % 2 == 0:
                if bracket_depth == 0:
                    segment_end = index
                    break
                bracket_depth -= 1
            elif (
                bracket_depth == 0
                and char in {";", "&", "|", "\n"}
                and _count_preceding_backslashes(text, index) % 2 == 0
            ):
                segment_end = index
                break
            index += 1
        ranges.append((executable_start, min(segment_end, executable_start + CURL_COMMAND_SCAN_CHARS)))
        covered_until = segment_end
    return ranges


def _curl_candidate_limit_exceeded(text: str) -> bool:
    candidate_count = 0
    for _ in CURL_SCAN_PREFIX_RE.finditer(text):
        candidate_count += 1
        if candidate_count > MAX_CURL_EXECUTABLE_CANDIDATES:
            return True
    for start, end in _curl_executable_spans(text):
        if CURL_SCAN_PREFIX_RE.search(text[start:end]) is not None:
            continue
        candidate_count += 1
        if candidate_count > MAX_CURL_EXECUTABLE_CANDIDATES:
            return True
    return False


def _subprocess_candidate_limit_exceeded(text: str) -> bool:
    for index, _ in enumerate(SUBPROCESS_CALL_PREFIX_RE.finditer(text), start=1):
        if index > MAX_SUBPROCESS_CALL_CANDIDATES:
            return True
    return False


def _redact_curl_credentials(text: str) -> str:
    if _curl_candidate_limit_exceeded(text):
        return REDACTED_EVIDENCE_VALUE
    for start, end in reversed(_curl_command_ranges(text)):
        fragment = text[start:end]
        fragment = COMMAND_SEPARATELY_QUOTED_CERT_SHELL_WORD_RE.sub(_redact_shell_word_credential, fragment)
        fragment = COMMAND_SEPARATELY_QUOTED_USER_SHELL_WORD_RE.sub(_redact_shell_word_credential, fragment)
        fragment = COMMAND_CERT_PASSWORD_QUOTED_RE.sub(_redact_quoted_certificate_password, fragment)
        fragment = COMMAND_CERT_PASSWORD_RE.sub(_redact_certificate_password, fragment)
        fragment = COMMAND_QUOTED_USER_PASSWORD_RE.sub(_redact_quoted_command_user_password, fragment)
        fragment = COMMAND_SUBSTITUTION_USER_PASSWORD_RE.sub(_redact_substitution_command_user_password, fragment)
        fragment = COMMAND_USER_PASSWORD_RE.sub(_redact_command_user_password, fragment)
        fragment = COMMAND_CERT_SHELL_WORD_RE.sub(_redact_shell_word_credential, fragment)
        fragment = COMMAND_USER_SHELL_WORD_RE.sub(_redact_shell_word_credential, fragment)
        text = f"{text[:start]}{fragment}{text[end:]}"
    return text


def _redact_curl_config_fragment(fragment: str) -> str:
    fragment = COMMAND_CONFIG_QUOTED_USER_PASSWORD_RE.sub(_redact_quoted_command_user_password, fragment)
    fragment = COMMAND_CONFIG_USER_PASSWORD_RE.sub(_redact_command_user_password, fragment)
    fragment = COMMAND_CONFIG_CERT_PASSWORD_QUOTED_RE.sub(_redact_quoted_certificate_password, fragment)
    fragment = COMMAND_CONFIG_CERT_PASSWORD_RE.sub(_redact_certificate_password, fragment)
    return COMMAND_CONFIG_SECRET_OPTION_RE.sub(_redact_command_positional_secret, fragment)


def _find_preceding_shell_pipe(text: str, start: int, end: int) -> tuple[int, int]:
    quote: str | None = None
    pipeline_start = start
    last_pipe = -1
    last_pipe_source_start = start
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            if char == quote and _count_preceding_backslashes(text, index) % 2 == 0:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if text.startswith(("&&", "||"), index):
            pipeline_start = index + 2
            last_pipe = -1
            index += 2
            continue
        if char == ";":
            pipeline_start = index + 1
            last_pipe = -1
        elif char == "|":
            last_pipe = index
            last_pipe_source_start = pipeline_start
        index += 1
    return last_pipe, last_pipe_source_start


def _redact_inline_curl_config_passwords(text: str) -> str:
    """Redact credentials only inside inline curl config and netrc sources."""
    ranges: list[tuple[int, int, bool]] = []
    for command_start, command_end in _curl_command_ranges(text):
        for match in CURL_CONFIG_SOURCE_OPTION_RE.finditer(text, command_start, command_end):
            is_netrc = match.group("netrc") is not None
            if match.group("source") == "<(":
                ranges.append((match.end(), _find_shell_group_end(text, match.end()), is_netrc))
                continue

            line_start = text.rfind("\n", 0, command_start) + 1
            pipe, input_start = _find_preceding_shell_pipe(text, line_start, command_start)
            if pipe >= 0:
                ranges.append((input_start, pipe, is_netrc))
                piped_heredoc_range = _find_shell_heredoc_body_range(text, input_start)
                if piped_heredoc_range is not None:
                    ranges.append((*piped_heredoc_range, is_netrc))

            line_end = text.find("\n", match.end())
            if line_end < 0:
                line_end = len(text)
            here_string = _search_unquoted_shell_pattern(SHELL_HERE_STRING_VALUE_RE, text, match.end(), line_end)
            if here_string is not None:
                ranges.append((here_string.start("value"), here_string.end("value"), is_netrc))
            heredoc_range = _find_shell_heredoc_body_range(text, match.end())
            if heredoc_range is not None:
                ranges.append((*heredoc_range, is_netrc))

    for start, end, is_netrc in reversed(ranges):
        fragment = text[start:end]
        if is_netrc:
            fragment = COMMAND_NETRC_PASSWORD_RE.sub(_redact_netrc_password, fragment)
        else:
            fragment = _redact_curl_config_fragment(fragment)
        text = f"{text[:start]}{fragment}{text[end:]}"
    return text


def _redact_quoted_certificate_password(match: re.Match[str]) -> str:
    if (
        match.start("quote") == match.end("option")
        and match.start() > 0
        and match.string[match.start() - 1] == match.group("quote")
    ):
        return match.group(0)
    return (
        f"{match.group('option')}{match.group('prefix')}{match.group('quote')}"
        f"{match.group('certificate')}{REDACTED_EVIDENCE_VALUE}{match.group('closing')}"
    )


def _redact_serialized_command_option(match: re.Match[str]) -> str:
    return (
        f"{match.group('option')}{match.group('prefix')}{match.group('slashes')}{match.group('quote')}"
        f"{REDACTED_EVIDENCE_VALUE}{match.group('slashes')}{match.group('quote')}"
    )


def _redact_certificate_password(match: re.Match[str]) -> str:
    return f"{match.group('option')}{match.group('certificate')}{REDACTED_EVIDENCE_VALUE}"


def _redact_shell_word_credential(match: re.Match[str]) -> str:
    argument = match.group("argument")
    preceding_backslashes = 0
    colon_index = -1
    for index, char in enumerate(argument):
        if char == ":" and preceding_backslashes % 2 == 0:
            colon_index = index
            break
        preceding_backslashes = preceding_backslashes + 1 if char == "\\" else 0
    if colon_index < 0 or colon_index + 1 >= len(argument):
        return match.group(0)

    password = argument[colon_index + 1 :]
    if REDACTED_EVIDENCE_VALUE in password:
        return match.group(0)
    closing_quote = ""
    if (len(argument) >= 2 and argument[0] in {"'", '"'} and argument[-1] == argument[0]) or (
        len(argument) >= 3 and argument[0] == "$" and argument[1] in {"'", '"'} and argument[-1] == argument[1]
    ):
        closing_quote = argument[-1]
    if closing_quote:
        return f"{match.group('option')}{argument[: colon_index + 1]}{REDACTED_EVIDENCE_VALUE}{closing_quote}"
    return f"{match.group('option')}{argument[: colon_index + 1]}{_redact_positional_secret_value(password)}"


def _find_function_argument_end(text: str, start: int) -> int:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}" and bracket_depth > 0:
            bracket_depth -= 1
        elif (char in {",", ")", ";", "\n"}) and bracket_depth == 0:
            return index
        index += 1
    return len(text)


def _normalize_sensitive_function_key(key: str) -> str | None:
    decoded_key = _decode_key_escapes(key)
    return _normalize_sensitive_key(decoded_key.lstrip("-"))


def _redact_sensitive_function_value(raw_value: str) -> str:
    leading = raw_value[: len(raw_value) - len(raw_value.lstrip())]
    trailing = raw_value[len(raw_value.rstrip()) :]
    value = raw_value.strip()
    if COMMAND_EVIDENCE_RE.search(value):
        safe_value = _redact_sensitive_command_value(value)
    else:
        safe_value = f'"{REDACTED_EVIDENCE_VALUE}"'
    return f"{leading}{safe_value}{trailing}"


def _redact_sensitive_argv_pairs(text: str) -> str:
    """Redact adjacent quoted option/value pairs such as ['--api-key', 'secret']."""
    replacements: list[tuple[int, int, str]] = []
    search_start = 0
    while match := SENSITIVE_ARGV_PAIR_RE.search(text, search_start):
        if match.group("collection_prefix") == ",":
            inside_list = text.rfind("[", 0, match.start()) > text.rfind("]", 0, match.start())
            inside_tuple = text.rfind("(", 0, match.start()) > text.rfind(")", 0, match.start())
            if not inside_list and not inside_tuple:
                search_start = match.start() + 1
                continue
        decoded_key = _decode_key_escapes(match.group("key"))
        sensitive_key = _normalize_sensitive_function_key(decoded_key) is not None
        is_curl_argv = _argv_pair_is_for_curl(text, match.start())
        curl_cookie_option = CURL_SHORT_COOKIE_OPTION_RE.fullmatch(decoded_key) is not None and is_curl_argv
        curl_credential_value = (
            _redact_curl_argv_credential_value(decoded_key, match.group("value")) if is_curl_argv else None
        )
        if sensitive_key or curl_cookie_option:
            replacements.append((match.start("value"), match.end("value"), REDACTED_EVIDENCE_VALUE))
        elif curl_credential_value is not None:
            replacements.append((match.start("value"), match.end("value"), curl_credential_value))
        search_start = match.start() + 1

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _argv_pair_is_for_curl(text: str, pair_start: int) -> bool:
    list_start = text.rfind("[", 0, pair_start)
    tuple_start = text.rfind("(", 0, pair_start)
    collection_start = max(list_start, tuple_start)
    if collection_start < 0:
        return False
    collection_prefix = text[collection_start + 1 : pair_start]
    if PYTHON_CURL_ARGV_START_RE.match(collection_prefix) is not None:
        return True
    try:
        prefix_values = _safe_eval_string_expr(ast.parse(f"[{collection_prefix}]", mode="eval"))
    except SyntaxError:
        return False
    if not isinstance(prefix_values, list) or not prefix_values:
        return False

    return _curl_argv_executable_index(prefix_values) is not None


def _curl_argv_executable_index(arguments: list[str]) -> int | None:
    """Return the curl executable position after supported command wrappers."""
    if not arguments:
        return None

    for index, value in enumerate(arguments):
        executable = value.replace("\\", "/").rsplit("/", 1)[-1]
        if re.fullmatch(CURL_EXECUTABLE_NAME_PATTERN, executable, re.IGNORECASE) is None:
            continue
        if index == 0 or _shell_wrapper_prefix_allows_command(shlex.join(arguments[:index])):
            return index
        return None
    return None


def _redact_curl_argv_credential_value(option: str, value: str) -> str | None:
    if option in {"-u", "-U", "--user", "--proxy-user"}:
        prefix = "--user "
        redacted = COMMAND_USER_PASSWORD_RE.sub(_redact_command_user_password, f"{prefix}{value}", count=1)
    elif option in {"-E", "--cert", "--proxy-cert"}:
        prefix = "--cert "
        redacted = COMMAND_CERT_PASSWORD_RE.sub(_redact_certificate_password, f"{prefix}{value}", count=1)
    else:
        return None
    return redacted[len(prefix) :] if redacted != f"{prefix}{value}" else None


def _safe_eval_subprocess_command(raw_argument: str) -> str | EvaluatedStringSequence | None:
    try:
        return _safe_eval_string_expr(ast.parse(raw_argument.strip(), mode="eval"))
    except SyntaxError:
        return None


def _is_stdin_auth_subprocess_command(raw_argument: str) -> bool:
    command = _safe_eval_subprocess_command(raw_argument)
    if isinstance(command, str):
        return bool(
            re.search(
                r"(?is)^\s*(?:[^\s]+[\\/])?docker(?:\.exe)?\s+login\b.{0,1024}?--password-stdin(?![\w-])",
                command,
            )
            or re.search(
                r"(?is)^\s*(?:[^\s]+[\\/])?gh(?:\.exe)?\s+auth\s+login\b.{0,1024}?--with-token(?![\w-])",
                command,
            )
        )
    if not isinstance(command, (list, tuple)) or not command:
        return False
    executable = command[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    executable = executable.removesuffix(".exe")
    normalized_args = [argument.casefold() for argument in command[1:]]
    if executable == "docker":
        return "login" in normalized_args and "--password-stdin" in normalized_args
    if executable == "gh":
        return normalized_args[:2] == ["auth", "login"] and "--with-token" in normalized_args
    return False


def _curl_config_arguments_use_stdin(arguments: list[str]) -> bool:
    stdin_sources = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
    for index, argument in enumerate(arguments):
        option, separator, source = argument.partition("=")
        if separator and option.casefold() in {"--config", "--netrc-file"} and source in stdin_sources:
            return True
        if (
            argument.casefold() in {"--config", "--netrc-file"}
            and index + 1 < len(arguments)
            and arguments[index + 1] in stdin_sources
        ):
            return True
        short_option = re.match(rf"(?i)^(?P<option>{CURL_CONFIG_SHORT_OPTION_PATTERN})(?P<source>.*)$", argument)
        if short_option is not None and short_option.group("source") in stdin_sources:
            return True
        if (
            re.fullmatch(CURL_CONFIG_SHORT_OPTION_PATTERN, argument) is not None
            and index + 1 < len(arguments)
            and arguments[index + 1] == "-"
        ):
            return True
    return False


def _is_curl_config_subprocess_command(raw_argument: str) -> bool:
    command = _safe_eval_subprocess_command(raw_argument)
    if isinstance(command, str):
        for command_start, command_end in _curl_command_ranges(command):
            fragment = command[command_start:command_end]
            match = CURL_EXECUTABLE_RE.search(fragment)
            if match is None:
                continue
            argument_start = match.end()
            if argument_start < len(fragment) and fragment[argument_start] in {"'", '"'}:
                argument_start += 1
            try:
                arguments = shlex.split(fragment[argument_start:])
            except ValueError:
                continue
            if _curl_config_arguments_use_stdin(arguments):
                return True
        return False
    if not isinstance(command, (list, tuple)) or not command:
        return False
    command_arguments = list(command)
    executable_index = _curl_argv_executable_index(command_arguments)
    return executable_index is not None and _curl_config_arguments_use_stdin(command_arguments[executable_index + 1 :])


def _safe_eval_bytes_expr(node: ast.AST) -> bytes | None:
    if isinstance(node, ast.Expression):
        return _safe_eval_bytes_expr(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value if len(node.value) <= MAX_EVALUATED_KEY_CHARS else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _safe_eval_bytes_expr(node.left)
        right = _safe_eval_bytes_expr(node.right)
        if left is not None and right is not None and len(left) + len(right) <= MAX_EVALUATED_KEY_CHARS:
            return left + right
    return None


def _safe_eval_curl_config_input(node: ast.AST) -> str | bytes | None:
    if isinstance(node, ast.Expression):
        return _safe_eval_curl_config_input(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value if len(node.value) <= EVIDENCE_URL_LOOKAHEAD_CHARS else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        joined = "".join(parts)
        return joined if len(joined) <= EVIDENCE_URL_LOOKAHEAD_CHARS else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _safe_eval_curl_config_input(node.left)
        right = _safe_eval_curl_config_input(node.right)
        if isinstance(left, str) and isinstance(right, str):
            combined = left + right
            return combined if len(combined) <= EVIDENCE_URL_LOOKAHEAD_CHARS else None
        if isinstance(left, bytes) and isinstance(right, bytes):
            combined_bytes = left + right
            return combined_bytes if len(combined_bytes) <= EVIDENCE_URL_LOOKAHEAD_CHARS else None
    return None


def _redact_static_curl_config_input(raw_value: str) -> str | None:
    raw_redacted = COMMAND_NETRC_PASSWORD_RE.sub(_redact_netrc_password, _redact_curl_config_fragment(raw_value))
    if raw_redacted != raw_value:
        return raw_redacted
    try:
        node = ast.parse(raw_value.strip(), mode="eval")
    except SyntaxError:
        return None
    value = _safe_eval_curl_config_input(node)
    if isinstance(value, str):
        redacted = COMMAND_NETRC_PASSWORD_RE.sub(_redact_netrc_password, _redact_curl_config_fragment(value))
        return repr(redacted) if redacted != value else None
    if not isinstance(value, bytes):
        return None
    decoded = value.decode("utf-8", errors="replace")
    redacted = COMMAND_NETRC_PASSWORD_RE.sub(_redact_netrc_password, _redact_curl_config_fragment(decoded))
    if redacted == decoded:
        return None
    redacted_bytes = redacted.encode()
    return repr(redacted_bytes)


def _is_static_string_input(raw_value: str) -> bool:
    try:
        node = ast.parse(raw_value.strip(), mode="eval")
    except SyntaxError:
        return False
    return isinstance(_safe_eval_string_expr(node), str) or _safe_eval_bytes_expr(node) is not None


def _redact_subprocess_curl_config_inputs(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    for call_match in SUBPROCESS_CALL_PREFIX_RE.finditer(text):
        argument_start = call_match.end()
        arguments: list[tuple[int, int, re.Match[str] | None]] = []
        while argument_start < len(text):
            argument_end = _find_function_argument_end(text, argument_start)
            raw_argument = text[argument_start:argument_end]
            if raw_argument.strip():
                arguments.append((argument_start, argument_end, FUNCTION_KEYWORD_ARGUMENT_RE.match(raw_argument)))
            if argument_end >= len(text) or text[argument_end] != ",":
                break
            argument_start = argument_end + 1

        command_argument = next((text[start:end] for start, end, keyword in arguments if keyword is None), None)
        if command_argument is None:
            command_argument = next(
                (
                    text[start + keyword.end() : end]
                    for start, end, keyword in arguments
                    if keyword is not None and keyword.group("name").casefold() == "args"
                ),
                None,
            )
        if command_argument is None or not _is_curl_config_subprocess_command(command_argument):
            continue

        for start, end, keyword in arguments:
            if keyword is None or keyword.group("name").casefold() != "input":
                continue
            value_start = start + keyword.end()
            raw_value = text[value_start:end]
            redacted_value = _redact_static_curl_config_input(raw_value)
            if redacted_value is not None and redacted_value != raw_value:
                replacements.append((value_start, end, redacted_value))

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_subprocess_stdin_auth_inputs(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    for call_match in SUBPROCESS_CALL_PREFIX_RE.finditer(text):
        argument_start = call_match.end()
        arguments: list[tuple[int, int, re.Match[str] | None]] = []
        while argument_start < len(text):
            argument_end = _find_function_argument_end(text, argument_start)
            raw_argument = text[argument_start:argument_end]
            if raw_argument.strip():
                arguments.append((argument_start, argument_end, FUNCTION_KEYWORD_ARGUMENT_RE.match(raw_argument)))
            if argument_end >= len(text) or text[argument_end] != ",":
                break
            argument_start = argument_end + 1

        command_argument = next(
            (text[start:end] for start, end, keyword in arguments if keyword is None),
            None,
        )
        if command_argument is None:
            command_argument = next(
                (
                    text[start + keyword.end() : end]
                    for start, end, keyword in arguments
                    if keyword is not None and keyword.group("name").casefold() == "args"
                ),
                None,
            )
        if command_argument is None or not _is_stdin_auth_subprocess_command(command_argument):
            continue

        for start, end, keyword in arguments:
            if keyword is None or keyword.group("name").casefold() != "input":
                continue
            value_start = start + keyword.end()
            raw_value = text[value_start:end]
            if _is_static_string_input(raw_value):
                replacements.append((value_start, end, _redact_sensitive_function_value(raw_value)))

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_sensitive_setter_arguments(text: str) -> str:
    """Redact value-bearing arguments passed to setter methods named for sensitive keys."""
    replacements: list[tuple[int, int, str]] = []
    covered_until = 0
    for match in SENSITIVE_SETTER_CALL_RE.finditer(text):
        if match.start() < covered_until:
            continue
        snake_key = match.group("key")
        if snake_key is not None and _normalize_sensitive_key(snake_key) is None:
            continue
        argument_start = match.end()
        arguments: list[tuple[int, int, re.Match[str] | None]] = []
        while argument_start < len(text):
            argument_end = _find_function_argument_end(text, argument_start)
            raw_argument = text[argument_start:argument_end]
            if raw_argument.strip():
                arguments.append((argument_start, argument_end, FUNCTION_KEYWORD_ARGUMENT_RE.match(raw_argument)))
            if argument_end >= len(text) or text[argument_end] != ",":
                covered_until = argument_end + 1
                break
            argument_start = argument_end + 1
        else:
            covered_until = len(text)

        positional_arguments = [argument for argument in arguments if argument[2] is None]
        keyword_arguments = [argument for argument in arguments if argument[2] is not None]
        redacted_keyword = False
        for start, end, keyword_match in keyword_arguments:
            if keyword_match is None:
                continue
            keyword_name = keyword_match.group("name")
            value_bearing = keyword_name.lower() in {"default", "value"}
            value_bearing = value_bearing or _normalize_sensitive_function_key(keyword_name) is not None
            value_bearing = value_bearing or (len(arguments) == 1 and not positional_arguments)
            if not value_bearing:
                continue
            value_start = start + keyword_match.end()
            raw_value = text[value_start:end]
            if raw_value.strip():
                replacements.append((value_start, end, _redact_sensitive_function_value(raw_value)))
                redacted_keyword = True

        positional_values = [] if redacted_keyword else positional_arguments
        for start, end, _ in positional_values:
            replacements.append((start, end, _redact_sensitive_function_value(text[start:end])))

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_keyword_sensitive_function_arguments(text: str) -> str:
    """Redact defaults or values when a call declares a sensitive key by keyword."""
    replacements: list[tuple[int, int, str]] = []
    for match in FUNCTION_CALL_PREFIX_RE.finditer(text):
        declaration_prefix = text[max(0, match.start() - 32) : match.start()]
        if re.search(r"(?is)\b(?:async\s+def|def|class)\s+$", declaration_prefix):
            continue

        argument_start = match.end()
        arguments: list[tuple[int, int, re.Match[str] | None]] = []
        while argument_start < len(text):
            argument_end = _find_function_argument_end(text, argument_start)
            raw_argument = text[argument_start:argument_end]
            if raw_argument.strip():
                arguments.append((argument_start, argument_end, FUNCTION_KEYWORD_ARGUMENT_RE.match(raw_argument)))
            if argument_end >= len(text) or text[argument_end] != ",":
                break
            argument_start = argument_end + 1

        sensitive_descriptor = False
        for start, end, keyword_match in arguments:
            if keyword_match is None or keyword_match.group("name").lower() not in {"key", "name", "option_strings"}:
                continue
            value_start = start + keyword_match.end()
            if _sensitive_function_key_from_safe_expression(text[value_start:end].strip()) is not None:
                sensitive_descriptor = True
                break
        if not sensitive_descriptor:
            continue

        for start, end, keyword_match in arguments:
            if keyword_match is None or keyword_match.group("name").lower() not in {"default", "value"}:
                continue
            value_start = start + keyword_match.end()
            raw_value = text[value_start:end]
            if raw_value.strip():
                replacements.append((value_start, end, _redact_sensitive_function_value(raw_value)))

    non_overlapping: list[tuple[int, int, str]] = []
    covered_until = -1
    for candidate_replacement in sorted(replacements, key=lambda item: (item[0], -item[1])):
        if candidate_replacement[0] < covered_until:
            continue
        non_overlapping.append(candidate_replacement)
        covered_until = candidate_replacement[1]
    for start, end, replacement_text in reversed(non_overlapping):
        text = f"{text[:start]}{replacement_text}{text[end:]}"
    return text


def _redact_sensitive_function_arguments(text: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    covered_until = 0
    prefix_matches: list[tuple[re.Match[str], str | None]] = [
        (match, _normalize_sensitive_function_key(match.group("key")))
        for match in SENSITIVE_FUNCTION_ARGUMENT_PREFIX_RE.finditer(text)
    ]
    prefix_matches.extend(
        (match, _sensitive_function_key_from_safe_expression(match.group("key")))
        for match in COMPOSED_SENSITIVE_FUNCTION_ARGUMENT_PREFIX_RE.finditer(text)
    )
    for match, normalized_key in sorted(prefix_matches, key=lambda item: item[0].start()):
        if match.start() < covered_until:
            continue

        declaration_call = match.group("callee").rsplit(".", 1)[-1].lower() == "add_argument"
        if normalized_key is None and not declaration_call:
            continue
        sensitive_declaration = normalized_key is not None
        argument_start = match.end()
        redacted_positional_value = False
        while argument_start < len(text):
            argument_end = _find_function_argument_end(text, argument_start)
            raw_argument = text[argument_start:argument_end]
            keyword_match = FUNCTION_KEYWORD_ARGUMENT_RE.match(raw_argument)
            if keyword_match is not None:
                if keyword_match.group("name").lower() == "default" and sensitive_declaration:
                    value_start = argument_start + keyword_match.end()
                    raw_value = text[value_start:argument_end]
                    if raw_value.strip():
                        replacements.append((value_start, argument_end, _redact_sensitive_function_value(raw_value)))
            elif declaration_call:
                sensitive_declaration = (
                    _sensitive_function_key_from_safe_expression(raw_argument.strip()) is not None
                    or sensitive_declaration
                )
            elif not redacted_positional_value and raw_argument.strip():
                replacements.append((argument_start, argument_end, _redact_sensitive_function_value(raw_argument)))
                redacted_positional_value = True

            if argument_end >= len(text) or text[argument_end] != ",":
                covered_until = argument_end + 1
                break
            argument_start = argument_end + 1
        else:
            covered_until = len(text)

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_command_structured_value(match: re.Match[str]) -> str:
    quote = match.group("value_quote")
    return f"{match.group(1)}{quote}{REDACTED_EVIDENCE_VALUE}{quote}"


def _redact_command_body_option(match: re.Match[str]) -> str:
    argument = match.group("argument")
    prefix = "$" if argument.startswith("$") else ""
    value = argument[len(prefix) :]
    quote = value[0] if value and value[0] in {"'", '"'} else ""
    body = value[1:-1] if quote and value.endswith(quote) else value
    redacted_body = redact_evidence_string(body, max_chars=len(body) + EVIDENCE_REDACTION_LOOKAHEAD_CHARS)
    if redacted_body == body:
        return match.group(0)
    suffix = quote if quote and value.endswith(quote) else ""
    return f"{match.group('option')}{prefix}{quote}{redacted_body}{suffix}"


def _redact_command_shell_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    prefix = "$" if value.startswith("$") else ""
    unprefixed = value[len(prefix) :]
    quote = unprefixed[0] if unprefixed and unprefixed[0] in {"'", '"'} else ""
    suffix = quote if quote and unprefixed.endswith(quote) else ""
    return f"{match.group('prefix')}{prefix}{quote}{REDACTED_EVIDENCE_VALUE}{suffix}"


def _find_command_context_end(text: str, start: int) -> int:
    quote: str | None = None
    quote_slashes = 0
    triple = False
    bracket_depth = 0
    closed_top_level_call = False
    index = start
    while index < len(text):
        char = text[index]
        if quote is not None:
            current_slashes = _count_preceding_backslashes(text, index) if char == quote else -1
            closes_plain_quote = quote_slashes == 0 and current_slashes % 2 == 0
            closes_serialized_quote = quote_slashes > 0 and current_slashes == quote_slashes
            if triple and text.startswith(quote * 3, index) and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                triple = False
                index += 3
            elif not triple and char == quote and (closes_plain_quote or closes_serialized_quote):
                quote = None
                quote_slashes = 0
                index += 1
            else:
                index += 1
            continue

        if char in {"'", '"'}:
            quote = char
            quote_slashes = _count_preceding_backslashes(text, index)
            triple = text.startswith(char * 3, index)
            index += 3 if triple else 1
            continue
        if char in {",", ";", "|", ")", "]", "}"} and _count_preceding_backslashes(text, index) % 2 == 1:
            index += 1
            continue
        if bracket_depth == 0 and index > start:
            if char in {",", ";", "|", "\n", ")", "]", "}"}:
                return index
            if closed_top_level_call and (char.isspace() or char in {"+", "-", "*", "/", "%"}):
                return index
        if char in "([{":
            bracket_depth += 1
        elif char in ")]}":
            if bracket_depth == 0:
                return index
            bracket_depth -= 1
            if bracket_depth == 0:
                closed_top_level_call = True
        index += 1
    return len(text)


def _command_context_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in COMMAND_EVIDENCE_RE.finditer(text):
        span_start = match.start()
        if re.fullmatch(CURL_EXECUTABLE_NAME_PATTERN, match.group(0), re.IGNORECASE):
            executable_start = _curl_executable_token_start(text, match.start())
            segment_start, enclosing_quote, quote_start = _shell_segment_context(text, match.start())
            if executable_start is None or not _curl_executable_is_command(text, executable_start):
                span_start = segment_start
            elif enclosing_quote is not None and quote_start >= segment_start:
                span_start = quote_start
        if spans and span_start < spans[-1][1]:
            continue
        end = _find_command_context_end(text, span_start)
        if spans and span_start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((span_start, end))
    return spans


def _redact_sensitive_command_value_chunk(text: str) -> str:
    markers = f"({re.escape(REDACTED_EVIDENCE_VALUE)}|{re.escape(REDACTED_URL_CREDENTIALS)})"
    parts = re.split(markers, text)
    redacted_parts = [
        part
        if part in {REDACTED_EVIDENCE_VALUE, REDACTED_URL_CREDENTIALS}
        else COMMAND_SENSITIVE_VALUE_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, part)
        for part in parts
    ]
    return "".join(redacted_parts)


def _redact_non_command_sensitive_value_tokens(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in _command_context_spans(text):
        pieces.append(_redact_sensitive_command_value_chunk(text[cursor:start]))
        pieces.append(text[start:end])
        cursor = end
    pieces.append(_redact_sensitive_command_value_chunk(text[cursor:]))
    return "".join(pieces)


def _redact_sensitive_command_value(text: str) -> str:
    redacted = _redact_command_evidence_text(_redact_command_string_literals(text))
    return _redact_non_command_sensitive_value_tokens(redacted)


def _redact_adjacent_command_literal_groups(text: str) -> str:
    """Fold bounded adjacent string literals only when their joined command reveals a credential."""
    token_input = text.replace("\x00", " ")
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(token_input).readline))
    except (IndentationError, SyntaxError, tokenize.TokenError, UnicodeError):
        return text

    line_offsets = [0]
    line_offsets.extend(match.end() for match in re.finditer("\n", text))

    def position_offset(position: tuple[int, int]) -> int:
        line, column = position
        return min(len(text), line_offsets[min(line - 1, len(line_offsets) - 1)] + column)

    literal_groups: list[list[tuple[int, int, str]]] = []
    current_group: list[tuple[int, int, str]] = []
    fstring_start = getattr(tokenize, "FSTRING_START", -1)
    fstring_end = getattr(tokenize, "FSTRING_END", -1)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        literal: tuple[int, int, str] | None = None
        if token.type == tokenize.STRING:
            literal = (position_offset(token.start), position_offset(token.end), token.string)
        elif token.type == fstring_start:
            depth = 1
            end_index = index + 1
            while end_index < len(tokens):
                if tokens[end_index].type == fstring_start:
                    depth += 1
                elif tokens[end_index].type == fstring_end:
                    depth -= 1
                    if depth == 0:
                        break
                end_index += 1
            if depth == 0:
                start = position_offset(token.start)
                end = position_offset(tokens[end_index].end)
                literal = (start, end, text[start:end])
                index = end_index

        if literal is not None:
            current_group.append(literal)
        elif current_group and token.type not in {tokenize.COMMENT, tokenize.NL}:
            if len(current_group) > 1:
                literal_groups.append(current_group)
            current_group = []
        index += 1
    if len(current_group) > 1:
        literal_groups.append(current_group)
    if not literal_groups:
        return text

    replacements: list[tuple[int, int, str]] = []
    for group in literal_groups:
        decoded_parts: list[str] = []
        for _start, _end, literal_text in group:
            try:
                decoded = _safe_eval_string_expr(ast.parse(literal_text, mode="eval"))
            except SyntaxError:
                decoded_parts = []
                break
            if not isinstance(decoded, str):
                decoded_parts = []
                break
            decoded_parts.append(decoded)
        if not decoded_parts:
            continue
        joined = "".join(decoded_parts)
        if not COMMAND_EVIDENCE_RE.search(joined):
            continue
        redacted_joined = URL_RE.sub(_redact_url, joined)
        redacted_joined = _redact_command_evidence_text(redacted_joined)
        if redacted_joined == joined or not any(
            marker in redacted_joined for marker in {REDACTED_EVIDENCE_VALUE, REDACTED_URL_CREDENTIALS}
        ):
            continue
        replacements.append((group[0][0], group[-1][1], repr(redacted_joined)))

    for start, end, replacement in reversed(replacements):
        text = f"{text[:start]}{replacement}{text[end:]}"
    return text


def _redact_command_string_literals(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in PYTHON_STRING_LITERAL_DETECT_RE.finditer(text):
        pieces.append(COMMAND_BARE_SENSITIVE_RE.sub(REDACTED_EVIDENCE_VALUE, text[cursor : match.start()]))
        pieces.append(_redact_sensitive_command_literal(match))
        cursor = match.end()
    pieces.append(COMMAND_BARE_SENSITIVE_RE.sub(REDACTED_EVIDENCE_VALUE, text[cursor:]))
    return "".join(pieces)


def _redact_command_evidence_text(text: str) -> str:
    if _curl_candidate_limit_exceeded(text) or _subprocess_candidate_limit_exceeded(text):
        return REDACTED_EVIDENCE_VALUE
    redacted = _redact_inline_curl_config_passwords(text)
    redacted = _redact_inline_password_sources(redacted)
    redacted = _redact_subprocess_curl_config_inputs(redacted)
    redacted = _redact_subprocess_stdin_auth_inputs(redacted)
    redacted = _redact_inline_command_secret_sources(redacted)
    redacted = NPMRC_SCOPED_AUTH_ASSIGNMENT_RE.sub(_redact_command_positional_secret, redacted)
    redacted = NPM_CONFIG_SCOPED_AUTH_ARGUMENT_RE.sub(_redact_command_positional_secret, redacted)
    redacted = POETRY_CONFIG_PYPI_TOKEN_RE.sub(_redact_command_positional_secret, redacted)
    redacted = POETRY_CONFIG_HTTP_BASIC_RE.sub(_redact_command_positional_secret, redacted)
    redacted = COMMAND_SHELL_SENSITIVE_ASSIGNMENT_RE.sub(_redact_command_shell_assignment, redacted)
    redacted = DOCKER_LOGIN_PASSWORD_RE.sub(_redact_command_positional_secret, redacted)
    redacted = AWS_CONFIGURE_SET_SECRET_RE.sub(_redact_command_positional_secret, redacted)
    redacted = MYSQL_ATTACHED_PASSWORD_RE.sub(_redact_command_positional_secret, redacted)
    redacted = MYSQL_SEPARATED_PASSWORD_RE.sub(_redact_command_positional_secret, redacted)
    redacted = OPENSSL_ENC_PASSWORD_RE.sub(_redact_openssl_password_source, redacted)
    redacted = COMMAND_PROGRAM_SHORT_PASSWORD_RE.sub(_redact_command_positional_secret, redacted)
    redacted = COMMAND_QUOTED_COOKIE_HEADER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}\2", redacted)
    redacted = COMMAND_STRUCTURED_SENSITIVE_VALUE_RE.sub(_redact_command_structured_value, redacted)
    redacted = COMPOUND_AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
    redacted = AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
    redacted = UNKNOWN_AUTHORIZATION_SCHEME_VALUE_RE.sub(_redact_unknown_authorization_scheme_value, redacted)
    redacted = BARE_AUTHORIZATION_VALUE_RE.sub(_redact_bare_authorization_value, redacted)
    redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = COMMAND_SENSITIVE_HEADER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = CURL_ATTACHED_COOKIE_SERIALIZED_QUOTED_RE.sub(_redact_serialized_command_option, redacted)
    redacted = CURL_ATTACHED_COOKIE_OPTION_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = COMMAND_SECRET_OPTION_SERIALIZED_QUOTED_RE.sub(_redact_serialized_command_option, redacted)
    redacted = COMMAND_SECRET_OPTION_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    redacted = COMMAND_BODY_OPTION_RE.sub(_redact_command_body_option, redacted)
    redacted = _redact_curl_credentials(redacted)
    pieces: list[str] = []
    cursor = 0
    for match in COMMAND_URL_CONTEXT_RE.finditer(redacted):
        chunk = _redact_standalone_secret_tokens(redacted[cursor : match.start()])
        chunk = HIGH_ENTROPY_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, chunk)
        pieces.append(COMMAND_LITERAL_SENSITIVE_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, chunk))
        pieces.append(match.group(0))
        cursor = match.end()
    chunk = _redact_standalone_secret_tokens(redacted[cursor:])
    chunk = HIGH_ENTROPY_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, chunk)
    pieces.append(COMMAND_LITERAL_SENSITIVE_TOKEN_RE.sub(REDACTED_EVIDENCE_VALUE, chunk))
    return "".join(pieces)


def _redact_command_context_tokens(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in _command_context_spans(text):
        pieces.append(text[cursor:start])
        pieces.append(_redact_command_evidence_text(text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _redact_sensitive_command_literal(match: re.Match[str]) -> str:
    literal = match.group(0)
    if COMMAND_CONTEXT_LITERAL_RE.search(literal):
        return _redact_command_evidence_text(literal)
    return REDACTED_EVIDENCE_VALUE


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return f"{text[: max_chars - 3]}..."


def redact_evidence_string(text: str, max_chars: int = 180) -> str:
    """Redact credentials from a scanner evidence string before truncating it."""
    redaction_budget = max(0, max_chars) + EVIDENCE_REDACTION_LOOKAHEAD_CHARS
    url_budget = max(0, max_chars) + EVIDENCE_URL_LOOKAHEAD_CHARS
    redacted = text[:url_budget]
    if _curl_candidate_limit_exceeded(redacted) or _subprocess_candidate_limit_exceeded(redacted):
        return _truncate(REDACTED_EVIDENCE_VALUE, max_chars)
    redacted = _redact_adjacent_command_literal_groups(redacted)
    redacted = _normalize_serialized_url_slashes(redacted)
    if "://" in redacted:
        redacted = URL_RE.sub(_redact_url, redacted)
    redacted = redacted[:redaction_budget]
    if _curl_candidate_limit_exceeded(redacted) or _subprocess_candidate_limit_exceeded(redacted):
        return _truncate(REDACTED_EVIDENCE_VALUE, max_chars)
    redacted = _normalize_serialized_assignment_separators(redacted)
    redacted = _normalize_serialized_quote_escapes(redacted)
    redacted = _normalize_embedded_control_sensitive_keys(redacted)
    redacted = _normalize_serialized_structured_sensitive_keys(redacted)
    folded = redacted.casefold()
    has_sensitive_key_signal = any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS)
    if has_sensitive_key_signal and ("=" in redacted or ":" in redacted) and ('"' in redacted or "'" in redacted):
        redacted = STRUCTURED_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_structured_quoted_assignment, redacted)
    redacted = _redact_inline_curl_config_passwords(redacted)
    redacted = _redact_inline_curl_cookie_sources(redacted)
    redacted = _redact_inline_password_sources(redacted)
    redacted = _redact_curl_credentials(redacted)
    redacted = _redact_command_context_tokens(redacted)
    redacted = _redact_sensitive_argv_pairs(redacted)
    redacted = _redact_sensitive_setter_arguments(redacted)
    redacted = _redact_keyword_sensitive_function_arguments(redacted)
    redacted = _redact_sensitive_function_arguments(redacted)
    redacted = _normalize_expression_sensitive_keys(redacted)
    redacted = _normalize_quoted_sensitive_keys(redacted)
    redacted = _normalize_subscript_sensitive_keys(redacted)
    redacted = _normalize_unquoted_sensitive_keys(redacted)
    redacted = _redact_sensitive_comparison_statements(redacted)
    redacted = _redact_sensitive_literal_expressions(redacted)
    folded = redacted.casefold()
    has_quotes = '"' in redacted or "'" in redacted
    has_assignment_separator = "=" in redacted or ":" in redacted
    has_sensitive_key_signal = any(signal in folded for signal in SENSITIVE_KEYWORD_SIGNALS)
    has_authorization_signal = "auth" in folded
    has_bearer_signal = "bearer" in folded
    if has_quotes and has_assignment_separator and has_sensitive_key_signal:
        redacted = TRIPLE_QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_prefixed_quoted_value, redacted)
    if has_quotes and has_assignment_separator and has_authorization_signal:
        redacted = TRIPLE_QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_prefixed_quoted_value, redacted)
    if has_quotes and has_bearer_signal:
        redacted = TRIPLE_QUOTED_BEARER_VALUE_RE.sub(_redact_prefixed_quoted_value, redacted)
    redacted = _redact_unclosed_quoted_values(redacted)
    if has_quotes and has_assignment_separator and has_sensitive_key_signal:
        redacted = QUOTED_SENSITIVE_ASSIGNMENT_RE.sub(_redact_quoted_assignment, redacted)
    if has_quotes and has_assignment_separator and has_authorization_signal:
        redacted = QUOTED_AUTHORIZATION_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    if has_quotes and has_bearer_signal:
        redacted = QUOTED_BEARER_VALUE_RE.sub(_redact_quoted_authorization, redacted)
    redacted = _redact_adjacent_string_literals(redacted)
    redacted = _redact_residual_expression_literals(redacted)
    if has_assignment_separator and has_authorization_signal:
        redacted = COMPOUND_AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
        redacted = AUTHORIZATION_VALUE_RE.sub(_redact_authorization_value, redacted)
        redacted = UNKNOWN_AUTHORIZATION_SCHEME_VALUE_RE.sub(_redact_unknown_authorization_scheme_value, redacted)
        redacted = BARE_AUTHORIZATION_VALUE_RE.sub(_redact_bare_authorization_value, redacted)
    if has_bearer_signal:
        redacted = BEARER_VALUE_RE.sub(rf"\1{REDACTED_EVIDENCE_VALUE}", redacted)
    if has_assignment_separator and has_sensitive_key_signal:
        redacted = SENSITIVE_ASSIGNMENT_RE.sub(_redact_unquoted_sensitive_assignment, redacted)
    redacted = NPMRC_SCOPED_AUTH_ASSIGNMENT_RE.sub(_redact_command_positional_secret, redacted)
    redacted = NPM_CONFIG_SCOPED_AUTH_ARGUMENT_RE.sub(_redact_command_positional_secret, redacted)
    redacted = _redact_shared_provider_tokens(redacted)
    return _truncate(_escape_evidence_controls(redacted), max_chars)
