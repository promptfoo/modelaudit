"""Recognize bounded, literal setup and inference examples in Markdown.

The returned spans describe routine documented URLs, not the safety of a model
or of code downloaded by a reader. Other findings in each example stay intact.
"""

import ast
import re
import shlex
from urllib.parse import urlsplit

from modelaudit.detectors.network_comm import NetworkCommDetector

MAX_EXAMPLE_BYTES = 16 * 1024
MAX_FENCES = 128
FENCE_PATTERN = re.compile(rb"(?m)^ {0,3}(?P<fence>`{3,}|~{3,})(?P<language>\w*)[ \t]*\r?$")
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>`]+")
INDEX_HOSTS = frozenset({"pypi.org", "pypi.python.org", "download.pytorch.org", "wheels.vllm.ai"})
PYTHON_EXECUTION_NAMES = frozenset({"exec", "eval", "compile", "__import__", "subprocess", "system", "popen"})
URL_RISK_TERMS = (
    NetworkCommDetector.INFORMATIONAL_URL_RISK_TERMS
    + tuple(term.decode("ascii") for term in NetworkCommDetector.CC_PATTERNS)
    + ("payload",)
)


def _plain_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
            and not parsed.query
            and not parsed.fragment
            and not any(term in url.casefold() for term in URL_RISK_TERMS)
            and re.fullmatch(r"[A-Za-z0-9:/._\[\]-]+", url) is not None
            and all(part not in {".", ".."} for part in parsed.path.split("/"))
        )
    except ValueError:
        return False


def _local_api_url(url: str) -> bool:
    if not _plain_url(url):
        return False
    parsed = urlsplit(url)
    return parsed.hostname in {"localhost", "127.0.0.1", "::1"} and parsed.path in {"/v1", "/v1/"}


def _repository_url(url: str) -> bool:
    return _plain_url(url) and re.fullmatch(r"https://github\.com/[\w-]+/[\w.-]+(?:\.git)?", url) is not None


def _index_url(url: str) -> bool:
    if not _plain_url(url):
        return False
    parsed = urlsplit(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname in INDEX_HOSTS
        and parsed.port in {None, 443}
        and re.fullmatch(r"/[\w/-]*", parsed.path) is not None
    )


def _setup_command_urls(words: list[str]) -> set[str] | None:
    """Accept ordinary setup commands; reject unproven flags and execution chains."""
    if words[:2] == ["git", "clone"]:
        args = words[2:]
        while args and args[0] in {"--branch", "-b", "--depth", "--single-branch"}:
            option = args.pop(0)
            if option == "--single-branch":
                continue
            if not args or re.fullmatch(r"[\w./-]+", args.pop(0)) is None:
                return None
        if len(args) == 1 and _repository_url(args[0]):
            return {args[0]}
        return None

    for prefix in (
        ["pip", "install"],
        ["pip3", "install"],
        ["uv", "pip", "install"],
        ["python", "-m", "pip", "install"],
    ):
        if words[: len(prefix)] != prefix:
            continue
        urls: set[str] = set()
        install_args = iter(words[len(prefix) :])
        for arg in install_args:
            if arg in {"--index-url", "--extra-index-url", "-i"}:
                url = next(install_args, "")
                if not _index_url(url):
                    return None
                urls.add(url)
            elif arg == "--index-strategy":
                if next(install_args, "") not in {"first-index", "unsafe-first-match", "unsafe-best-match"}:
                    return None
            elif arg not in {"--pre", "--upgrade", "-U", "-e"}:
                if arg.startswith("-") or re.fullmatch(r"[\w.\[\],=+!~-]+", arg) is None:
                    return None
        return urls

    if any(
        words[: len(prefix)] == prefix
        for prefix in (
            ["cd"],
            ["conda", "create"],
            ["conda", "activate"],
            ["cmake", "-B"],
            ["cmake", "--build"],
            ["vllm", "serve"],
        )
    ) and all(re.fullmatch(r"[\w./=+:-]+", arg) is not None for arg in words):
        return set()
    return None


def _shell_url_spans(source: bytes) -> list[tuple[int, int]]:
    # Preserve byte offsets while joining explicit shell continuation lines.
    joined = re.sub(rb"\\\r?\n", lambda match: b" " * len(match.group()), source)
    spans: list[tuple[int, int]] = []
    offset = 0
    for line in joined.splitlines(keepends=True):
        command = line.lstrip()
        if command.startswith(b"#"):
            command = command[1:].lstrip()
            if not command.startswith(b"git clone "):
                offset += len(line)
                continue
        if not command.strip():
            offset += len(line)
            continue
        if any(char in command for char in b"$`;&|<>\\"):
            return []
        try:
            words = shlex.split(command.decode("utf-8"), comments=True)
        except (UnicodeDecodeError, ValueError):
            return []
        urls = _setup_command_urls(words)
        if urls is None:
            return []
        spans.extend(
            (offset + match.start(), offset + match.end())
            for match in URL_PATTERN.finditer(line)
            if match.group().decode("utf-8") in urls
        )
        offset += len(line)
    return spans


def _literal_api_url(node: ast.expr) -> ast.Constant | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "getenv"
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in {"OPENAI_BASE_URL", "LLM_BASE_URL"}
    ):
        node = node.args[1]
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and _local_api_url(node.value):
        return node
    return None


def _python_url_spans(source: bytes) -> list[tuple[int, int]]:
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
        return []
    nodes = list(ast.walk(tree))
    if any(
        (isinstance(node, ast.Name) and node.id in PYTHON_EXECUTION_NAMES)
        or (isinstance(node, ast.Attribute) and node.attr in PYTHON_EXECUTION_NAMES)
        or (isinstance(node, ast.alias) and node.name.split(".")[0] in PYTHON_EXECUTION_NAMES)
        for node in nodes
    ):
        return []

    literals: dict[ast.Constant, str] = {}
    for node in nodes:
        if isinstance(node, ast.keyword) and node.arg == "base_url":
            literal = _literal_api_url(node.value)
            if literal is not None:
                literals[literal] = str(literal.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=False):
                if isinstance(key, ast.Constant) and key.value in {"base_url", "model_server", "api_base"}:
                    literal = _literal_api_url(value)
                    if literal is not None:
                        literals[literal] = str(literal.value)

    # Prompt URLs must remain literal user-message data, used only as messages.
    parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    message_uses = [node for node in nodes if isinstance(node, ast.Name) and node.id == "messages"]
    if all(
        (isinstance(node.ctx, ast.Store) and isinstance(parents.get(node), ast.Assign))
        or (
            isinstance(node.ctx, ast.Load)
            and isinstance(parent := parents.get(node), ast.keyword)
            and parent.arg == "messages"
        )
        for node in message_uses
    ):
        for statement in tree.body:
            if not (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == "messages"
            ):
                continue
            if not isinstance(statement.value, ast.List):
                continue
            for message in statement.value.elts:
                if not isinstance(message, ast.Dict) or len(message.keys) != 2:
                    continue
                fields = {
                    key.value: value
                    for key, value in zip(message.keys, message.values, strict=False)
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
                role, content = fields.get("role"), fields.get("content")
                if not (
                    isinstance(role, ast.Constant)
                    and role.value == "user"
                    and isinstance(content, ast.Constant)
                    and isinstance(content.value, str)
                ):
                    continue
                url = content.value.split(" ", 1)[0]
                if _plain_url(url) and re.fullmatch(r"https://[\w.-]+\.github\.io/(?:blog|docs)/[\w/-]*", url):
                    literals[content] = url

    line_offsets = [0]
    for line in source.splitlines(keepends=True):
        line_offsets.append(line_offsets[-1] + len(line))
    spans: list[tuple[int, int]] = []
    for literal, url in literals.items():
        if literal.end_lineno is None or literal.end_col_offset is None:
            continue
        start = line_offsets[literal.lineno - 1] + literal.col_offset
        end = line_offsets[literal.end_lineno - 1] + literal.end_col_offset
        spans.extend(
            (start + match.start(), start + match.end())
            for match in URL_PATTERN.finditer(source[start:end])
            if match.group().decode("utf-8") == url
        )
    return spans


def routine_documentation_url_spans(payload: bytes) -> tuple[tuple[int, int], ...]:
    """Return URL spans only inside complete, recognized Markdown fences."""
    spans: list[tuple[int, int]] = []
    opening: re.Match[bytes] | None = None
    for count, match in enumerate(FENCE_PATTERN.finditer(payload)):
        if count >= MAX_FENCES * 2:
            return ()
        if opening is None:
            opening = match
            continue
        if (
            match.group("language")
            or match.group("fence")[:1] != opening.group("fence")[:1]
            or len(match.group("fence")) < len(opening.group("fence"))
        ):
            continue
        start, end = opening.end() + 1, match.start()
        if (
            end - start <= MAX_EXAMPLE_BYTES
            and re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]|\r(?!\n)", payload[start:end]) is None
        ):
            language = opening.group("language").lower()
            source = payload[start:end]
            examples = (
                _shell_url_spans(source)
                if language in {b"sh", b"bash", b"shell"}
                else _python_url_spans(source)
                if language in {b"py", b"python"}
                else []
            )
            spans.extend((start + left, start + right) for left, right in examples)
        opening = None
    return tuple(spans)
