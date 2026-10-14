"""Recognize bounded, literal setup and inference examples in Markdown.

The returned spans describe routine documented URLs, not the safety of a model
or of code downloaded by a reader. Other findings in each example stay intact.
"""

import ast
import re
import shlex
from html.parser import HTMLParser
from urllib.parse import urlsplit

from modelaudit.detectors.network_comm import NetworkCommDetector

MAX_EXAMPLE_BYTES = 16 * 1024
MAX_FENCES = 128
PARSED_FENCE_LANGUAGES = frozenset({b"", b"sh", b"bash", b"shell", b"console", b"terminal", b"py", b"python"})
FENCE_PATTERN = re.compile(rb"(?m)^ {0,3}(?P<fence>`{3,}|~{3,})(?P<language>[^\r\n]*?)[ \t]*\r?$")
INDENTED_CODE_BLOCK_PATTERN = re.compile(rb"(?m)^(?: {4}|\t)[^\n]*\n?(?:(?: {4}|\t)[^\n]*\n?|[ \t]*\n)*")
BACKTICK_PATTERN = re.compile(rb"`+")
URL_PATTERN = re.compile(rb"https?://[^\s\"'<>`]+")
INDEX_HOSTS = frozenset({"pypi.org", "pypi.python.org", "download.pytorch.org", "wheels.vllm.ai"})
PYTHON_EXECUTION_NAMES = frozenset(
    {"exec", "eval", "compile", "__import__", "subprocess", "system", "popen", "runpy", "run_path", "run_module"}
)
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


def _cmake_script_options(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if arg.startswith(("-P", "-C", "-E", "--workflow", "--install")):
            return True
        if arg.startswith("-D") or (index > 0 and args[index - 1] == "-D"):
            key = arg.removeprefix("-D").partition("=")[0].partition(":")[0]
            if (
                key == "CMAKE_TOOLCHAIN_FILE"
                or (key.startswith("CMAKE_PROJECT_") and "INCLUDE" in key)
                or key.startswith("CMAKE_USER_MAKE_RULES_OVERRIDE")
            ):
                return True
    return False


def _setup_command_urls(words: list[str]) -> set[str] | None:
    """Accept ordinary setup commands; reject unproven flags and execution chains."""
    if words and re.fullmatch(r"python3(?:\.\d+)?", words[0]):
        words = ["python", *words[1:]]
    if words[:1] == ["cmake"] and _cmake_script_options(words[1:]):
        return None
    if words[:2] == ["git", "clone"]:
        args = words[2:]
        while args:
            if args[0] == "--":
                args.pop(0)
                break
            option, separator, value = args[0].partition("=")
            if option not in {"--branch", "-b", "--depth", "--single-branch"}:
                break
            args.pop(0)
            if option == "--single-branch":
                if separator:
                    return None
                continue
            if not separator:
                value = args.pop(0) if args else ""
            if re.fullmatch(r"[\w./-]+", value) is None or value.startswith("-"):
                return None
            if option == "--depth" and (not value.isdecimal() or not value.strip("0")):
                return None
        if len(args) == 2:
            destination = args.pop()
            if (
                destination.startswith("-")
                or re.fullmatch(r"[\w./-]+", destination) is None
                or any(part in {"", ".."} for part in destination.split("/"))
            ):
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
            option, separator, value = arg.partition("=")
            if option in {"--index-url", "--extra-index-url"} or arg == "-i":
                url = value if separator else next(install_args, "")
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
    # A backslash in a shell comment does not continue the command. Keep
    # ambiguous comment/quote combinations out of this narrow exception.
    if re.search(rb"#[^\r\n]*\\\r?\n", source):
        return []
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


def _command_executes_script(words: list[str]) -> bool:
    while words and words[0] in {"$", ">", ">>>"}:
        words = words[1:]
    if words[:2] in (["command", "-v"], ["command", "-V"]):
        return False
    wrapped = False
    while words and (
        words[0] in {"env", "command", "exec", "nohup", "--"} or re.match(r"[A-Za-z_]\w*=", words[0]) is not None
    ):
        wrapped = True
        words = words[1:]
    if not words or _setup_command_urls(words) is not None:
        return False
    command = words[0].rsplit("/", 1)[-1].lower().removesuffix(".exe")
    if (
        words[0].startswith("$")
        or (wrapped and command.startswith("-"))
        or command.endswith(
            (".py", ".pyw", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd")
        )
    ):
        return True
    python_command = re.fullmatch(r"(?:python[23]?|pypy3?)(?:\.\d+)?", command) is not None
    if not wrapped and (words[1:] in (["--version"], ["-V"], ["--help"]) or (python_command and words[1:] == ["-h"])):
        return False
    return (
        python_command
        or command
        in {
            "sh",
            "bash",
            "zsh",
            "dash",
            "ksh",
            "source",
            "eval",
            ".",
            "node",
            "nodejs",
            "ruby",
            "perl",
            "php",
            "pwsh",
            "powershell",
            "sudo",
            "npx",
        }
        or (command in {"uv", "pipx", "npm"} and words[1:2] in (["run"], ["exec"]))
        or (command == "cmake" and _cmake_script_options(words[1:]))
    )


def _example_executes_script(source: bytes, language: bytes) -> bool:
    if language in {b"bibtex", b"json", b"text", b"plaintext"}:
        language = b""
    elif language not in PARSED_FENCE_LANGUAGES:
        # An unparsed language cannot establish that a clone is setup-only.
        return bool(source.strip())
    if language in {b"", b"py", b"python"}:
        try:
            tree = ast.parse(source.decode("utf-8"))
            nodes = list(ast.walk(tree))
        except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
            if language:
                return True
        else:
            executes_script = any(
                (isinstance(node, ast.Name) and node.id in PYTHON_EXECUTION_NAMES)
                or (isinstance(node, ast.Attribute) and node.attr in PYTHON_EXECUTION_NAMES)
                or (isinstance(node, ast.alias) and node.name.split(".")[0] in PYTHON_EXECUTION_NAMES)
                for node in nodes
            )
            if (
                language
                or executes_script
                or any(
                    isinstance(
                        node,
                        (ast.Call, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Import, ast.ImportFrom),
                    )
                    for node in nodes
                )
                or all(
                    isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                    for statement in tree.body
                )
            ):
                return executes_script
    if re.search(rb"#[^\r\n]*\\\r?\n", source):
        return True
    joined = re.sub(rb"\\\r?\n", b" ", source)
    try:
        for line in joined.decode("utf-8").splitlines():
            # Preserve quotes so a quoted operator remains an argument.
            lexer = shlex.shlex(line, posix=False, punctuation_chars=";&|()")
            lexer.whitespace_split = True
            words: list[str] = []
            for raw in lexer:
                if "`" in raw and not (raw.startswith("'") and raw.endswith("'")):
                    return True
                if raw and all(char in ";&|()" for char in raw):
                    if _command_executes_script(words):
                        return True
                    words = []
                    continue
                parsed = shlex.split(raw, comments=False)
                if len(parsed) != 1:
                    return True
                words.extend(parsed)
            if _command_executes_script(words):
                return True
    except (UnicodeDecodeError, ValueError):
        return True
    return False


def _inline_examples_execute_script(payload: bytes, regions: list[tuple[int, int]]) -> bool:
    delimiter_count = 0
    html_regions: list[tuple[int, int]] = []
    for start, end in regions:
        previous_end = start
        delimiters: list[re.Match[bytes]] = []
        for match in BACKTICK_PATTERN.finditer(payload, start, end):
            delimiter_count += 1
            if delimiter_count > MAX_FENCES * 2:
                return True
            delimiters.append(match)
        next_by_length: dict[int, int] = {}
        closing: dict[int, int] = {}
        for index in range(len(delimiters) - 1, -1, -1):
            delimiter = delimiters[index]
            width = delimiter.end() - delimiter.start()
            cursor = delimiter.start() - 1
            while cursor >= start and payload[cursor] == ord("\\"):
                cursor -= 1
            # Escapes apply only while locating an opening delimiter.
            opening_width = width - ((delimiter.start() - cursor - 1) % 2)
            if opening_width in next_by_length:
                closing[index] = next_by_length[opening_width]
            next_by_length[width] = index
        index = 0
        while index < len(delimiters):
            close = closing.get(index)
            if close is None:
                index += 1
                continue
            left, right = delimiters[index], delimiters[close]
            if right.start() - left.end() > MAX_EXAMPLE_BYTES:
                return True
            source = payload[left.end() : right.start()].replace(b"\r", b" ").replace(b"\n", b" ").strip()
            prefix = payload[max(start, left.start() - 64) : left.start()]
            command_context = re.search(rb"\s|[();|&]", source) is not None or re.search(
                rb"\b(?:run|execute|invoke|launch|source)[ \t]*$", prefix, re.IGNORECASE
            )
            if command_context and _example_executes_script(source, b""):
                return True
            html_regions.append((previous_end, left.start()))
            previous_end = right.end()
            index = close + 1
        html_regions.append((previous_end, end))
    return _html_examples_execute_script(payload, html_regions)


class _HTMLCodeExamples(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.parts: list[str] = []
        self.size = 0
        self.count = 0
        self.executes_script = False
        self.before = ""
        self.command_context = False
        self.language = b""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.executes_script:
            return
        if tag in {"pre", "code"}:
            if not self.tags:
                self.command_context = (
                    re.search(r"\b(?:run|execute|invoke|launch|source)[ \t]*$", self.before, re.IGNORECASE) is not None
                )
                self.language = b""
            self.command_context |= tag == "pre"
            for attribute, value in attrs:
                if attribute == "class" and value:
                    for name in value.split():
                        if name.startswith("language-"):
                            self.language = name.removeprefix("language-").lower().encode()
            self.count += 1
            if self.count > MAX_FENCES:
                self.executes_script = True
                return
            self.tags.append(tag)
        elif self.tags and tag == "br":
            self.handle_data("\n")

    def handle_endtag(self, tag: str) -> None:
        if self.executes_script or tag not in {"pre", "code"}:
            return
        if not self.tags or self.tags.pop() != tag:
            self.executes_script = True
            return
        if not self.tags:
            source = "".join(self.parts).encode().strip()
            if self.command_context or re.search(rb"\s|[();|&]", source):
                self.executes_script = _example_executes_script(source, self.language)
            self.parts.clear()
            self.size = 0
            self.before = ""

    def handle_data(self, data: str) -> None:
        if self.tags and not self.executes_script:
            self.size += len(data.encode())
            if self.size > MAX_EXAMPLE_BYTES:
                self.executes_script = True
            else:
                self.parts.append(data)
        elif not self.tags:
            self.before = (self.before + data)[-64:]


def _html_examples_execute_script(payload: bytes, regions: list[tuple[int, int]]) -> bool:
    parser = _HTMLCodeExamples()
    for start, end in regions:
        try:
            parser.feed(payload[start:end].decode("utf-8"))
            parser.close()
        except (UnicodeDecodeError, ValueError, RecursionError):
            return True
        if parser.executes_script or parser.tags:
            return True
    return False


def _outside_fence_examples_execute_script(payload: bytes, regions: list[tuple[int, int]]) -> bool:
    count = 0
    inline_regions: list[tuple[int, int]] = []
    for start, end in regions:
        previous_end = start
        for match in INDENTED_CODE_BLOCK_PATTERN.finditer(payload, start, end):
            count += 1
            if count > MAX_FENCES or match.end() - match.start() > MAX_EXAMPLE_BYTES:
                return True
            source = re.sub(rb"(?m)^(?: {4}|\t)", b"", match.group())
            if _example_executes_script(source, b""):
                return True
            inline_regions.append((previous_end, match.start()))
            previous_end = match.end()
        inline_regions.append((previous_end, end))
    return _inline_examples_execute_script(payload, inline_regions)


def routine_documentation_url_spans(payload: bytes) -> tuple[tuple[int, int], ...]:
    """Return URL spans only inside complete, recognized Markdown fences."""
    spans: list[tuple[int, int]] = []
    opening: re.Match[bytes] | None = None
    executes_script = False
    outside_fences: list[tuple[int, int]] = []
    previous_end = 0
    for count, match in enumerate(FENCE_PATTERN.finditer(payload)):
        if count >= MAX_FENCES * 2:
            return ()
        if opening is None:
            outside_fences.append((previous_end, match.start()))
            opening = match
            continue
        if (
            match.group("language")
            or match.group("fence")[:1] != opening.group("fence")[:1]
            or len(match.group("fence")) < len(opening.group("fence"))
        ):
            continue
        start, end = opening.end() + 1, match.start()
        info = opening.group("language").lower().split()
        language = info[0] if info else b""
        if (
            end - start <= MAX_EXAMPLE_BYTES
            and re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]|\r(?!\n)", payload[start:end]) is None
        ):
            source = payload[start:end]
            executes_script |= _example_executes_script(source, language)
            examples = (
                _shell_url_spans(source)
                if language in {b"sh", b"bash", b"shell"}
                else _python_url_spans(source)
                if language in {b"py", b"python"}
                else []
            )
            spans.extend((start + left, start + right) for left, right in examples)
        else:
            executes_script = True
        previous_end = match.end()
        opening = None
    if opening is not None:
        executes_script = True
    else:
        outside_fences.append((previous_end, len(payload)))
    if not executes_script:
        executes_script = _outside_fence_examples_execute_script(payload, outside_fences)
    if executes_script:
        spans = [(start, end) for start, end in spans if not _repository_url(payload[start:end].decode("utf-8"))]
    return tuple(spans)
