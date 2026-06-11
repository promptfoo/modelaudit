"""JAX Checkpoint Scanner - Handles non-msgpack JAX/Flax model formats."""

from __future__ import annotations

import json
import os
import pickletools
import re
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ..core_results import mark_operational_scan_error
from ..scanner_results import INCONCLUSIVE_SCAN_OUTCOME, mark_inconclusive_scan_result
from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ..utils.file.detection import (
    JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
    huggingface_tokenizer_json_has_template_route_evidence,
    is_confirmed_jax_json_checkpoint_file,
    is_huggingface_tokenizer_json_file,
    is_jax_json_checkpoint_file,
)
from ._evidence_redaction import redact_evidence_string
from .base import BaseScanner, IssueSeverity, ScanResult

JAX_SKIP_XGBOOST_JSON_OVERLAP_CONFIG_KEY = "_jax_skip_xgboost_json_overlap"
JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY = "_jax_skip_jinja_json_overlap"

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:  # pragma: no cover
    HAS_NUMPY = False
    if TYPE_CHECKING:
        import numpy as np  # type: ignore[no-redef]
    else:
        np = None  # type: ignore[assignment]


@dataclass
class _PatternFindingBudget:
    """Track per-file metadata pattern findings so repeated strings stay bounded."""

    max_findings: int
    recorded_findings: int = 0
    limit_reported: bool = False


@dataclass
class _BoundedJsonPrefixFrame:
    """Track visible JSON container position while a bounded prefix is walked."""

    kind: str
    context: str
    state: str
    pending_key: str | None = None
    next_index: int = 0


@dataclass
class _OrbaxDirectoryAccounting:
    """Track files and bytes actually inspected by the Orbax directory scanner."""

    bytes_scanned: int = 0
    files_scanned: int = 0


class JaxCheckpointScanner(BaseScanner):
    """Scanner for JAX checkpoint files in various formats (Orbax, pickle-based, etc.)."""

    name = "jax_checkpoint"
    description = "Scans JAX checkpoint files in various serialization formats"
    supported_extensions: ClassVar[list[str]] = [
        ".ckpt",  # JAX checkpoint files (when not PyTorch)
        ".checkpoint",  # Explicit checkpoint files
        ".orbax-checkpoint",  # Orbax checkpoint directories
        ".pickle",  # JAX models saved as pickle (when context suggests JAX)
    ]
    _JAX_INDICATORS: ClassVar[tuple[str, ...]] = (
        "jax",
        "flax",
        "haiku",
        "orbax",
        "arrayimpl",
        "jaxlib",
        "device_array",
    )
    _NON_JAX_NEAR_MATCH_PREFIXES: ClassVar[frozenset[str]] = frozenset({"a"})
    _DOCUMENTATION_CONTEXT_HINTS: ClassVar[frozenset[str]] = frozenset(
        {
            "description",
            "doc",
            "docs",
            "documentation",
            "comment",
            "comments",
            "note",
            "notes",
            "help",
            "readme",
            "example",
            "examples",
        }
    )
    _PICKLE_STRING_OPCODES: ClassVar[frozenset[str]] = frozenset(
        {
            "STRING",
            "BINSTRING",
            "SHORT_BINSTRING",
            "UNICODE",
            "BINUNICODE",
            "SHORT_BINUNICODE",
            "BINUNICODE8",
            "BYTEARRAY8",
        }
    )
    _PICKLE_MARKER: ClassVar[object] = object()
    _PICKLE_PLACEHOLDER: ClassVar[object] = object()
    _PICKLE_STACK_STATE_LIMIT: ClassVar[int] = 4096
    _PICKLE_MEMO_STATE_LIMIT: ClassVar[int] = 4096
    _PICKLE_STICKY_MEMO_STATE_LIMIT: ClassVar[int] = 16384
    _MAX_METADATA_TRAVERSAL_DEPTH: ClassVar[int] = 64
    _JAX_INDICATOR_SCAN_CHUNK_BYTES: ClassVar[int] = 8192
    _UTF8_BOM: ClassVar[bytes] = b"\xef\xbb\xbf"
    DEFAULT_MAX_METADATA_PATTERN_FINDINGS: ClassVar[int] = 256
    DEFAULT_MAX_PICKLE_OPCODE_FINDINGS: ClassVar[int] = 256
    DEFAULT_MAX_ORBAX_CHECKPOINT_FILES: ClassVar[int] = 4096
    DEFAULT_MAX_ORBAX_DIRECTORY_ENTRIES: ClassVar[int] = 8192
    _ORBAX_CHECKPOINT_ENTRY_PREFIXES: ClassVar[tuple[str, ...]] = ("step_", "params_", "state_", "model_")
    _DANGEROUS_PICKLE_GLOBALS: ClassVar[frozenset[tuple[str, str]]] = frozenset(
        {
            ("builtins", "__import__"),
            ("builtins", "compile"),
            ("builtins", "delattr"),
            ("builtins", "eval"),
            ("builtins", "exec"),
            ("builtins", "file"),
            ("builtins", "getattr"),
            ("builtins", "open"),
            ("builtins", "setattr"),
            ("cprofile", "run"),
            ("cprofile", "runctx"),
            ("ctypes", "cast"),
            ("ctypes", "cdll"),
            ("ctypes", "cfunctype"),
            ("ctypes", "oledll"),
            ("ctypes", "pydll"),
            ("ctypes", "pythonapi"),
            ("ctypes", "windll"),
            ("ctypes", "winfunctype"),
            ("dill", "load"),
            ("dill", "loads"),
            ("importlib", "import_module"),
            ("io", "open"),
            ("joblib", "_pickle_load"),
            ("joblib", "load"),
            ("marshal", "load"),
            ("marshal", "loads"),
            ("nt", "system"),
            ("numpy", "load"),
            ("numpy.testing._private.utils", "runstring"),
            ("operator", "attrgetter"),
            ("operator", "getitem"),
            ("operator", "itemgetter"),
            ("operator", "methodcaller"),
            ("os", "execl"),
            ("os", "execle"),
            ("os", "execlp"),
            ("os", "execlpe"),
            ("os", "execv"),
            ("os", "execve"),
            ("os", "execvp"),
            ("os", "execvpe"),
            ("os", "popen"),
            ("os", "popen2"),
            ("os", "popen3"),
            ("os", "popen4"),
            ("os", "spawn"),
            ("os", "spawnl"),
            ("os", "spawnle"),
            ("os", "spawnlp"),
            ("os", "spawnlpe"),
            ("os", "spawnv"),
            ("os", "spawnve"),
            ("os", "spawnvp"),
            ("os", "spawnvpe"),
            ("os", "system"),
            ("pdb", "run"),
            ("pdb", "runcall"),
            ("pdb", "runctx"),
            ("pdb", "runeval"),
            ("pickle", "load"),
            ("pickle", "loads"),
            ("pip", "main"),
            ("pip._internal", "main"),
            ("pip._internal.cli.main", "main"),
            ("pip._vendor.distlib.scripts", "scriptmaker"),
            ("pkgutil", "resolve_name"),
            ("posix", "system"),
            ("profile", "run"),
            ("profile", "runctx"),
            ("runpy", "_run_module_as_main"),
            ("shutil", "copy"),
            ("shutil", "copytree"),
            ("shutil", "move"),
            ("shutil", "rmtree"),
            ("site", "main"),
            ("subprocess", "call"),
            ("subprocess", "check_call"),
            ("subprocess", "check_output"),
            ("subprocess", "getoutput"),
            ("subprocess", "getstatusoutput"),
            ("subprocess", "popen"),
            ("subprocess", "run"),
            ("test.support.script_helper", "assert_python_ok"),
            ("timeit", "repeat"),
            ("timeit", "timeit"),
            ("torch", "load"),
            ("torch._inductor.codecache", "compile_file"),
            ("torch.distributed.rpc", "remote"),
            ("torch.distributed.rpc", "remotemodule"),
            ("torch.distributed.rpc", "rpc_async"),
            ("torch.distributed.rpc", "rpc_sync"),
            ("torch.hub", "load"),
            ("torch.hub", "load_state_dict_from_url"),
            ("torch.serialization", "load"),
            ("torch.storage", "_load_from_bytes"),
            ("types", "codetype"),
            ("types", "functiontype"),
            ("uuid", "_get_command_stdout"),
            ("uuid", "_popen"),
            ("_aix_support", "_read_cmd_output"),
            ("_io", "fileio"),
            ("_osx_support", "_read_output"),
            ("_pyrepl.pager", "pipe_pager"),
        }
    )
    _DANGEROUS_RESTORE_FN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:eval|exec|__import__|os\.system|os\.popen|subprocess\.(?:popen|run|call|check_call|check_output))\b",
        re.IGNORECASE,
    )
    DEFAULT_MAX_PICKLE_SCAN_BYTES: ClassVar[int] = 16 * 1024 * 1024
    _JSON_ANALYSIS_SIZE_LIMIT_REASON: ClassVar[str] = "jax_json_checkpoint_analysis_size_limit"
    _JSON_PREFIX_PATTERN_READ_FAILED_REASON: ClassVar[str] = "jax_json_checkpoint_prefix_pattern_read_failed"
    _ORBAX_METADATA_ANALYSIS_SIZE_LIMIT_REASON: ClassVar[str] = "jax_orbax_metadata_analysis_size_limit"
    _ORBAX_METADATA_PREFIX_PATTERN_READ_FAILED_REASON: ClassVar[str] = "jax_orbax_metadata_prefix_pattern_read_failed"
    _ORBAX_DIRECTORY_ENTRY_COUNT_LIMIT_REASON: ClassVar[str] = "jax_orbax_directory_entry_count_limit"
    _ORBAX_CHECKPOINT_FILE_COUNT_LIMIT_REASON: ClassVar[str] = "jax_orbax_checkpoint_file_count_limit"
    _ORBAX_CHECKPOINT_ENTRY_UNINSPECTED_REASON: ClassVar[str] = "jax_orbax_checkpoint_entry_uninspected"
    _METADATA_TRAVERSAL_LIMIT_REASON: ClassVar[str] = "jax_metadata_traversal_depth_limit"
    _PICKLE_SCAN_LIMIT_REASON: ClassVar[str] = "jax_pickle_scan_limit_exceeded"
    _LEGACY_PICKLE_INITIAL_OPCODES: ClassVar[bytes] = (
        b"()BCcFGIJKLMNPSTUVX]}\x82\x83\x84\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x95\x96\x97"
    )
    _LEGACY_PICKLE_PREFIX_PROBE_BYTES: ClassVar[int] = 8192

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize JAX checkpoint scanning limits and regex detectors."""
        super().__init__(config)
        self.max_file_size = self._get_int_config(
            "max_file_size",
            100 * 1024 * 1024 * 1024,
            minimum=0,
        )
        self.max_pickle_scan_bytes = self._get_int_config(
            "jax_pickle_max_scan_bytes",
            self.DEFAULT_MAX_PICKLE_SCAN_BYTES,
            minimum=1024,
        )
        self.max_pickle_opcode_findings = self._get_int_config(
            "jax_pickle_max_opcode_findings",
            self.DEFAULT_MAX_PICKLE_OPCODE_FINDINGS,
            minimum=1,
        )
        self.max_metadata_pattern_findings = self._get_int_config(
            "jax_metadata_max_pattern_findings",
            self.DEFAULT_MAX_METADATA_PATTERN_FINDINGS,
            minimum=1,
        )
        self.max_orbax_checkpoint_files = self._get_int_config(
            "jax_orbax_max_checkpoint_files",
            self.DEFAULT_MAX_ORBAX_CHECKPOINT_FILES,
            minimum=1,
        )
        self.max_orbax_directory_entries = self._get_int_config(
            "jax_orbax_max_directory_entries",
            self.DEFAULT_MAX_ORBAX_DIRECTORY_ENTRIES,
            minimum=1,
        )

        # JAX-specific suspicious patterns
        self.jax_suspicious_patterns = [
            # JAX transform misuse
            re.compile(r"jax\.experimental\.host_callback\.call", re.IGNORECASE),
            re.compile(r"jax\.experimental\.io_callback", re.IGNORECASE),
            re.compile(r"jax\.debug\.callback", re.IGNORECASE),
            # Dangerous JAX operations
            re.compile(r"jax\.lax\.stop_gradient.*eval", re.IGNORECASE),
            re.compile(r"jax\.lax\.cond.*exec", re.IGNORECASE),
            # Orbax-specific threats
            re.compile(r"orbax\.checkpoint\.restore.*eval", re.IGNORECASE),
            re.compile(r"orbax\.checkpoint\.save.*exec", re.IGNORECASE),
            # JAX compilation threats
            re.compile(r"jax\.jit.*subprocess", re.IGNORECASE),
            re.compile(r"jax\.pmap.*os\.system", re.IGNORECASE),
        ]

    def _get_int_config(self, key: str, default: int, minimum: int = 0) -> int:
        """Return a bounded integer config value with safe fallback."""
        raw_value = self.config.get(key, default)
        try:
            parsed = int(raw_value)
        except (TypeError, ValueError):
            parsed = default
        return max(parsed, minimum)

    @classmethod
    def _looks_like_documentation_context(cls, context: str) -> bool:
        """Return True when a metadata path looks documentation-only."""
        lowered = context.lower()
        context_parts = [part for part in re.split(r"[.\[\]_-]+", lowered) if part]
        return any(part in cls._DOCUMENTATION_CONTEXT_HINTS for part in context_parts)

    @staticmethod
    def _looks_like_documentation_text(text: str) -> bool:
        """Return True when a metadata string looks like prose-only documentation.

        This prefilter is intentionally narrow: it only rejects doc-like strings
        that contain obvious code punctuation or high-signal execution keywords,
        rather than every token in `_DANGEROUS_PICKLE_GLOBALS`, to avoid widening
        false positives in prose metadata. `_add_suspicious_pattern_checks()`
        still performs the full regex scan for JAX/Orbax payload strings in
        metadata values that pass this heuristic.
        """
        stripped = text.strip()
        if not stripped:
            return True
        if any(token in stripped for token in ("(", ")", "'", '"', "`", ";", "|", "&", "$", "/", "\\")):
            return False
        return not re.search(
            r"(?<![A-Za-z0-9_])(?:os\.system|subprocess|eval|exec|import)(?![A-Za-z0-9_])",
            stripped,
            re.IGNORECASE,
        )

    @classmethod
    def _header_looks_like_json(cls, header: bytes) -> bool:
        """Return True when a file header is JSON after stripping BOM and whitespace."""
        normalized_header = header.lstrip()
        if normalized_header.startswith(cls._UTF8_BOM):
            normalized_header = normalized_header[len(cls._UTF8_BOM) :].lstrip()
        return normalized_header.startswith((b"{", b"["))

    @classmethod
    def _iter_string_metadata(
        cls,
        value: Any,
        context: str = "root",
        *,
        depth: int = 0,
        depth_cap_contexts: set[str] | None = None,
    ) -> Iterator[tuple[str, str]]:
        """Yield string leaves from nested metadata with their traversal context."""
        if depth >= cls._MAX_METADATA_TRAVERSAL_DEPTH:
            if depth_cap_contexts is not None:
                depth_cap_contexts.add(context)
            return

        if isinstance(value, str):
            yield context, value
            return

        if isinstance(value, dict):
            for key, nested_value in value.items():
                yield from cls._iter_string_metadata(
                    nested_value,
                    f"{context}.{key}",
                    depth=depth + 1,
                    depth_cap_contexts=depth_cap_contexts,
                )
            return

        if isinstance(value, (list, tuple, set)):
            for index, nested_value in enumerate(value):
                yield from cls._iter_string_metadata(
                    nested_value,
                    f"{context}[{index}]",
                    depth=depth + 1,
                    depth_cap_contexts=depth_cap_contexts,
                )

    def _add_metadata_traversal_depth_limit_checks(
        self,
        *,
        contexts: set[str],
        check_name: str,
        location: str,
        result: ScanResult,
    ) -> None:
        """Surface metadata traversal truncation so deeply nested payloads do not fail open."""
        if not contexts:
            return

        mark_inconclusive_scan_result(result, self._METADATA_TRAVERSAL_LIMIT_REASON)
        for context in sorted(contexts):
            result.add_check(
                name=check_name,
                passed=False,
                message=(
                    f"Reached the maximum JAX metadata traversal depth at {context}; "
                    "nested metadata below this path was not scanned"
                ),
                severity=IssueSeverity.INFO,
                location=location,
                details={
                    "context": context,
                    "max_metadata_traversal_depth": self._MAX_METADATA_TRAVERSAL_DEPTH,
                    "traversal_depth_cap_reached": True,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._METADATA_TRAVERSAL_LIMIT_REASON,
                },
                rule_code="S902",
            )

    def _add_suspicious_pattern_checks(
        self,
        text: str,
        *,
        context: str,
        check_name: str,
        message_prefix: str,
        location: str,
        result: ScanResult,
        finding_budget: _PatternFindingBudget,
    ) -> None:
        """Match suspicious JAX regexes against one metadata/text context."""
        if self._looks_like_documentation_context(context) and self._looks_like_documentation_text(text):
            return

        for pattern in self.jax_suspicious_patterns:
            if not pattern.search(text):
                continue
            if finding_budget.recorded_findings >= finding_budget.max_findings:
                if not finding_budget.limit_reported:
                    limit_check_name = check_name.replace(" Security Check", " Finding Limit")
                    if limit_check_name == check_name:
                        limit_check_name = f"{check_name} Finding Limit"
                    result.add_check(
                        name=limit_check_name,
                        passed=False,
                        message=(
                            "Reached the maximum number of recorded JAX metadata pattern findings; "
                            "additional matches were suppressed"
                        ),
                        severity=IssueSeverity.WARNING,
                        location=location,
                        details={
                            "max_metadata_pattern_findings": finding_budget.max_findings,
                        },
                        rule_code="S902",
                    )
                    finding_budget.limit_reported = True
                return

            result.add_check(
                name=check_name,
                passed=False,
                message=f"{message_prefix}: {pattern.pattern}",
                severity=IssueSeverity.CRITICAL,
                location=location,
                details={"pattern": pattern.pattern, "context": context},
                rule_code="S902",
            )
            finding_budget.recorded_findings += 1

    def scan_pickle_pattern_text(self, path: str, text: str) -> ScanResult:
        """Run the JAX-specific pickle text checks on already-read data."""
        result = self._create_result()
        self._add_suspicious_pattern_checks(
            text,
            context="pickle_checkpoint",
            check_name="JAX Pattern Security Check",
            message_prefix="Suspicious JAX pattern in pickle",
            location=path,
            result=result,
            finding_budget=_PatternFindingBudget(self.max_metadata_pattern_findings),
        )
        result.finish(success=True)
        return result

    @staticmethod
    def _decode_truncated_json_string_fragment(fragment: str) -> str | None:
        """Decode visible string content cut off by the bounded prefix read."""
        candidate = fragment
        try:
            decoded = json.loads(f'"{candidate}"')
        except json.JSONDecodeError:
            escape_start = candidate.rfind("\\")
            if escape_start < 0:
                return None

            preceding_backslashes = 0
            for character in reversed(candidate[:escape_start]):
                if character != "\\":
                    break
                preceding_backslashes += 1
            if preceding_backslashes % 2 != 0:
                return None

            incomplete_escape = candidate[escape_start:]
            if incomplete_escape != "\\" and re.fullmatch(r"\\u[0-9a-fA-F]{0,3}", incomplete_escape) is None:
                return None

            try:
                decoded = json.loads(f'"{candidate[:escape_start]}"')
            except json.JSONDecodeError:
                return None

        return decoded if isinstance(decoded, str) else None

    @classmethod
    def _skip_bounded_json_prefix_container(cls, prefix_text: str, offset: int) -> int | None:
        """Return the end of a balanced nested container without visiting its values."""
        opening = prefix_text[offset]
        if opening not in "{[":
            return None

        closing_for = {"{": "}", "[": "]"}
        nested_containers = [opening]
        decoder = json.JSONDecoder()
        offset += 1
        while offset < len(prefix_text):
            marker = prefix_text[offset]
            if marker == '"':
                try:
                    _, offset = decoder.raw_decode(prefix_text, offset)
                except json.JSONDecodeError:
                    return None
                continue
            if marker in "{[":
                nested_containers.append(marker)
            elif marker in "}]":
                if marker != closing_for[nested_containers[-1]]:
                    return None
                nested_containers.pop()
                if not nested_containers:
                    return offset + 1
            offset += 1
        return None

    @classmethod
    def _iter_bounded_json_prefix_strings(
        cls,
        prefix_text: str,
        *,
        root_context: str = "json_checkpoint_bounded_prefix",
        depth_cap_contexts: set[str] | None = None,
    ) -> Iterator[tuple[str, str]]:
        """Yield decoded visible JSON strings with bounded ancestor context."""
        decoder = json.JSONDecoder()
        frames: list[_BoundedJsonPrefixFrame] = []
        offset = 0
        root_complete = False

        def finish_value() -> None:
            if not frames:
                return
            parent = frames[-1]
            parent.state = "separator"
            parent.pending_key = None
            if parent.kind == "array":
                parent.next_index += 1

        def value_context(frame: _BoundedJsonPrefixFrame) -> str | None:
            if frame.kind == "object":
                return f"{frame.context}.{frame.pending_key}" if frame.pending_key is not None else None
            return f"{frame.context}[{frame.next_index}]"

        while offset < len(prefix_text):
            if prefix_text[offset].isspace():
                offset += 1
                continue

            if not frames:
                if root_complete:
                    return
                if prefix_text[offset] not in "{[":
                    return
                kind = "object" if prefix_text[offset] == "{" else "array"
                state = "key" if kind == "object" else "value"
                frames.append(_BoundedJsonPrefixFrame(kind, root_context, state))
                offset += 1
                continue

            frame = frames[-1]
            marker = prefix_text[offset]
            if frame.kind == "object" and frame.state == "key":
                if marker == "}":
                    frames.pop()
                    offset += 1
                    root_complete = not frames
                    finish_value()
                    continue
                if marker != '"':
                    return
                try:
                    key, offset = decoder.raw_decode(prefix_text, offset)
                except json.JSONDecodeError:
                    return
                if not isinstance(key, str):
                    return
                frame.pending_key = key
                frame.state = "colon"
                continue

            if frame.kind == "object" and frame.state == "colon":
                if marker != ":":
                    return
                frame.state = "value"
                offset += 1
                continue

            if frame.state == "value":
                if frame.kind == "array" and marker == "]":
                    frames.pop()
                    offset += 1
                    root_complete = not frames
                    finish_value()
                    continue
                context = value_context(frame)
                if context is None:
                    return
                if marker == '"':
                    try:
                        text_value, offset = decoder.raw_decode(prefix_text, offset)
                    except json.JSONDecodeError:
                        text_value = cls._decode_truncated_json_string_fragment(prefix_text[offset + 1 :])
                        if text_value:
                            yield context, text_value
                        return
                    if not isinstance(text_value, str):
                        return
                    yield context, text_value
                    finish_value()
                    continue
                if marker in "{[":
                    if len(frames) >= cls._MAX_METADATA_TRAVERSAL_DEPTH:
                        if depth_cap_contexts is not None:
                            depth_cap_contexts.add(context)
                        skipped_offset = cls._skip_bounded_json_prefix_container(prefix_text, offset)
                        if skipped_offset is None:
                            return
                        offset = skipped_offset
                        finish_value()
                        continue
                    kind = "object" if marker == "{" else "array"
                    state = "key" if kind == "object" else "value"
                    frames.append(_BoundedJsonPrefixFrame(kind, context, state))
                    offset += 1
                    continue
                scalar_end = offset
                while scalar_end < len(prefix_text) and prefix_text[scalar_end] not in ",}]":
                    scalar_end += 1
                if scalar_end == len(prefix_text):
                    return
                offset = scalar_end
                finish_value()
                continue

            if frame.state != "separator":
                return
            closing_marker = "}" if frame.kind == "object" else "]"
            if marker == closing_marker:
                frames.pop()
                offset += 1
                root_complete = not frames
                finish_value()
                continue
            if marker != ",":
                return
            frame.state = "key" if frame.kind == "object" else "value"
            offset += 1

    def _scan_bounded_json_prefix_patterns(
        self,
        path: str,
        result: ScanResult,
        *,
        root_context: str = "json_checkpoint_bounded_prefix",
        check_name: str = "JSON Pattern Security Check",
        message_prefix: str = "Suspicious pattern in bounded JSON checkpoint prefix",
        depth_limit_check_name: str = "JSON Metadata Traversal Depth Limit",
        detect_orbax_restore_fn: bool = False,
    ) -> None:
        """Scan decoded JSON string content visible inside the bounded prefix."""
        with open(path, "rb") as source:
            prefix_text = source.read(JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES).decode("utf-8-sig", errors="ignore")

        depth_cap_contexts: set[str] = set()
        first_token_offset = len(prefix_text) - len(prefix_text.lstrip())
        try:
            parsed_root, _ = json.JSONDecoder().raw_decode(prefix_text, first_token_offset)
        except (json.JSONDecodeError, RecursionError):
            string_values = self._iter_bounded_json_prefix_strings(
                prefix_text,
                root_context=root_context,
                depth_cap_contexts=depth_cap_contexts,
            )
        else:
            string_values = self._iter_string_metadata(
                parsed_root,
                root_context,
                depth_cap_contexts=depth_cap_contexts,
            )

        finding_budget = _PatternFindingBudget(self.max_metadata_pattern_findings)
        orbax_restore_context = f"{root_context}.restore_fn"
        first_orbax_restore_fn: str | None = None
        dangerous_orbax_restore_fn: str | None = None
        for context, text_value in string_values:
            if detect_orbax_restore_fn and (
                context == orbax_restore_context
                or context.startswith(f"{orbax_restore_context}.")
                or context.startswith(f"{orbax_restore_context}[")
            ):
                if first_orbax_restore_fn is None:
                    first_orbax_restore_fn = text_value
                if dangerous_orbax_restore_fn is None and self._DANGEROUS_RESTORE_FN_PATTERN.search(text_value):
                    dangerous_orbax_restore_fn = text_value
            self._add_suspicious_pattern_checks(
                text_value,
                context=context,
                check_name=check_name,
                message_prefix=message_prefix,
                location=path,
                result=result,
                finding_budget=finding_budget,
            )
        if dangerous_orbax_restore_fn is not None:
            self._add_orbax_restore_fn_check(dangerous_orbax_restore_fn, path, result)
        elif first_orbax_restore_fn is not None:
            self._add_orbax_restore_fn_check(first_orbax_restore_fn, path, result)
        self._add_metadata_traversal_depth_limit_checks(
            contexts=depth_cap_contexts,
            check_name=depth_limit_check_name,
            location=path,
            result=result,
        )

    @staticmethod
    def _parse_pickle_global_reference(arg: str) -> tuple[str, str] | None:
        """Parse pickle GLOBAL/INST opcode args into ``(module, name)``."""
        normalized = arg.replace("\n", " ").strip()
        if not normalized:
            return None

        parts = normalized.split()
        if len(parts) < 2:
            return None

        module_name = parts[0].strip()
        global_name = " ".join(parts[1:]).strip()
        if not module_name or not global_name:
            return None
        return module_name, global_name

    @classmethod
    def _is_dangerous_pickle_global(cls, module_name: str, global_name: str) -> bool:
        """Return True for pickle globals that can launch code execution."""
        normalized = (module_name.strip().lower(), global_name.strip().lower())
        return normalized in cls._DANGEROUS_PICKLE_GLOBALS

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Return True when a path looks like a JAX/Orbax checkpoint."""
        if not os.path.exists(path):
            return False

        # Handle directory-based checkpoints (like Orbax)
        if os.path.isdir(path):
            return cls._is_jax_checkpoint_directory(path)

        # Handle file-based checkpoints
        if os.path.isfile(path):
            if is_huggingface_tokenizer_json_file(path) or huggingface_tokenizer_json_has_template_route_evidence(path):
                return False
            ext = os.path.splitext(path)[1].lower()
            if ext == ".json":
                return is_confirmed_jax_json_checkpoint_file(path)
            if ext in cls.supported_extensions:
                return cls._is_likely_jax_file(path) or is_jax_json_checkpoint_file(path)
            return is_jax_json_checkpoint_file(path)

        return False

    @classmethod
    def _is_jax_checkpoint_directory(cls, path: str) -> bool:
        """Check if directory looks like a JAX/Orbax checkpoint."""
        path_obj = Path(path)

        # Orbax checkpoint indicators
        orbax_files = ["metadata.json", "_CHECKPOINT", "orbax_checkpoint_metadata.json"]

        # Check for Orbax files
        for orbax_file in orbax_files:
            if (path_obj / orbax_file).exists():
                return True

        # Probe once and route oversized directories into the scanner's
        # fail-closed entry-limit handling.
        for entry_index, entry in enumerate(path_obj.iterdir(), start=1):
            if entry_index > cls.DEFAULT_MAX_ORBAX_DIRECTORY_ENTRIES:
                return True
            if cls._is_orbax_checkpoint_entry_name(entry.name):
                return True
        return False

    @classmethod
    def _is_orbax_checkpoint_entry_name(cls, name: str) -> bool:
        """Return whether a top-level entry has a recognized Orbax/JAX checkpoint name."""
        return name == "checkpoint" or name.startswith(("checkpoint_", *cls._ORBAX_CHECKPOINT_ENTRY_PREFIXES))

    @classmethod
    def _header_starts_with_legacy_pickle_opcode(cls, header: bytes) -> bool:
        return bool(header) and header[:1] in cls._LEGACY_PICKLE_INITIAL_OPCODES

    @staticmethod
    def _is_truncated_pickle_parse_error(error: ValueError) -> bool:
        message = str(error)
        return (
            "pickle exhausted before seeing STOP" in message
            or "not enough data" in message
            or "no newline found" in message
            or ("expected " in message and " bytes " in message and "remain" in message)
        )

    def _has_structural_legacy_pickle_prefix(self, path: str, header: bytes) -> bool:
        if not self._header_starts_with_legacy_pickle_opcode(header):
            return False

        read_limit = max(len(header), min(self.max_pickle_scan_bytes, self._LEGACY_PICKLE_PREFIX_PROBE_BYTES))
        with suppress(ValueError):
            file_size = os.path.getsize(path)
            with open(path, "rb") as source:
                data = source.read(read_limit)

            marker = object()
            stack: list[object] = []
            memo_indices: set[int] = set()
            next_memo_index = 0
            parsed_opcode = False
            observed_security_relevant_opcode = False

            def _memo_index(value: Any) -> int | None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

            def _apply_probe_stack_effect(opcode_info: Any) -> bool:
                if opcode_info.name == "MARK":
                    stack.append(marker)
                    return True

                stack_before = list(getattr(opcode_info, "stack_before", ()))
                stack_after = list(getattr(opcode_info, "stack_after", ()))

                if pickletools.markobject in stack_before:
                    preserved_items_before_mark = stack_before.index(pickletools.markobject)
                    if marker not in stack:
                        return False
                    marker_index = len(stack) - 1 - stack[::-1].index(marker)
                    if marker_index < preserved_items_before_mark:
                        return False
                    del stack[marker_index:]
                    if len(stack_after) > preserved_items_before_mark:
                        stack.extend(object() for _ in range(len(stack_after) - preserved_items_before_mark))
                    elif len(stack_after) < preserved_items_before_mark:
                        remove_count = preserved_items_before_mark - len(stack_after)
                        if len(stack) < remove_count:
                            return False
                        del stack[-remove_count:]
                    return True

                if len(stack) < len(stack_before):
                    return False
                if stack_before:
                    del stack[-len(stack_before) :]
                stack.extend(object() for _ in stack_after)
                return True

            try:
                for opcode, arg, _pos in pickletools.genops(data):
                    parsed_opcode = True
                    if opcode.name == "GLOBAL" and isinstance(arg, str):
                        parsed_global = self._parse_pickle_global_reference(arg)
                        if parsed_global is not None and self._is_dangerous_pickle_global(*parsed_global):
                            observed_security_relevant_opcode = True
                    elif opcode.name in {"STACK_GLOBAL", "REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST"}:
                        observed_security_relevant_opcode = True
                    if opcode.name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                        if not stack:
                            return False
                        memo_index = _memo_index(arg)
                        if memo_index is not None:
                            memo_indices.add(memo_index)
                            next_memo_index = max(next_memo_index, memo_index + 1)
                    elif opcode.name == "MEMOIZE":
                        if not stack:
                            return False
                        memo_indices.add(next_memo_index)
                        next_memo_index += 1
                    elif opcode.name in {"BINGET", "LONG_BINGET", "GET"}:
                        memo_index = _memo_index(arg)
                        if memo_index is None or memo_index not in memo_indices:
                            return False
                    if not _apply_probe_stack_effect(opcode):
                        return False
                    if opcode.name == "STOP":
                        return True
            except ValueError as e:
                if "pickle exhausted before seeing STOP" in str(e):
                    if file_size > len(data):
                        return parsed_opcode or self._header_starts_with_legacy_pickle_opcode(header)
                    return parsed_opcode and observed_security_relevant_opcode
                if file_size > len(data) and self._is_truncated_pickle_parse_error(e):
                    return parsed_opcode or self._header_starts_with_legacy_pickle_opcode(header)

        return False

    @classmethod
    def _legacy_pickle_header_has_jax_indicator(cls, path: str, header: bytes) -> bool:
        if not cls._header_starts_with_legacy_pickle_opcode(header):
            return False

        with open(path, "rb") as source:
            data = source.read(max(8192, len(header)))
        return cls._contains_jax_indicator(data.decode("utf-8", errors="ignore"))

    @classmethod
    def _is_likely_jax_file(cls, path: str) -> bool:
        """Determine if a file is likely a JAX checkpoint."""
        try:
            with open(path, "rb") as f:
                header = f.read(512)
                # Check for pickle formats with JAX indicators. Protocol 0
                # pickles are textual and can begin directly with a string
                # opcode such as `Vjax`, so they do not have the binary
                # protocol marker.
                if header.startswith(b"\x80") or cls._header_starts_with_legacy_pickle_opcode(header):
                    with suppress(Exception):
                        data = header + f.read(max(0, 8192 - len(header)))
                        data_str = data.decode("utf-8", errors="ignore").lower()
                        return cls._contains_jax_indicator(data_str)

            decoded_header = header.decode("utf-8", errors="ignore").lower()

            # Check for JSON metadata files, including extensionful `.checkpoint`
            # files that contain JAX/Orbax metadata rather than pickle bytes.
            if cls._header_looks_like_json(header):
                return cls._contains_jax_indicator(decoded_header) or cls._file_contains_jax_indicator(path)

            # Check for NumPy files in JAX context
            if header.startswith(b"\x93NUMPY") and cls._contains_jax_indicator(path.lower()):
                return True

        except Exception:
            return False

        return False

    @classmethod
    def _file_contains_jax_indicator(cls, path: str) -> bool:
        """Stream-search a file for JAX indicators beyond the initial routing header."""
        chunk_tail = ""
        tail_length = max(len(indicator) for indicator in cls._JAX_INDICATORS) - 1

        try:
            with open(path, "rb") as f:
                while chunk := f.read(cls._JAX_INDICATOR_SCAN_CHUNK_BYTES):
                    decoded_chunk = chunk.decode("utf-8", errors="ignore").lower()
                    search_text = chunk_tail + decoded_chunk
                    if cls._contains_jax_indicator(search_text):
                        return True
                    chunk_tail = search_text[-tail_length:]
        except Exception:
            return False

        return False

    @classmethod
    def _contains_jax_indicator(cls, text: str) -> bool:
        """Return True when text contains a JAX-family indicator that is not a suffix."""
        lowered_text = text.lower()
        for indicator in cls._JAX_INDICATORS:
            start = 0
            while (index := lowered_text.find(indicator, start)) != -1:
                prefix = lowered_text[index - 1] if index > 0 else ""
                if prefix not in cls._NON_JAX_NEAR_MATCH_PREFIXES:
                    return True
                start = index + 1
        return False

    @classmethod
    def should_analyze_inconclusive_json_overlap(cls, path: str) -> bool:
        """Return whether bounded JAX analysis should supplement ambiguous JSON routing."""
        if Path(path).suffix.lower() in cls.supported_extensions:
            return True
        try:
            with open(path, "rb") as source:
                prefix_text = source.read(JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES).decode("utf-8-sig", errors="ignore")
        except OSError:
            return False
        return any(
            cls._contains_jax_indicator(text_value)
            for _, text_value in cls._iter_bounded_json_prefix_strings(prefix_text)
        )

    def _add_orbax_metadata_read_failure(
        self,
        *,
        result: ScanResult,
        metadata_path: Path,
        metadata_file: str,
        error: Exception | str,
    ) -> None:
        """Record incomplete Orbax metadata coverage without treating it as a security finding."""
        error_message = str(error)
        mark_inconclusive_scan_result(result, "jax_orbax_metadata_read_failed")
        result.add_check(
            name="Orbax Metadata Read Check",
            passed=False,
            message=f"Error reading Orbax metadata: {error_message}",
            severity=IssueSeverity.INFO,
            location=str(metadata_path),
            rule_code="S902",
            details={
                "error": error_message,
                "file": metadata_file,
                "analysis_incomplete": True,
                "scan_outcome_reason": "jax_orbax_metadata_read_failed",
            },
        )

    def _add_uninspected_orbax_checkpoint_entry(
        self,
        *,
        result: ScanResult,
        entry_path: Path,
        entry_type: str,
    ) -> None:
        """Fail closed when a recognized checkpoint entry is not a regular file."""
        mark_inconclusive_scan_result(result, self._ORBAX_CHECKPOINT_ENTRY_UNINSPECTED_REASON)
        result.add_check(
            name="Orbax Checkpoint Entry Coverage",
            passed=False,
            message="Recognized Orbax/JAX checkpoint entry is not a regular file and was not inspected",
            severity=IssueSeverity.INFO,
            location=str(entry_path),
            rule_code="S902",
            details={
                "entry": entry_path.name,
                "entry_type": entry_type,
                "analysis_incomplete": True,
                "scan_outcome_reason": self._ORBAX_CHECKPOINT_ENTRY_UNINSPECTED_REASON,
            },
        )

    def _handle_oversized_orbax_metadata(
        self,
        *,
        metadata_path: Path,
        metadata_file: str,
        file_size: int,
        result: ScanResult,
    ) -> None:
        """Fail closed on oversized Orbax metadata while scanning a bounded visible prefix."""
        mark_inconclusive_scan_result(result, self._ORBAX_METADATA_ANALYSIS_SIZE_LIMIT_REASON)
        result.add_check(
            name="Orbax Metadata Analysis Limit",
            passed=False,
            message="Orbax metadata analysis incomplete because the file exceeds the bounded parsing limit",
            severity=IssueSeverity.INFO,
            location=str(metadata_path),
            rule_code="S902",
            details={
                "file": metadata_file,
                "file_size": file_size,
                "max_json_analysis_bytes": JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
                "analysis_incomplete": True,
                "scan_outcome_reason": self._ORBAX_METADATA_ANALYSIS_SIZE_LIMIT_REASON,
            },
        )
        try:
            self._scan_bounded_json_prefix_patterns(
                str(metadata_path),
                result,
                root_context="orbax_metadata_bounded_prefix",
                check_name="Orbax Pattern Security Check",
                message_prefix="Suspicious pattern in bounded Orbax metadata prefix",
                depth_limit_check_name="Orbax Metadata Traversal Depth Limit",
                detect_orbax_restore_fn=True,
            )
        except OSError as e:
            mark_operational_scan_error(result, self._ORBAX_METADATA_PREFIX_PATTERN_READ_FAILED_REASON)
            result.add_check(
                name="Orbax Metadata Bounded Prefix Pattern Scan",
                passed=False,
                message=f"Unable to inspect bounded Orbax metadata prefix: {e}",
                severity=IssueSeverity.INFO,
                location=str(metadata_path),
                details={
                    "file": metadata_file,
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._ORBAX_METADATA_PREFIX_PATTERN_READ_FAILED_REASON,
                },
                rule_code="S902",
            )

    def _scan_orbax_checkpoint(self, path: str, result: ScanResult) -> _OrbaxDirectoryAccounting:
        """Scan Orbax checkpoint directory."""
        path_obj = Path(path)
        accounting = _OrbaxDirectoryAccounting()

        # Check metadata files
        metadata_files = ["metadata.json", "orbax_checkpoint_metadata.json", "_CHECKPOINT"]

        for metadata_file in metadata_files:
            metadata_path = path_obj / metadata_file
            if metadata_path.exists():
                if not metadata_path.is_file():
                    self._add_orbax_metadata_read_failure(
                        result=result,
                        metadata_path=metadata_path,
                        metadata_file=metadata_file,
                        error="metadata path is not a regular file",
                    )
                    continue
                try:
                    file_size = metadata_path.stat().st_size
                except OSError as e:
                    self._add_orbax_metadata_read_failure(
                        result=result,
                        metadata_path=metadata_path,
                        metadata_file=metadata_file,
                        error=e,
                    )
                    continue

                accounting.files_scanned += 1
                accounting.bytes_scanned += min(file_size, JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES)

                if file_size > JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES:
                    self._handle_oversized_orbax_metadata(
                        metadata_path=metadata_path,
                        metadata_file=metadata_file,
                        file_size=file_size,
                        result=result,
                    )
                    continue

                try:
                    with open(metadata_path, encoding="utf-8") as f:
                        metadata = json.load(f)

                    # Analyze metadata for suspicious content
                    self._analyze_orbax_metadata(metadata, str(metadata_path), result)

                except json.JSONDecodeError as e:
                    mark_inconclusive_scan_result(result, "jax_orbax_metadata_parse_failed")
                    result.add_check(
                        name="Orbax Metadata JSON Validation",
                        passed=False,
                        message=f"Invalid JSON in Orbax metadata: {e}",
                        severity=IssueSeverity.INFO,
                        location=str(metadata_path),
                        rule_code="S902",
                        details={
                            "error": str(e),
                            "file": metadata_file,
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "jax_orbax_metadata_parse_failed",
                        },
                    )
                except Exception as e:
                    self._add_orbax_metadata_read_failure(
                        result=result,
                        metadata_path=metadata_path,
                        metadata_file=metadata_file,
                        error=e,
                    )

        # Scan checkpoint files
        directory_entries_seen = 0
        checkpoint_files_seen = 0
        uninspected_checkpoint_entry_reported = False
        for checkpoint_file in path_obj.iterdir():
            directory_entries_seen += 1
            if directory_entries_seen > self.max_orbax_directory_entries:
                mark_inconclusive_scan_result(result, self._ORBAX_DIRECTORY_ENTRY_COUNT_LIMIT_REASON)
                result.add_check(
                    name="Orbax Directory Entry Count Limit",
                    passed=False,
                    message=(
                        "Reached the maximum number of Orbax directory entries to inspect; "
                        "additional entries were skipped"
                    ),
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "max_orbax_directory_entries": self.max_orbax_directory_entries,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self._ORBAX_DIRECTORY_ENTRY_COUNT_LIMIT_REASON,
                    },
                    rule_code="S902",
                )
                break
            if not self._is_orbax_checkpoint_entry_name(checkpoint_file.name):
                continue
            if checkpoint_file.is_symlink() or not checkpoint_file.is_file():
                if not uninspected_checkpoint_entry_reported:
                    entry_type = (
                        "symlink"
                        if checkpoint_file.is_symlink()
                        else "directory"
                        if checkpoint_file.is_dir()
                        else "non_regular"
                    )
                    self._add_uninspected_orbax_checkpoint_entry(
                        result=result,
                        entry_path=checkpoint_file,
                        entry_type=entry_type,
                    )
                    uninspected_checkpoint_entry_reported = True
                continue
            checkpoint_files_seen += 1
            if checkpoint_files_seen > self.max_orbax_checkpoint_files:
                mark_inconclusive_scan_result(result, self._ORBAX_CHECKPOINT_FILE_COUNT_LIMIT_REASON)
                result.add_check(
                    name="Orbax Checkpoint File Count Limit",
                    passed=False,
                    message=(
                        "Reached the maximum number of Orbax checkpoint files to inspect; "
                        "additional checkpoint entries were skipped"
                    ),
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "max_orbax_checkpoint_files": self.max_orbax_checkpoint_files,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self._ORBAX_CHECKPOINT_FILE_COUNT_LIMIT_REASON,
                    },
                    rule_code="S902",
                )
                break
            with suppress(OSError):
                accounting.bytes_scanned += checkpoint_file.stat().st_size
            accounting.files_scanned += 1
            self._scan_checkpoint_file(
                str(checkpoint_file),
                result,
                treat_legacy_pickle_header_as_checkpoint=True,
            )

        result.metadata["orbax_files_inspected"] = accounting.files_scanned
        result.metadata["directory_accounting_scope"] = "orbax_selected_files"
        return accounting

    def _add_orbax_restore_fn_check(self, restore_fn_value: str, path: str, result: ScanResult) -> None:
        """Preserve Orbax restore hook reporting for full and bounded-prefix metadata scans."""
        restore_fn_is_dangerous = bool(self._DANGEROUS_RESTORE_FN_PATTERN.search(restore_fn_value))
        result.add_check(
            name="Orbax Restore Function Check",
            passed=False,
            message=(
                "Dangerous restore function detected in Orbax metadata"
                if restore_fn_is_dangerous
                else "Custom restore function detected in Orbax metadata"
            ),
            severity=IssueSeverity.CRITICAL if restore_fn_is_dangerous else IssueSeverity.WARNING,
            location=path,
            details={"restore_fn": redact_evidence_string(restore_fn_value, max_chars=200)},
            rule_code="S302",
        )

    def _analyze_orbax_metadata(self, metadata: dict[str, Any], path: str, result: ScanResult) -> None:
        """Analyze Orbax metadata for security issues."""

        # Check for suspicious restore functions
        if "restore_fn" in metadata:
            self._add_orbax_restore_fn_check(str(metadata["restore_fn"]), path, result)

        # Check for code injection in metadata
        pattern_finding_budget = _PatternFindingBudget(self.max_metadata_pattern_findings)
        metadata_depth_cap_contexts: set[str] = set()
        for context, text_value in self._iter_string_metadata(
            metadata,
            "orbax_metadata",
            depth_cap_contexts=metadata_depth_cap_contexts,
        ):
            self._add_suspicious_pattern_checks(
                text_value,
                context=context,
                check_name="Orbax Pattern Security Check",
                message_prefix="Suspicious pattern in Orbax metadata",
                location=path,
                result=result,
                finding_budget=pattern_finding_budget,
            )
        self._add_metadata_traversal_depth_limit_checks(
            contexts=metadata_depth_cap_contexts,
            check_name="Orbax Metadata Traversal Depth Limit",
            location=path,
            result=result,
        )

        # Extract useful metadata
        if isinstance(metadata, dict):
            result.metadata.update(
                {
                    "orbax_version": metadata.get("version"),
                    "checkpoint_type": metadata.get("type", "unknown"),
                    "save_format": metadata.get("format", "unknown"),
                }
            )

    def _scan_checkpoint_file(
        self,
        path: str,
        result: ScanResult,
        *,
        treat_legacy_pickle_header_as_checkpoint: bool = False,
    ) -> None:
        """Scan individual checkpoint file."""
        try:
            file_size = os.path.getsize(path)

            if self.max_file_size > 0 and file_size > self.max_file_size:
                result.add_check(
                    name="Checkpoint File Size Check",
                    passed=False,
                    message=f"Checkpoint file too large: {file_size:,} bytes",
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"file_size": file_size, "max_size": self.max_file_size},
                    rule_code="S902",
                )

            with open(path, "rb") as f:
                header = f.read(1024)

            # Check file format
            legacy_pickle_header = self._has_structural_legacy_pickle_prefix(path, header)
            if (
                header.startswith(b"\x80")
                or (legacy_pickle_header and treat_legacy_pickle_header_as_checkpoint)
                or (legacy_pickle_header and self._legacy_pickle_header_has_jax_indicator(path, header))
            ):
                self._scan_pickle_checkpoint(path, result)
            elif header.startswith(b"\x93NUMPY"):  # NumPy format
                self._scan_numpy_checkpoint(path, result)
            elif self._header_looks_like_json(header) or is_jax_json_checkpoint_file(path):  # JSON format
                self._scan_json_checkpoint(path, result)
            else:
                result.add_check(
                    name="Checkpoint Format Detection",
                    passed=True,
                    message=f"Unknown checkpoint file format: {path}",
                    location=path,
                    details={"format": "unknown"},
                    rule_code=None,  # Passing check
                )

        except Exception as e:
            mark_inconclusive_scan_result(result, "jax_checkpoint_file_scan_failed")
            result.add_check(
                name="Checkpoint File Scan",
                passed=False,
                message=f"Error scanning checkpoint file: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_checkpoint_file_scan_failed",
                },
                rule_code="S902",
            )

    def _scan_pickle_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan pickle-based JAX checkpoint."""
        try:
            with open(path, "rb") as f:
                data = f.read(self.max_pickle_scan_bytes + 1)

            pickle_prefix_truncated = False
            if len(data) > self.max_pickle_scan_bytes:
                data = data[: self.max_pickle_scan_bytes]
                pickle_prefix_truncated = True
                mark_inconclusive_scan_result(result, self._PICKLE_SCAN_LIMIT_REASON)
                result.add_check(
                    name="Pickle Checkpoint Prefix Scan Limit",
                    passed=False,
                    message=(
                        f"Only the first {self.max_pickle_scan_bytes} bytes of the pickle checkpoint were "
                        "inspected for opcode patterns"
                    ),
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "max_pickle_scan_bytes": self.max_pickle_scan_bytes,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self._PICKLE_SCAN_LIMIT_REASON,
                    },
                    rule_code="S902",
                )

            pickle_stack: list[Any] = []
            pickle_memo: OrderedDict[int, Any] = OrderedDict()
            sticky_pickle_memo: OrderedDict[int, Any] = OrderedDict()
            next_pickle_memo_index = 0
            dangerous_pickle_memo_tokens = frozenset(
                token
                for module_name, global_name in self._DANGEROUS_PICKLE_GLOBALS
                for token in (module_name, global_name)
            )
            dangerous_opcode_findings = 0
            finding_limit_reported = False
            sticky_memo_limit_reported = False
            memo_lookup_gap_reported = False

            def _push_pickle_value(value: Any) -> None:
                """Push one modeled pickle stack value while bounding stack state."""
                pickle_stack.append(value)
                if len(pickle_stack) > self._PICKLE_STACK_STATE_LIMIT:
                    del pickle_stack[: -self._PICKLE_STACK_STATE_LIMIT]

            def _memo_key(value: Any) -> int | None:
                """Coerce a memo opcode argument to an integer key."""
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

            def _memoize_pickle_value(memo_index: int) -> None:
                """Store the current stack top in the bounded pickle memo model."""
                nonlocal next_pickle_memo_index, sticky_memo_limit_reported

                if not pickle_stack:
                    return
                memo_value = pickle_stack[-1]
                next_pickle_memo_index = max(next_pickle_memo_index, memo_index + 1)
                if memo_index in pickle_memo:
                    pickle_memo.move_to_end(memo_index)
                elif len(pickle_memo) >= self._PICKLE_MEMO_STATE_LIMIT:
                    pickle_memo.popitem(last=False)
                pickle_memo[memo_index] = memo_value
                if (isinstance(memo_value, str) and memo_value.lower() in dangerous_pickle_memo_tokens) or (
                    isinstance(memo_value, tuple)
                    and len(memo_value) == 2
                    and isinstance(memo_value[0], str)
                    and isinstance(memo_value[1], str)
                    and self._is_dangerous_pickle_global(memo_value[0], memo_value[1])
                ):
                    if memo_index in sticky_pickle_memo:
                        sticky_pickle_memo.move_to_end(memo_index)
                    elif len(sticky_pickle_memo) >= self._PICKLE_STICKY_MEMO_STATE_LIMIT:
                        sticky_pickle_memo.popitem(last=False)
                        if not sticky_memo_limit_reported:
                            result.add_check(
                                name="Pickle Sticky Memo State Limit",
                                passed=False,
                                message=(
                                    "Reached the maximum sticky pickle memo size for preserving dangerous memo "
                                    "values; older dangerous memo slots may require reconstruction-gap warnings"
                                ),
                                rule_code="S902",
                                severity=IssueSeverity.WARNING,
                                location=path,
                                details={
                                    "max_pickle_sticky_memo_state": self._PICKLE_STICKY_MEMO_STATE_LIMIT,
                                },
                            )
                            sticky_memo_limit_reported = True
                    sticky_pickle_memo[memo_index] = memo_value
                else:
                    sticky_pickle_memo.pop(memo_index, None)

            def _pop_pickle_mark() -> None:
                """Pop modeled stack values until the most recent MARK sentinel."""
                while pickle_stack:
                    value = pickle_stack.pop()
                    if value is self._PICKLE_MARKER:
                        return

            def _pop_pickle_values(count: int) -> None:
                """Pop up to ``count`` modeled stack values."""
                for _ in range(min(count, len(pickle_stack))):
                    pickle_stack.pop()

            def _sync_unhandled_pickle_stack_effect(opcode_info: Any) -> None:
                """Apply generic stack effects for opcodes not modeled explicitly."""
                stack_before = list(getattr(opcode_info, "stack_before", ()))
                stack_after = list(getattr(opcode_info, "stack_after", ()))
                if not stack_before and not stack_after:
                    return

                if pickletools.markobject in stack_before:
                    preserved_items_before_mark = stack_before.index(pickletools.markobject)
                    _pop_pickle_mark()
                    if len(stack_after) > preserved_items_before_mark:
                        for _ in range(len(stack_after) - preserved_items_before_mark):
                            _push_pickle_value(self._PICKLE_PLACEHOLDER)
                    elif len(stack_after) < preserved_items_before_mark:
                        _pop_pickle_values(preserved_items_before_mark - len(stack_after))
                    return

                _pop_pickle_values(len(stack_before))
                for _ in stack_after:
                    _push_pickle_value(self._PICKLE_PLACEHOLDER)

            try:
                for opcode, arg, pos in pickletools.genops(data):
                    if opcode.name in self._PICKLE_STRING_OPCODES and isinstance(arg, str):
                        _push_pickle_value(arg)
                        continue
                    if opcode.name == "MARK":
                        _push_pickle_value(self._PICKLE_MARKER)
                        continue
                    if opcode.name == "POP":
                        if pickle_stack:
                            pickle_stack.pop()
                        continue
                    if opcode.name == "POP_MARK":
                        _pop_pickle_mark()
                        continue
                    if opcode.name == "DUP":
                        if pickle_stack:
                            _push_pickle_value(pickle_stack[-1])
                        continue
                    if opcode.name == "MEMOIZE":
                        _memoize_pickle_value(next_pickle_memo_index)
                        continue
                    if opcode.name in {"BINPUT", "LONG_BINPUT", "PUT"}:
                        memo_index = _memo_key(arg)
                        if memo_index is not None:
                            _memoize_pickle_value(memo_index)
                        continue
                    if opcode.name in {"BINGET", "LONG_BINGET", "GET"}:
                        memo_index = _memo_key(arg)
                        if memo_index is None:
                            continue
                        if memo_index in pickle_memo:
                            _push_pickle_value(pickle_memo[memo_index])
                        elif memo_index in sticky_pickle_memo:
                            _push_pickle_value(sticky_pickle_memo[memo_index])
                        else:
                            _push_pickle_value(self._PICKLE_PLACEHOLDER)
                            if memo_index < next_pickle_memo_index and not memo_lookup_gap_reported:
                                result.add_check(
                                    name="Pickle Memo Reconstruction Gap",
                                    passed=False,
                                    message=(
                                        "Unable to resolve a pickle memo reference from the bounded scanner state; "
                                        "STACK_GLOBAL reconstruction may be incomplete for evicted memo slots"
                                    ),
                                    rule_code="S902",
                                    severity=IssueSeverity.WARNING,
                                    location=path,
                                    details={
                                        "opcode": opcode.name,
                                        "position": pos,
                                        "memo_index": memo_index,
                                        "max_pickle_memo_state": self._PICKLE_MEMO_STATE_LIMIT,
                                    },
                                )
                                memo_lookup_gap_reported = True
                        continue

                    parsed_global = None
                    if opcode.name in {"GLOBAL", "INST"} and isinstance(arg, str):
                        parsed_global = self._parse_pickle_global_reference(arg)
                        if parsed_global is not None:
                            _push_pickle_value(parsed_global)
                    elif opcode.name == "STACK_GLOBAL" and len(pickle_stack) >= 2:
                        global_name = pickle_stack.pop()
                        module_name = pickle_stack.pop()
                        if isinstance(module_name, str) and isinstance(global_name, str):
                            parsed_global = (module_name, global_name)
                            _push_pickle_value(parsed_global)

                    if parsed_global is not None and self._is_dangerous_pickle_global(*parsed_global):
                        module_name, global_name = parsed_global
                        if dangerous_opcode_findings >= self.max_pickle_opcode_findings:
                            if not finding_limit_reported:
                                result.add_check(
                                    name="Pickle Opcode Finding Limit",
                                    passed=False,
                                    message=(
                                        "Reached the maximum number of recorded dangerous pickle opcode findings; "
                                        "additional matches were suppressed"
                                    ),
                                    rule_code="S902",
                                    severity=IssueSeverity.WARNING,
                                    location=path,
                                    details={
                                        "max_pickle_opcode_findings": self.max_pickle_opcode_findings,
                                    },
                                )
                                finding_limit_reported = True
                            continue

                        result.add_check(
                            name="Pickle Opcode Security Check",
                            passed=False,
                            message=(f"Dangerous pickle opcode detected: {opcode.name} {module_name}.{global_name}"),
                            rule_code="S902",
                            severity=IssueSeverity.CRITICAL,
                            location=path,
                            details={
                                "opcode": opcode.name,
                                "position": pos,
                                "global": f"{module_name}.{global_name}",
                            },
                        )
                        dangerous_opcode_findings += 1
                        continue

                    if parsed_global is not None:
                        continue

                    _sync_unhandled_pickle_stack_effect(opcode)
            except ValueError:
                if not pickle_prefix_truncated:
                    raise

            result.merge(self.scan_pickle_pattern_text(path, data.decode("utf-8", errors="ignore")))

        except Exception as e:
            mark_inconclusive_scan_result(result, "jax_pickle_scan_failed")
            result.add_check(
                name="Pickle Checkpoint Scan",
                passed=False,
                message=f"Error scanning pickle checkpoint: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_pickle_scan_failed",
                },
                rule_code="S902",
            )

    def _scan_numpy_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan NumPy-based JAX checkpoint."""
        if not HAS_NUMPY:
            mark_inconclusive_scan_result(result, "jax_numpy_analysis_unavailable")
            result.add_check(
                name="NumPy Library Check",
                passed=False,
                message="NumPy not available for checkpoint analysis",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "required_library": "numpy",
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_numpy_analysis_unavailable",
                },
                rule_code="S902",
            )
            return

        try:
            # Load and validate NumPy array
            array = np.load(path, allow_pickle=False)  # Disable pickle for security

            # Check array properties
            if array.size > 100_000_000:  # 100M elements
                result.add_check(
                    name="NumPy Array Size Check",
                    passed=False,
                    message=f"Large NumPy array detected: {array.size:,} elements",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"size": array.size, "shape": array.shape, "threshold": 100_000_000},
                    rule_code="S904",
                )

            # Validate array shape
            if any(dim <= 0 for dim in array.shape):
                result.add_check(
                    name="NumPy Array Shape Validation",
                    passed=False,
                    message="Invalid array shape with non-positive dimensions",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={"shape": array.shape},
                    rule_code="S902",
                )

        except Exception as e:
            mark_inconclusive_scan_result(result, "jax_numpy_load_failed")
            result.add_check(
                name="NumPy Checkpoint Load",
                passed=False,
                message=f"Error loading NumPy checkpoint: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_numpy_load_failed",
                },
                rule_code="S902",
            )

    def _scan_json_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan JSON-based checkpoint metadata."""
        file_size = os.path.getsize(path)
        if file_size > JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES:
            mark_inconclusive_scan_result(result, self._JSON_ANALYSIS_SIZE_LIMIT_REASON)
            result.add_check(
                name="JSON Checkpoint Analysis Limit",
                passed=False,
                message="JSON checkpoint analysis incomplete because the file exceeds the bounded parsing limit",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "file_size": file_size,
                    "max_json_analysis_bytes": JAX_JSON_CHECKPOINT_STRUCTURE_READ_BYTES,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": self._JSON_ANALYSIS_SIZE_LIMIT_REASON,
                },
                rule_code="S902",
            )
            try:
                self._scan_bounded_json_prefix_patterns(path, result)
            except OSError as e:
                mark_operational_scan_error(result, self._JSON_PREFIX_PATTERN_READ_FAILED_REASON)
                result.add_check(
                    name="JSON Bounded Prefix Pattern Scan",
                    passed=False,
                    message=f"Unable to inspect bounded JSON checkpoint prefix: {e}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "error_type": type(e).__name__,
                        "analysis_incomplete": True,
                        "scan_outcome_reason": self._JSON_PREFIX_PATTERN_READ_FAILED_REASON,
                    },
                    rule_code="S902",
                )
            self._scan_jinja_json_overlap(path, result)
            self._scan_xgboost_json_overlap(path, result)
            return

        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.load(f)

            # Analyze JSON content for suspicious patterns
            pattern_finding_budget = _PatternFindingBudget(self.max_metadata_pattern_findings)
            metadata_depth_cap_contexts: set[str] = set()
            for context, text_value in self._iter_string_metadata(
                data,
                "json_checkpoint",
                depth_cap_contexts=metadata_depth_cap_contexts,
            ):
                self._add_suspicious_pattern_checks(
                    text_value,
                    context=context,
                    check_name="JSON Pattern Security Check",
                    message_prefix="Suspicious pattern in JSON checkpoint",
                    location=path,
                    result=result,
                    finding_budget=pattern_finding_budget,
                )
            self._add_metadata_traversal_depth_limit_checks(
                contexts=metadata_depth_cap_contexts,
                check_name="JSON Metadata Traversal Depth Limit",
                location=path,
                result=result,
            )

        except json.JSONDecodeError as e:
            mark_inconclusive_scan_result(result, "jax_json_parse_failed")
            result.add_check(
                name="JSON Checkpoint Validation",
                passed=False,
                message=f"Invalid JSON in checkpoint: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_json_parse_failed",
                },
                rule_code="S902",
            )
        except Exception as e:
            mark_inconclusive_scan_result(result, "jax_json_scan_failed")
            result.add_check(
                name="JSON Checkpoint Scan",
                passed=False,
                message=f"Error scanning JSON checkpoint: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_json_scan_failed",
                },
                rule_code="S902",
            )
        self._scan_jinja_json_overlap(path, result)
        self._scan_xgboost_json_overlap(path, result)

    def _merge_filename_owned_result(self, result: ScanResult, owner_result: ScanResult) -> None:
        """Merge an owner scan without dropping existing incomplete-coverage reasons."""
        existing_reasons = list(result.metadata.get("scan_outcome_reasons", []))
        result.merge(owner_result)
        for reason in existing_reasons:
            mark_inconclusive_scan_result(result, reason)

    def _scan_jinja_json_overlap(self, path: str, result: ScanResult) -> None:
        """Preserve template analysis for JAX-owned tokenizer/config JSON files."""
        if self.config.get(JAX_SKIP_JINJA_JSON_OVERLAP_CONFIG_KEY) is True:
            return
        if Path(path).name.lower() not in {
            "tokenizer.json",
            "tokenizer_config.json",
            "chat_template.json",
            "generation_config.json",
        }:
            return

        from .jinja2_template_scanner import Jinja2TemplateScanner

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("jinja2_template"):
            self._merge_filename_owned_result(result, Jinja2TemplateScanner(config=self.config).scan(path))
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "jinja2_template",
                scanner_selection,
                context="overlapping Jinja JSON analysis",
            )

    def _scan_xgboost_json_overlap(self, path: str, result: ScanResult) -> None:
        """Preserve XGBoost JSON analysis when JAX evidence overlaps."""
        if self.config.get(JAX_SKIP_XGBOOST_JSON_OVERLAP_CONFIG_KEY) is True:
            return
        if Path(path).suffix.lower() != ".json":
            return

        from .xgboost_scanner import XGBOOST_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY, XGBoostScanner

        if not XGBoostScanner.can_handle(path):
            return

        scanner_selection = policy_from_config(self.config)
        if scanner_selection.allows("xgboost"):
            xgboost_config = dict(self.config)
            xgboost_config[XGBOOST_SKIP_JAX_JSON_OVERLAP_CONFIG_KEY] = True
            self._merge_filename_owned_result(result, XGBoostScanner(config=xgboost_config).scan(path))
        elif scanner_selection.active:
            add_scanner_selection_skip_check(
                result,
                path,
                "xgboost",
                scanner_selection,
                context="overlapping XGBoost JSON analysis",
            )

    def scan(self, path: str) -> ScanResult:
        """Scan JAX checkpoint file or directory."""
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()

        # Add file integrity check for compliance
        self.add_file_integrity_check(path, result)

        try:
            self.current_file_path = path

            if os.path.isdir(path):
                # Scan directory-based checkpoint (like Orbax)
                result.metadata["checkpoint_type"] = "directory"
                result.metadata["path_type"] = "directory"

                accounting = self._scan_orbax_checkpoint(path, result)
                result.bytes_scanned = accounting.bytes_scanned
                result.metadata["total_size"] = accounting.bytes_scanned

            else:
                # Scan single file checkpoint
                result.metadata["checkpoint_type"] = "file"
                result.metadata["path_type"] = "file"

                file_size = os.path.getsize(path)
                result.bytes_scanned = file_size
                result.metadata["file_size"] = file_size

                self._scan_checkpoint_file(path, result)

        except Exception as e:
            mark_inconclusive_scan_result(result, "jax_checkpoint_scan_failed")
            result.add_check(
                name="JAX Checkpoint Scan",
                passed=False,
                message=f"Unexpected error scanning JAX checkpoint: {e}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": "jax_checkpoint_scan_failed",
                },
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        result.finish(success=result.metadata.get("scan_outcome") != INCONCLUSIVE_SCAN_OUTCOME)
        return result
