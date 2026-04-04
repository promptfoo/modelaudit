"""JAX Checkpoint Scanner - Handles non-msgpack JAX/Flax model formats."""

from __future__ import annotations

import json
import os
import pickletools
import re
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from .base import BaseScanner, IssueSeverity, ScanResult

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
        for context in sorted(contexts):
            result.add_check(
                name=check_name,
                passed=False,
                message=(
                    f"Reached the maximum JAX metadata traversal depth at {context}; "
                    "nested metadata below this path was not scanned"
                ),
                severity=IssueSeverity.WARNING,
                location=location,
                details={
                    "context": context,
                    "max_metadata_traversal_depth": self._MAX_METADATA_TRAVERSAL_DEPTH,
                    "traversal_depth_cap_reached": True,
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
            ext = os.path.splitext(path)[1].lower()
            if ext in cls.supported_extensions:
                return cls._is_likely_jax_file(path)

        return False

    @classmethod
    def _is_jax_checkpoint_directory(cls, path: str) -> bool:
        """Check if directory looks like a JAX/Orbax checkpoint."""
        path_obj = Path(path)

        # Orbax checkpoint indicators
        orbax_files = ["checkpoint", "checkpoint_0", "metadata.json", "_CHECKPOINT", "orbax_checkpoint_metadata.json"]

        # Check for Orbax files
        for orbax_file in orbax_files:
            if (path_obj / orbax_file).exists():
                return True

        # Check for JAX checkpoint patterns
        jax_patterns = ["step_*", "params_*", "state_*", "model_*"]
        return any(list(path_obj.glob(pattern)) for pattern in jax_patterns)

    @classmethod
    def _is_likely_jax_file(cls, path: str) -> bool:
        """Determine if a file is likely a JAX checkpoint."""
        try:
            with open(path, "rb") as f:
                header = f.read(512)

            # Check for pickle format with JAX indicators
            if header.startswith(b"\x80"):  # Pickle protocol
                # Read more to check for JAX-specific content
                try:
                    with open(path, "rb") as f:
                        data = f.read(8192)  # Read first 8KB
                        data_str = data.decode("utf-8", errors="ignore").lower()

                    return any(indicator in data_str for indicator in cls._JAX_INDICATORS)
                except Exception:
                    pass

            decoded_header = header.decode("utf-8", errors="ignore").lower()

            # Check for JSON metadata files, including extensionful `.checkpoint`
            # files that contain JAX/Orbax metadata rather than pickle bytes.
            if cls._header_looks_like_json(header):
                return any(
                    indicator in decoded_header for indicator in cls._JAX_INDICATORS
                ) or cls._file_contains_jax_indicator(path)

            # Check for NumPy files in JAX context
            if header.startswith(b"\x93NUMPY") and "jax" in path.lower():
                return True

        except Exception:
            pass

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
                    if any(indicator in search_text for indicator in cls._JAX_INDICATORS):
                        return True
                    chunk_tail = search_text[-tail_length:]
        except Exception:
            return False

        return False

    def _scan_orbax_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan Orbax checkpoint directory."""
        path_obj = Path(path)

        # Check metadata files
        metadata_files = ["metadata.json", "orbax_checkpoint_metadata.json", "_CHECKPOINT"]

        for metadata_file in metadata_files:
            metadata_path = path_obj / metadata_file
            if metadata_path.exists():
                try:
                    with open(metadata_path, encoding="utf-8") as f:
                        metadata = json.load(f)

                    # Analyze metadata for suspicious content
                    self._analyze_orbax_metadata(metadata, str(metadata_path), result)

                except json.JSONDecodeError as e:
                    result.add_check(
                        name="Orbax Metadata JSON Validation",
                        passed=False,
                        message=f"Invalid JSON in Orbax metadata: {e}",
                        severity=IssueSeverity.WARNING,
                        location=str(metadata_path),
                        rule_code="S902",
                        details={"error": str(e), "file": metadata_file},
                    )
                except Exception as e:
                    result.add_check(
                        name="Orbax Metadata Read Check",
                        passed=False,
                        message=f"Error reading Orbax metadata: {e}",
                        severity=IssueSeverity.WARNING,
                        location=str(metadata_path),
                        rule_code="S902",
                    )

        # Scan checkpoint files
        checkpoint_files = list(path_obj.glob("checkpoint*"))
        for checkpoint_file in checkpoint_files:
            if checkpoint_file.is_file():
                self._scan_checkpoint_file(str(checkpoint_file), result)

    def _analyze_orbax_metadata(self, metadata: dict[str, Any], path: str, result: ScanResult) -> None:
        """Analyze Orbax metadata for security issues."""

        # Check for suspicious restore functions
        if "restore_fn" in metadata:
            restore_fn_value = str(metadata["restore_fn"])
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
                details={"restore_fn": restore_fn_value[:200]},
                rule_code="S302",
            )

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

    def _scan_checkpoint_file(self, path: str, result: ScanResult) -> None:
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
            if header.startswith(b"\x80"):  # Pickle format
                self._scan_pickle_checkpoint(path, result)
            elif header.startswith(b"\x93NUMPY"):  # NumPy format
                self._scan_numpy_checkpoint(path, result)
            elif self._header_looks_like_json(header):  # JSON format
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
            result.add_check(
                name="Checkpoint File Scan",
                passed=False,
                message=f"Error scanning checkpoint file: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
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
                result.add_check(
                    name="Pickle Checkpoint Prefix Scan Limit",
                    passed=False,
                    message=(
                        f"Only the first {self.max_pickle_scan_bytes} bytes of the pickle checkpoint were "
                        "inspected for opcode patterns"
                    ),
                    severity=IssueSeverity.WARNING,
                    location=path,
                    details={"max_pickle_scan_bytes": self.max_pickle_scan_bytes},
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

            # Check for JAX-specific suspicious content
            data_str = data.decode("utf-8", errors="ignore")
            self._add_suspicious_pattern_checks(
                data_str,
                context="pickle_checkpoint",
                check_name="JAX Pattern Security Check",
                message_prefix="Suspicious JAX pattern in pickle",
                location=path,
                result=result,
                finding_budget=_PatternFindingBudget(self.max_metadata_pattern_findings),
            )

        except Exception as e:
            result.add_check(
                name="Pickle Checkpoint Scan",
                passed=False,
                message=f"Error scanning pickle checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )

    def _scan_numpy_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan NumPy-based JAX checkpoint."""
        if not HAS_NUMPY:
            result.add_check(
                name="NumPy Library Check",
                passed=False,
                message="NumPy not available for checkpoint analysis",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"required_library": "numpy"},
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
            result.add_check(
                name="NumPy Checkpoint Load",
                passed=False,
                message=f"Error loading NumPy checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )

    def _scan_json_checkpoint(self, path: str, result: ScanResult) -> None:
        """Scan JSON-based checkpoint metadata."""
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
            result.add_check(
                name="JSON Checkpoint Validation",
                passed=False,
                message=f"Invalid JSON in checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e)},
                rule_code="S902",
            )
        except Exception as e:
            result.add_check(
                name="JSON Checkpoint Scan",
                passed=False,
                message=f"Error scanning JSON checkpoint: {e}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
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

                self._scan_orbax_checkpoint(path, result)

                # Calculate total size
                total_size = sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())
                result.bytes_scanned = total_size
                result.metadata["total_size"] = total_size

            else:
                # Scan single file checkpoint
                result.metadata["checkpoint_type"] = "file"
                result.metadata["path_type"] = "file"

                file_size = os.path.getsize(path)
                result.bytes_scanned = file_size
                result.metadata["file_size"] = file_size

                self._scan_checkpoint_file(path, result)

        except Exception as e:
            result.add_check(
                name="JAX Checkpoint Scan",
                passed=False,
                message=f"Unexpected error scanning JAX checkpoint: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"error": str(e), "error_type": type(e).__name__},
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result
