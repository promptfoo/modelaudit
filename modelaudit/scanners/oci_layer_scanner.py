"""Scanner for OCI container image layers containing model artifacts."""

import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, ClassVar

from ..utils import is_within_directory, sanitize_archive_path
from ..utils.file.detection import detect_file_format
from ..utils.model_extensions import get_model_extensions
from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import yaml for YAML manifests
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False


class OciLayerScanner(BaseScanner):
    """Scanner for OCI/Artifactory manifest files with .tar.gz layers."""

    name = "oci_layer"
    description = "Scans container manifests and embedded layers for model files"
    supported_extensions: ClassVar[list[str]] = [".manifest"]
    _DETECTED_FORMAT_SUFFIXES: ClassVar[dict[str, str]] = {
        "pickle": ".pkl",
        "onnx": ".onnx",
        "hdf5": ".h5",
        "safetensors": ".safetensors",
        "numpy": ".npy",
        "protobuf": ".pb",
        "zip": ".zip",
        "gguf": ".gguf",
        "ggml": ".gguf",
    }

    @staticmethod
    def _get_scannable_extension(member_name: str) -> str | None:
        suffixes = [suffix.lower() for suffix in Path(member_name.rstrip(" .")).suffixes]
        if not suffixes:
            return None

        scannable_extensions = get_model_extensions()
        best_candidate: tuple[int, int, str] | None = None

        for start in range(len(suffixes)):
            for end in range(len(suffixes), start, -1):
                candidate = "".join(suffixes[start:end])
                if candidate not in scannable_extensions:
                    continue
                candidate_width = end - start
                if (
                    best_candidate is None
                    or candidate_width > best_candidate[0]
                    or (candidate_width == best_candidate[0] and start < best_candidate[1])
                ):
                    best_candidate = (candidate_width, start, candidate)

        return best_candidate[2] if best_candidate is not None else None

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False
        # Quick check for .tar.gz references to avoid conflicts with ManifestScanner
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                snippet = f.read(2048)
            return ".tar.gz" in snippet
        except Exception:
            return False

    @staticmethod
    def _rewrite_embedded_location(
        location: str | None,
        *,
        manifest_path: str,
        layer_ref: str,
        member_name: str,
        extracted_path: str,
    ) -> str:
        """Replace temporary extraction paths with the original OCI member location."""
        member_location = f"{manifest_path}:{layer_ref}:{member_name}"
        if not location:
            return member_location
        if location == extracted_path:
            return member_location
        if location.startswith(extracted_path):
            return f"{member_location}{location[len(extracted_path) :]}"
        return f"{member_location} {location}"

    @classmethod
    def _get_detected_format_suffix(cls, extracted_path: str) -> str | None:
        """Return a canonical suffix for detected content-based formats."""
        detected_format = detect_file_format(extracted_path)
        return cls._DETECTED_FORMAT_SUFFIXES.get(detected_format)

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        manifest_data: Any = None

        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            try:
                manifest_data = json.loads(text)
            except Exception:
                if HAS_YAML:
                    manifest_data = yaml.safe_load(text)
                else:
                    raise
        except Exception as e:
            result.add_check(
                name="OCI Manifest Parse",
                passed=False,
                message=f"Error parsing manifest: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception_type": type(e).__name__},
                rule_code="S902",
            )
            result.finish(success=False)
            return result

        # Find layer paths ending with .tar.gz
        layer_paths: list[str] = []

        def _search(obj: Any) -> None:
            if isinstance(obj, dict):
                for v in obj.values():
                    _search(v)
            elif isinstance(obj, list):
                for item in obj:
                    _search(item)
            elif isinstance(obj, str) and obj.endswith(".tar.gz"):
                layer_paths.append(obj)

        _search(manifest_data)

        manifest_dir = os.path.dirname(path)

        for layer_ref in layer_paths:
            layer_path, is_safe = sanitize_archive_path(layer_ref, manifest_dir)

            if not is_safe or not is_within_directory(manifest_dir, layer_path):
                result.add_check(
                    name="Layer Path Traversal Protection",
                    passed=False,
                    message=f"Layer reference {layer_ref} attempted path traversal outside manifest directory",
                    severity=IssueSeverity.CRITICAL,
                    location=f"{path}:{layer_ref}",
                    details={"layer": layer_ref, "resolved_path": layer_path},
                    rule_code="S405",
                )
                continue

            if not os.path.exists(layer_path):
                result.add_check(
                    name="Layer File Existence Check",
                    passed=False,
                    message=f"Layer not found: {layer_ref}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{layer_ref}",
                    rule_code="S902",
                )
                continue
            try:
                with tarfile.open(layer_path, "r:gz") as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        name = member.name
                        matched_ext = self._get_scannable_extension(name)
                        normalized_name = name.rstrip(" .")
                        should_probe_extensionless = not Path(normalized_name).suffixes
                        if matched_ext is None and not should_probe_extensionless:
                            continue
                        fileobj = tar.extractfile(member)
                        if fileobj is None:
                            continue
                        tmp_path: str | None = None
                        try:
                            with tempfile.NamedTemporaryFile(
                                suffix=matched_ext or "",
                                delete=False,
                            ) as tmp:
                                tmp_path = tmp.name
                                shutil.copyfileobj(fileobj, tmp)

                            from .. import core

                            file_result = core.scan_file(tmp_path, self.config)
                            detected_suffix = self._get_detected_format_suffix(tmp_path)
                            if (
                                file_result.scanner_name == "unknown"
                                and detected_suffix
                                and not tmp_path.endswith(detected_suffix)
                            ):
                                retargeted_path = f"{tmp_path}{detected_suffix}"
                                os.replace(tmp_path, retargeted_path)
                                tmp_path = retargeted_path
                                file_result = core.scan_file(tmp_path, self.config)
                            for check in file_result.checks:
                                check.location = self._rewrite_embedded_location(
                                    check.location,
                                    manifest_path=path,
                                    layer_ref=layer_ref,
                                    member_name=name,
                                    extracted_path=tmp_path,
                                )
                            for issue in file_result.issues:
                                issue.location = self._rewrite_embedded_location(
                                    issue.location,
                                    manifest_path=path,
                                    layer_ref=layer_ref,
                                    member_name=name,
                                    extracted_path=tmp_path,
                                )
                                if issue.details is None:
                                    issue.details = {}
                                issue.details["layer"] = layer_ref
                            result.merge(file_result)
                        finally:
                            fileobj.close()
                            if tmp_path and os.path.exists(tmp_path):
                                os.unlink(tmp_path)
            except Exception as e:
                result.add_check(
                    name="Layer Processing",
                    passed=False,
                    message=f"Error processing layer {layer_ref}: {e}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{layer_ref}",
                    details={"exception_type": type(e).__name__},
                    rule_code="S902",
                )

        result.finish(success=True)
        return result
