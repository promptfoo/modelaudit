import json
import os
import tarfile
import tempfile
from typing import Any

from .base import BaseScanner, IssueSeverity, ScanResult

# Try to import yaml for YAML manifests
try:
    import yaml  # type: ignore

    HAS_YAML = True
except Exception:
    HAS_YAML = False


class OciLayerScanner(BaseScanner):
    """Scanner for OCI/Artifactory manifest files with .tar.gz layers."""

    name = "oci_layer"
    description = "Scans container manifests and embedded layers for model files"
    supported_extensions = [".manifest"]

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in cls.supported_extensions:
            return False
        # Quick check for .tar.gz references to avoid conflicts with ManifestScanner
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                snippet = f.read(2048)
            return ".tar.gz" in snippet
        except Exception:
            return False

    def scan(self, path: str) -> ScanResult:
        path_check = self._check_path(path)
        if path_check:
            return path_check

        result = self._create_result()
        manifest_data: Any = None

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            try:
                manifest_data = json.loads(text)
            except Exception:
                if HAS_YAML:
                    manifest_data = yaml.safe_load(text)
                else:
                    raise
        except Exception as e:
            result.add_issue(
                f"Error parsing manifest: {e}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception_type": type(e).__name__},
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

        for layer_ref in layer_paths:
            layer_path = layer_ref
            if not os.path.isabs(layer_path):
                layer_path = os.path.join(os.path.dirname(path), layer_ref)
            if not os.path.exists(layer_path):
                result.add_issue(
                    f"Layer not found: {layer_ref}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{layer_ref}",
                )
                continue
            try:
                from . import SCANNER_REGISTRY

                with tarfile.open(layer_path, "r:gz") as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        name = member.name
                        _, ext = os.path.splitext(name)
                        if not any(s.can_handle(name) for s in SCANNER_REGISTRY):
                            continue
                        fileobj = tar.extractfile(member)
                        if fileobj is None:
                            continue
                        with tempfile.NamedTemporaryFile(
                            suffix=ext, delete=False
                        ) as tmp:
                            tmp.write(fileobj.read())
                            tmp_path = tmp.name
                        fileobj.close()
                        try:
                            from .. import core

                            file_result = core.scan_file(tmp_path, self.config)
                            for issue in file_result.issues:
                                if issue.location:
                                    issue.location = (
                                        f"{path}:{layer_ref}:{name} {issue.location}"
                                    )
                                else:
                                    issue.location = f"{path}:{layer_ref}:{name}"
                                if issue.details is None:
                                    issue.details = {}
                                issue.details["layer"] = layer_ref
                            result.merge(file_result)
                        finally:
                            os.unlink(tmp_path)
            except Exception as e:
                result.add_issue(
                    f"Error processing layer {layer_ref}: {e}",
                    severity=IssueSeverity.WARNING,
                    location=f"{path}:{layer_ref}",
                    details={"exception_type": type(e).__name__},
                )

        result.finish(success=True)
        return result
