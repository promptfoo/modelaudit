import json
import os
import re
from pathlib import Path
from typing import Any, Optional, Union

import requests

# Import Pydantic models instead of using dataclasses
from modelaudit.models import CopyrightNoticeModel as CopyrightInfo
from modelaudit.models import LicenseInfoModel as LicenseInfo

# Common license patterns with SPDX IDs and commercial use status
LICENSE_PATTERNS = {
    # Permissive licenses (commercial-friendly)
    r"MIT\s+License|License\s*:\s*MIT|SPDX-License-Identifier:\s*MIT": {
        "spdx_id": "MIT",
        "name": "MIT License",
        "commercial_allowed": True,
    },
    r"Apache\s+License,?\s*Version\s+2\.0|Apache-2\.0|SPDX-License-Identifier:\s*Apache-2\.0": {
        "spdx_id": "Apache-2.0",
        "name": "Apache License 2.0",
        "commercial_allowed": True,
    },
    r"BSD\s+3-Clause|3-Clause\s+BSD|SPDX-License-Identifier:\s*BSD-3-Clause": {
        "spdx_id": "BSD-3-Clause",
        "name": "BSD 3-Clause License",
        "commercial_allowed": True,
    },
    r"BSD\s+2-Clause|2-Clause\s+BSD|SPDX-License-Identifier:\s*BSD-2-Clause": {
        "spdx_id": "BSD-2-Clause",
        "name": "BSD 2-Clause License",
        "commercial_allowed": True,
    },
    # Copyleft licenses (require careful consideration)
    r"GNU\s+General\s+Public\s+License.*version\s+3|GPL-3\.0|GPLv3|SPDX-License-Identifier:\s*GPL-3\.0": {
        "spdx_id": "GPL-3.0",
        "name": "GNU General Public License v3.0",
        "commercial_allowed": True,  # But with obligations
    },
    r"GNU\s+General\s+Public\s+License.*version\s+2|GPL-2\.0|GPLv2|SPDX-License-Identifier:\s*GPL-2\.0": {
        "spdx_id": "GPL-2.0",
        "name": "GNU General Public License v2.0",
        "commercial_allowed": True,  # But with obligations
    },
    r"GNU\s+Affero\s+General\s+Public\s+License|AGPL-3\.0|AGPLv3|SPDX-License-Identifier:\s*AGPL-3\.0": {
        "spdx_id": "AGPL-3.0",
        "name": "GNU Affero General Public License v3.0",
        "commercial_allowed": True,  # But with strong network use obligations
    },
    r"GNU\s+Lesser\s+General\s+Public\s+License|LGPL-2\.1|LGPL-3\.0|LGPLv[23]|SPDX-License-Identifier:\s*LGPL-[23]\.": {
        "spdx_id": "LGPL-2.1+",
        "name": "GNU Lesser General Public License",
        "commercial_allowed": True,  # But with linking obligations
    },
    # Creative Commons licenses
    r"Creative\s+Commons.*Attribution.*4\.0|CC\s+BY\s+4\.0|CC-BY-4\.0": {
        "spdx_id": "CC-BY-4.0",
        "name": "Creative Commons Attribution 4.0",
        "commercial_allowed": True,
    },
    r"Creative\s+Commons.*Attribution.*ShareAlike.*4\.0|CC\s+BY-SA\s+4\.0|CC-BY-SA-4\.0": {
        "spdx_id": "CC-BY-SA-4.0",
        "name": "Creative Commons Attribution ShareAlike 4.0",
        "commercial_allowed": True,  # But with share-alike obligations
    },
    r"Creative\s+Commons.*Attribution.*NonCommercial|CC\s+BY-NC|CC-BY-NC": {
        "spdx_id": "CC-BY-NC-4.0",
        "name": "Creative Commons Attribution NonCommercial",
        "commercial_allowed": False,
    },
    # Common dataset licenses
    r"Open\s+Data\s+Commons.*Open\s+Database\s+License|ODbL-1\.0": {
        "spdx_id": "ODbL-1.0",
        "name": "Open Data Commons Open Database License",
        "commercial_allowed": True,  # But with share-alike obligations
    },
    r"Open\s+Data\s+Commons.*Public\s+Domain\s+Dedication|PDDL-1\.0": {
        "spdx_id": "PDDL-1.0",
        "name": "Open Data Commons Public Domain Dedication",
        "commercial_allowed": True,
    },
    # BigScience and RAIL licenses
    r"BigScience\s+Open\s+RAIL(?:-M)?|BigScience\s+RAIL": {
        "spdx_id": "BigScience-OpenRAIL-M",
        "name": "BigScience Open RAIL License",
        "commercial_allowed": True,
    },
    r"Responsible\s+AI\s+License|RAIL(?:\s+License)?|OpenRAIL": {
        "spdx_id": "RAIL",
        "name": "Responsible AI License",
        "commercial_allowed": True,
    },
}

# Copyright notice patterns
COPYRIGHT_PATTERNS = [
    r"Copyright\s+(?:\(c\)\s*)?(\d{4}(?:-\d{4})?)\s+(.+?)(?:\n|$)",
    r"\(c\)\s*(\d{4}(?:-\d{4})?)\s+(.+?)(?:\n|$)",
    r"©\s*(\d{4}(?:-\d{4})?)\s+(.+?)(?:\n|$)",
]

# Patterns indicating unlicensed or problematic licensing
UNLICENSED_INDICATORS = [
    r"all\s+rights\s+reserved",
    r"proprietary",
    r"confidential",
    r"internal\s+use\s+only",
]

# SPDX license metadata
SPDX_LICENSE_PATH = Path(__file__).with_name("spdx_licenses.json")
SPDX_LICENSE_URL = "https://raw.githubusercontent.com/spdx/license-list-data/master/json/licenses.json"
_SPDX_LICENSES: Optional[dict[str, Any]] = None


def load_spdx_license_data(download: bool = False) -> dict[str, Any]:
    """Load SPDX license metadata from bundled JSON or download if requested."""
    global _SPDX_LICENSES
    if _SPDX_LICENSES is not None and not download:
        return _SPDX_LICENSES

    if not SPDX_LICENSE_PATH.exists() or download:
        try:
            response = requests.get(SPDX_LICENSE_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            SPDX_LICENSE_PATH.write_text(json.dumps(data))
        except Exception:
            data = {}
    else:
        try:
            data = json.loads(SPDX_LICENSE_PATH.read_text())
        except Exception:
            data = {}

    _SPDX_LICENSES = {lic["licenseId"]: lic for lic in data.get("licenses", [])}
    return _SPDX_LICENSES


# File extensions that commonly contain license information
LICENSE_FILES = {
    "license",
    "license.txt",
    "license.md",
    "licence",
    "licence.txt",
    "licence.md",
    "copying",
    "copying.txt",
    "copyright",
    "copyright.txt",
    "notice",
    "notice.txt",
    "legal",
    "legal.txt",
    "terms",
    "terms.txt",
}

# Dataset file patterns that often lack proper licensing
DATASET_EXTENSIONS = {
    ".csv",
    ".json",
    ".jsonl",
    ".parquet",
    ".tsv",
    ".pkl",
    ".npy",
    ".npz",
}

# Model file patterns
MODEL_EXTENSIONS = {
    ".pkl",
    ".joblib",
    ".pt",
    ".pth",
    ".onnx",
    ".pb",
    ".h5",
    ".keras",
    ".safetensors",
}


def scan_for_license_headers(file_path: str, max_lines: int = 50) -> list[LicenseInfo]:
    """
    Scan a file's header for license information.

    Args:
        file_path: Path to the file to scan
        max_lines: Maximum number of lines to scan from the beginning

    Returns:
        List of detected license information
    """
    licenses: list[LicenseInfo] = []

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            content = ""
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                content += line
    except (OSError, UnicodeDecodeError):
        # Try reading as binary for files that might not be text
        try:
            with open(file_path, "rb") as f:
                binary_content = f.read(1024 * 10)  # Read first 10KB
                content = binary_content.decode("utf-8", errors="ignore")
        except Exception:
            return licenses

    # Search for license patterns
    for pattern, info in LICENSE_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        if matches:
            license_info = LicenseInfo(
                spdx_id=str(info["spdx_id"]) if info["spdx_id"] else None,
                name=str(info["name"]) if info["name"] else None,
                commercial_allowed=info["commercial_allowed"] if isinstance(info["commercial_allowed"], bool) else None,
                source="file_header",
                confidence=0.8,  # High confidence for explicit patterns
                url=None,
                text=None,
            )
            licenses.append(license_info)

    return licenses


def extract_copyright_notices(
    file_path: str,
    max_lines: int = 50,
) -> list[CopyrightInfo]:
    """
    Extract copyright notices from a file.

    Args:
        file_path: Path to the file to scan
        max_lines: Maximum number of lines to scan

    Returns:
        List of copyright information found
    """
    copyrights: list[CopyrightInfo] = []

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            content = ""
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                content += line
    except Exception:
        return copyrights

    # Search for copyright patterns
    for pattern in COPYRIGHT_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if len(match) >= 2:
                year = match[0].strip()
                holder = match[1].strip()
                copyright_info = CopyrightInfo(
                    holder=holder,
                    year=year,
                    text=f"Copyright {year} {holder}",
                    confidence=0.8,
                )
                copyrights.append(copyright_info)

    return copyrights


def find_license_files(directory: str) -> list[str]:
    """
    Find license files in a directory.

    Args:
        directory: Directory to search

    Returns:
        List of paths to license files
    """
    license_files: list[str] = []

    if not os.path.isdir(directory):
        return license_files

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower() in LICENSE_FILES:
                license_files.append(os.path.join(root, file))

        # Don't recurse too deep
        if len(Path(root).parts) - len(Path(directory).parts) > 2:
            dirs.clear()

    return license_files


def detect_unlicensed_datasets(file_paths: list[str]) -> list[str]:
    """
    Detect dataset files that may lack proper licensing.

    Args:
        file_paths: List of file paths to check

    Returns:
        List of file paths that appear to be unlicensed datasets
    """
    unlicensed = []

    # Check if this looks like an ML model directory
    is_ml_model_dir = _is_ml_model_directory(file_paths)

    for file_path in file_paths:
        ext = Path(file_path).suffix.lower()
        filename = Path(file_path).name.lower()

        if ext in DATASET_EXTENSIONS:
            # Skip model files in ML model directories
            if is_ml_model_dir and ext in MODEL_EXTENSIONS:
                continue

            # Skip common ML configuration files in ML model directories
            if is_ml_model_dir and _is_ml_config_file(filename):
                continue

            # Check if there's a nearby license file
            dir_path = Path(file_path).parent
            try:
                existing_files = {f.name.lower() for f in dir_path.iterdir() if f.is_file()}
                has_license = bool(LICENSE_FILES & existing_files)
            except OSError:
                has_license = False

            if not has_license:
                # Check if the file itself contains license info
                licenses = scan_for_license_headers(file_path, max_lines=10)
                if not licenses:
                    unlicensed.append(file_path)

    return unlicensed


def _is_ml_config_file(filename: str) -> bool:
    """
    Determine if a filename represents an ML configuration file.

    Args:
        filename: Lowercase filename to check

    Returns:
        True if this appears to be an ML configuration file
    """
    ml_config_patterns = {
        "config.json",
        "model.json",
        "tokenizer_config.json",
        "tokenizer.json",
        "vocab.json",
        "merges.txt",
        "generation_config.json",
        "preprocessor_config.json",
        "model_config.json",
        "training_args.json",
        "optimizer.json",
        "scheduler.json",
    }

    return filename in ml_config_patterns


def _is_ml_model_directory(file_paths: list[str]) -> bool:
    """
    Determine if the file paths represent an ML model directory.

    Args:
        file_paths: List of file paths to analyze

    Returns:
        True if this appears to be an ML model directory
    """
    if not file_paths:
        return False

    # Get all filenames
    filenames = [Path(fp).name.lower() for fp in file_paths]

    # Common ML model directory indicators
    ml_indicators = {
        "config.json",
        "model.json",
        "tokenizer_config.json",
        "model.safetensors",
        "pytorch_model.bin",
        "tf_model.h5",
        "model.onnx",
        "model.pb",
        "saved_model.pb",
    }

    # Check if we have typical ML model files
    has_ml_files = any(filename in ml_indicators for filename in filenames)

    # Check for model weight files with typical patterns
    has_weight_files = any(
        "model" in filename and any(ext in filename for ext in [".bin", ".h5", ".safetensors"])
        for filename in filenames
    )

    # Check for config files
    has_config_files = any("config" in filename and filename.endswith(".json") for filename in filenames)

    return has_ml_files or (has_weight_files and has_config_files)


def detect_agpl_components(scan_results: Union[dict[str, Any], Any]) -> list[str]:
    """
    Detect components that use AGPL licensing.

    Args:
        scan_results: Scan results dictionary

    Returns:
        List of file paths with AGPL licensing
    """
    agpl_files = []

    file_metadata = scan_results.get("file_metadata", {})
    for file_path, metadata in file_metadata.items():
        licenses = metadata.get("license_info", [])
        for license_info in licenses:
            if isinstance(license_info, dict):
                spdx_id = license_info.get("spdx_id", "")
                if "AGPL" in spdx_id:
                    agpl_files.append(file_path)
            elif hasattr(license_info, "spdx_id"):
                if license_info.spdx_id and "AGPL" in license_info.spdx_id:
                    agpl_files.append(file_path)

    return agpl_files


def _get_spdx_info(spdx_id: str) -> Optional[dict[str, Any]]:
    """Return SPDX metadata for a license ID if available."""
    licenses = load_spdx_license_data()
    return licenses.get(spdx_id)


def check_spdx_license_issues(scan_results: dict[str, Any], strict: bool = False) -> list[dict[str, Any]]:
    """Check for deprecated or incompatible licenses using SPDX data."""
    warnings: list[dict[str, Any]] = []
    file_metadata = scan_results.get("file_metadata", {})
    deprecated_files: list[str] = []
    incompatible_files: list[str] = []

    for file_path, metadata in file_metadata.items():
        for license_info in metadata.get("license_info", []):
            spdx_id = None
            if isinstance(license_info, dict):
                spdx_id = license_info.get("spdx_id")
            elif hasattr(license_info, "spdx_id"):
                spdx_id = license_info.spdx_id

            if not spdx_id:
                continue

            info = _get_spdx_info(spdx_id)
            if not info:
                continue

            if info.get("isDeprecatedLicenseId"):
                deprecated_files.append(file_path)

            if not info.get("isOsiApproved", True):
                incompatible_files.append(file_path)

    if deprecated_files:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "error" if strict else "warning",
                "message": (f"Deprecated licenses detected ({len(deprecated_files)} files)."),
                "details": {
                    "files": deprecated_files[:5],
                    "total_count": len(deprecated_files),
                },
            }
        )

    if incompatible_files:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "error" if strict else "warning",
                "message": (f"Incompatible licenses detected ({len(incompatible_files)} files)."),
                "details": {
                    "files": incompatible_files[:5],
                    "total_count": len(incompatible_files),
                },
            }
        )

    return warnings


def check_commercial_use_warnings(
    scan_results: Union[dict[str, Any], Any], *, strict: bool = False
) -> list[dict[str, Any]]:
    """
    Check for common license warnings related to commercial use.

    Args:
        scan_results: Scan results dictionary
        strict: Treat incompatible licenses as errors

    Returns:
        List of warning dictionaries
    """
    warnings = []

    # Check for AGPL components
    agpl_files = detect_agpl_components(scan_results)
    if agpl_files:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "warning",
                "message": f"AGPL-licensed components detected ({len(agpl_files)} files). Review network use "
                f"restrictions for SaaS deployment.",
                "details": {
                    "files": agpl_files[:5],  # Show first 5 files
                    "total_count": len(agpl_files),
                    "license_type": "AGPL",
                    "impact": "Requires source code disclosure for network services",
                },
            },
        )

    # Check for datasets with unspecified licenses
    # Only warn if we have multiple files or files that are clearly datasets
    all_files = list(scan_results.get("file_metadata", {}).keys())
    unlicensed_datasets = detect_unlicensed_datasets(all_files)

    # Filter out single files that might be tests or simple examples
    significant_unlicensed_datasets = []
    if len(all_files) > 1:  # Multiple files - likely a project
        significant_unlicensed_datasets = unlicensed_datasets
    else:
        # Single file case - only warn if it's clearly a substantial dataset
        for file_path in unlicensed_datasets:
            try:
                file_size = os.path.getsize(file_path)
                # Only warn about single files that are substantial (>100KB)
                if file_size > 100 * 1024:
                    significant_unlicensed_datasets.append(file_path)
            except OSError:
                pass

    if significant_unlicensed_datasets:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "warning",
                "message": f"Datasets with unspecified licenses detected "
                f"({len(significant_unlicensed_datasets)} files). Verify data usage rights.",
                "details": {
                    "files": significant_unlicensed_datasets[:5],  # Show first 5 files
                    "total_count": len(significant_unlicensed_datasets),
                    "impact": "May restrict commercial use or redistribution",
                },
            },
        )

    # Check for non-commercial licenses
    nc_files = []
    file_metadata = scan_results.get("file_metadata", {})
    for file_path, metadata in file_metadata.items():
        licenses = metadata.get("license_info", [])
        for license_info in licenses:
            commercial_allowed = None
            if isinstance(license_info, dict):
                commercial_allowed = license_info.get("commercial_allowed")
            elif hasattr(license_info, "commercial_allowed"):
                commercial_allowed = license_info.commercial_allowed

            if commercial_allowed is False:
                nc_files.append(file_path)
                break

    if nc_files:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "warning",
                "message": f"Non-commercial licensed components detected ({len(nc_files)} files). These cannot "
                f"be used commercially.",
                "details": {
                    "files": nc_files[:5],
                    "total_count": len(nc_files),
                    "impact": "Prohibited for commercial use",
                },
            },
        )

    # Check for strong copyleft licenses mixed with proprietary code
    copyleft_files = []
    for file_path, metadata in file_metadata.items():
        licenses = metadata.get("license_info", [])
        for license_info in licenses:
            spdx_id = None
            if isinstance(license_info, dict):
                spdx_id = license_info.get("spdx_id")
            elif hasattr(license_info, "spdx_id"):
                spdx_id = license_info.spdx_id

            if spdx_id and any(gpl in spdx_id for gpl in ["GPL-", "AGPL-"]):
                copyleft_files.append(file_path)
                break

    if copyleft_files:
        warnings.append(
            {
                "type": "license_warning",
                "severity": "info",
                "message": f"Strong copyleft licensed components detected ({len(copyleft_files)} files). May "
                f"require derivative works to be open-sourced.",
                "details": {
                    "files": copyleft_files[:5],
                    "total_count": len(copyleft_files),
                    "impact": "May require making derivative works available under the same license",
                },
            },
        )

    # Append SPDX license warnings
    warnings.extend(check_spdx_license_issues(scan_results, strict=strict))

    return warnings


def collect_license_metadata(file_path: str) -> dict[str, Any]:
    """
    Collect comprehensive license metadata for a file.

    Args:
        file_path: Path to the file to analyze

    Returns:
        Dictionary containing license metadata
    """
    metadata = {
        "license_info": [],
        "copyright_notices": [],
        "license_files_nearby": [],
        "is_dataset": False,
        "is_model": False,
    }

    # Detect file type
    ext = Path(file_path).suffix.lower()
    metadata["is_dataset"] = ext in DATASET_EXTENSIONS
    metadata["is_model"] = ext in MODEL_EXTENSIONS

    # Scan for license headers
    licenses = scan_for_license_headers(file_path)
    metadata["license_info"] = [
        {
            "spdx_id": lic.spdx_id,
            "name": lic.name,
            "commercial_allowed": lic.commercial_allowed,
            "source": lic.source,
            "confidence": lic.confidence,
        }
        for lic in licenses
    ]

    # Extract copyright notices
    copyrights = extract_copyright_notices(file_path)
    metadata["copyright_notices"] = [
        {
            "holder": cr.holder,
            "year": cr.year,
            "text": cr.text,
        }
        for cr in copyrights
    ]

    # Find nearby license files
    if os.path.isfile(file_path):
        dir_path = str(Path(file_path).parent)
        nearby_licenses = find_license_files(dir_path)
        metadata["license_files_nearby"] = nearby_licenses

    return metadata
