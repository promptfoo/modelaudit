import json
import os
import re
from typing import Any

from .base import BaseScanner, IssueSeverity, ScanResult, logger

# Try to import the name policies module
try:
    from modelaudit.config.name_blacklist import check_model_name_policies

    HAS_NAME_POLICIES = True
except ImportError:
    HAS_NAME_POLICIES = False

    # Create a placeholder function when the module is not available
    def check_model_name_policies(
        model_name: str,
        additional_patterns: list[str] | None = None,
    ) -> tuple[bool, str]:
        return False, ""


# Try to import yaml, but handle the case where it's not installed
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Common manifest and config file formats
MANIFEST_EXTENSIONS = [
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".config",
    ".manifest",
    ".model",
    ".metadata",
]

# Keys that might contain model names
MODEL_NAME_KEYS_LOWER = [
    "name",
    "model_name",
    "model",
    "model_id",
    "id",
    "title",
    "artifact_name",
    "artifact_id",
    "package_name",
]

# Comprehensive allowlist of trusted domains for ML model configs
# URLs from domains NOT in this list will be flagged
# This is more secure than a blocklist - attackers can't bypass by registering new domains
TRUSTED_URL_DOMAINS = [
    # ===========================================
    # MODEL HUBS & CODE REPOSITORIES
    # ===========================================
    "huggingface.co",
    "hf.co",
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "github.io",
    "gitlab.com",
    "gitlab.io",
    "bitbucket.org",
    "codeberg.org",
    "sourceforge.net",
    # ===========================================
    # ML FRAMEWORKS & TOOLS
    # ===========================================
    "pytorch.org",
    "download.pytorch.org",
    "tensorflow.org",
    "keras.io",
    "onnx.ai",
    "onnxruntime.ai",
    "mlflow.org",
    "wandb.ai",
    "neptune.ai",
    "comet.ml",
    "dvc.org",
    "labelstud.io",
    "roboflow.com",
    "ultralytics.com",
    "lightning.ai",
    "ray.io",
    "anyscale.com",
    "determined.ai",
    "bentoml.com",
    "gradio.app",
    "streamlit.io",
    # ===========================================
    # CLOUD STORAGE & CDNs
    # ===========================================
    # AWS S3 (multiple URL patterns)
    "s3.amazonaws.com",
    "s3-",  # s3-us-west-2.amazonaws.com
    ".s3.",  # bucket.s3.region.amazonaws.com
    "cloudfront.net",
    # Google Cloud
    "storage.googleapis.com",
    "storage.cloud.google.com",
    "gcr.io",
    # Azure
    "blob.core.windows.net",
    "azureedge.net",
    "azure.com",
    # Other CDNs
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "fastly.net",
    # ===========================================
    # AI/ML COMPANIES
    # ===========================================
    "openai.com",
    "anthropic.com",
    "google.com",
    "ai.google",
    "deepmind.com",
    "meta.com",
    "ai.meta.com",
    "llama.meta.com",
    "microsoft.com",
    "nvidia.com",
    "developer.nvidia.com",
    "stability.ai",
    "mistral.ai",
    "cohere.com",
    "cohere.ai",
    "replicate.com",
    "together.ai",
    "fireworks.ai",
    "perplexity.ai",
    "databricks.com",
    "snowflake.com",
    "datarobot.com",
    "h2o.ai",
    "clarifai.com",
    "scale.com",
    "labelbox.com",
    "appen.com",
    # ===========================================
    # RESEARCH & ACADEMIC
    # ===========================================
    "arxiv.org",
    "paperswithcode.com",
    "semanticscholar.org",
    "aclanthology.org",
    "neurips.cc",
    "openreview.net",
    "ieee.org",
    "acm.org",
    "springer.com",
    "nature.com",
    "sciencedirect.com",
    "researchgate.net",
    # ===========================================
    # DATASETS & DATA PLATFORMS
    # ===========================================
    "kaggle.com",
    "zenodo.org",
    "dataverse.harvard.edu",
    "data.world",
    "registry.opendata.aws",
    "commoncrawl.org",
    "ftp.ncbi.nlm.nih.gov",
    "physionet.org",
    "image-net.org",
    "cocodataset.org",
    "visualgenome.org",
    "cs.stanford.edu",
    "cs.cmu.edu",
    "cs.berkeley.edu",
    "cs.toronto.edu",
    "cs.nyu.edu",
    "yann.lecun.com",
    # ===========================================
    # PACKAGE REPOSITORIES
    # ===========================================
    "pypi.org",
    "files.pythonhosted.org",
    "anaconda.org",
    "conda.anaconda.org",
    "npmjs.com",
    "crates.io",
    "packagist.org",
    "rubygems.org",
    "mvnrepository.com",
    # ===========================================
    # DOCUMENTATION & HOSTING
    # ===========================================
    "readthedocs.io",
    "readthedocs.org",
    "rtfd.io",
    "gitbook.io",
    "notion.so",
    "medium.com",
    "towardsdatascience.com",
    "dev.to",
    "substack.com",
    # ===========================================
    # CONTAINER REGISTRIES
    # ===========================================
    "docker.io",
    "docker.com",
    "quay.io",
    "ghcr.io",
    "nvcr.io",
    "registry.hub.docker.com",
    # ===========================================
    # INTERNAL/LOCALHOST (for development)
    # ===========================================
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
]

# Regex to find URLs in text
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+[^\s<>"\',.]')


class ManifestScanner(BaseScanner):
    """
    Scanner for model manifest and configuration files.

    Checks for:
    - Blacklisted model names (user-configured)
    - Blacklisted terms in file content (user-configured)

    Extracts metadata for reporting:
    - Model architecture information (HuggingFace configs)
    - License information
    """

    name = "manifest"
    description = "Scans model manifest files for blacklisted names and terms"
    supported_extensions = MANIFEST_EXTENSIONS

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Get blacklist patterns from config
        self.blacklist_patterns = self.config.get("blacklist_patterns", [])

    @classmethod
    def can_handle(cls, path: str) -> bool:
        """Check if this scanner can handle the given path"""
        if not os.path.isfile(path):
            return False

        filename = os.path.basename(path).lower()

        # Whitelist: Only scan files that are unique to AI/ML models
        aiml_specific_patterns = [
            # HuggingFace/Transformers specific configuration files
            "config.json",
            "generation_config.json",
            "preprocessor_config.json",
            "feature_extractor_config.json",
            "image_processor_config.json",
            "scheduler_config.json",
            # Model metadata and manifest files specific to ML
            "model_index.json",
            "model_card.json",
            "pytorch_model.bin.index.json",
            "model.safetensors.index.json",
            "tf_model.h5.index.json",
            # ML-specific execution and deployment configs
            "inference_config.json",
            "deployment_config.json",
            "serving_config.json",
            # ONNX model specific
            "onnx_config.json",
            # Custom model configs
            "custom_config.json",
            "runtime_config.json",
        ]

        # Check if filename matches any AI/ML specific pattern
        if any(pattern in filename for pattern in aiml_specific_patterns):
            return True

        # Additional check: files with "config" in name that are in ML model context
        if (
            "config" in filename
            and "tokenizer" not in filename
            and filename
            not in [
                "config.py",
                "config.yaml",
                "config.yml",
                "config.ini",
                "config.cfg",
            ]
        ):
            # Only if it's likely an ML model config
            path_lower = path.lower()
            if any(
                ml_term in path_lower for ml_term in ["model", "checkpoint", "huggingface", "transformers"]
            ) or os.path.splitext(path)[1].lower() in [".json"]:
                return True

        return False

    def scan(self, path: str) -> ScanResult:
        """Scan a manifest or configuration file for blacklisted content"""
        # Check if path is valid
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            # Check the raw file content for blacklisted terms
            self._check_file_for_blacklist(path, result)

            # Parse the file based on its extension
            ext = os.path.splitext(path)[1].lower()
            content = self._parse_file(path, ext, result)

            if content:
                result.bytes_scanned = file_size
                if isinstance(content, dict):
                    result.metadata["keys"] = list(content.keys())

                    # Extract model metadata for HuggingFace config files
                    if os.path.basename(path) == "config.json":
                        model_info = self._extract_model_metadata(content)
                        if model_info:
                            result.metadata["model_info"] = model_info

                    # Extract license information if present
                    license_info = self._extract_license_info(content)
                    if license_info:
                        result.metadata["license"] = license_info

                    # Check for blacklisted model names in config values
                    self._check_model_name_policies(content, result)

                    # Check for suspicious URLs in config values
                    self._check_suspicious_urls(content, result)

            else:
                result.add_check(
                    name="Manifest Parse Attempt",
                    passed=False,
                    message=f"Unable to parse file as a manifest or configuration: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                )

        except Exception as e:
            result.add_check(
                name="Manifest File Scan",
                passed=False,
                message=f"Error scanning manifest file: {e!s}",
                severity=IssueSeverity.CRITICAL,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )
            result.finish(success=False)
            return result

        result.finish(success=True)
        return result

    def _check_file_for_blacklist(self, path: str, result: ScanResult) -> None:
        """Check the entire file content for blacklisted terms"""
        if not self.blacklist_patterns:
            return

        try:
            with open(path, encoding="utf-8") as f:
                content = f.read().lower()

            found_blacklisted = False
            for pattern in self.blacklist_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in content:
                    result.add_check(
                        name="Blacklist Pattern Check",
                        passed=False,
                        message=f"Blacklisted term '{pattern}' found in file",
                        severity=IssueSeverity.CRITICAL,
                        location=self.current_file_path,
                        details={"blacklisted_term": pattern, "file_path": path},
                        why=(
                            "This term matches a user-defined blacklist pattern. Organizations use blacklists to "
                            "identify models or configurations that violate security policies or contain known "
                            "malicious indicators."
                        ),
                    )
                    found_blacklisted = True

            if not found_blacklisted:
                result.add_check(
                    name="Blacklist Pattern Check",
                    passed=True,
                    message="No blacklisted patterns found in file",
                    location=self.current_file_path,
                    details={"patterns_checked": len(self.blacklist_patterns)},
                )
        except Exception as e:
            result.add_check(
                name="Blacklist Pattern Check",
                passed=False,
                message=f"Error checking file for blacklist: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
            )

    def _parse_file(
        self,
        path: str,
        ext: str,
        result: ScanResult | None = None,
    ) -> dict[str, Any] | None:
        """Parse the file based on its extension"""
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

            # Try JSON format first
            if ext in [
                ".json",
                ".manifest",
                ".model",
                ".metadata",
            ] or content.strip().startswith(("{", "[")):
                return json.loads(content)

            # Try YAML format if available
            if HAS_YAML and (ext in [".yaml", ".yml"] or content.strip().startswith("---")):
                return yaml.safe_load(content)

            # For other formats, try JSON and then YAML if available
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                if HAS_YAML:
                    try:
                        return yaml.safe_load(content)
                    except Exception:
                        pass

        except Exception as e:
            logger.warning(f"Error parsing file {path}: {e!s}")
            if result is not None:
                result.add_check(
                    name="File Parse Error",
                    passed=False,
                    message=f"Error parsing file: {path}",
                    severity=IssueSeverity.DEBUG,
                    location=path,
                    details={"exception": str(e), "exception_type": type(e).__name__},
                )

        return None

    def _extract_model_metadata(self, content: dict[str, Any]) -> dict[str, Any]:
        """Extract model metadata from HuggingFace config files"""
        model_info = {}

        # Extract key model configuration
        metadata_keys = {
            "model_type": "model_type",
            "architectures": "architectures",
            "num_parameters": "num_parameters",
            "hidden_size": "hidden_size",
            "num_hidden_layers": "num_layers",
            "num_attention_heads": "num_heads",
            "vocab_size": "vocab_size",
            "task": "task",
            "transformers_version": "framework_version",
        }

        for source_key, dest_key in metadata_keys.items():
            if source_key in content:
                model_info[dest_key] = content[source_key]

        return model_info

    def _extract_license_info(self, content: dict[str, Any]) -> str | None:
        """Return license string if found in manifest content"""
        potential_keys = ["license", "licence", "licenses"]
        for key in potential_keys:
            if key in content:
                value = content[key]
                if isinstance(value, str):
                    return value
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, str):
                        return first

        return None

    def _check_model_name_policies(self, content: dict[str, Any], result: ScanResult) -> None:
        """Check for blacklisted model names in config values"""

        def check_dict(d: Any, prefix: str = "") -> None:
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                key_lower = key.lower()
                full_key = f"{prefix}.{key}" if prefix else key

                # Check if this key might contain a model name
                if key_lower in MODEL_NAME_KEYS_LOWER:
                    blocked, reason = check_model_name_policies(
                        str(value),
                        self.blacklist_patterns,
                    )
                    if blocked:
                        result.add_check(
                            name="Model Name Policy Check",
                            passed=False,
                            message=f"Model name blocked by policy: {value}",
                            severity=IssueSeverity.CRITICAL,
                            location=self.current_file_path,
                            details={
                                "model_name": str(value),
                                "reason": reason,
                                "key": full_key,
                            },
                            why=(
                                "This model name matches a blacklist pattern. Organizations use model name "
                                "blacklists to prevent use of banned, malicious, or policy-violating models."
                            ),
                        )
                    else:
                        result.add_check(
                            name="Model Name Policy Check",
                            passed=True,
                            message=f"Model name '{value}' passed policy check",
                            location=self.current_file_path,
                            details={
                                "model_name": str(value),
                                "key": full_key,
                            },
                        )

                # Recursively check nested structures
                if isinstance(value, dict):
                    check_dict(value, full_key)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            check_dict(item, f"{full_key}[{i}]")

        check_dict(content)

    def _check_suspicious_urls(self, content: dict[str, Any], result: ScanResult) -> None:
        """Check for untrusted URLs in config values using allowlist approach.

        Only URLs from trusted domains (huggingface, github, pytorch, etc.) are allowed.
        Any URL from a domain NOT in the allowlist is flagged.

        This is more secure than a blocklist because attackers cannot bypass
        detection by registering new domains.
        """
        seen_urls: set[str] = set()

        def is_trusted_domain(url_lower: str) -> bool:
            """Check if URL is from a trusted domain in the allowlist."""
            return any(domain in url_lower for domain in TRUSTED_URL_DOMAINS)

        def extract_urls_from_value(value: Any, key_path: str) -> None:
            """Recursively extract and check URLs from any value type."""
            if isinstance(value, str):
                urls = URL_PATTERN.findall(value)
                for url in urls:
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    url_lower = url.lower()

                    # Flag any URL not from a trusted domain
                    if not is_trusted_domain(url_lower):
                        result.add_check(
                            name="Untrusted URL Check",
                            passed=False,
                            message=f"URL from untrusted domain: {url}",
                            severity=IssueSeverity.INFO,
                            location=self.current_file_path,
                            details={
                                "url": url,
                                "key_path": key_path,
                            },
                            why=(
                                "This URL is from a domain not in the trusted allowlist. "
                                "ML model configs should only reference well-known sources. "
                                "Unknown domains may indicate supply chain attacks or "
                                "data exfiltration attempts."
                            ),
                        )

            elif isinstance(value, dict):
                for k, v in value.items():
                    new_path = f"{key_path}.{k}" if key_path else k
                    extract_urls_from_value(v, new_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    extract_urls_from_value(item, f"{key_path}[{i}]")

        extract_urls_from_value(content, "")
