import json
import os
import re
from typing import Any
from urllib.parse import urlparse

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

# Cloud storage URL patterns for detecting external resource references
# These patterns detect references to cloud storage that could indicate
# external dependencies or potential data exfiltration vectors
CLOUD_STORAGE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # AWS S3
    (re.compile(r"s3://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "AWS S3 URI", "s3"),
    (
        re.compile(r"https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "AWS S3 URL",
        "s3",
    ),
    (
        re.compile(r"https?://s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "AWS S3 URL",
        "s3",
    ),
    (
        re.compile(r"https?://s3\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "AWS S3 Regional URL",
        "s3",
    ),
    # Google Cloud Storage
    (re.compile(r"gs://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Google Cloud Storage URI", "gcs"),
    (
        re.compile(r"https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "Google Cloud Storage URL",
        "gcs",
    ),
    (
        re.compile(r"https?://storage\.cloud\.google\.com/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "Google Cloud Storage URL",
        "gcs",
    ),
    # Azure Blob Storage
    (
        re.compile(r"https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "Azure Blob Storage URL",
        "azure",
    ),
    (re.compile(r"az://[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE), "Azure Storage URI", "azure"),
    (
        re.compile(r"wasbs?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "Azure WASB URI",
        "azure",
    ),
    (
        re.compile(r"abfss?://[^\s\"'<>@]+@[a-zA-Z0-9.\-_]+\.dfs\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "Azure ADLS Gen2 URI",
        "azure",
    ),
    # Hugging Face Hub (external model references)
    (
        re.compile(r"https?://huggingface\.co/[a-zA-Z0-9.\-_]+/[a-zA-Z0-9.\-_]+(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "HuggingFace Hub URL",
        "huggingface",
    ),
]

# Keys that indicate hash/checksum values used for integrity verification
# These are used to detect weak hash algorithms (MD5, SHA1)
HASH_INTEGRITY_KEYS = [
    "hash",
    "checksum",
    "digest",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "file_hash",
    "model_hash",
    "weight_hash",
    "integrity",
]

# Regex pattern for hexadecimal strings (used to detect hash values)
HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")

# Comprehensive allowlist of trusted domains for ML model configs
# URLs from domains NOT in this list will be flagged as untrusted
# This is more secure than a blocklist - attackers can't bypass by registering new domains
#
# MAINTENANCE: When adding domains, ensure they are:
# 1. Established ML/AI infrastructure (not personal sites)
# 2. Commonly referenced in model configs
# 3. Not easily exploitable for hosting malicious content
TRUSTED_URL_DOMAINS = [
    # ===========================================
    # MODEL HUBS & REPOSITORIES
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
    # International model hubs
    "modelscope.cn",  # Alibaba's model hub
    "civitai.com",  # Popular for diffusion models
    "tfhub.dev",  # TensorFlow Hub
    # ===========================================
    # ML FRAMEWORKS & LIBRARIES
    # ===========================================
    "pytorch.org",
    "download.pytorch.org",
    "tensorflow.org",
    "keras.io",
    "onnx.ai",
    "onnxruntime.ai",
    "scikit-learn.org",
    "spacy.io",
    "huggingface.co",
    "jax.readthedocs.io",
    # ===========================================
    # ML OPERATIONS & EXPERIMENT TRACKING
    # ===========================================
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
    "mosaicml.com",
    # ===========================================
    # VECTOR DATABASES (for RAG/embeddings)
    # ===========================================
    "pinecone.io",
    "weaviate.io",
    "qdrant.tech",
    "milvus.io",
    "chroma.ai",
    "lancedb.com",
    "vespa.ai",
    # ===========================================
    # CLOUD STORAGE & CDNs
    # ===========================================
    # AWS
    "s3.amazonaws.com",
    "s3-",  # Regional: s3-us-west-2.amazonaws.com
    ".s3.",  # Bucket URLs: bucket.s3.region.amazonaws.com
    "cloudfront.net",
    # Google Cloud
    "storage.googleapis.com",
    "storage.cloud.google.com",
    "googleusercontent.com",  # User content storage
    "gcr.io",
    # Azure
    "blob.core.windows.net",
    "azureedge.net",
    "azure.com",
    # CDNs
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "fastly.net",
    "akamaized.net",
    "replicate.delivery",  # Replicate CDN
    # ===========================================
    # AI/ML COMPANIES
    # ===========================================
    # Major labs
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
    # Model providers
    "stability.ai",
    "mistral.ai",
    "cohere.com",
    "cohere.ai",
    "replicate.com",
    "together.ai",
    "together.xyz",
    "fireworks.ai",
    "perplexity.ai",
    "ai21.com",  # AI21 Labs
    "aleph-alpha.com",
    "runwayml.com",
    "midjourney.com",
    # ML platforms
    "databricks.com",
    "snowflake.com",
    "datarobot.com",
    "h2o.ai",
    "clarifai.com",
    "scale.com",
    "labelbox.com",
    "appen.com",
    "sagemaker.aws",
    "vertexai.google.com",
    # ===========================================
    # RESEARCH ORGANIZATIONS
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
    # Non-profit AI research
    "eleuther.ai",
    "laion.ai",
    "allenai.org",
    "bigscience.huggingface.co",
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
    "lvis-dataset.org",
    "openimages.github.io",
    # Academic CS departments (common dataset hosts)
    "cs.stanford.edu",
    "cs.cmu.edu",
    "cs.berkeley.edu",
    "cs.toronto.edu",
    "cs.nyu.edu",
    "yann.lecun.com",
    "people.eecs.berkeley.edu",
    "nlp.stanford.edu",
    "vision.stanford.edu",
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
    # DOCUMENTATION
    # ===========================================
    "readthedocs.io",
    "readthedocs.org",
    "rtfd.io",
    "gitbook.io",
    "docs.python.org",
    # ===========================================
    # CONTAINER REGISTRIES
    # ===========================================
    "docker.io",
    "docker.com",
    "quay.io",
    "ghcr.io",
    "nvcr.io",
    "registry.hub.docker.com",
    "ecr.aws",
    # ===========================================
    # PLACEHOLDER/EXAMPLE DOMAINS (RFC 2606)
    # These are reserved and commonly used in examples
    # ===========================================
    "example.com",
    "example.org",
    "example.net",
    # ===========================================
    # LOCALHOST (for development/testing)
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

        # Check if filename matches any AI/ML specific pattern (exact match or suffix match)
        # Exclude tokenizer configs - they don't contain security-relevant model info
        if "tokenizer" in filename:
            return False

        # Exclude common web/JS framework configs that are unrelated to ML
        web_configs = ["package.json", "tsconfig.json", "jsconfig.json", "webpack.config.json"]
        if filename in web_configs:
            return False

        if any(filename == pattern or filename.endswith(pattern) for pattern in aiml_specific_patterns):
            return True

        # Additional check: files with "config" in name that are in ML model context
        # Note: tokenizer files are already excluded above
        if "config" in filename and filename not in [
            "config.py",
            "config.yaml",
            "config.yml",
            "config.ini",
            "config.cfg",
        ]:
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

            # Check for cloud storage URLs (external resource references)
            self._check_cloud_storage_urls(path, result)

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

                    # Check for weak hash algorithms used for integrity verification
                    self._check_weak_hashes(content, result)

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

    def _check_cloud_storage_urls(self, path: str, result: ScanResult) -> None:
        """Check for cloud storage URLs (external resource references).

        Detects references to AWS S3, Google Cloud Storage, Azure Blob Storage,
        and other external resources that could indicate:
        - External model dependencies
        - Potential data exfiltration vectors
        - Supply chain risks from external resources
        """
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()

            seen_urls: set[str] = set()

            for pattern, description, provider in CLOUD_STORAGE_PATTERNS:
                for match in pattern.finditer(content):
                    url = match.group()

                    # Skip duplicates
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    # Determine severity based on context
                    # INFO for most cloud URLs (informational - may be legitimate)
                    severity = IssueSeverity.INFO

                    # Check for suspicious indicators that might elevate severity
                    url_lower = url.lower()
                    suspicious_indicators = ["malware", "exploit", "hack", "evil", "backdoor", "exfil"]
                    if any(indicator in url_lower for indicator in suspicious_indicators):
                        severity = IssueSeverity.WARNING

                    result.add_check(
                        name="Cloud Storage URL Detection",
                        passed=False,  # Finding a cloud URL is informational, not a pass/fail
                        message=f"{description} detected: {url[:150]}",
                        severity=severity,
                        location=self.current_file_path,
                        details={
                            "url": url,
                            "provider": provider,
                            "description": description,
                        },
                        why=(
                            "External cloud storage references in model configs may indicate external "
                            "dependencies or potential supply chain risks. Verify that these URLs point "
                            "to trusted sources and are required for model operation."
                        ),
                    )

        except Exception as e:
            logger.debug(f"Error checking cloud storage URLs in {path}: {e}")

    def _check_suspicious_urls(self, content: dict[str, Any], result: ScanResult) -> None:
        """Check for untrusted URLs in config values using allowlist approach.

        Only URLs from trusted domains (huggingface, github, pytorch, etc.) are allowed.
        Any URL from a domain NOT in the allowlist is flagged.

        This is more secure than a blocklist because attackers cannot bypass
        detection by registering new domains.
        """
        seen_urls: set[str] = set()

        def is_trusted_domain(url: str) -> bool:
            """Check if URL host is in the trusted domain allowlist."""
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host:
                return False

            for domain in TRUSTED_URL_DOMAINS:
                trusted = domain.lower().rstrip(".")
                if host == trusted or host.endswith(f".{trusted}"):
                    return True
            return False

        def extract_urls_from_value(value: Any, key_path: str) -> None:
            """Recursively extract and check URLs from any value type."""
            if isinstance(value, str):
                urls = URL_PATTERN.findall(value)
                for url in urls:
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    # Flag any URL not from a trusted domain
                    if not is_trusted_domain(url):
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

    def _check_weak_hashes(self, content: dict[str, Any], result: ScanResult) -> None:
        """Check for weak hash algorithms (MD5, SHA1) used for integrity verification.

        MD5 and SHA1 are cryptographically broken and should not be used for
        integrity verification of model files. This check detects when these
        weak algorithms are used in config files.

        CWE-328: Use of Weak Hash
        """

        def _is_hex_string(value: str) -> bool:
            """Check if a string is a valid hexadecimal value."""
            return bool(HEX_PATTERN.match(value))

        def _detect_hash_algorithm(value: str) -> str | None:
            """Detect hash algorithm based on string length."""
            if not _is_hex_string(value):
                return None

            # Map hash length to algorithm name
            length_to_algorithm = {
                32: "MD5",
                40: "SHA1",
                64: "SHA256",
                128: "SHA512",
            }
            return length_to_algorithm.get(len(value))

        def check_value(key: str, value: Any, path: str) -> None:
            """Check a single key-value pair for weak hash usage."""
            if not isinstance(value, str):
                return

            key_lower = key.lower()

            # Check if this key is likely a hash/checksum field
            is_hash_key = any(h in key_lower for h in HASH_INTEGRITY_KEYS)

            if not is_hash_key:
                return

            algorithm = _detect_hash_algorithm(value)

            if algorithm in ("MD5", "SHA1"):
                # Weak hash detected
                result.add_check(
                    name="Weak Hash Detection",
                    passed=False,
                    message=f"{algorithm} hash detected for integrity verification: {key}",
                    severity=IssueSeverity.WARNING,
                    location=self.current_file_path,
                    details={
                        "key": path,
                        "algorithm": algorithm,
                        "hash_preview": value[:16] + "..." if len(value) > 16 else value,
                    },
                    why=(
                        f"{algorithm} is cryptographically broken and vulnerable to collision attacks. "
                        "Use SHA256 or stronger for model integrity verification. "
                        "See CWE-328: Use of Weak Hash."
                    ),
                )
            elif algorithm in ("SHA256", "SHA512"):
                # Strong hash - good!
                result.add_check(
                    name="Weak Hash Detection",
                    passed=True,
                    message=f"Strong hash algorithm ({algorithm}) used for: {key}",
                    severity=IssueSeverity.DEBUG,
                    location=self.current_file_path,
                    details={
                        "key": path,
                        "algorithm": algorithm,
                    },
                )

        def traverse_for_hashes(d: Any, prefix: str = "") -> None:
            """Recursively check dictionary for weak hashes."""
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                full_key = f"{prefix}.{key}" if prefix else key

                if isinstance(value, str):
                    check_value(key, value, full_key)
                elif isinstance(value, dict):
                    traverse_for_hashes(value, full_key)
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            traverse_for_hashes(item, f"{full_key}[{i}]")
                        elif isinstance(item, str):
                            check_value(f"{key}[{i}]", item, f"{full_key}[{i}]")

        traverse_for_hashes(content)
