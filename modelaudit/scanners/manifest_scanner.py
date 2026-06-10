"""Scanner for model manifest and configuration files."""

import configparser
import importlib
import json
import os
import re
from dataclasses import dataclass
from itertools import chain
from types import ModuleType
from typing import Any, Final
from urllib.parse import urlparse, urlsplit, urlunsplit

from modelaudit.core_results import mark_operational_scan_error, scan_result_has_operational_error
from modelaudit.scanner_results import mark_inconclusive_scan_result

from ..scanner_selection import add_scanner_selection_skip_check, policy_from_config
from ._evidence_redaction import redact_evidence_string
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult, logger

try:
    _tomllib: ModuleType | None = importlib.import_module("tomllib")
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    try:
        _tomllib = importlib.import_module("tomli")
    except ImportError:
        _tomllib = None

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
MANIFEST_EXACT_FILENAMES = frozenset(
    {
        "manifest.json",
        "model.json",
        "params.json",
        "hyperparams.yaml",
        "training_args.json",
        "dataset_info.json",
        "environment.yml",
        "conda.yaml",
        "metadata.json",
        "index.json",
    }
)
MANIFEST_EXACT_EXTENSIONS = frozenset({".manifest"})

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
        re.compile(r"https?://[a-zA-Z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "AWS S3 Regional URL",
        "s3",
    ),
    (
        re.compile(r"https?://[a-zA-Z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE),
        "AWS S3 Regional URL",
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
JINJA_TEMPLATE_FIELD_NAMES = frozenset({"chat_template", "template", "jinja_template", "custom_chat_template"})
JINJA_TEMPLATE_INDICATORS = ("{{", "{%", "{#")
JINJA_TEMPLATE_COLLECTION_BUDGET_REASON: Final[str] = "manifest_jinja_template_collection_budget_exceeded"
MANIFEST_SCAN_TIMEOUT_REASON: Final[str] = "manifest_scan_timeout"
JINJA_TEMPLATE_COLLECTION_MAX_DEPTH_CONFIG_KEY: Final[str] = "jinja_template_collection_max_depth"
JINJA_TEMPLATE_COLLECTION_MAX_ITEMS_CONFIG_KEY: Final[str] = "jinja_template_collection_max_items"
DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH: Final[int] = 64
DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS: Final[int] = 50_000
JINJA_TEMPLATE_LOCATION_MAX_CHARS: Final[int] = 240
_JINJA_COLLECTION_MODE_FIELDS: Final[str] = "fields"
_JINJA_COLLECTION_MODE_CONTAINER: Final[str] = "container"


@dataclass
class _JinjaTemplateCollection:
    templates: dict[str, str]
    budget_exceeded: bool = False
    limit_type: str = ""
    path: str = ""
    items_visited: int = 0
    max_depth: int = DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH
    max_items: int = DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS


@dataclass
class _JinjaTraversalFrame:
    mode: str
    value: Any
    path: str
    depth: int
    allow_plain_field_scalar: bool = False
    iterator: Any | None = None
    visited: bool = False


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

# Broad user-content hosting domains should only trust the exact host, not
# arbitrary attacker-controlled subdomains.
TRUSTED_URL_EXACT_DOMAINS = {
    # CDNs — anyone can provision an endpoint
    "akamaized.net",
    "azureedge.net",
    "cloudfront.net",
    "fastly.net",
    # User-content hosting — arbitrary subdomains are attacker-controlled
    "ghcr.io",
    "gitbook.io",
    "github.io",
    "gitlab.io",
    "googleusercontent.com",
    "gradio.app",
    "nvcr.io",
    "quay.io",
    "readthedocs.io",
    "rtfd.io",
    "sourceforge.net",
    "streamlit.io",
}
_NORMALIZED_TRUSTED_URL_DOMAINS: Final[frozenset[str]] = frozenset(
    domain.lower().rstrip(".") for domain in TRUSTED_URL_DOMAINS
)
_NORMALIZED_TRUSTED_URL_EXACT_DOMAINS: Final[frozenset[str]] = frozenset(
    domain.lower().rstrip(".") for domain in TRUSTED_URL_EXACT_DOMAINS
)
_TRUSTED_URL_SUBDOMAIN_SUFFIXES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(
        normalized_domain
        for domain in TRUSTED_URL_DOMAINS
        if (normalized_domain := domain.lower().rstrip(".")) not in _NORMALIZED_TRUSTED_URL_EXACT_DOMAINS
    )
)

# Regex to find URLs in text
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+[^\s<>"\',.]')
_AWS_S3_REGION_PATTERN = r"[a-z]{2}(?:-[a-z0-9]+)+-\d"
_S3_HOST_LABEL_PATTERN = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_S3_BUCKET_HOST_PREFIX_PATTERN = rf"{_S3_HOST_LABEL_PATTERN}(?:\.{_S3_HOST_LABEL_PATTERN})*"
_TRUSTED_S3_ENDPOINT_HOST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^{_S3_BUCKET_HOST_PREFIX_PATTERN}\.s3\.amazonaws\.com$"),
    re.compile(rf"^{_S3_BUCKET_HOST_PREFIX_PATTERN}\.s3\.{_AWS_S3_REGION_PATTERN}\.amazonaws\.com$"),
    re.compile(rf"^{_S3_BUCKET_HOST_PREFIX_PATTERN}\.s3-{_AWS_S3_REGION_PATTERN}\.amazonaws\.com$"),
)
_PARSE_FAILED: Final = object()
_INI_SECTION_HEADER_RE = re.compile(r"^\s*\[[A-Za-z0-9_. -]+\]\s*(?:[#;].*)?(?:\r?\n|$)")


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    """Return True when the manifest result includes WARNING/CRITICAL findings."""
    return any(issue.severity in {IssueSeverity.WARNING, IssueSeverity.CRITICAL} for issue in result.issues)


def _is_trusted_s3_endpoint_host(host: str) -> bool:
    """Return True for supported S3 endpoint host layouts only."""
    return any(pattern.match(host) for pattern in _TRUSTED_S3_ENDPOINT_HOST_PATTERNS)


def _redact_url_for_display(url: str) -> str:
    """Strip credential-bearing URL components before storing scan output."""
    try:
        parts = urlsplit(url)
    except Exception:
        return "<url redacted>"

    if not parts.scheme:
        return url

    netloc = parts.netloc
    if "@" in parts.netloc:
        netloc = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            port = None
        if port is not None:
            netloc = f"{netloc}:{port}"
        netloc = f"<credentials-redacted>@{netloc}"

    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _is_trusted_url_domain(url: str) -> bool:
    """Check if a URL host is in the trusted domain allowlist."""
    parsed = urlparse(url)

    # URLs with userinfo (user@host) are inherently suspicious — an attacker
    # can craft https://evil.com@github.com/payload where urlparse sees the
    # hostname as github.com while the visual target appears to be evil.com.
    if parsed.username or parsed.password:
        return False

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False

    if _is_trusted_s3_endpoint_host(host):
        return True

    if host in _NORMALIZED_TRUSTED_URL_DOMAINS:
        return True

    return any(host.endswith(f".{trusted}") for trusted in _TRUSTED_URL_SUBDOMAIN_SUFFIXES)


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

        if filename in MANIFEST_EXACT_FILENAMES:
            return True

        if os.path.splitext(filename)[1] in MANIFEST_EXACT_EXTENSIONS:
            return True

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
            if self._is_unreadable_path_result(path_check_result):
                return self._finish_read_failure(
                    self._create_result(),
                    path,
                    PermissionError(f"Path is not readable: {path}"),
                )
            return path_check_result

        size_check = self._check_size_limit(path)
        if size_check:
            return size_check

        self._start_scan_timer()
        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        self._manifest_text_cache: dict[str, str] = {}

        try:
            # Store the file path for use in issue locations
            self.current_file_path = path

            self._check_timeout()

            # Check the raw file content for blacklisted terms
            self._check_file_for_blacklist(path, result)
            if scan_result_has_operational_error(result):
                self._finish_manifest_result(result)
                return result
            self._check_timeout()

            # Check for cloud storage URLs (external resource references)
            self._check_cloud_storage_urls(path, result)
            self._check_timeout()

            # Parse the file based on its extension
            ext = os.path.splitext(path)[1].lower()
            content = self._parse_file(path, ext, result)
            self._check_timeout()

            if content is _PARSE_FAILED:
                result.add_check(
                    name="Manifest Parse Coverage",
                    passed=False,
                    message=f"Unable to complete manifest analysis because the file could not be parsed: {path}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "manifest_parse_failed",
                        "file_path": path,
                    },
                    why=(
                        "Model manifest parsing did not complete, so structured security checks for model names, "
                        "URLs, and integrity hashes could not be applied."
                    ),
                    rule_code="S902",
                )
                self._mark_inconclusive_scan_result(result, "manifest_parse_failed")
            elif isinstance(content, (dict, list)):
                result.bytes_scanned = file_size
                if isinstance(content, dict):
                    result.metadata["root_type"] = "dict"
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

                else:
                    result.metadata["root_type"] = "list"
                    result.metadata["entry_count"] = len(content)

                # Check for blacklisted model names in config values
                self._check_model_name_policies(content, result)
                self._check_timeout()

                # Check for suspicious URLs in config values
                self._check_suspicious_urls(content, result)
                self._check_timeout()

                # Check for weak hash algorithms used for integrity verification
                self._check_weak_hashes(content, result)
                self._check_timeout()

                # Manifest-owned configs can still carry executable chat
                # templates, so preserve manifest checks while delegating those
                # embedded fields to the dedicated Jinja analyzer.
                self._scan_embedded_jinja_templates(path, content, result)
                self._check_timeout()

            else:
                result.add_check(
                    name="Manifest Structure",
                    passed=False,
                    message=f"Unsupported manifest root type: {type(content).__name__}",
                    severity=IssueSeverity.INFO,
                    location=path,
                    details={
                        "reason": "manifest_unsupported_root_type",
                        "root_type": type(content).__name__,
                    },
                    why=(
                        "The file parsed successfully, but the parsed value is not an object or list, so structured "
                        "manifest security checks could not be applied."
                    ),
                    rule_code="S902",
                )
                self._mark_inconclusive_scan_result(result, "manifest_unsupported_root_type")

        except TimeoutError as e:
            self._mark_inconclusive_scan_result(result, MANIFEST_SCAN_TIMEOUT_REASON)
            mark_operational_scan_error(result, MANIFEST_SCAN_TIMEOUT_REASON)
            result.add_check(
                name="Manifest Scan Timeout",
                passed=False,
                message=f"Scan timed out: {e!s}",
                severity=IssueSeverity.INFO,
                location=path,
                details={
                    "timeout_seconds": self.timeout,
                    "analysis_incomplete": True,
                    "scan_outcome_reason": MANIFEST_SCAN_TIMEOUT_REASON,
                },
                why="Manifest scanning exceeded the configured timeout before all checks completed",
            )
            self._finish_manifest_result(result)
            return result
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
        finally:
            self._manifest_text_cache.clear()

        self._finish_manifest_result(result)
        return result

    def _mark_inconclusive_scan_result(self, result: ScanResult, reason: str) -> None:
        """Mark a manifest scan as inconclusive when structured analysis is incomplete."""
        mark_inconclusive_scan_result(result, reason)

    def _finish_manifest_result(self, result: ScanResult) -> None:
        """Fail closed for inconclusive manifests unless real security findings were recovered."""
        if scan_result_has_operational_error(result):
            result.finish(success=False)
            return

        if result.metadata.get("scan_outcome") == INCONCLUSIVE_SCAN_OUTCOME and not _scan_result_has_security_findings(
            result
        ):
            result.finish(success=False)
            return

        result.finish(success=True)

    @staticmethod
    def _is_unreadable_path_result(result: ScanResult) -> bool:
        return any(check.name == "Path Readable" and check.status == CheckStatus.FAILED for check in result.checks)

    @staticmethod
    def _record_read_failure(
        result: ScanResult,
        path: str,
        error: OSError | UnicodeError,
        *,
        reason: str,
        check_name: str,
        message: str,
    ) -> None:
        mark_inconclusive_scan_result(result, reason)
        mark_operational_scan_error(result, reason)
        result.add_check(
            name=check_name,
            passed=False,
            message=f"{message}: {error!s}",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "exception": str(error),
                "exception_type": type(error).__name__,
                "analysis_incomplete": True,
                "scan_outcome_reason": reason,
            },
        )

    @classmethod
    def _finish_read_failure(
        cls,
        result: ScanResult,
        path: str,
        error: OSError | UnicodeError,
        *,
        reason: str = "manifest_read_failed",
    ) -> ScanResult:
        cls._record_read_failure(
            result,
            path,
            error,
            reason=reason,
            check_name="Manifest File Read",
            message="Unable to read manifest file",
        )
        result.finish(success=False)
        return result

    def _check_file_for_blacklist(self, path: str, result: ScanResult) -> None:
        """Check the entire file content for blacklisted terms"""
        if not self.blacklist_patterns:
            return

        try:
            content = self._read_manifest_text(path).lower()

            found_blacklisted = False
            for pattern in self.blacklist_patterns:
                self._check_timeout()
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
                        rule_code="S1001",
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
        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            self._record_read_failure(
                result,
                path,
                e,
                reason="manifest_blacklist_read_failed",
                check_name="Blacklist Pattern Check",
                message="Unable to load manifest text for configured policy analysis",
            )
        except Exception as e:
            result.add_check(
                name="Blacklist Pattern Check",
                passed=False,
                message=f"Error checking file for blacklist: {e!s}",
                severity=IssueSeverity.WARNING,
                location=path,
                details={"exception": str(e), "exception_type": type(e).__name__},
                rule_code="S1001",
            )

    def _parse_file(
        self,
        path: str,
        ext: str,
        result: ScanResult | None = None,
    ) -> Any:
        """Parse the file based on its extension"""
        try:
            content = self._read_manifest_text(path)

            stripped_content = content.strip()

            if ext == ".toml":
                if _tomllib is None:
                    raise ValueError("TOML parsing requires Python 3.11+ or the tomli package")
                return _tomllib.loads(content)

            if ext in [".ini", ".cfg"] or (ext == ".config" and self._looks_like_ini_file(stripped_content)):
                return self._parse_ini_file(content)

            # Try JSON format first
            if ext in [
                ".json",
                ".manifest",
                ".model",
                ".metadata",
            ] or stripped_content.startswith(("{", "[")):
                return json.loads(content)

            # Try YAML format if available
            if HAS_YAML and (ext in [".yaml", ".yml"] or stripped_content.startswith("---")):
                return yaml.safe_load(content)

            # For other formats, try JSON and then YAML if available
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                if HAS_YAML:
                    try:
                        return yaml.safe_load(content)
                    except TimeoutError:
                        raise
                    except Exception:
                        pass

        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            logger.warning(f"Error reading file {path}: {e!s}")
            if result is not None:
                self._record_read_failure(
                    result,
                    path,
                    e,
                    reason="manifest_read_failed",
                    check_name="Manifest File Read",
                    message="Unable to read manifest file for structured analysis",
                )
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
                    rule_code="S902",
                )

        return _PARSE_FAILED

    def _scan_embedded_jinja_templates(self, path: str, content: Any, result: ScanResult) -> None:
        scanner_selection = policy_from_config(self.config)
        if not scanner_selection.allows("jinja2_template"):
            if scanner_selection.active:
                add_scanner_selection_skip_check(
                    result,
                    path,
                    "jinja2_template",
                    scanner_selection,
                    context="embedded Jinja template analysis",
                )
            return

        collection = self._collect_jinja_template_fields_with_budget(content)
        templates = collection.templates
        if collection.budget_exceeded:
            self._record_jinja_collection_budget_exceeded(result, path, collection)
            self._check_timeout()

        if not templates:
            return

        from .jinja2_template_scanner import Jinja2TemplateScanner

        safe_templates = self._redact_jinja_template_locations(templates)
        result.merge(Jinja2TemplateScanner(config=self.config).scan_extracted_templates(path, safe_templates))

    def _collect_jinja_template_fields(self, value: Any, path: str = "") -> dict[str, str]:
        return self._collect_jinja_template_fields_with_budget(value, path).templates

    def _collect_jinja_template_fields_with_budget(self, value: Any, path: str = "") -> _JinjaTemplateCollection:
        return self._collect_jinja_templates_with_budget(value, path, _JINJA_COLLECTION_MODE_FIELDS)

    def _collect_jinja_template_container(self, value: Any, path: str) -> dict[str, str]:
        return self._collect_jinja_templates_with_budget(value, path, _JINJA_COLLECTION_MODE_CONTAINER).templates

    def _collect_jinja_templates_with_budget(
        self,
        value: Any,
        path: str,
        mode: str,
    ) -> _JinjaTemplateCollection:
        max_depth = self._get_positive_int_config(
            JINJA_TEMPLATE_COLLECTION_MAX_DEPTH_CONFIG_KEY,
            DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_DEPTH,
        )
        max_items = self._get_positive_int_config(
            JINJA_TEMPLATE_COLLECTION_MAX_ITEMS_CONFIG_KEY,
            DEFAULT_JINJA_TEMPLATE_COLLECTION_MAX_ITEMS,
        )
        collection = _JinjaTemplateCollection(
            templates={},
            max_depth=max_depth,
            max_items=max_items,
        )
        stack = [
            _JinjaTraversalFrame(
                mode=mode,
                value=value,
                path=path,
                depth=0,
                allow_plain_field_scalar=mode == _JINJA_COLLECTION_MODE_CONTAINER,
            )
        ]
        expanded_container_depths: dict[tuple[str, bool, int], int] = {}

        while stack:
            self._check_timeout()
            frame = stack[-1]

            if not frame.visited:
                frame.visited = True
                collection.items_visited += 1
                if collection.items_visited > max_items:
                    self._mark_jinja_collection_budget_exceeded(collection, "items", frame.path)
                    break

                if isinstance(frame.value, (dict, list)):
                    container_key = (
                        frame.mode,
                        "chat_template" in frame.path.lower(),
                        id(frame.value),
                    )
                    expanded_depth = expanded_container_depths.get(container_key)
                    if expanded_depth is not None and expanded_depth <= frame.depth:
                        stack.pop()
                        continue

                if frame.depth > max_depth:
                    self._mark_jinja_collection_budget_exceeded(collection, "depth", frame.path)
                    stack.pop()
                    continue

                if isinstance(frame.value, str):
                    self._record_jinja_scalar_if_template(
                        collection.templates,
                        frame.mode,
                        frame.path,
                        frame.value,
                        allow_plain_field_scalar=frame.allow_plain_field_scalar,
                    )
                    stack.pop()
                    continue

                if isinstance(frame.value, dict):
                    expanded_container_depths[(frame.mode, "chat_template" in frame.path.lower(), id(frame.value))] = (
                        frame.depth
                    )
                    if frame.mode == _JINJA_COLLECTION_MODE_FIELDS:
                        priority_items = (
                            (field_name, frame.value[field_name])
                            for field_name in sorted(JINJA_TEMPLATE_FIELD_NAMES)
                            if field_name in frame.value
                        )
                        remaining_items = (
                            (key, item) for key, item in frame.value.items() if key not in JINJA_TEMPLATE_FIELD_NAMES
                        )
                        frame.iterator = chain(priority_items, remaining_items)
                    else:
                        frame.iterator = iter(frame.value.items())
                    continue

                if isinstance(frame.value, list):
                    expanded_container_depths[(frame.mode, "chat_template" in frame.path.lower(), id(frame.value))] = (
                        frame.depth
                    )
                    frame.iterator = enumerate(frame.value)
                    continue

                stack.pop()
                continue

            if frame.iterator is None:
                stack.pop()
                continue

            try:
                key, item = next(frame.iterator)
            except StopIteration:
                stack.pop()
                continue

            self._check_timeout()
            child_path = self._jinja_collection_child_path(frame.path, key, isinstance(frame.value, list))
            child_mode = frame.mode
            allow_plain_field_scalar = False
            if frame.mode == _JINJA_COLLECTION_MODE_FIELDS:
                is_template_field = isinstance(key, str) and key in JINJA_TEMPLATE_FIELD_NAMES
                child_mode = _JINJA_COLLECTION_MODE_CONTAINER if is_template_field else _JINJA_COLLECTION_MODE_FIELDS
                allow_plain_field_scalar = is_template_field
            stack.append(
                _JinjaTraversalFrame(
                    mode=child_mode,
                    value=item,
                    path=child_path,
                    depth=frame.depth + 1,
                    allow_plain_field_scalar=allow_plain_field_scalar,
                )
            )

        return collection

    def _get_positive_int_config(self, key: str, default: int) -> int:
        try:
            value = int(self.config.get(key, default))
        except (OverflowError, TypeError, ValueError):
            return default
        return value if value > 0 else default

    @staticmethod
    def _mark_jinja_collection_budget_exceeded(
        collection: _JinjaTemplateCollection,
        limit_type: str,
        path: str,
    ) -> None:
        if collection.budget_exceeded and limit_type != "items":
            return
        collection.budget_exceeded = True
        collection.limit_type = limit_type
        collection.path = path

    def _record_jinja_scalar_if_template(
        self,
        templates: dict[str, str],
        mode: str,
        path: str,
        value: str,
        *,
        allow_plain_field_scalar: bool,
    ) -> None:
        if mode != _JINJA_COLLECTION_MODE_CONTAINER or not value.strip():
            return
        if allow_plain_field_scalar or self._looks_like_jinja(value):
            self._record_jinja_template(templates, path, value)

    @staticmethod
    def _jinja_collection_child_path(path: str, key: Any, parent_is_list: bool) -> str:
        key_text = str(key)
        if parent_is_list:
            candidate = f"{path}[{key_text}]" if path else f"[{key_text}]"
        else:
            safe_key = redact_evidence_string(key_text, max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS)
            candidate = f"{path}.{safe_key}" if path else safe_key

        preserve_chat_template_context = "chat_template" in path.casefold() or "chat_template" in key_text.casefold()
        context_suffix = ".chat_template" if preserve_chat_template_context else ""
        safe_path = redact_evidence_string(
            candidate,
            max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS - len(context_suffix),
        )
        if context_suffix and "chat_template" not in safe_path.casefold():
            safe_path = f"{safe_path}{context_suffix}"
        return safe_path

    def _record_jinja_collection_budget_exceeded(
        self,
        result: ScanResult,
        path: str,
        collection: _JinjaTemplateCollection,
    ) -> None:
        self._mark_inconclusive_scan_result(result, JINJA_TEMPLATE_COLLECTION_BUDGET_REASON)
        result.add_check(
            name="Embedded Jinja Collection Budget",
            passed=False,
            message=(
                "Embedded Jinja template analysis incomplete because parsed manifest traversal exceeded "
                "the configured collection budget"
            ),
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "reason": JINJA_TEMPLATE_COLLECTION_BUDGET_REASON,
                "scan_outcome_reason": JINJA_TEMPLATE_COLLECTION_BUDGET_REASON,
                "analysis_incomplete": True,
                "limit_type": collection.limit_type,
                "path": redact_evidence_string(collection.path, max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS),
                "items_visited": collection.items_visited,
                "max_depth": collection.max_depth,
                "max_items": collection.max_items,
                "templates_collected": len(collection.templates),
            },
            why=(
                "Manifest configs can contain attacker-controlled nested JSON, YAML, TOML, or INI structures. "
                "The embedded Jinja collector stops at a bounded traversal budget and marks analysis incomplete "
                "rather than recursively walking untrusted structures without limit."
            ),
        )

    @classmethod
    def _redact_jinja_template_locations(cls, templates: dict[str, str]) -> dict[str, str]:
        safe_templates: dict[str, str] = {}
        for path, value in templates.items():
            context_suffix = ".chat_template" if "chat_template" in path.casefold() else ""
            safe_path = redact_evidence_string(
                path,
                max_chars=JINJA_TEMPLATE_LOCATION_MAX_CHARS - len(context_suffix),
            )
            if context_suffix and "chat_template" not in safe_path.casefold():
                safe_path = f"{safe_path}{context_suffix}"
            cls._record_jinja_template(safe_templates, safe_path, value)
        return safe_templates

    @staticmethod
    def _record_jinja_template(templates: dict[str, str], path: str, value: str) -> None:
        if path not in templates:
            templates[path] = value
            return

        duplicate_index = len(templates) + 1
        unique_path = f"{path} [duplicate {duplicate_index}]"
        while unique_path in templates:
            duplicate_index += 1
            unique_path = f"{path} [duplicate {duplicate_index}]"
        templates[unique_path] = value

    @classmethod
    def _merge_jinja_templates(cls, templates: dict[str, str], collected: dict[str, str]) -> None:
        for path, value in collected.items():
            cls._record_jinja_template(templates, path, value)

    @staticmethod
    def _looks_like_jinja(value: str) -> bool:
        return any(indicator in value for indicator in JINJA_TEMPLATE_INDICATORS)

    def _parse_ini_file(self, content: str) -> dict[str, Any]:
        """Parse INI-style manifests into nested dictionaries."""
        parser = configparser.ConfigParser()
        parser.read_string(content)

        parsed: dict[str, Any] = {}
        defaults = dict(parser.defaults())
        if defaults:
            parsed["DEFAULT"] = defaults

        for section in parser.sections():
            parsed[section] = dict(parser.items(section))

        return parsed

    @staticmethod
    def _looks_like_ini_file(stripped_content: str) -> bool:
        """Return True when stripped content starts with an INI section header."""
        return bool(_INI_SECTION_HEADER_RE.match(stripped_content))

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

    def _check_model_name_policies(self, content: Any, result: ScanResult) -> None:
        """Check for blacklisted model names in config values"""
        visited_containers: set[int] = set()

        def check_value(value: Any, prefix: str = "") -> None:
            self._check_timeout()

            if isinstance(value, (dict, list)):
                container_id = id(value)
                if container_id in visited_containers:
                    return
                visited_containers.add(container_id)

            if isinstance(value, dict):
                for key, nested_value in value.items():
                    key_text = str(key)
                    key_lower = key_text.lower()
                    full_key = f"{prefix}.{key_text}" if prefix else key_text

                    # Check if this key might contain a model name
                    if key_lower in MODEL_NAME_KEYS_LOWER:
                        blocked, reason = check_model_name_policies(
                            str(nested_value),
                            self.blacklist_patterns,
                        )
                        if blocked:
                            result.add_check(
                                name="Model Name Policy Check",
                                passed=False,
                                message=f"Model name blocked by policy: {nested_value}",
                                severity=IssueSeverity.CRITICAL,
                                location=self.current_file_path,
                                details={
                                    "model_name": str(nested_value),
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
                                message=f"Model name '{nested_value}' passed policy check",
                                location=self.current_file_path,
                                details={
                                    "model_name": str(nested_value),
                                    "key": full_key,
                                },
                            )

                    check_value(nested_value, full_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{prefix}[{i}]")

        check_value(content)

    def _check_cloud_storage_urls(self, path: str, result: ScanResult) -> None:
        """Check for cloud storage URLs (external resource references).

        Detects references to AWS S3, Google Cloud Storage, Azure Blob Storage,
        and other external resources that could indicate:
        - External model dependencies
        - Potential data exfiltration vectors
        - Supply chain risks from external resources
        """
        try:
            content = self._read_manifest_text(path)

            self._check_timeout()
            seen_urls: set[str] = set()

            for pattern, description, provider in CLOUD_STORAGE_PATTERNS:
                self._check_timeout()
                for match in pattern.finditer(content):
                    self._check_timeout()
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

                    display_url = _redact_url_for_display(url)
                    result.add_check(
                        name="Cloud Storage URL Detection",
                        passed=False,  # Finding a cloud URL is informational, not a pass/fail
                        message=f"{description} detected: {display_url[:150]}",
                        severity=severity,
                        location=self.current_file_path,
                        details={
                            "url": display_url,
                            "provider": provider,
                            "description": description,
                        },
                        why=(
                            "External cloud storage references in model configs may indicate external "
                            "dependencies or potential supply chain risks. Verify that these URLs point "
                            "to trusted sources and are required for model operation."
                        ),
                    )

        except TimeoutError:
            raise
        except (OSError, UnicodeError) as e:
            self._record_read_failure(
                result,
                path,
                e,
                reason="manifest_cloud_storage_read_failed",
                check_name="Cloud Storage URL Detection",
                message="Unable to load manifest text for cloud storage URL analysis",
            )
        except Exception as e:
            logger.debug(f"Error checking cloud storage URLs in {path}: {e}")

    def _read_manifest_text(self, path: str) -> str:
        cached_content = getattr(self, "_manifest_text_cache", {}).get(path)
        if cached_content is not None:
            return cached_content

        with open(path, encoding="utf-8") as f:
            content = f.read()

        if hasattr(self, "_manifest_text_cache"):
            self._manifest_text_cache[path] = content
        return content

    def _check_suspicious_urls(self, content: Any, result: ScanResult) -> None:
        """Check for untrusted URLs in config values using allowlist approach.

        Only URLs from trusted domains (huggingface, github, pytorch, etc.) are allowed.
        Any URL from a domain NOT in the allowlist is flagged.

        This is more secure than a blocklist because attackers cannot bypass
        detection by registering new domains.
        """
        seen_urls: set[str] = set()
        visited_containers: set[int] = set()

        def is_trusted_domain(url: str) -> bool:
            """Check if URL host is in the trusted domain allowlist."""
            return _is_trusted_url_domain(url)

        def extract_urls_from_value(value: Any, key_path: str) -> None:
            """Recursively extract and check URLs from any value type."""
            self._check_timeout()
            if isinstance(value, (dict, list)):
                container_id = id(value)
                if container_id in visited_containers:
                    return
                visited_containers.add(container_id)

            if isinstance(value, str):
                urls = URL_PATTERN.findall(value)
                for url in urls:
                    self._check_timeout()
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    # Flag any URL not from a trusted domain
                    if not is_trusted_domain(url):
                        display_url = _redact_url_for_display(url)
                        result.add_check(
                            name="Untrusted URL Check",
                            passed=False,
                            message=f"URL from untrusted domain: {display_url}",
                            severity=IssueSeverity.INFO,
                            location=self.current_file_path,
                            details={
                                "url": display_url,
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
                    key_text = str(k)
                    new_path = f"{key_path}.{key_text}" if key_path else key_text
                    extract_urls_from_value(v, new_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    extract_urls_from_value(item, f"{key_path}[{i}]")

        extract_urls_from_value(content, "")

    def _check_weak_hashes(self, content: Any, result: ScanResult) -> None:
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

        def check_hash_value(key: str, value: Any, path: str) -> None:
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

        visited_containers: set[int] = set()

        def traverse_for_hashes(value: Any, prefix: str = "", parent_key: str = "") -> None:
            """Recursively check parsed manifest content for weak hashes."""
            self._check_timeout()
            if isinstance(value, (dict, list)):
                container_id = id(value)
                if container_id in visited_containers:
                    return
                visited_containers.add(container_id)

            if isinstance(value, dict):
                for key, nested_value in value.items():
                    key_text = str(key)
                    full_key = f"{prefix}.{key_text}" if prefix else key_text
                    traverse_for_hashes(nested_value, full_key, key_text)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{prefix}[{i}]"
                    traverse_for_hashes(item, item_path, parent_key)
            elif isinstance(value, str) and parent_key:
                check_hash_value(parent_key, value, prefix)

        traverse_for_hashes(content)
