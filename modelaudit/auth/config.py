"""Configuration management for ModelAudit authentication."""

import os
import re
from contextlib import suppress
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from uuid import uuid4

import idna
import yaml
from platformdirs import user_config_dir

from ..utils._path_hardening import (
    _ensure_secure_directory,
    _has_symlink_component,
    _is_secure_directory,
    _tighten_permissions,
)

# Environment variable for API host (matches promptfoo)
API_HOST = os.getenv("API_HOST", "https://api.promptfoo.app")
API_HOST_ALLOWED_HOSTS_ENV = "MODELAUDIT_API_ALLOWED_HOSTS"
_API_HOST_ENV_VARS = ("MODELAUDIT_API_HOST", "API_HOST")
_PROMPTFOO_API_HOST_SUFFIX = "promptfoo.app"
_DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DEEP_MERGE_CONFIG_SECTIONS = frozenset({"account", "cloud"})


def _normalize_api_hostname(hostname: str) -> str:
    """Normalize hostnames before trust comparisons."""
    normalized = hostname.lower().rstrip(".")
    if ":" in normalized:
        try:
            address = ip_address(normalized)
        except ValueError as error:
            raise ValueError("Invalid API hostname") from error
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            return f"::ffff:{address.ipv4_mapped}"
        return address.compressed

    try:
        ascii_hostname = idna.encode(normalized, uts46=True).decode("ascii")
    except idna.IDNAError as error:
        raise ValueError("Invalid API hostname") from error

    labels = ascii_hostname.split(".")
    if len(ascii_hostname) > 253 or any(not _DNS_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise ValueError("Invalid API hostname")
    return ascii_hostname


def _authority_from_config_value(value: str, *, allow_host_only: bool) -> tuple[str, int | None] | None:
    """Normalize a configured hostname or base URL to an authority."""
    candidate = value.strip()
    if (
        not candidate
        or "\\" in candidate
        or "%" in candidate
        or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        return None

    try:
        has_scheme = "://" in candidate
        parsed = urlparse(candidate if has_scheme else f"//{candidate}")
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.hostname is None
        or (parsed.scheme and parsed.scheme.lower() != "https")
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or port == 0
        or parsed.netloc.endswith(":")
    ):
        return None
    try:
        hostname = _normalize_api_hostname(parsed.hostname)
    except ValueError:
        return None
    if allow_host_only and not has_scheme and port is None:
        return hostname, None
    return hostname, port or 443


def _get_explicitly_trusted_api_authorities() -> set[tuple[str, int | None]]:
    """Return caller-configured authorities allowed to receive API bearer tokens."""
    raw_hosts = os.getenv(API_HOST_ALLOWED_HOSTS_ENV, "")
    authorities = {
        authority
        for authority in (_authority_from_config_value(value, allow_host_only=True) for value in raw_hosts.split(","))
        if authority is not None
    }
    authorities.update(
        authority
        for authority in (
            _authority_from_config_value(os.getenv(name, ""), allow_host_only=False) for name in _API_HOST_ENV_VARS
        )
        if authority is not None
    )
    return authorities


def _is_promptfoo_api_host(hostname: str) -> bool:
    return hostname == _PROMPTFOO_API_HOST_SUFFIX or hostname.endswith(f".{_PROMPTFOO_API_HOST_SUFFIX}")


def _is_trusted_api_host(hostname: str, port: int) -> bool:
    configured_authorities = _get_explicitly_trusted_api_authorities()
    return (
        (_is_promptfoo_api_host(hostname) and port == 443)
        or (hostname, port) in configured_authorities
        or (hostname, None) in configured_authorities
    )


def validate_api_host_for_bearer_auth(api_host: str) -> str:
    """Return a normalized caller-selected or persisted HTTPS API host."""
    stripped_host = api_host.strip()
    if (
        not stripped_host
        or "\\" in stripped_host
        or "%" in stripped_host
        or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in stripped_host)
    ):
        raise ValueError("API host for bearer-token authentication must be a valid HTTPS URL")

    try:
        parsed = urlparse(stripped_host)
        hostname = _normalize_api_hostname(parsed.hostname) if parsed.hostname else None
        port = parsed.port
    except ValueError as error:
        raise ValueError("API host for bearer-token authentication must be a valid HTTPS URL") from error

    if parsed.scheme.lower() != "https":
        raise ValueError("API host for bearer-token authentication must use HTTPS")

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("API host for bearer-token authentication must not include credentials")

    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("API host for bearer-token authentication must be a base API URL")

    if hostname is None:
        raise ValueError("API host for bearer-token authentication must include a hostname")
    if parsed.netloc.endswith(":"):
        raise ValueError("API host for bearer-token authentication must include a valid port")
    if port == 0:
        raise ValueError("API host for bearer-token authentication must include a valid port")
    normalized_port_number = port or 443
    if not _is_trusted_api_host(hostname, normalized_port_number):
        raise ValueError(
            "API host for bearer-token authentication must be a trusted Promptfoo API host "
            f"or explicitly configured through {API_HOST_ALLOWED_HOSTS_ENV}, MODELAUDIT_API_HOST, or API_HOST"
        )

    normalized_hostname = f"[{hostname}]" if ":" in hostname else hostname
    normalized_port = f":{port}" if port not in (None, 443) else ""
    return f"https://{normalized_hostname}{normalized_port}"


class GlobalConfig:
    """Global configuration structure matching promptfoo."""

    def __init__(self, data: dict[str, Any] | None = None):
        """Initialize global config."""
        if data is None:
            data = {}

        self.id = data.get("id", str(uuid4()))
        self.has_harmful_redteam_consent = data.get("hasHarmfulRedteamConsent", False)
        self.account = data.get("account", {})
        self.cloud = data.get("cloud", {})

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "hasHarmfulRedteamConsent": self.has_harmful_redteam_consent,
            "account": self.account,
            "cloud": self.cloud,
        }


class CloudConfig:
    """Cloud configuration class matching promptfoo's CloudConfig."""

    def __init__(self):
        """Initialize cloud config."""
        saved_config = read_global_config().cloud
        self.config = {
            "appUrl": saved_config.get("appUrl", "https://www.promptfoo.app"),
            "apiHost": saved_config.get("apiHost", API_HOST),
            "apiKey": saved_config.get("apiKey"),
        }

    def is_enabled(self) -> bool:
        """Check if cloud config is enabled."""
        return bool(self.config.get("apiKey"))

    def set_api_host(self, api_host: str) -> None:
        """Set API host."""
        self._persist_config_update(
            {"apiHost": validate_api_host_for_bearer_auth(api_host)},
            "Unable to persist cloud API host",
        )

    def set_api_key(self, api_key: str) -> None:
        """Set API key."""
        self.config["apiKey"] = api_key
        self._save_config()

    def set_credentials(self, api_host: str, api_key: str, app_url: str) -> None:
        """Persist bearer-token configuration as one atomic cloud update."""
        self._persist_config_update(
            {
                "apiHost": validate_api_host_for_bearer_auth(api_host),
                "apiKey": api_key,
                "appUrl": app_url,
            },
            "Unable to persist cloud authentication credentials",
        )

    def _persist_config_update(self, updates: dict[str, Any], failure_message: str) -> None:
        """Save a cloud config update without exposing uncommitted in-memory state."""
        previous_config = dict(self.config)
        expected_config = {**previous_config, **updates}
        self.config = expected_config
        try:
            self._save_config()
        except Exception:
            self.config = previous_config
            raise

        if any(self.config.get(key) != expected_value for key, expected_value in updates.items()):
            self.config = previous_config
            raise OSError(failure_message)

    def get_api_key(self) -> str | None:
        """Get API key."""
        return cast(str | None, self.config.get("apiKey"))

    def get_api_host(self) -> str:
        """Get API host."""
        return cast(str, self.config.get("apiHost", API_HOST))

    def set_app_url(self, app_url: str) -> None:
        """Set app URL."""
        self.config["appUrl"] = app_url
        self._save_config()

    def get_app_url(self) -> str:
        """Get app URL."""
        return cast(str, self.config.get("appUrl", "https://www.promptfoo.app"))

    def delete(self) -> None:
        """Delete cloud configuration."""
        write_global_config_partial({"cloud": None})

    def _save_config(self) -> None:
        """Save cloud configuration."""
        write_global_config_partial({"cloud": self.config})
        self._reload()

    def _reload(self) -> None:
        """Reload configuration from file."""
        saved_config = read_global_config().cloud
        self.config = {
            "appUrl": saved_config.get("appUrl", "https://www.promptfoo.app"),
            "apiHost": saved_config.get("apiHost", API_HOST),
            "apiKey": saved_config.get("apiKey"),
        }


def _home_fallback_config_dir() -> Path:
    """Return a user-private fallback config directory."""
    return Path.home() / ".promptfoo"


def _config_dir_candidates() -> list[Path]:
    """Return config directory candidates in preference order."""
    candidates = [Path(user_config_dir("promptfoo")), _home_fallback_config_dir()]
    unique_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        unique_candidates.append(candidate)
        seen.add(key)
    return unique_candidates


def _select_config_directory(create_if_not_exists: bool = False) -> Path:
    """Pick the best available configuration directory."""
    candidates = _config_dir_candidates()
    for candidate in candidates:
        if create_if_not_exists:
            if _ensure_secure_directory(candidate):
                return candidate
            continue

        if _is_secure_directory(candidate):
            return candidate

    for candidate in candidates:
        try:
            if not _has_symlink_component(candidate):
                return candidate
        except OSError:
            continue

    return _home_fallback_config_dir()


def _get_config_file_path(create_if_not_exists: bool = False) -> Path:
    """Return the shared Promptfoo config file path."""
    if not create_if_not_exists:
        for config_dir in _config_dir_candidates():
            if not _is_secure_directory(config_dir):
                continue
            config_file = config_dir / "promptfoo.yaml"
            try:
                if config_file.exists() and config_file.is_file() and not config_file.is_symlink():
                    return config_file
            except OSError:
                continue

    config_dir = _select_config_directory(create_if_not_exists=create_if_not_exists)
    return config_dir / "promptfoo.yaml"


def _write_yaml_atomic(config_file_path: Path, data: dict[str, Any]) -> None:
    """Write config atomically with private permissions."""
    config_dir = config_file_path.parent
    if not _ensure_secure_directory(config_dir):
        raise OSError(f"Unable to create secure config directory: {config_dir}")

    payload = yaml.safe_dump(data, sort_keys=False)
    temp_path = config_dir / f".promptfoo.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(temp_path, flags, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
        _tighten_permissions(temp_path, 0o600)
        os.replace(temp_path, config_file_path)
        _tighten_permissions(config_file_path, 0o600)
    except Exception:
        with suppress(OSError):
            temp_path.unlink()
        raise


def get_config_directory_path(create_if_not_exists: bool = False) -> str:
    """Get configuration directory path."""
    config_dir = _select_config_directory(create_if_not_exists=create_if_not_exists)
    return str(config_dir)


def read_global_config() -> GlobalConfig:
    """Read global configuration from file."""
    global_config_data = {"id": str(uuid4())}
    config_file_path = _get_config_file_path()

    try:
        parent_path_is_safe = not _has_symlink_component(config_file_path.parent)
    except OSError:
        parent_path_is_safe = False

    if parent_path_is_safe and config_file_path.exists():
        with suppress(OSError, yaml.YAMLError):
            if config_file_path.is_symlink():
                raise OSError("Refusing to read symlinked config file")

            with open(config_file_path) as f:
                loaded_config = yaml.safe_load(f) or {}
                global_config_data = loaded_config

        if not global_config_data.get("id"):
            global_config_data["id"] = str(uuid4())
            write_global_config(GlobalConfig(global_config_data))
    else:
        with suppress(OSError, PermissionError):
            write_global_config(GlobalConfig(global_config_data))

    return GlobalConfig(global_config_data)


def write_global_config(config: GlobalConfig) -> None:
    """Write global configuration to file."""
    try:
        config_file_path = _get_config_file_path(create_if_not_exists=True)
        _write_yaml_atomic(config_file_path, config.to_dict())
    except (OSError, PermissionError):
        # In restricted environments, skip file writing
        pass


def _deep_merge_config_dicts(current: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge nested config dictionaries without dropping siblings."""
    merged = dict(current)
    for key, value in updates.items():
        existing_value = merged.get(key)
        if isinstance(existing_value, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_config_dicts(existing_value, value)
        else:
            merged[key] = value
    return merged


def write_global_config_partial(partial_config: dict[str, Any]) -> None:
    """Merge partial configuration into existing config."""
    current_config = read_global_config()
    current_data = current_config.to_dict()

    # Merge the partial config
    for key, value in partial_config.items():
        if value is None:
            # Remove the property if value is None
            current_data.pop(key, None)
            continue

        existing_value = current_data.get(key)
        if key in _DEEP_MERGE_CONFIG_SECTIONS and isinstance(existing_value, dict) and isinstance(value, dict):
            current_data[key] = _deep_merge_config_dicts(existing_value, value)
        else:
            current_data[key] = value

    write_global_config(GlobalConfig(current_data))


def get_user_id() -> str:
    """Get user ID, creating one if it doesn't exist."""
    global_config = read_global_config()
    if not global_config.id:
        new_id = str(uuid4())
        updated_config = GlobalConfig(global_config.to_dict())
        updated_config.id = new_id
        write_global_config(updated_config)
        return new_id

    return cast(str, global_config.id)


def get_user_email() -> str | None:
    """Get user email from global config."""
    global_config = read_global_config()
    return cast(str | None, global_config.account.get("email"))


def set_user_email(email: str) -> None:
    """Set user email in global config."""
    config = {"account": {"email": email}}
    write_global_config_partial(config)


# Legacy compatibility class for existing ModelAudit code
class ModelAuditConfig:
    """Legacy configuration class for backward compatibility."""

    def __init__(self):
        """Initialize configuration."""
        self.cloud_config = CloudConfig()

    def get_api_key(self) -> str | None:
        """Get API key with delegation-aware precedence."""
        # 1. Environment (ModelAudit-specific)
        env_key = os.environ.get("MODELAUDIT_API_KEY")
        if env_key:
            return env_key

        # 2. Check if delegated from promptfoo
        if os.environ.get("PROMPTFOO_DELEGATED"):
            # Use shared promptfoo config
            return self.cloud_config.get_api_key()

        # 3. Fall back to regular config
        return self.cloud_config.get_api_key()

    def set_api_key(self, api_key: str) -> None:
        """Set API key in config."""
        self.cloud_config.set_api_key(api_key)

    def get_api_host(self) -> str:
        """Get API host with delegation-aware precedence."""
        # 1. Environment (ModelAudit-specific or standard)
        env_host = os.environ.get("MODELAUDIT_API_HOST") or os.environ.get("API_HOST")
        if env_host:
            return env_host

        # 2. Use shared promptfoo config (works for both delegated and normal cases)
        return self.cloud_config.get_api_host()

    def set_api_host(self, api_host: str) -> None:
        """Set API host in config."""
        self.cloud_config.set_api_host(api_host)

    def get_user_email(self) -> str | None:
        """Get user email with delegation-aware precedence."""
        # 1. Environment (ModelAudit-specific)
        env_email = os.environ.get("MODELAUDIT_USER_EMAIL")
        if env_email:
            return env_email

        # 2. Use shared promptfoo config (works for both delegated and normal cases)
        return get_user_email()

    def set_user_email(self, user_email: str) -> None:
        """Set user email in config."""
        set_user_email(user_email)

    def get_app_url(self) -> str:
        """Get app URL from environment or config."""
        # Check environment first (maintaining compatibility)
        env_url = os.environ.get("MODELAUDIT_APP_URL")
        if env_url:
            return env_url

        return self.cloud_config.get_app_url()

    def set_app_url(self, app_url: str) -> None:
        """Set app URL in config."""
        self.cloud_config.set_app_url(app_url)

    def clear_credentials(self) -> None:
        """Clear all stored credentials."""
        self.cloud_config.delete()
        set_user_email("")

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.get_api_key() is not None

    def is_delegated(self) -> bool:
        """Check if running in delegation mode from promptfoo."""
        return bool(os.environ.get("PROMPTFOO_DELEGATED"))

    def get_auth_source(self) -> str:
        """Get the source of authentication (modelaudit or promptfoo)."""
        if self.is_delegated():
            return "promptfoo"
        env_key = os.environ.get("MODELAUDIT_API_KEY")
        if env_key:
            return "modelaudit-env"
        return "modelaudit-config"


def is_delegated_from_promptfoo() -> bool:
    """Check if ModelAudit is being run in delegation mode from promptfoo."""
    return bool(os.environ.get("PROMPTFOO_DELEGATED"))


# Global instances
cloud_config = CloudConfig()
config = ModelAuditConfig()
