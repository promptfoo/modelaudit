"""Configuration management for ModelAudit authentication."""

import os
from typing import Any, Optional, cast
from uuid import uuid4

import yaml
from platformdirs import user_config_dir

# Environment variable for API host (matches promptfoo)
API_HOST = os.getenv("API_HOST", "https://api.promptfoo.app")


class GlobalConfig:
    """Global configuration structure matching promptfoo."""

    def __init__(self, data: Optional[dict[str, Any]] = None):
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
        self.config["apiHost"] = api_host
        self._save_config()

    def set_api_key(self, api_key: str) -> None:
        """Set API key."""
        self.config["apiKey"] = api_key
        self._save_config()

    def get_api_key(self) -> Optional[str]:
        """Get API key."""
        return cast(Optional[str], self.config.get("apiKey"))

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
        write_global_config_partial({"cloud": {}})

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


def get_config_directory_path(create_if_not_exists: bool = False) -> str:
    """Get configuration directory path."""
    config_dir = user_config_dir("promptfoo")
    if create_if_not_exists:
        try:
            os.makedirs(config_dir, exist_ok=True)
        except (OSError, PermissionError):
            # In Docker or restricted environments, use a temporary directory
            config_dir = "/tmp/promptfoo"
            os.makedirs(config_dir, exist_ok=True)
    return config_dir


def read_global_config() -> GlobalConfig:
    """Read global configuration from file."""
    config_dir = get_config_directory_path()
    config_file_path = os.path.join(config_dir, "promptfoo.yaml")

    global_config_data = {"id": str(uuid4())}

    if os.path.exists(config_file_path):
        try:
            with open(config_file_path) as f:
                loaded_config = yaml.safe_load(f) or {}
                global_config_data = loaded_config
        except (OSError, yaml.YAMLError):
            pass

        if not global_config_data.get("id"):
            global_config_data["id"] = str(uuid4())
            write_global_config(GlobalConfig(global_config_data))
    else:
        try:
            os.makedirs(config_dir, exist_ok=True)
            with open(config_file_path, "w") as f:
                yaml.dump(global_config_data, f)
        except (OSError, PermissionError):
            # In Docker/restricted environments, skip file creation
            pass

    return GlobalConfig(global_config_data)


def write_global_config(config: GlobalConfig) -> None:
    """Write global configuration to file."""
    try:
        config_dir = get_config_directory_path(create_if_not_exists=True)
        config_file_path = os.path.join(config_dir, "promptfoo.yaml")

        with open(config_file_path, "w") as f:
            yaml.dump(config.to_dict(), f)
    except (OSError, PermissionError):
        # In Docker/restricted environments, skip file writing
        pass


def write_global_config_partial(partial_config: dict[str, Any]) -> None:
    """Merge partial configuration into existing config."""
    current_config = read_global_config()
    current_data = current_config.to_dict()

    # Merge the partial config
    for key, value in partial_config.items():
        if value is not None:
            current_data[key] = value
        else:
            # Remove the property if value is None
            current_data.pop(key, None)

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


def get_user_email() -> Optional[str]:
    """Get user email from global config."""
    global_config = read_global_config()
    return cast(Optional[str], global_config.account.get("email"))


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

    def get_api_key(self) -> Optional[str]:
        """Get API key with delegation-aware precedence."""
        # 1. Environment (ModelAudit-specific)
        env_key = os.environ.get("MODELAUDIT_API_KEY")
        if env_key:
            return env_key

        # 2. Check if delegated from promptfoo
        if os.environ.get("PROMPTFOO_DELEGATED"):
            # Use shared promptfoo config
            return cast(Optional[str], self.cloud_config.get_api_key())

        # 3. Fall back to regular config
        return cast(Optional[str], self.cloud_config.get_api_key())

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
        return cast(str, self.cloud_config.get_api_host())

    def set_api_host(self, api_host: str) -> None:
        """Set API host in config."""
        self.cloud_config.set_api_host(api_host)

    def get_user_email(self) -> Optional[str]:
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

        return cast(str, self.cloud_config.get_app_url())

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
