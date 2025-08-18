"""Configuration management for ModelAudit authentication."""

import json
import os
from typing import Any, Optional

from platformdirs import user_config_dir


class ModelAuditConfig:
    """Manages ModelAudit configuration and credentials."""

    def __init__(self):
        """Initialize configuration."""
        self.config_dir = user_config_dir("modelaudit")
        self.config_file = os.path.join(self.config_dir, "config.json")
        self._config_data: Optional[dict[str, Any]] = None

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from file."""
        if self._config_data is not None:
            return self._config_data

        if not os.path.exists(self.config_file):
            self._config_data = {}
            return self._config_data

        try:
            with open(self.config_file) as f:
                self._config_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            self._config_data = {}

        return self._config_data

    def _save_config(self) -> None:
        """Save configuration to file."""
        if self._config_data is None:
            return

        os.makedirs(self.config_dir, exist_ok=True)

        # Create file with secure permissions (owner read/write only)
        with open(self.config_file, "w") as f:
            json.dump(self._config_data, f, indent=2)

        # Set secure permissions (0o600 = owner read/write only)
        os.chmod(self.config_file, 0o600)

    def get_api_key(self) -> Optional[str]:
        """Get API key from environment or config."""
        # Check environment first (for promptfoo integration)
        env_key = os.environ.get("MODELAUDIT_API_KEY")
        if env_key:
            return env_key

        # Fall back to config file
        config = self._load_config()
        return config.get("api_key")

    def set_api_key(self, api_key: str) -> None:
        """Set API key in config."""
        config = self._load_config()
        config["api_key"] = api_key
        self._save_config()

    def get_api_host(self) -> str:
        """Get API host from environment or config."""
        # Check environment first (for promptfoo integration)
        env_host = os.environ.get("MODELAUDIT_API_HOST")
        if env_host:
            return env_host

        # Fall back to config file
        config = self._load_config()
        return str(config.get("api_host", "https://api.promptfoo.app"))

    def set_api_host(self, api_host: str) -> None:
        """Set API host in config."""
        config = self._load_config()
        config["api_host"] = api_host
        self._save_config()

    def get_user_email(self) -> Optional[str]:
        """Get user email from environment or config."""
        # Check environment first (for promptfoo integration)
        env_email = os.environ.get("MODELAUDIT_USER_EMAIL")
        if env_email:
            return env_email

        # Fall back to config file
        config = self._load_config()
        return config.get("user_email")

    def set_user_email(self, user_email: str) -> None:
        """Set user email in config."""
        config = self._load_config()
        config["user_email"] = user_email
        self._save_config()

    def get_app_url(self) -> Optional[str]:
        """Get app URL from environment or config."""
        # Check environment first (for promptfoo integration)
        env_url = os.environ.get("MODELAUDIT_APP_URL")
        if env_url:
            return env_url

        # Fall back to config file
        config = self._load_config()
        return config.get("app_url")

    def set_app_url(self, app_url: str) -> None:
        """Set app URL in config."""
        config = self._load_config()
        config["app_url"] = app_url
        self._save_config()

    def clear_credentials(self) -> None:
        """Clear all stored credentials."""
        self._config_data = {}
        if os.path.exists(self.config_file):
            os.remove(self.config_file)

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.get_api_key() is not None


# Global config instance
config = ModelAuditConfig()
