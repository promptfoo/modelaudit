"""Configuration management for ModelAudit authentication."""

import json
import os
from pathlib import Path
from typing import Optional

from platformdirs import user_config_dir


class ModelAuditConfig:
    """Manages authentication configuration for ModelAudit."""
    
    def __init__(self):
        """Initialize configuration manager."""
        self.config_dir = Path(user_config_dir("modelaudit", "promptfoo"))
        self.config_file = self.config_dir / "config.json"
        self._config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from file."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=2)
    
    def get_api_key(self) -> Optional[str]:
        """Get API key from environment or config file."""
        # Check environment variable first (from promptfoo wrapper)
        env_key = os.getenv('MODELAUDIT_API_KEY')
        if env_key:
            return env_key
        
        # Fall back to stored config
        return self._config.get('api_key')
    
    def set_api_key(self, api_key: str) -> None:
        """Set API key in config."""
        self._config['api_key'] = api_key
        self._save_config()
    
    def get_api_host(self) -> str:
        """Get API host from environment or config file."""
        # Check environment variable first (from promptfoo wrapper)
        env_host = os.getenv('MODELAUDIT_API_HOST')
        if env_host:
            return env_host
        
        # Fall back to stored config or default
        return self._config.get('api_host', 'https://api.promptfoo.app')
    
    def set_api_host(self, api_host: str) -> None:
        """Set API host in config."""
        self._config['api_host'] = api_host
        self._save_config()
    
    def get_user_email(self) -> Optional[str]:
        """Get user email from environment or config file."""
        # Check environment variable first (from promptfoo wrapper)
        env_email = os.getenv('MODELAUDIT_USER_EMAIL')
        if env_email:
            return env_email
        
        # Fall back to stored config
        return self._config.get('user_email')
    
    def set_user_email(self, email: str) -> None:
        """Set user email in config."""
        self._config['user_email'] = email
        self._save_config()
    
    def get_app_url(self) -> str:
        """Get app URL from config."""
        return self._config.get('app_url', 'https://www.promptfoo.app')
    
    def set_app_url(self, app_url: str) -> None:
        """Set app URL in config."""
        self._config['app_url'] = app_url
        self._save_config()
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return bool(self.get_api_key())
    
    def delete_config(self) -> None:
        """Delete all configuration."""
        if self.config_file.exists():
            self.config_file.unlink()
        self._config = {}


# Global config instance
config = ModelAuditConfig()
