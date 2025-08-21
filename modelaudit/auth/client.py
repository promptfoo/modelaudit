"""Authentication client for ModelAudit - mirrors promptfoo's implementation."""

import logging
import os
from typing import Any, Optional, cast

import requests

from .config import cloud_config, get_user_email

logger = logging.getLogger("modelaudit.auth")


def fetch_with_proxy(url: str, **kwargs) -> requests.Response:
    """Fetch with proxy support, mirroring promptfoo's fetchWithProxy."""
    # Set default timeout
    kwargs.setdefault("timeout", 30)

    # Add proxy configuration if environment variables are set
    proxies = {}
    if os.getenv("HTTP_PROXY"):
        proxies["http"] = os.getenv("HTTP_PROXY")
    if os.getenv("HTTPS_PROXY"):
        proxies["https"] = os.getenv("HTTPS_PROXY")

    if proxies:
        kwargs["proxies"] = proxies

    # Use requests for HTTP calls
    return requests.get(url, **kwargs)


class CloudUser:
    """Cloud user data structure."""

    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id")
        self.name = data.get("name")
        self.email = data.get("email")
        self.created_at = data.get("createdAt")
        self.updated_at = data.get("updatedAt")


class CloudOrganization:
    """Cloud organization data structure."""

    def __init__(self, data: dict[str, Any]):
        self.id = data.get("id")
        self.name = data.get("name")
        self.created_at = data.get("createdAt")
        self.updated_at = data.get("updatedAt")


class CloudApp:
    """Cloud app data structure."""

    def __init__(self, data: dict[str, Any]):
        self.url = data.get("url")


class AuthClient:
    """Handles authentication API calls - mirrors promptfoo's CloudConfig methods."""

    def validate_and_set_api_token(self, token: str, api_host: Optional[str] = None) -> dict[str, Any]:
        """
        Validate API token and set configuration - mirrors promptfoo's validateAndSetApiToken.

        Args:
            token: API token to validate
            api_host: Optional API host URL

        Returns:
            Dictionary with user, organization, and app information

        Raises:
            Exception: If token validation fails
        """
        host = api_host or cloud_config.get_api_host()

        try:
            response = fetch_with_proxy(
                f"{host}/api/v1/users/me",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "modelaudit-cli",
                },
            )

            if not response.ok:
                error_message = response.text
                logger.error(
                    f"[Cloud] Failed to validate API token: {error_message}. "
                    f"HTTP Status: {response.status_code} - {response.reason}."
                )
                raise Exception(f"Failed to validate API token: {response.reason}")

            data = cast(dict[str, Any], response.json())
            user = data.get("user", {})
            organization = data.get("organization", {})
            app = data.get("app", {})

            # Set configuration exactly like promptfoo
            cloud_config.set_api_key(token)
            cloud_config.set_api_host(host)
            cloud_config.set_app_url(app.get("url", "https://www.promptfoo.app"))

            return {"user": CloudUser(user), "organization": CloudOrganization(organization), "app": CloudApp(app)}

        except requests.RequestException as error:
            error_message = str(error)
            logger.error(f"[Cloud] Failed to validate API token with host {host}: {error_message}")
            if hasattr(error, "__cause__") and error.__cause__:
                logger.error(f"Cause: {error.__cause__}")
            raise

    def get_user_info(self) -> dict[str, Any]:
        """
        Get current user information.

        Returns:
            Dictionary with user information

        Raises:
            Exception: If not authenticated or API call fails
        """
        email = get_user_email()
        api_key = cloud_config.get_api_key()

        if not email or not api_key:
            raise Exception("Not logged in. Run 'modelaudit auth login' to login.")

        api_host = cloud_config.get_api_host()

        try:
            response = fetch_with_proxy(
                f"{api_host}/api/v1/users/me",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "User-Agent": "modelaudit-cli",
                },
            )

            if not response.ok:
                raise Exception(f"Failed to fetch user info: {response.reason}")

            return cast(dict[str, Any], response.json())

        except requests.RequestException as error:
            error_message = str(error)
            logger.error(f"Failed to get user info: {error_message}")
            raise Exception(f"Failed to get user info: {error_message}") from error


# Global auth client instance
auth_client = AuthClient()
