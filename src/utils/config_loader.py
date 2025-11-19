"""
Configuration loader for Elastic SecOps Copilot.
Compatible with Python 3.13+
Supports YAML configuration and environment variable substitution.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
import re
from dotenv import load_dotenv


class ConfigError(Exception):
    """Configuration error."""
    pass


class ConfigLoader:
    """Load and manage configuration from YAML files."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize config loader.

        Args:
            config_path: Path to config.yaml file

        Raises:
            ConfigError: If config file not found or invalid
        """
        # Load environment variables from .env file
        load_dotenv()

        if config_path is None:
            config_path = os.getenv(
                "SECOPS_CONFIG_PATH",
                "config/config.yaml"
            )

        self.config_path = Path(config_path)

        if not self.config_path.exists():
            raise ConfigError(
                f"Configuration file not found: {self.config_path}"
            )

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load and parse YAML configuration."""
        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            if config is None:
                config = {}

            # Substitute environment variables
            config = self._substitute_env_vars(config)

            return config

        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to load config file: {e}")

    def _substitute_env_vars(self, obj: Any) -> Any:
        """
        Recursively substitute environment variables in config.
        Supports ${VAR_NAME} syntax.
        """
        if isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}

        if isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]

        if isinstance(obj, str):
            # Match ${VAR_NAME} or ${VAR_NAME:default_value}
            pattern = r'\$\{([^}]+)\}'

            def replace_var(match: re.Match[str]) -> str:
                var_spec = match.group(1)

                if ":" in var_spec:
                    var_name, default = var_spec.split(":", 1)
                    return os.getenv(var_name, default)
                else:
                    value = os.getenv(var_spec)
                    if value is None:
                        raise ConfigError(
                            f"Environment variable not set: {var_spec}"
                        )
                    return value

            return re.sub(pattern, replace_var, obj)

        return obj

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Examples:
            config.get("elastic.deployment_type")
            config.get("enrichment.virustotal.enabled")

        Args:
            key: Configuration key with dot notation
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self.config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value

    def get_required(self, key: str) -> Any:
        """
        Get required configuration value.

        Args:
            key: Configuration key

        Returns:
            Configuration value

        Raises:
            ConfigError: If key not found
        """
        value = self.get(key)
        if value is None:
            raise ConfigError(f"Required config key not found: {key}")
        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.

        Args:
            section: Section name

        Returns:
            Section dictionary
        """
        return self.get(section, {})

    def validate_elastic_config(self) -> bool:
        """
        Validate Elastic configuration.

        Returns:
            True if valid, raises ConfigError otherwise
        """
        deployment_type = self.get("elastic.deployment_type")

        if deployment_type not in ["serverless", "cloud", "self-hosted"]:
            raise ConfigError(
                f"Invalid deployment_type: {deployment_type}"
            )

        if deployment_type == "serverless":
            endpoint = self.get("elastic.serverless.api_endpoint")
            api_key = self.get("elastic.serverless.api_key")

            if not endpoint or not api_key:
                raise ConfigError(
                    "Serverless deployment requires api_endpoint and api_key"
                )

        elif deployment_type == "cloud":
            cloud_id = self.get("elastic.cloud.cloud_id")
            username = self.get("elastic.cloud.username")
            password = self.get("elastic.cloud.password")

            if not all([cloud_id, username, password]):
                raise ConfigError(
                    "Cloud deployment requires cloud_id, username, and password"
                )

        elif deployment_type == "self-hosted":
            hosts = self.get("elastic.self_hosted.hosts")
            username = self.get("elastic.self_hosted.username")
            password = self.get("elastic.self_hosted.password")

            if not all([hosts, username, password]):
                raise ConfigError(
                    "Self-hosted deployment requires hosts, username, and password"
                )

        return True

    def validate_enrichment_config(self) -> bool:
        """
        Validate enrichment configuration.

        Returns:
            True if valid, raises ConfigError otherwise
        """
        enrichment = self.get("enrichment", {})

        # Check that at least one enrichment source is enabled
        sources = ["virustotal", "abuseipdb", "shodan", "maxmind", "whois"]
        enabled_sources = [
            s for s in sources
            if enrichment.get(s, {}).get("enabled", False)
        ]

        if not enabled_sources:
            raise ConfigError("At least one enrichment source must be enabled")

        return True

    def get_elastic_client_config(self) -> Dict[str, Any]:
        """
        Get configuration for Elasticsearch client.

        Returns:
            Configuration dictionary for elasticsearch.Elasticsearch()
        """
        deployment_type = self.get("elastic.deployment_type")

        if deployment_type == "serverless":
            return {
                "api_key": self.get("elastic.serverless.api_key"),
                "hosts": [self.get("elastic.serverless.api_endpoint")],
            }

        elif deployment_type == "cloud":
            return {
                "cloud_id": self.get("elastic.cloud.cloud_id"),
                "basic_auth": (
                    self.get("elastic.cloud.username"),
                    self.get("elastic.cloud.password"),
                ),
            }

        elif deployment_type == "self-hosted":
            hosts = self.get("elastic.self_hosted.hosts")
            return {
                "hosts": hosts,
                "basic_auth": (
                    self.get("elastic.self_hosted.username"),
                    self.get("elastic.self_hosted.password"),
                ),
                "verify_certs": self.get("elastic.self_hosted.verify_certs", True),
                "ca_certs": self.get("elastic.self_hosted.ca_certs"),
            }

        raise ConfigError(f"Unknown deployment type: {deployment_type}")

    def reload(self) -> None:
        """Reload configuration from file."""
        self.config = self._load_config()

    def to_dict(self) -> Dict[str, Any]:
        """Get entire configuration as dictionary."""
        return self.config.copy()


def load_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Convenience function to load configuration.

    Args:
        config_path: Optional path to config file

    Returns:
        ConfigLoader instance
    """
    return ConfigLoader(config_path)


# Singleton pattern for global config
_global_config: Optional[ConfigLoader] = None


def get_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Get global configuration instance.

    Args:
        config_path: Optional path to config file (used on first call)

    Returns:
        ConfigLoader instance
    """
    global _global_config

    if _global_config is None:
        _global_config = ConfigLoader(config_path)

    return _global_config