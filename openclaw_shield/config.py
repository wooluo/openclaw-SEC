"""
Configuration Module
Handles configuration management and validation
"""

import os
import json
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from loguru import logger


class Config:
    """
    Configuration manager for OpenClaw Security Shield.
    Handles loading, validation, and access to configuration settings.
    """

    DEFAULT_CONFIG = {
        'security': {
            'scan_on_install': True,
            'block_malicious': True,
            'quarantine_dir': './quarantine',
            'keys_file': './config/.keyring'
        },
        'api_key': {
            'encryption': True,
            'auto_rotate': True,
            'rotation_interval': 86400  # 24 hours
        },
        'network': {
            'monitor': True,
            'auto_block': True,
            'whitelist': [
                'api.openclaw.ai',
                '*.cdn.openclaw.ai'
            ],
            'blacklist_file': './config/blacklist.txt'
        },
        'logging': {
            'level': 'INFO',
            'file': './logs/security.log',
            'encrypt_logs': False,
            'retention_days': 90
        },
        'threat_detection': {
            'enabled': True,
            'sensitivity': 'high',
            'auto_block': True,
            'rules_file': './config/threat_rules.yaml'
        },
        'audit': {
            'database': './data/audit.db',
            'retention_days': 90
        },
        'skills': {
            'directory': '~/.openclaw/workspace/skills',
            'auto_scan': True,
            'require_approval': False
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_path: Path to configuration file (YAML or JSON)
        """
        self._config = self.DEFAULT_CONFIG.copy()
        self._config_path = config_path

        if config_path:
            self._load_config(config_path)
        else:
            # Try default locations
            self._try_load_default()

        # Expand environment variables
        self._expand_env_vars()

        logger.info("Configuration initialized")

    def _try_load_default(self):
        """Try to load configuration from default locations."""
        default_locations = [
            Path('./openclaw-shield.yaml'),
            Path('./openclaw-shield.yml'),
            Path('./openclaw-shield.json'),
            Path.home() / '.openclaw' / 'shield-config.yaml',
            Path.home() / '.openclaw' / 'shield-config.json',
        ]

        for location in default_locations:
            if location.exists():
                self._load_config(str(location))
                self._config_path = str(location)
                logger.info(f"Loaded config from: {location}")
                break

    def _load_config(self, config_path: str):
        """Load configuration from file."""
        path = Path(config_path)

        if not path.exists():
            logger.warning(f"Config file not found: {config_path}")
            return

        try:
            with open(path, 'r') as f:
                if path.suffix in ['.yaml', '.yml']:
                    loaded_config = yaml.safe_load(f)
                else:
                    loaded_config = json.load(f)

            # Deep merge with defaults
            self._deep_merge(self._config, loaded_config)

        except Exception as e:
            logger.error(f"Failed to load config: {e}")

    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _expand_env_vars(self):
        """Expand environment variables in configuration."""
        def expand(obj):
            if isinstance(obj, str):
                # Expand ${VAR} and $VAR patterns
                if '${' in obj or '$' in obj:
                    return os.path.expandvars(obj)
                return obj
            elif isinstance(obj, dict):
                return {k: expand(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [expand(item) for item in obj]
            return obj

        self._config = expand(self._config)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'security.scan_on_install')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set a configuration value using dot notation.

        Args:
            key: Configuration key
            value: Value to set
        """
        keys = key.split('.')
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def to_dict(self) -> Dict:
        """Get configuration as dictionary."""
        return self._config.copy()

    def save(self, path: Optional[str] = None):
        """
        Save configuration to file.

        Args:
            path: Path to save to (uses current path if not specified)
        """
        save_path = Path(path or self._config_path or './openclaw-shield.yaml')

        # Create parent directory if needed
        save_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(save_path, 'w') as f:
                if save_path.suffix in ['.yaml', '.yml']:
                    yaml.dump(self._config, f, default_flow_style=False)
                else:
                    json.dump(self._config, f, indent=2)

            logger.info(f"Configuration saved to: {save_path}")

        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def validate(self) -> bool:
        """Validate configuration settings."""
        errors = []

        # Check security settings
        if self.get('security.quarantine_dir'):
            qdir = Path(self.get('security.quarantine_dir'))
            if not qdir.is_absolute():
                logger.warning("Quarantine directory path is relative")

        # Check logging settings
        log_level = self.get('logging.level', 'INFO')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level not in valid_levels:
            errors.append(f"Invalid log level: {log_level}")

        # Check threat detection sensitivity
        sensitivity = self.get('threat_detection.sensitivity', 'medium')
        valid_sensitivities = ['low', 'medium', 'high']
        if sensitivity not in valid_sensitivities:
            errors.append(f"Invalid sensitivity: {sensitivity}")

        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False

        return True

    def reset(self):
        """Reset configuration to defaults."""
        self._config = self.DEFAULT_CONFIG.copy()
        logger.info("Configuration reset to defaults")

    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'Config':
        """Create configuration from dictionary."""
        config = cls()
        config._deep_merge(config._config, config_dict)
        return config
