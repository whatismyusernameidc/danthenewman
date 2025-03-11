#!/usr/bin/env python3

"""
Utility module for Manus AI Log Monitor.
Contains shared functions, classes, and constants.
"""

# Standard library imports
import os
import re
import yaml
import time
import logging
import json
from pathlib import Path
from threading import Lock
from typing import Dict, List, Any, Optional, Tuple, Callable

# Third-party imports (handled by check_optional_dependency)
try:
    from prometheus_client import start_http_server, Counter, Gauge
except ImportError:
    pass  # Handled below

# Configure logging for the monitor
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app/logs/system/monitor.log')  # Fixed path
    ]
)
logger = logging.getLogger('manus_monitor')

# Standardize optional dependency handling
def check_optional_dependency(module_name: str, install_command: str) -> bool:
    """
    Check if an optional dependency is available.

    Args:
        module_name: Name of the module to check
        install_command: Command to install the module if missing

    Returns:
        bool: True if module is available, False otherwise
    """
    try:
        __import__(module_name)
        return True
    except ImportError:
        logger.warning(f"{module_name} not found. Install with: {install_command}")
        return False

PROMETHEUS_AVAILABLE = check_optional_dependency("prometheus_client", "pip install prometheus_client")
VAULT_AVAILABLE = check_optional_dependency("hvac", "pip install hvac")

# Define Prometheus metrics if available
if PROMETHEUS_AVAILABLE:
    from prometheus_client import start_http_server, Counter, Gauge
    EMAILS_SENT = Counter("manus_monitor_emails_sent", "Total number of alert emails sent")
    ALERTS_TRIGGERED = Counter("manus_monitor_alerts_triggered", "Total number of alerts triggered")
    CURRENT_LOG_POSITION = Gauge("manus_monitor_log_position", "Current read position in log file")
    PENDING_ALERTS = Gauge("manus_monitor_pending_alerts", "Number of alerts in queue")
    ALERTS_BY_SEVERITY = Counter("manus_monitor_alerts_by_severity", "Number of alerts by severity", ["severity"])
    PATTERN_MATCHES = Counter("manus_monitor_pattern_matches", "Number of matches by pattern", ["pattern"])
    HEARTBEAT = Gauge("manus_monitor_heartbeat", "Monitor heartbeat timestamp")
    ALERT_LATENCY = Gauge("manus_monitor_alert_latency", "Time from alert generation to sending (seconds)")
    CONFIG_RELOADS = Counter("manus_monitor_config_reloads", "Number of configuration reloads")
    HEALTH_CHECK_FAILURES = Counter("manus_monitor_health_check_failures", "Number of health check failures")
else:
    class DummyMetric:
        def __init__(self, *args, **kwargs):
            pass
        def inc(self, *args, **kwargs):
            pass
        def set(self, *args, **kwargs):
            pass
        def labels(self, *args, **kwargs):
            return self
    EMAILS_SENT = DummyMetric()
    ALERTS_TRIGGERED = DummyMetric()
    CURRENT_LOG_POSITION = DummyMetric()
    PENDING_ALERTS = DummyMetric()
    ALERTS_BY_SEVERITY = DummyMetric()
    PATTERN_MATCHES = DummyMetric()
    HEARTBEAT = DummyMetric()
    ALERT_LATENCY = DummyMetric()
    CONFIG_RELOADS = DummyMetric()
    HEALTH_CHECK_FAILURES = DummyMetric()

### Custom Exceptions
class ManusConfigError(Exception):
    """Raised for configuration errors."""
    pass

class ManusSecurityError(Exception):
    """Raised for security violations."""
    pass

class ManusVaultError(Exception):
    """Raised for Vault-related errors."""
    pass

class ManusAlertError(Exception):
    """Raised for alert-related errors."""
    pass

### Vault Service
class VaultService:
    """Manages interactions with HashiCorp Vault."""
    def __init__(self, config):
        """
        Initialize VaultService with configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.client = None
        if VAULT_AVAILABLE and config.get('vault', {}).get('enabled', False):
            import hvac
            self.client = hvac.Client(url=config['vault']['address'], token=os.getenv('VAULT_TOKEN'))

    def get_secret(self, path):
        """
        Fetch a secret from Vault.

        Args:
            path: Path to secret in Vault

        Returns:
            dict: Secret data, or None if unavailable

        Raises:
            ManusVaultError: If fetching the secret fails
        """
        if not self.client:
            logger.warning("Vault support unavailable or not initialized.")
            return None
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=path)
            logger.debug(f"Successfully fetched secret from Vault for path: {path}")
            return response['data']['data'] if response else None
        except Exception as e:
            logger.error(f"Vault error: {str(e)}")
            raise ManusVaultError(f"Failed to fetch secret from {path}") from e

### Utility Functions
def initialize_metrics(port: int):
    """
    Initialize the Prometheus metrics server.

    Args:
        port: Port number to start the metrics server on
    """
    if PROMETHEUS_AVAILABLE:
        start_http_server(port)
        logger.info(f"Metrics server started on port {port}")

def ensure_config_exists(config_path: str) -> bool:
    """
    Generate a default config.yaml if missing.

    Args:
        config_path: Path to configuration file

    Returns:
        bool: True if config exists or was created

    Raises:
        ManusConfigError: If creation fails
    """
    config_file = Path(config_path)
    if not config_file.exists():
        logger.warning(f"Config file {config_path} not found. Creating default configuration.")
        default_config = {
            "vault": {
                "enabled": True,
                "address": "http://127.0.0.1:8200",
                "secrets": {
                    "openai": "secretv2/data/openai",
                    "smtp": "secretv2/data/smtp",
                    "notifications": "secretv2/data/notifications",
                    "security": "secretv2/data/security"
                }
            },
            "logging": {
                "level": "info",
                "log_file": "app/logs/system/manus.log",  # Fixed path
                "audit_log": "app/logs/audit/audit.log",  # Fixed path
                "patterns_file": "app/config/patterns.json",  # Fixed path
                "max_log_size": 10,
                "backup_count": 5
            },
            "security": {
                "vault_failure_mode": "warn",
                "vault_path": "secretv2/data/security",
                "password": None,
                "blocked_patterns": ["rm -rf", "shutdown", "format", "delete", "sudo", "chmod"],
                "allowed_pattern": r"^[a-zA-Z0-9\s.,!?]+$",
                "enforce_strict_validation": True,
                "max_input_length": 1000
            },
            "smtp": {
                "use_vault": True,
                "vault_path": "secretv2/data/smtp",
                "fallback": {
                    "enabled": True,
                    "server": "smtp.development.com",
                    "port": 587,
                    "use_tls": True,
                    "username": None,
                    "password": None,
                    "from_email": "alerts@yourdomain.com"
                },
                "disable_on_vault_failure": True
            },
            "notifications": {
                "use_vault": True,
                "vault_path": "secretv2/data/notifications",
                "email": "notify@yourdomain.com",
                "fallback_email": "backup@yourdomain.com",
                "disable_on_vault_failure": True
            },
            "check_interval": 10,
            "throttle_minutes": 15,
            "max_rotated_files": 3,
            "max_lines_per_check": 10000,
            "max_deduplication_cache": 1000,
            "dry_run": False,
            "use_watchdog": True,
            "metrics_port": 8000,
            "health_check_port": 8080,
            "heartbeat_file": "app/logs/heartbeat.json",  # Fixed path
            "heartbeat_interval": 60,
            "alerters": {
                "email": True,
                "slack": {
                    "enabled": False,
                    "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                    "channel": "#alerts",
                    "username": "Manus Monitor",
                    "icon_emoji": ":warning:"
                },
                "pagerduty": {
                    "enabled": False,
                    "routing_key": "",
                    "api_key": "",
                    "service_id": ""
                }
            },
            "telemetry": {
                "enabled": False,
                "log_file": "app/logs/system/telemetry.log"  # Fixed path
            }
        }
        try:
            config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, "w") as f:
                yaml.safe_dump(default_config, f)
            secure_file_permissions(config_file)
            logger.info(f"Default configuration created at {config_path}. Please edit with your settings.")
        except Exception as e:
            logger.error(f"Failed to create default configuration: {str(e)}")
            raise ManusConfigError(f"Failed to create default configuration: {str(e)}")
    return True

def secure_file_permissions(file_path: Path) -> bool:
    """
    Ensure file has secure permissions (owner read/write only).

    Args:
        file_path: Path to file

    Returns:
        bool: True if permissions set successfully

    Raises:
        ManusSecurityError: If permissions cannot be set
    """
    if os.name == 'posix' and file_path.exists():
        try:
            os.chmod(file_path, 0o600)
            logger.debug(f"Set permissions on {file_path} to 0600")
            return True
        except PermissionError as e:
            logger.error(f"Unable to set secure permissions on {file_path}: {e}")
            raise ManusSecurityError(f"Unable to set secure permissions on {file_path}: {e}")
    return True

def secure_directory_permissions(dir_path: Path) -> bool:
    """
    Ensure directory has secure permissions (owner read/write/execute only).

    Args:
        dir_path: Path to directory

    Returns:
        bool: True if permissions set successfully

    Raises:
        ManusSecurityError: If permissions cannot be set
    """
    if os.name == 'posix':
        try:
            if not dir_path.exists():
                dir_path.mkdir(parents=True, exist_ok=True)
            os.chmod(dir_path, 0o700)
            logger.debug(f"Set permissions on {dir_path} to 0700")
            return True
        except PermissionError as e:
            logger.error(f"Unable to set secure permissions on {dir_path}: {e}")
            raise ManusSecurityError(f"Unable to set secure permissions on {dir_path}: {e}")
    elif not dir_path.exists():
        dir_path.mkdir(parents=True, exist_ok=True)
    return True

def authenticate(config: Dict[str, Any]) -> bool:
    """
    Authenticate user with a password.

    Args:
        config: Configuration dictionary

    Returns:
        bool: True if authentication successful

    Raises:
        ManusSecurityError: If authentication fails
    """
    password = config.get('security', {}).get('password')
    if password:
        try:
            from getpass import getpass
        except ImportError:
            def getpass(prompt="Password: "):
                import sys
                sys.stdout.write(prompt)
                return input()
        if getpass("Enter password: ") != password:
            logger.error("Authentication failed")
            raise ManusSecurityError("Authentication failed")
        logger.info("Authentication successful")
    return True

def validate_input(prompt: str, config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate user input based on configuration.

    Args:
        prompt: User input string
        config: Configuration dictionary

    Returns:
        Tuple[bool, str]: (is_valid, sanitized_or_error_message)
    """
    max_length = config.get('security', {}).get('max_input_length', 1000)
    if len(prompt) > max_length:
        return False, "Input exceeds maximum allowed length"
    blocked_patterns = config.get('security', {}).get('blocked_patterns', [])
    allowed_pattern = config.get('security', {}).get('allowed_pattern', r'^[a-zA-Z0-9\s.,!?]+$')
    sanitized_prompt = re.sub(r'[\x00-\x1F\x7F<>]', '', prompt)
    if config.get('security', {}).get('enforce_strict_validation', True):
        if not re.match(allowed_pattern, sanitized_prompt):
            return False, "Input contains invalid characters"
    if any(pat in sanitized_prompt.lower() for pat in blocked_patterns):
        return False, "Blocked pattern detected in input"
    return True, sanitized_prompt

def load_patterns(patterns_file: str) -> Dict[str, str]:
    """
    Load patterns from a JSON file.

    Args:
        patterns_file: Path to the patterns JSON file

    Returns:
        Dict[str, str]: Dictionary of patterns where keys are pattern names and values are regex patterns

    Raises:
        ManusConfigError: If the file is missing, contains invalid JSON, or doesn't contain a dictionary
    """
    try:
        with open(patterns_file, 'r') as f:
            patterns = json.load(f)
        if not isinstance(patterns, dict):
            raise ValueError("Patterns file must contain a dictionary")
        return patterns
    except FileNotFoundError:
        logger.error(f"Patterns file not found: {patterns_file}")
        raise ManusConfigError(f"Patterns file not found: {patterns_file}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in patterns file: {str(e)}")
        raise ManusConfigError(f"Invalid JSON in patterns file: {str(e)}")
    except Exception as e:
        logger.error(f"Error loading patterns: {str(e)}")
        raise ManusConfigError(f"Error loading patterns: {str(e)}")

### Configuration Classes
class ConfigValidator:
    """Validates the monitor configuration."""
    @staticmethod
    def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """
        Validate configuration.

        Args:
            config: Configuration dictionary

        Returns:
            Tuple[bool, List[str], List[str]]: (is_valid, errors, warnings)
        """
        errors, warnings = [], []
        required_sections = ['logging']
        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: {section}")
        if 'logging' in config:
            if not any(key in config['logging'] for key in ['log_file', 'audit_log']):
                errors.append("No log file specified in logging section")
        if 'notifications' in config and not config['notifications'].get('email'):
            warnings.append("No notification email specified")
        vault_config = config.get('vault', {})
        if vault_config.get('enabled', False):
            if not vault_config.get('address'):
                errors.append("Vault address required when vault enabled")
            for secret_type in ['smtp', 'notifications', 'security']:
                if secret_type not in vault_config.get('secrets', {}):
                    warnings.append(f"No vault path for {secret_type} secrets")
        security = config.get('security', {})
        if not security:
            warnings.append("No security section in configuration")
        elif 'vault_failure_mode' not in security:
            warnings.append("vault_failure_mode not specified")
        if config.get('check_interval', 1) < 1:
            errors.append("check_interval must be at least 1 second")
        if config.get('max_lines_per_check', 100) < 100:
            warnings.append("max_lines_per_check very low (<100)")
        optional_sections = ['smtp', 'metrics', 'alerters', 'telemetry']
        for section in optional_sections:
            if section not in config:
                warnings.append(f"Optional section '{section}' not found")
        return len(errors) == 0, errors, warnings

class ConfigManager:
    """Manages configuration loading, validation, and reloading."""
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize ConfigManager.

        Args:
            config_path: Path to config file (optional)
        """
        self.config_path = config_path or os.getenv("CONFIG_PATH")
        self.config = self._get_default_config()
        self.last_load_time = 0
        self.reload_lock = Lock()
        self.reload_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'log_file': 'app/logs/audit/audit.log',  # Fixed default path
            'email': None,
            'patterns_file': 'app/config/patterns.json',  # Fixed path
            'check_interval': 10,
            'throttle_minutes': 15,
            'dry_run': False,
            'use_vault': False,
            'metrics_port': 8000,
            'health_check_port': 8080,
            'vault_path': 'secretv2/data/smtp',
            'max_rotated_files': 3,
            'max_lines_per_check': 10000,
            'max_deduplication_cache': 1000,
            'required_smtp_vars': ['SMTP_SERVER', 'SMTP_USERNAME', 'SMTP_PASSWORD'],
            'secure_log_permissions': True,
            'fail_on_permission_error': False,
            'alerters': {
                'email': True,
                'slack': {
                    'enabled': False,
                    'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
                    'channel': '#alerts',
                    'username': 'Manus Monitor',
                    'icon_emoji': ':warning:'
                },
                'pagerduty': {
                    'enabled': False,
                    'routing_key': '',
                    'api_key': '',
                    'service_id': ''
                }
            },
            'heartbeat_file': 'app/logs/heartbeat.json',  # Fixed path
            'heartbeat_interval': 60
        }

    def load_config(self, validate: bool = True) -> Dict[str, Any]:
        """
        Load configuration from file and environment.

        Args:
            validate: Whether to validate config

        Returns:
            Dict[str, Any]: Configuration dictionary
        """
        if not self.config_path:
            logger.warning("No config path provided. Using defaults.")
            return self._get_default_config()
        ensure_config_exists(self.config_path)
        config = self._get_default_config()
        try:
            with open(self.config_path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
                if not isinstance(file_config, dict):
                    logger.warning(f"Invalid YAML in {self.config_path}. Using defaults.")
                    return config
                self._merge_config(config, file_config)
                logger.info(f"Loaded config from {self.config_path}")
            self._resolve_paths(config)
            self.last_load_time = time.time()
            if validate:
                is_valid, errors, warnings = ConfigValidator.validate_config(config)
                for error in errors:
                    logger.error(f"Config error: {error}")
                for warning in warnings:
                    logger.warning(f"Config warning: {warning}")
                if not is_valid:
                    logger.error("Validation failed. Using previous/default config.")
                    return self.config
            self.config = config
        except Exception as e:
            logger.error(f"Failed to load config from {self.config_path}: {str(e)}")
        return self.config

    def _merge_config(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Recursively merge source config into target."""
        for key, value in source.items():
            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                self._merge_config(target[key], value)
            else:
                target[key] = value

    def _resolve_paths(self, config: Dict[str, Any]) -> None:
        """Resolve relative paths in configuration."""
        if not self.config_path:
            return
        base_dir = Path(os.path.dirname(os.path.abspath(self.config_path)))
        for key in ['log_file', 'patterns_file', 'heartbeat_file']:
            if key in config and config[key] and not os.path.isabs(config[key]):
                config[key] = str(base_dir / config[key])
                logger.debug(f"Resolved {key} to: {config[key]}")
        if 'logging' in config and isinstance(config['logging'], dict):
            for key in ['log_file', 'audit_log', 'patterns_file']:
                if key in config['logging'] and config['logging'][key] and not os.path.isabs(config['logging'][key]):
                    config['logging'][key] = str(base_dir / config['logging'][key])
                    logger.debug(f"Resolved logging.{key} to: {config['logging'][key]}")
                    parent_dir = Path(config['logging'][key]).parent
                    if not parent_dir.exists():
                        parent_dir.mkdir(parents=True, exist_ok=True)
                        secure_directory_permissions(parent_dir)

    def register_reload_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register callback for config reload."""
        self.reload_callbacks.append(callback)

    def reload(self) -> bool:
        """Reload config and notify callbacks."""
        with self.reload_lock:
            try:
                new_config = self.load_config(validate=True)
                for callback in self.reload_callbacks:
                    callback(new_config)
                logger.info("Configuration reloaded successfully")
                CONFIG_RELOADS.inc()
                return True
            except Exception as e:
                logger.error(f"Failed to reload config: {str(e)}")
                return False
