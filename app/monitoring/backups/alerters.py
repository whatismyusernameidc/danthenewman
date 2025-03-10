#!/usr/bin/env python3
"""
Alert system module for Manus AI Log Monitor.
Contains base alerter class and specific implementations.
"""

# Standard library imports
import os
import re
import time
import smtplib
import json
import requests
from abc import ABC, abstractmethod
from email.message import EmailMessage
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from collections import OrderedDict
from typing import Dict, List, Any, Optional

# Local imports
from utils import (
    logger,
    ManusAlertError,
    ManusVaultError,
    EMAILS_SENT,
    PENDING_ALERTS,
    ALERT_LATENCY,
    VAULT_AVAILABLE,
    VaultService
)

class BaseAlerter(ABC):
    """Base class for alert mechanisms."""
    sensitive_patterns = [
        r'(password[=:"\s\']+)[^\s&;"\']+',
        r'(token[=:"\s\']+)[^\s&;"\']+',
        r'(secret[=:"\s\']+)[^\s&;"\']+',
        r'(key[=:"\s\']+)[^\s&;"\']+',
        r'(auth[=:"\s\']+)[^\s&;"\']+',
        r'(credential[=:"\s\']+)[^\s&;"\']+',
        r'(api[_\-]?key[=:"\s\']+)[^\s&;"\']+',
        r'(session[_\-]?id[=:"\s\']+)[^\s&;"\']+',
        r'(session[_\-]?token[=:"\s\']+)[^\s&;"\']+',
        r'(bearer[=:"\s\']+)[^\s&;"\']+',
        r'(ssn[=:"\s\']+)\d[\d\-]+',
        r'(social[_\-]?security[=:"\s\']+)\d[\d\-]+',
        r'(credit[_\-]?card[=:"\s\']+)\d[\d\-]+',
        r'(cc[_\-]?num[=:"\s\']+)\d[\d\-]+',
        r'(card[_\-]?number[=:"\s\']+)\d[\d\-]+',
        r'(bot[_\-]?token[=:"\s\']+)[^\s&;"\']+',
        r'(slack[_\-]?token[=:"\s\']+)[^\s&;"\']+',
        r'(discord[_\-]?token[=:"\s\']+)[^\s&;"\']+',
        r'(telegram[_\-]?token[=:"\s\']+)[^\s&;"\']+',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ]
    compiled_sensitive_patterns = [re.compile(pat, re.IGNORECASE) for pat in sensitive_patterns]

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize alerter.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.name = self.__class__.__name__
        self.dry_run = config.get('dry_run', False)

    @abstractmethod
    def send_alert(self, alerts: List[Dict[str, Any]], subject_prefix: str = "SECURITY ALERT") -> bool:
        """Send alert for given alerts."""
        pass

    def sanitize_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sanitize alerts to remove sensitive information.

        Args:
            alerts: List of alert dictionaries

        Returns:
            Sanitized alert dictionaries
        """
        sanitized = []
        for alert in alerts:
            s_alert = alert.copy()
            log_line = alert.get('log_line', '')
            for pattern in self.compiled_sensitive_patterns:
                log_line = pattern.sub(r'\1***REDACTED***', log_line)
            s_alert['log_line'] = log_line
            sanitized.append(s_alert)
        return sanitized

class EmailAlerter(BaseAlerter):
    """Sends alerts via email."""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.email = config.get('notifications', {}).get('email')
        self.use_vault = config.get('vault', {}).get('enabled', False)
        self.vault_service = VaultService(config) if self.use_vault else None
        smtp_config = config.get('smtp', {})
        self.vault_path = smtp_config.get('vault_path') or config.get('vault', {}).get('secrets', {}).get('smtp', 'secretv2/data/smtp')
        self.vault_cached_credentials = None
        self.vault_last_error_time = 0

    def send_alert(self, alerts: List[Dict[str, Any]], subject_prefix: str = "SECURITY ALERT") -> bool:
        """
        Send email alert.

        Args:
            alerts: List of alert dictionaries
            subject_prefix: Email subject prefix

        Returns:
            bool: True if sent successfully

        Raises:
            ManusAlertError: If sending the alert fails
        """
        if not self.email:
            logger.error("No email address configured")
            raise ManusAlertError("No email address configured")
        if self.dry_run:
            logger.info(f"[DRY RUN] Would send {subject_prefix} with {len(alerts)} alerts to {self.email}")
            EMAILS_SENT.inc()
            return True
        try:
            sanitized = self.sanitize_alerts(alerts)
            msg = EmailMessage()
            msg['Subject'] = f"{subject_prefix}: Suspicious Activity ({len(sanitized)} alerts)"
            smtp_config = self._load_smtp_config()
            if not smtp_config:
                raise ManusAlertError("SMTP config missing")
            msg['From'] = smtp_config.get("from_email", "alerts@yourdomain.com")
            msg['To'] = self.email
            content = f"Suspicious activity at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}:\n\n"
            for severity in ["critical", "high", "medium", "low"]:
                severity_alerts = [a for a in sanitized if a.get("severity") == severity]
                if severity_alerts:
                    content += f"== {severity.upper()} ALERTS ==\n"
                    for alert in severity_alerts:
                        excerpt = alert['log_line'][:200] + ('...' if len(alert['log_line']) > 200 else '')
                        content += f"Alert: {alert['description']}\nPattern: {alert['pattern']}\nLog: {excerpt}\n\n"
            content += "\n---\nAutomated alert from Manus AI Log Monitor.\n"
            msg.set_content(content)
            if smtp_config.get("server") and smtp_config.get("username"):
                with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as server:
                    if smtp_config.get("tls", True):
                        server.starttls()
                    if smtp_config.get("use_oauth") and smtp_config.get("oauth_token"):
                        auth_str = f"user={smtp_config['username']}\1auth=Bearer {smtp_config['oauth_token']}\1\1"
                        server.auth("XOAUTH2", lambda x: auth_str, initial_response_ok=True)
                    elif smtp_config.get("password"):
                        server.login(smtp_config["username"], smtp_config["password"])
                    else:
                        raise ManusAlertError("No valid SMTP credentials")
                    server.send_message(msg)
                logger.info(f"Email sent to {self.email}")
                EMAILS_SENT.inc()
                return True
            raise ManusAlertError("SMTP credentials missing")
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            raise ManusAlertError(f"Failed to send email alert: {str(e)}") from e

    def _load_smtp_config(self) -> Optional[Dict[str, Any]]:
        """Load SMTP configuration."""
        return self._get_vault_credentials() if self.use_vault else self._get_env_smtp_config()

    def _get_env_smtp_config(self) -> Optional[Dict[str, Any]]:
        """Load SMTP settings from environment variables."""
        smtp_config = self.config.get('smtp', {})
        fallback = smtp_config.get('fallback', {})
        if not fallback.get('enabled', False):
            required_vars = ['SMTP_SERVER', 'SMTP_USERNAME']
            use_oauth = os.getenv('SMTP_USE_OAUTH', 'false').lower() == 'true'
            required_vars.append('SMTP_OAUTH_TOKEN' if use_oauth else 'SMTP_PASSWORD')
            missing = [var for var in required_vars if not os.getenv(var)]
            if missing:
                logger.error(f"Missing SMTP env vars: {', '.join(missing)}")
                return None
            return {
                "server": os.getenv("SMTP_SERVER"),
                "port": int(os.getenv("SMTP_PORT", 587)),
                "username": os.getenv("SMTP_USERNAME"),
                "password": os.getenv("SMTP_PASSWORD"),
                "from_email": os.getenv("SMTP_FROM", fallback.get("from_email", "alerts@yourdomain.com")),
                "use_oauth": use_oauth,
                "oauth_token": os.getenv("SMTP_OAUTH_TOKEN"),
                "tls": os.getenv("SMTP_USE_TLS", "true").lower() == 'true'
            }
        return {
            "server": fallback.get("server"),
            "port": fallback.get("port", 587),
            "username": os.getenv("SMTP_USERNAME") or fallback.get("username"),
            "password": os.getenv("SMTP_PASSWORD") or fallback.get("password"),
            "from_email": fallback.get("from_email", "alerts@yourdomain.com"),
            "use_oauth": False,
            "tls": fallback.get("use_tls", True)
        }

    def _get_vault_credentials(self) -> Optional[Dict[str, Any]]:
        """Retrieve SMTP credentials from Vault."""
        if not self.vault_service:
            logger.warning("Vault unavailable. Using env vars.")
            return self._get_env_smtp_config()
        if self.vault_cached_credentials:
            return self.vault_cached_credentials
        now = time.time()
        if now - self.vault_last_error_time < 60:
            logger.info("Recent Vault failure. Using env vars.")
            return self._get_env_smtp_config()
        try:
            secret = self.vault_service.get_secret(self.vault_path)
            if not secret:
                self.vault_last_error_time = now
                if self.config.get('smtp', {}).get('disable_on_vault_failure', False):
                    logger.warning("SMTP alerts disabled due to Vault failure")
                    return None
                return self._get_env_smtp_config()
            self.vault_cached_credentials = {
                "server": secret.get("server", "smtp.yourdomain.com"),
                "port": int(secret.get("port", 587)),
                "username": secret.get("username"),
                "password": secret.get("password"),
                "from_email": secret.get("from_email"),
                "use_oauth": secret.get("use_oauth", False),
                "oauth_token": secret.get("oauth_token"),
                "tls": secret.get("use_tls", True)
            }
            logger.info("Retrieved SMTP credentials from Vault.")
            return self.vault_cached_credentials
        except ManusVaultError as e:
            logger.error(f"Vault error: {str(e)}")
            self.vault_last_error_time = now
            return self._get_env_smtp_config()

class SlackAlerter(BaseAlerter):
    """Sends alerts via Slack webhooks."""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        slack_config = config.get('alerters', {}).get('slack', {})
        self.webhook_url = slack_config.get('webhook_url')
        self.channel = slack_config.get('channel')
        self.username = slack_config.get('username', 'Manus Monitor')
        self.icon_emoji = slack_config.get('icon_emoji', ':warning:')

    def send_alert(self, alerts: List[Dict[str, Any]], subject_prefix: str = "SECURITY ALERT") -> bool:
        """
        Send Slack alert.

        Args:
            alerts: List of alert dictionaries
            subject_prefix: Alert subject prefix

        Returns:
            bool: True if sent successfully

        Raises:
            ManusAlertError: If sending the alert fails
        """
        if not self.webhook_url:
            logger.error("No Slack webhook URL configured")
            raise ManusAlertError("No Slack webhook URL configured")
        if self.dry_run:
            logger.info(f"[DRY RUN] Would send {subject_prefix} with {len(alerts)} alerts to Slack")
            return True
        try:
            sanitized = self.sanitize_alerts(alerts)
            severity_counts = {s: 0 for s in ['critical', 'high', 'medium', 'low']}
            for alert in sanitized:
                severity_counts[alert.get('severity', 'medium')] += 1
            title = f"{subject_prefix}: {len(sanitized)} alerts detected"
            text = f"*{title}*\n\n*Alert Summary:*\n"
            for severity in severity_counts:
                if severity_counts[severity]:
                    text += f"• {severity.upper()}: {severity_counts[severity]}\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                severity_alerts = [a for a in sanitized if a.get('severity') == severity]
                if severity_alerts:
                    text += f"\n*{severity.upper()} ALERTS:*\n"
                    for idx, alert in enumerate(severity_alerts, 1):
                        excerpt = alert['log_line'][:100] + ('...' if len(alert['log_line']) > 100 else '')
                        text += f"*{idx}. {alert['description']}*\nPattern: `{alert['pattern']}`\nLog: `{excerpt}`\n\n"
            payload = {
                'text': text,
                'username': self.username,
                'icon_emoji': self.icon_emoji,
                'mrkdwn': True
            }
            if self.channel:
                payload['channel'] = self.channel
            response = requests.post(self.webhook_url, json=payload, headers={'Content-Type': 'application/json'}, timeout=10)
            if response.status_code == 200:
                logger.info("Alert sent to Slack")
                return True
            logger.error(f"Slack send failed: {response.status_code} {response.text}")
            raise ManusAlertError(f"Failed to send Slack alert: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
            raise ManusAlertError(f"Failed to send Slack alert: {str(e)}") from e

class PagerDutyAlerter(BaseAlerter):
    """Sends alerts via PagerDuty."""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        pd_config = config.get('alerters', {}).get('pagerduty', {})
        self.api_key = pd_config.get('api_key')
        self.routing_key = pd_config.get('routing_key')
        self.service_id = pd_config.get('service_id')

    def send_alert(self, alerts: List[Dict[str, Any]], subject_prefix: str = "SECURITY ALERT") -> bool:
        """
        Send PagerDuty alert.

        Args:
            alerts: List of alert dictionaries
            subject_prefix: Alert subject prefix

        Returns:
            bool: True if sent successfully

        Raises:
            ManusAlertError: If sending the alert fails
        """
        if not self.routing_key and not self.api_key:
            logger.error("No PagerDuty routing_key or api_key configured")
            raise ManusAlertError("No PagerDuty routing_key or api_key configured")
        if self.dry_run:
            logger.info(f"[DRY RUN] Would send {subject_prefix} with {len(alerts)} alerts to PagerDuty")
            return True
        try:
            sanitized = self.sanitize_alerts(alerts)
            pd_severity = "info"
            for alert in sanitized:
                severity = alert.get('severity', 'medium')
                if severity == 'critical':
                    pd_severity = "critical"
                    break
                elif severity == 'high' and pd_severity != "critical":
                    pd_severity = "error"
                elif severity == 'medium' and pd_severity not in ["critical", "error"]:
                    pd_severity = "warning"
            summary = f"{subject_prefix}: {len(sanitized)} alerts detected"
            details = {
                "alerts": [{"description": a.get('description'), "pattern": a.get('pattern'),
                            "severity": a.get('severity', 'medium'), "log_excerpt": a.get('log_line', '')[:200]}
                           for a in sanitized],
                "summary": {s: len([a for a in sanitized if a.get('severity') == s]) for s in ['critical', 'high', 'medium', 'low']}
            }
            if self.routing_key:
                payload = {
                    "routing_key": self.routing_key,
                    "event_action": "trigger",
                    "dedup_key": f"manus_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    "payload": {
                        "summary": summary,
                        "severity": pd_severity,
                        "source": "manus_monitor",
                        "component": "log_monitor",
                        "group": "security",
                        "class": "security_alert",
                        "custom_details": details
                    }
                }
                response = requests.post("https://events.pagerduty.com/v2/enqueue", json=payload,
                                         headers={"Content-Type": "application/json"}, timeout=10)
            elif self.api_key and self.service_id:
                payload = {
                    "incident": {
                        "type": "incident",
                        "title": summary,
                        "service": {"id": self.service_id, "type": "service_reference"},
                        "urgency": "high" if pd_severity in ["critical", "error"] else "low",
                        "body": {"type": "incident_body", "details": json.dumps(details, indent=2)}
                    }
                }
                response = requests.post("https://api.pagerduty.com/incidents", json=payload,
                                         headers={"Content-Type": "application/json",
                                                  "Accept": "application/vnd.pagerduty+json;version=2",
                                                  "Authorization": f"Token token={self.api_key}"}, timeout=10)
            else:
                raise ManusAlertError("PagerDuty requires routing_key or api_key and service_id")
            if response.status_code in [200, 201, 202]:
                logger.info("Alert sent to PagerDuty")
                return True
            logger.error(f"PagerDuty send failed: {response.status_code} {response.text}")
            raise ManusAlertError(f"Failed to send PagerDuty alert: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Error sending PagerDuty alert: {str(e)}")
            raise ManusAlertError(f"Failed to send PagerDuty alert: {str(e)}") from e

class AlertManager:
    """Manages alert processing, deduplication, and dispatching."""
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AlertManager.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.alerters = {}
        self.alert_queue = Queue()
        self.pending_low_alerts = []
        self.pending_medium_alerts = []
        self.recent_alerts = OrderedDict()
        self.alert_lock = Lock()
        self.stats_lock = Lock()
        self.throttle_seconds = config.get('throttle_minutes', 15) * 60
        self.last_alert_time = 0
        self.stats = {"alerts_triggered": 0, "alerts_sent": 0, "deduplicated_alerts": 0}
        self.running = True
        self._register_alerters()
        self.alert_thread = Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()

    def _register_alerters(self) -> None:
        """Register configured alerters."""
        self.register_alerter("email", EmailAlerter(self.config))
        slack_config = self.config.get('alerters', {}).get('slack', {})
        if isinstance(slack_config, dict) and slack_config.get('enabled', False) and slack_config.get('webhook_url'):
            self.register_alerter("slack", SlackAlerter(self.config))
        pd_config = self.config.get('alerters', {}).get('pagerduty', {})
        if isinstance(pd_config, dict) and pd_config.get('enabled', False) and (pd_config.get('routing_key') or
                                                                               (pd_config.get('api_key') and pd_config.get('service_id'))):
            self.register_alerter("pagerduty", PagerDutyAlerter(self.config))
        logger.info(f"Registered alerters: {', '.join(self.alerters.keys())}")

    def register_alerter(self, name: str, alerter: BaseAlerter) -> None:
        """Register an alerter."""
        self.alerters[name] = alerter

    def queue_alerts(self, alerts: List[Dict[str, Any]], bypass_throttle: bool = False) -> None:
        """
        Queue high-priority alerts.

        Args:
            alerts: List of alerts
            bypass_throttle: Bypass throttling
        """
        unique_alerts = []
        with self.alert_lock:
            current_time = time.time()
            for alert in alerts:
                alert_id = f"{alert['pattern']}_{hash(alert['log_line'])}"
                if alert_id not in self.recent_alerts or (current_time - self.recent_alerts[alert_id]) > 600:
                    unique_alerts.append(alert)
                    self.recent_alerts[alert_id] = current_time
                    self.recent_alerts.move_to_end(alert_id)
                else:
                    with self.stats_lock:
                        self.stats["deduplicated_alerts"] += 1
        if unique_alerts:
            self.alert_queue.put({"alerts": unique_alerts, "bypass_throttle": bypass_throttle})
            PENDING_ALERTS.set(self.alert_queue.qsize())
        with self.stats_lock:
            self.stats["alerts_triggered"] += len(unique_alerts)

    def queue_low_priority_alerts(self, alerts: List[Dict[str, Any]], severity: str = "medium") -> None:
        """
        Queue low/medium-priority alerts for batching.

        Args:
            alerts: List of alerts
            severity: Alert severity
        """
        unique_alerts = []
        with self.alert_lock:
            current_time = time.time()
            for alert in alerts:
                alert_id = f"{alert['pattern']}_{hash(alert['log_line'])}"
                if alert_id not in self.recent_alerts or (current_time - self.recent_alerts[alert_id]) > 600:
                    unique_alerts.append(alert)
                    self.recent_alerts[alert_id] = current_time
                    self.recent_alerts.move_to_end(alert_id)
                else:
                    with self.stats_lock:
                        self.stats["deduplicated_alerts"] += 1
        with self.alert_lock:
            if severity == "low":
                self.pending_low_alerts.extend(unique_alerts)
            else:
                self.pending_medium_alerts.extend(unique_alerts)
        with self.stats_lock:
            self.stats["alerts_triggered"] += len(unique_alerts)

    def stop(self) -> None:
        """Stop AlertManager."""
        self.running = False
        if self.alert_thread.is_alive():
            self.alert_thread.join(timeout=5)

    def _process_alerts(self) -> None:
        """Process alerts with batching and deduplication."""
        last_batch_time = last_cache_cleanup = 0
        while self.running or not self.alert_queue.empty():
            try:
                current_time = time.time()
                if not self.alert_queue.empty():
                    alert_package = self.alert_queue.get(timeout=1)
                    alerts = alert_package["alerts"]
                    bypass_throttle = alert_package.get("bypass_throttle", False)
                    if bypass_throttle or (current_time - self.last_alert_time >= self.throttle_seconds):
                        self._send_alerts(alerts)
                        self.last_alert_time = current_time
                    else:
                        wait = self.throttle_seconds - (current_time - self.last_alert_time)
                        logger.info(f"Alert throttled. Next in {int(wait)} seconds")
                        time.sleep(min(5, wait))
                        self.alert_queue.put({"alerts": alerts, "bypass_throttle": False})
                    self.alert_queue.task_done()
                if current_time - last_batch_time >= 3600:  # Hourly batch
                    with self.alert_lock:
                        batch_size = len(self.pending_low_alerts) + len(self.pending_medium_alerts)
                        if batch_size:
                            logger.info(f"Sending batch of {batch_size} low/medium alerts")
                            combined = self.pending_low_alerts + self.pending_medium_alerts
                            self._send_alerts(combined, subject_prefix="BATCH ALERT")
                            self.pending_low_alerts.clear()
                            self.pending_medium_alerts.clear()
                    last_batch_time = current_time
                if current_time - last_cache_cleanup >= 1800:  # 30-minute cleanup
                    self._clean_recent_alerts()
                    last_cache_cleanup = current_time
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error processing alerts: {str(e)}")
                time.sleep(1)

    def _send_alerts(self, alerts: List[Dict[str, Any]], subject_prefix: str = "SECURITY ALERT") -> None:
        """
        Send alerts via registered alerters.

        Args:
            alerts: List of alerts
            subject_prefix: Alert subject prefix
        """
        if not alerts:
            return
        alerters_config = self.config.get('alerters', {})
        enabled_alerters = ['email'] if alerters_config.get('email', True) else []
        if isinstance(alerters_config.get('slack', {}), dict) and alerters_config['slack'].get('enabled'):
            enabled_alerters.append('slack')
        if isinstance(alerters_config.get('pagerduty', {}), dict) and alerters_config['pagerduty'].get('enabled'):
            enabled_alerters.append('pagerduty')
        success = False
        for name in enabled_alerters:
            if name in self.alerters:
                try:
                    if self.alerters[name].send_alert(alerts, subject_prefix):
                        success = True
                        logger.info(f"Alerts sent via {name}")
                    else:
                        logger.warning(f"Failed to send via {name}")
                except ManusAlertError as e:
                    logger.error(f"Error sending via {name}: {str(e)}")
        if success:
            with self.stats_lock:
                self.stats["alerts_sent"] += 1

    def _clean_recent_alerts(self) -> None:
        """Clean old entries from recent_alerts."""
        current_time = time.time()
        with self.alert_lock:
            old = [k for k, ts in self.recent_alerts.items() if current_time - ts > 3600]
            for k in old:
                del self.recent_alerts[k]
            max_cache = self.config.get('max_deduplication_cache', 1000)
            if len(self.recent_alerts) > max_cache:
                excess = len(self.recent_alerts) - max_cache
                for _ in range(excess):
                    self.recent_alerts.popitem(last=False)
                logger.debug(f"Removed {excess} oldest alert entries")
