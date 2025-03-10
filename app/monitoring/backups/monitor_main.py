#!/usr/bin/env python3
"""
Manus AI Log Monitor
Real-time monitoring system for Manus AI logs that detects suspicious activity
and sends alerts when potential security issues are identified.

This is the main entry point module that coordinates the monitoring process.
"""

import os
import sys
import time
import signal
import argparse
import logging
import http.server
import socketserver
import json
from pathlib import Path
from threading import Thread
from typing import Dict, Any, Optional, List

from utils import (
    logger,
    ManusConfigError,
    ManusSecurityError,
    ConfigManager,
    authenticate,
    initialize_metrics,  # New function for metrics initialization
    HEALTH_CHECK_FAILURES,
    CONFIG_RELOADS
)
from log_processor import LogProcessor  # Import LogProcessor directly
from alerters import AlertManager  # Import AlertManager


class HealthCheckHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for health check endpoint."""
    
    def __init__(self, *args, monitor=None, **kwargs):
        self.monitor = monitor
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/health':
            if self.monitor and self.monitor.is_healthy():
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                health_data = {
                    'status': 'healthy',
                    'uptime': self.monitor.get_uptime(),
                    'stats': self.monitor.get_health_stats()
                }
                self.wfile.write(json.dumps(health_data).encode())
            else:
                self.send_response(503)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                health_data = {
                    'status': 'unhealthy',
                    'reason': 'Monitor is not running or in an error state'
                }
                self.wfile.write(json.dumps(health_data).encode())
                HEALTH_CHECK_FAILURES.inc()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"Health check: {format % args}")


class MonitorHealthChecker:
    """Monitors the health of the log monitor."""
    
    def __init__(self, config: Dict[str, Any], monitor: 'LogMonitor'):
        """
        Initialize the health checker.
        
        Args:
            config: Configuration dictionary
            monitor: LogMonitor instance
        """
        self.config = config
        self.monitor = monitor
        self.heartbeat_file = config.get('heartbeat_file', 'heartbeat.json')
        self.heartbeat_interval = config.get('heartbeat_interval', 60)
        self.last_heartbeat = 0
        self.running = False
        self.health_check_port = config.get('health_check_port', 8080)
        self.http_server = None
        
        # Initialize heartbeat file with secure permissions
        self._write_heartbeat(init=True)
    
    def start(self) -> None:
        """Start health checking."""
        if self.running:
            return
        
        self.running = True
        
        # Start heartbeat thread
        Thread(target=self._heartbeat_loop, daemon=True).start()
        
        # Start HTTP health check server if enabled
        if self.health_check_port:
            self._start_http_server()
    
    def stop(self) -> None:
        """Stop health checking."""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
    
    def _heartbeat_loop(self) -> None:
        """Periodically write heartbeat to file."""
        while self.running:
            try:
                self._write_heartbeat()
                from utils import HEARTBEAT
                HEARTBEAT.set(time.time())
                time.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat: {str(e)}")
                time.sleep(5)
    
    def _write_heartbeat(self, init: bool = False) -> None:
        """
        Write heartbeat information to file.
        
        Args:
            init: Whether this is the initial write (just creating the file)
        """
        try:
            heartbeat_path = Path(self.heartbeat_file)
            if init:
                if not heartbeat_path.parent.exists():
                    heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
                if not heartbeat_path.exists():
                    with open(heartbeat_path, 'w') as f:
                        json.dump({"init_time": time.time()}, f)
                    if os.name == 'posix':
                        os.chmod(heartbeat_path, 0o600)
                return
            heartbeat_data = {
                'timestamp': time.time(),
                'pid': os.getpid(),
                'uptime': self.monitor.get_uptime(),
                'stats': self.monitor.get_stats()
            }
            with open(self.heartbeat_file, 'w') as f:
                json.dump(heartbeat_data, f, indent=2)
            self.last_heartbeat = time.time()
            logger.debug(f"Heartbeat written to {self.heartbeat_file}")
        except Exception as e:
            logger.error(f"Failed to write heartbeat: {str(e)}")


class LogMonitor:
    """Main log monitoring system."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the log monitor.
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.start_time = time.time()
        # Use ConfigManager for configuration loading
        self.config_manager = ConfigManager(config_path or "app/config/config.yaml")
        self.config = self.config_manager.load_config()
        authenticate(self.config)
        
        # Initialize AlertManager
        self.alert_manager = AlertManager(self.config)
        
        # Load patterns (assumes a load_patterns function exists in utils)
        from utils import load_patterns
        self.patterns = load_patterns(self.config.get('patterns_file', 'app/config/patterns.json'))
        
        # Health checking
        self.health_checker = MonitorHealthChecker(self.config, self)
        self.running = False
        self.stats = {'alerts_processed': 0}
        
        # Metrics server using centralized function
        self.metrics_port = None if self.config.get('no_metrics') else self.config.get('metrics_port', 8000)
        if self.metrics_port:
            initialize_metrics(self.metrics_port)
        
        self._setup_signal_handlers()
    
    def handle_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """
        Handle new alerts by queuing them to AlertManager based on severity.
        
        Args:
            alerts: List of alert dictionaries
        """
        for alert in alerts:
            severity = alert.get('severity', 'medium')
            if severity in ['high', 'critical']:
                self.alert_manager.queue_alerts([alert], bypass_throttle=(severity == 'critical'))
            else:
                self.alert_manager.queue_low_priority_alerts([alert], severity)
            self.stats['alerts_processed'] += 1
    
    def start(self) -> None:
        """Start the log monitor with real-time watchdog support."""
        if self.running:
            logger.warning("Monitor already running")
            return
        
        logger.info("Starting Manus AI Log Monitor")
        self.running = True
        self.health_checker.start()
        
        log_file = (self.config.get('log_file') or 
                    self.config.get('logging', {}).get('audit_log') or 
                    "app/logs/audit.log")
        logger.info(f"Monitoring log file: {log_file} with watchdog (if available)")
        
        # Initialize LogProcessor with callback for real-time alerting
        self.log_processor = LogProcessor(
            log_file=log_file,
            patterns=self.patterns,
            config=self.config,
            alert_callback=self.handle_alerts
        )
        self.log_processor.start()
        
        try:
            while self.running:
                time.sleep(1)  # Main thread waits, watchdog handles events
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the log monitor."""
        if not self.running:
            return
        
        logger.info("Stopping Manus AI Log Monitor")
        self.running = False
        if hasattr(self, 'log_processor'):
            self.log_processor.stop()
        self.health_checker.stop()
        self.alert_manager.stop()
        logger.info("Monitor stopped")
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
    
    def _handle_signal(self, signum: int, frame) -> None:
        """
        Handle received signals.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if signum in (signal.SIGTERM, signal.SIGINT):
            logger.info(f"Received {'SIGTERM' if signum == signal.SIGTERM else 'SIGINT'}. Shutting down...")
            self.stop()
    
    def is_healthy(self) -> bool:
        """Check if the monitor is healthy."""
        if not self.running:
            return False
        if self.health_checker.last_heartbeat and \
           time.time() - self.health_checker.last_heartbeat > self.health_checker.heartbeat_interval * 2:
            logger.warning("Heartbeat is stale")
            return False
        return True
    
    def get_uptime(self) -> float:
        """Get monitor uptime in seconds."""
        return time.time() - self.start_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        return self.stats
    
    def get_health_stats(self) -> Dict[str, Any]:
        """Get health statistics."""
        return {
            'alerts_processed': self.stats['alerts_processed'],
            'log_file': self.config.get('log_file', 'app/logs/audit.log')
        }


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Manus AI Log Monitor')
    parser.add_argument('--config', type=str, default=None,
                        help='Path to configuration file')
    parser.add_argument('--log-file', '-l', type=str,
                        help='Path to the log file to monitor (overrides config)')
    return parser.parse_args()


def main() -> int:
    """
    Main entry point.
    
    Returns:
        Exit code
    """
    args = parse_args()
    config_path = args.config or "app/config/config.yaml"
    monitor = LogMonitor(config_path)
    
    if args.log_file:
        logger.info(f"Overriding log file with {args.log_file}")
        monitor.config['log_file'] = args.log_file
    
    try:
        monitor.start()
        return 0
    except ManusConfigError as e:
        logger.error(f"Configuration error: {str(e)}")
        return 1
    except ManusSecurityError as e:
        logger.error(f"Security error: {str(e)}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
