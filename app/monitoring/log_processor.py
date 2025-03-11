#!/usr/bin/env python3
"""
Log processing module for Manus AI Log Monitor.
Contains components for reading log files and matching patterns using watchdog for real-time monitoring.
"""

import os
import re
import time
from pathlib import Path
from threading import Thread
from typing import Dict, List, Any, Union, Callable, Optional

# Local imports (moved here to ensure logger is defined before use)
from utils import (
    logger,
    ManusSecurityError,
    CURRENT_LOG_POSITION,
    PATTERN_MATCHES,
    ALERTS_TRIGGERED,
    ALERTS_BY_SEVERITY,
    secure_file_permissions,
    secure_directory_permissions,
)

# Third-party imports (watchdog import with fallback)
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog library not found. Install with: pip install watchdog for real-time monitoring.")

class LogFileHandler(FileSystemEventHandler):
    """Watchdog event handler for log file changes."""
    
    def __init__(self, process_callback: Callable[[], None]):
        """
        Initialize the log file handler.
        
        Args:
            process_callback: Function to call when the log file changes
        """
        self.process_callback = process_callback
    
    def on_modified(self, event):
        """
        Handle file modification events.
        
        Args:
            event: File system event
        """
        if not event.is_directory:
            self.process_callback()

class LogProcessor:
    """Handles real-time log file processing using watchdog or polling."""
    
    def __init__(self, log_file: str, patterns: Dict[str, Union[str, Dict[str, str]]], config: Dict[str, Any], 
                 alert_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None):
        """
        Initialize the log processor.
        
        Args:
            log_file: Path to log file to monitor
            patterns: Dictionary of patterns and their metadata
            config: Monitor configuration
            alert_callback: Optional callback to handle new alerts in real-time
        """
        self.log_file = Path(log_file)
        self.patterns = patterns
        self.config = config
        self.alert_callback = alert_callback
        self.position = 0
        self.last_inode = None
        self.last_mtime = None
        self.last_activity_time = time.time()
        self.max_lines_per_check = config.get('max_lines_per_check', 10000)
        self.max_rotated_files = config.get('max_rotated_files', 3)
        self.fail_on_permission_error = config.get('fail_on_permission_error', False)
        self.check_interval = config.get('check_interval', 10)
        self.min_check_interval = self.check_interval
        self.max_check_interval = self.check_interval * 10
        self.current_check_interval = self.check_interval
        self.matcher = PatternMatcher(self.patterns)
        self.alerts: List[Dict[str, Any]] = []  # Retained for initial alerts or debugging
        self.running = False
        self.observer = None
        
        # Secure log file permissions using centralized utilities
        self._secure_log_files()
    
    def _secure_log_files(self) -> None:
        """Create log files with secure permissions using utility functions from utils.py."""
        try:
            if os.name == 'posix':
                log_dir = self.log_file.parent
                secure_directory_permissions(log_dir)  # Centralized directory security
                if not self.log_file.exists():
                    with open(self.log_file, 'a'):
                        pass
                    logger.info(f"Created log file: {self.log_file}")
                secure_file_permissions(self.log_file)  # Centralized file security
        except Exception as e:
            logger.error(f"Error securing log files: {str(e)}")
            if self.fail_on_permission_error:
                raise
    
    def start(self) -> None:
        """Start monitoring the log file."""
        if self.running:
            logger.warning("Log processor already running")
            return
        
        logger.info(f"Starting log processor for {self.log_file}")
        self.running = True
        
        if WATCHDOG_AVAILABLE and self.config.get('use_watchdog', True):
            self._start_watchdog_monitoring()
        else:
            self._start_polling()
    
    def stop(self) -> None:
        """Stop monitoring the log file."""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
    
    def _start_watchdog_monitoring(self) -> None:
        """Start monitoring using watchdog for file system events."""
        logger.info("Using watchdog for real-time file monitoring")
        event_handler = LogFileHandler(self.process_new_logs)
        self.observer = Observer()
        
        log_dir = self.log_file.parent
        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
        
        self.observer.schedule(event_handler, str(log_dir), recursive=False)
        self.observer.start()
        
        # Initial check
        if self.log_file.exists():
            self.process_new_logs()
        
        # Keep thread alive
        Thread(target=self._watchdog_monitor_loop, daemon=True).start()
    
    def _watchdog_monitor_loop(self) -> None:
        """Background loop for watchdog monitoring."""
        while self.running:
            if not self.log_file.exists():
                logger.warning(f"Log file missing: {self.log_file}. Waiting for it to appear...")
                self.alerts = []
            time.sleep(10)
    
    def _start_polling(self) -> None:
        """Start monitoring using polling as a fallback."""
        logger.info("Using polling for file monitoring (watchdog unavailable or disabled)")
        Thread(target=self._polling_loop, daemon=True).start()
    
    def _polling_loop(self) -> None:
        """Polling loop for file monitoring with adaptive intervals."""
        while self.running:
            self.process_new_logs()
            time.sleep(self.current_check_interval)
    
    def process_new_logs(self) -> None:
        """Process new log entries and invoke callback for real-time alerts."""
        try:
            if not self.log_file.exists():
                self.alerts = []
                logger.warning(f"Log file {self.log_file} does not exist")
                return
            self._handle_log_rotation()
            lines = self._read_new_lines()
            logger.debug(f"Read {len(lines)} new lines: {lines}")
            if lines:
                self._process_alerts(lines)
        except Exception as e:
            logger.error(f"Error processing logs: {str(e)}")
            raise ManusSecurityError(f"Log processing failed: {str(e)}") from e

    def _handle_log_rotation(self) -> None:
        """Handle log rotation and truncation scenarios."""
        current_inode = os.stat(self.log_file).st_ino
        current_mtime = os.stat(self.log_file).st_mtime
        file_size = os.path.getsize(self.log_file)
        if self.last_inode is not None and self.last_inode != current_inode:
            logger.info("Log rotation detected, seeking last 10KB")
            self.position = max(0, file_size - 10240)
            self._process_rotated_logs()
        elif file_size < self.position:
            logger.info("Log file truncated, seeking last 10KB")
            self.position = max(0, file_size - 10240)
        elif self.last_mtime is not None and current_mtime < self.last_mtime:
            logger.info("Log file rotated too quickly, forcing full scan")
            self.position = 0
        self.last_inode = current_inode
        self.last_mtime = current_mtime
    
    def _read_new_lines(self) -> List[str]:
        """Read new lines from the log file since the last position."""
        with open(self.log_file, 'r') as f:
            f.seek(self.position)
            new_lines = []
            for _ in range(self.max_lines_per_check):
                line = f.readline()
                if not line:
                    break
                new_lines.append(line)
            if new_lines:
                self.last_activity_time = time.time()
                self._adjust_check_interval(True)
            else:
                self._adjust_check_interval(False)
            self.position = f.tell()
            CURRENT_LOG_POSITION.set(self.position)
        return new_lines
    
    def _process_alerts(self, lines: List[str]) -> None:
        """Process new log lines for alerts and invoke callback if provided."""
        new_alerts = self.matcher.scan_lines(lines)
        if new_alerts:
            self.alerts = new_alerts
            if self.alert_callback:
                self.alert_callback(new_alerts)
    
    def _adjust_check_interval(self, activity_detected: bool) -> None:
        """Adjust polling interval based on log activity."""
        current_time = time.time()
        
        if activity_detected:
            if self.current_check_interval > self.min_check_interval:
                self.current_check_interval = self.min_check_interval
                logger.debug(f"Activity detected, decreasing check interval to {self.current_check_interval}s")
        else:
            time_since_activity = current_time - self.last_activity_time
            if time_since_activity > 300:  # 5 minutes
                new_interval = min(self.current_check_interval * 1.5, self.max_check_interval)
                if new_interval > self.current_check_interval:
                    logger.debug(f"No activity for {int(time_since_activity)}s, increasing interval to {int(new_interval)}s")
                    self.current_check_interval = new_interval
    
    def _process_rotated_logs(self) -> None:
        """Process recently rotated log files."""
        log_dir = self.log_file.parent
        base = self.log_file.stem
        ext = self.log_file.suffix
        
        rotated = sorted(
            log_dir.glob(f"{base}*{ext}*"),
            key=lambda p: os.path.getmtime(p),
            reverse=True
        )
        
        count = 0
        for log_file in rotated:
            if log_file == self.log_file:
                continue
            
            if count >= self.max_rotated_files:
                break
            
            try:
                logger.info(f"Reading rotated log: {log_file}")
                with open(log_file, "r") as f:
                    lines = f.readlines()
                    logger.info(f"Processing {len(lines)} lines from {log_file}")
                    rotated_alerts = self.matcher.scan_lines(lines)
                    if rotated_alerts:
                        self.alerts.extend(rotated_alerts)
                        if self.alert_callback:
                            self.alert_callback(rotated_alerts)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to read rotated log {log_file}: {str(e)}")

class PatternMatcher:
    """Handles pattern compilation and matching."""
    
    def __init__(self, patterns: Dict[str, Union[str, Dict[str, str]]]):
        """
        Initialize the pattern matcher.
        
        Args:
            patterns: Dictionary of patterns and their metadata
        """
        self.patterns = patterns
        self.compiled_patterns = {}
        self.compile_patterns()
    
    def compile_patterns(self) -> None:
        """Compile regex patterns for improved performance."""
        self.compiled_patterns = {}
        for pattern, alert_info in self.patterns.items():
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                if isinstance(alert_info, str):
                    self.compiled_patterns[compiled] = {
                        "description": alert_info,
                        "severity": "medium"
                    }
                else:
                    self.compiled_patterns[compiled] = alert_info
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
    
    def scan_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        Scan lines for suspicious patterns and return alerts.
        """
        from datetime import datetime
        alerts = []
        
        for line in lines:
            logger.debug(f"Scanning line: {line.strip()}")
            for pattern, alert_info in self.compiled_patterns.items():
                try:
                    if pattern.search(line):
                        logger.info(f"Match found: {pattern.pattern} in line: {line.strip()}")
                        PATTERN_MATCHES.labels(pattern=pattern.pattern).inc()
                        severity = alert_info.get("severity", "medium")
                        description = alert_info.get("description", alert_info)
                        
                        log_entry = {
                            "timestamp": datetime.now().isoformat(),
                            "description": description,
                            "severity": severity,
                            "pattern": pattern.pattern,
                            "log_line": line.strip()
                        }
                        
                        alerts.append(log_entry)
                        ALERTS_TRIGGERED.inc()
                        ALERTS_BY_SEVERITY.labels(severity=severity).inc()
                    else:
                        logger.debug(f"No match for pattern {pattern.pattern} in line: {line.strip()}")
                except Exception as e:
                    logger.error(f"Error matching pattern '{pattern.pattern}': {str(e)}")
        return alerts
