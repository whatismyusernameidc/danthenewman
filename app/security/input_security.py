import re
import logging
from typing import Tuple, Optional
from app.utils.config import Config

class InputSecurityManager:
    """Robust input validation and sanitization."""
    def __init__(self, config: Config):
        self.config = config
        self.blocked_patterns = [
            r'<script.*?>.*?</script>', r'javascript:', r'eval\s*\(', r'exec\s*\(',
            r'subprocess', r'open\s*\(.+?,\s*[\'"]w[\'"]'
        ]
        self.compiled_patterns = [re.compile(p) for p in self.blocked_patterns]
        self.request_history = []
        self.rate_limit_window = 60
        self.rate_limit_max = 30
        logging.info("Security manager initialized")

    def validate_input(self, text: str, ip_address: str = "unknown") -> Tuple[bool, str]:
        """Validate input for security issues."""
        if len(text) > self.config.max_input_length:
            return False, f"Input too long (max {self.config.max_input_length} characters)"
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                logging.warning(f"Blocked pattern detected in input from {ip_address}")
                return False, "Potentially harmful content detected"
        return True, ""

    def sanitize_input(self, text: str) -> str:
        """Sanitize input to remove harmful content."""
        sanitized = text.strip()
        for pattern in self.compiled_patterns:
            sanitized = pattern.sub("[BLOCKED]", sanitized)
        return sanitized
