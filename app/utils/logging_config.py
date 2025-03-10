import logging
import logging.handlers
import os
import re
import hashlib
import json
import time
from cryptography.fernet import Fernet
import sys
import socket
from datetime import datetime, timezone

class LoggingManager:
    """Centralized logging management with security features"""
    
    def __init__(self, app_name='manus', log_dir=None):
        """Initialize the logging manager with secure defaults"""
        self.app_name = app_name
        
        # Set up logging directory
        if log_dir is None:
            # Default to 'logs' directory in the parent of the current directory
            self.log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        else:
            self.log_dir = log_dir
            
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Initialize loggers
        self.main_logger = logging.getLogger(self.app_name)
        self.audit_logger = self._setup_audit_logger()
        
        # Configure based on environment
        self.environment = os.environ.get(f'{self.app_name.upper()}_ENV', 'development').lower()
        self._configure_logging()
        
        # Set permissions on log directory
        self._secure_log_files()
    
    def _configure_logging(self):
        """Configure logging based on environment and security requirements"""
        # Clear any existing handlers
        self.main_logger.handlers = []
        
        # Set logging level based on environment
        if self.environment == 'production':
            self.main_logger.setLevel(logging.WARNING)
        elif self.environment == 'testing':
            self.main_logger.setLevel(logging.INFO)
        else:  # development
            self.main_logger.setLevel(logging.DEBUG)
        
        # Standard log file with rotation
        standard_log_file = os.path.join(self.log_dir, f'{self.app_name}.log')
        file_handler = logging.handlers.RotatingFileHandler(
            standard_log_file,
            maxBytes=10_485_760,  # 10MB
            backupCount=5         # Keep 5 backup files
        )
        
        # Set up formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add console handler in non-production environments
        if self.environment != 'production':
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.main_logger.addHandler(console_handler)
        
        # Add sensitive data redaction
        sensitive_redactor = SensitiveDataRedactor()
        file_handler.addFilter(sensitive_redactor)
        
        self.main_logger.addHandler(file_handler)
        
        # Set up encrypted logging based on environment variable
        encrypt_logs = os.environ.get(f'{self.app_name.upper()}_ENCRYPT_LOGS', 'false').lower() == 'true'
        # Default to encrypted in production unless explicitly disabled
        if self.environment == 'production' and os.environ.get(f'{self.app_name.upper()}_ENCRYPT_LOGS') != 'false':
            encrypt_logs = True
            
        # Allow plaintext override for debugging
        force_plaintext = os.environ.get(f'{self.app_name.upper()}_FORCE_PLAINTEXT_LOGS', 'false').lower() == 'true'
        if force_plaintext:
            encrypt_logs = False  # Allow plaintext logs in production if needed
            self.main_logger.warning("Forced plaintext logging enabled - sensitive data may be exposed")
            
        if encrypt_logs:
            encrypted_log_file = os.path.join(self.log_dir, f'{self.app_name}_encrypted.log')
            encrypted_handler = EncryptedFileHandler(encrypted_log_file)
            encrypted_handler.setFormatter(formatter)
            encrypted_handler.addFilter(sensitive_redactor)
            self.main_logger.addHandler(encrypted_handler)
            self.main_logger.info("Logging with encryption enabled")
    
    def _setup_audit_logger(self):
        """Set up the audit logger for security events"""
        return AuditLogger(os.path.join(self.log_dir, 'audit.log'))
    
    def _secure_log_files(self):
        """Ensure log files have appropriate permissions"""
        try:
            # Restrict permissions to owner only (won't work on Windows)
            if os.name != 'nt':  # Skip on Windows
                for file in os.listdir(self.log_dir):
                    if file.endswith('.log') or file == '.log_key':
                        os.chmod(os.path.join(self.log_dir, file), 0o600)
        except Exception as e:
            # Log but don't fail if permissions can't be set
            self.main_logger.error(f"Failed to set secure permissions on log files: {str(e)}")
    
    def get_logger(self):
        """Get the configured main logger"""
        return self.main_logger
    
    def get_audit_logger(self):
        """Get the configured audit logger"""
        return self.audit_logger
    
    def log_audit_event(self, user_id, action, resource, details=None):
        """Convenience method to log an audit event"""
        self.audit_logger.log_event(user_id, action, resource, details)


class SensitiveDataRedactor(logging.Filter):
    """Filter to redact sensitive data from log messages"""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            # Authentication data
            r'\b(api[_-]?key|apiKey|userKey)\b\s*[=:]\s*[\w\-\.]+': '[REDACTED_API_KEY]',
            r'\b(password|passwd|pwd|passcode)\b\s*[=:]\s*\S+': '[REDACTED_PASSWORD]',
            r'\b(secret|private[_-]?key|privateKey)\b\s*[=:]\s*\S+': '[REDACTED_SECRET]',
            r'\b(token|auth[_-]?token|jwt)\b\s*[=:]\s*\S+': '[REDACTED_TOKEN]',
            r'\b(auth[_-]?token|authToken|bearer)\b\s*[=:]\s*\S+': '[REDACTED_AUTH_TOKEN]',
            
            # Personal identifiable information (PII)
            r'\b(?:\d{3}-\d{2}-\d{4})\b': '[REDACTED_SSN]',  # Social Security Number
            r'\b(?:\d{16}|\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4})\b': '[REDACTED_CC]',  # Credit Card
            r'\b(user[_-]?name|userName|userId)\b\s*[=:]\s*\S+': '[REDACTED_USERNAME]',
            
            # Email addresses and URLs with credentials
            r'\b[\w\.-]+@[\w\.-]+\.\w+\b': '[REDACTED_EMAIL]',  # Email
            r'https?://[^:]+:[^@]+@': '[REDACTED_URL_WITH_CREDENTIALS]',  # URL with credentials
            
            # Additional sensitive fields
            r'\b(access[_-]?key|accessKey)\b\s*[=:]\s*\S+': '[REDACTED_ACCESS_KEY]',
            r'\b(private[_-]?key|privateKey)\b\s*[=:]\s*\S+': '[REDACTED_PRIVATE_KEY]'
        }
        self.compiled_patterns = {re.compile(pattern, re.IGNORECASE): replacement
                                for pattern, replacement in self.patterns.items()}
    
    def filter(self, record):
        """Filter log records to redact sensitive information while preserving JSON structure"""
        if isinstance(record.msg, str):
            # Check if the message is JSON
            try:
                log_data = json.loads(record.msg)
                # Handle JSON data - redact specific keys
                self._redact_json_data(log_data)
                record.msg = json.dumps(log_data)
            except json.JSONDecodeError:
                # Not JSON, apply regex patterns
                message = record.msg
                for pattern, replacement in self.compiled_patterns.items():
                    message = pattern.sub(replacement, message)
                record.msg = message
        elif hasattr(record, 'getMessage'):
            message = record.getMessage()
            # Try to parse as JSON
            try:
                log_data = json.loads(message)
                self._redact_json_data(log_data)
                record.msg = json.dumps(log_data)
                record.args = ()
            except json.JSONDecodeError:
                # Apply regex patterns
                for pattern, replacement in self.compiled_patterns.items():
                    message = pattern.sub(replacement, message)
                record.msg = message
                record.args = ()
        return True
    
    def _redact_json_data(self, data):
        """Recursively redact sensitive fields in JSON data"""
        sensitive_keys = {
            'password', 'api_key', 'secret', 'token', 'auth_token', 
            'access_key', 'private_key', 'credit_card', 'ssn', 'email'
        }
        
        if isinstance(data, dict):
            for key, value in list(data.items()):
                # Check if the key is sensitive
                if any(pattern in key.lower() for pattern in sensitive_keys):
                    data[key] = "[REDACTED]"
                # Recursively process nested structures
                elif isinstance(value, (dict, list)):
                    self._redact_json_data(value)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._redact_json_data(item)


class EncryptedFileHandler(logging.FileHandler):
    """File handler that encrypts log entries"""
    
    def __init__(self, filename, mode='a', encoding=None, delay=False):
        """Initialize with encryption key management"""
        # Set up key file in the same directory as the log file
        key_file = os.path.join(os.path.dirname(filename), '.log_key')
        
        # Use existing key or generate a new one
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
            # Secure the key file
            if os.name != 'nt':  # Skip on Windows
                os.chmod(key_file, 0o600)
        
        self.encryptor = Fernet(self.key)
        super().__init__(filename, mode, encoding, delay)
    
    def emit(self, record):
        """Encrypt and emit the log record"""
        try:
            msg = self.format(record)
            encrypted_msg = self.encryptor.encrypt(msg.encode())
            self.stream.write(encrypted_msg.decode() + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)
    
    @staticmethod
    def decrypt_log(encrypted_file, key_file, output_file=None):
        """Utility method to decrypt a log file"""
        # Read the encryption key
        with open(key_file, 'rb') as f:
            key = f.read()
        
        decryptor = Fernet(key)
        
        # Set up output file if not provided
        if output_file is None:
            output_file = encrypted_file + '.decrypted'
        
        # Decrypt the file
        with open(encrypted_file, 'r') as in_file, open(output_file, 'w') as out_file:
            for line in in_file:
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        decrypted = decryptor.decrypt(line.encode()).decode()
                        out_file.write(decrypted + '\n')
                    except Exception as e:
                        out_file.write(f"[DECRYPTION ERROR: {str(e)}]\n")
        
        return output_file


class AuditLogger:
    """Logger for security-relevant events with integrity verification"""
    
    def __init__(self, log_file):
        """Initialize with log file path"""
        self.log_file = log_file
    
    def log_event(self, user_id, action, resource, details=None):
        """Log a security-relevant event with integrity hash"""
        # Use UTC time with ISO 8601 format for consistent timestamps
        timestamp = time.time()
        utc_dt = datetime.now(timezone.utc)
        
        event = {
            'timestamp': timestamp,
            'datetime': utc_dt.isoformat(),
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'details': details or {},
            'client_ip': self._get_client_ip()
        }
        
        # Create integrity hash of the event data
        event_str = json.dumps(event, sort_keys=True)
        event['integrity_hash'] = hashlib.sha256(event_str.encode()).hexdigest()
        
        # Write to audit log
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def _get_client_ip(self):
        """Retrieve system IP for local logging or environment IP if running in a web app"""
        # First check if we're in a web context
        remote_addr = os.environ.get('REMOTE_ADDR')
        if remote_addr:
            return remote_addr
            
        # If not, try to get the local machine's IP
        try:
            # Get local IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except Exception:
            # Fallback if socket methods fail
            return 'unknown'
    
    def verify_log_integrity(self):
        """Verify the integrity of the audit log file"""
        master_hash_file = os.path.join(os.path.dirname(self.log_file), 'audit_master_hash.json')
        integrity_violations = []
        log_entries = []
        
        with open(self.log_file, 'r') as f:
            for i, line in enumerate(f, 1):
                try:
                    event = json.loads(line)
                    stored_hash = event.pop('integrity_hash', None)
                    
                    if stored_hash:
                        # Recalculate hash
                        event_str = json.dumps(event, sort_keys=True)
                        calculated_hash = hashlib.sha256(event_str.encode()).hexdigest()
                        
                        if calculated_hash != stored_hash:
                            integrity_violations.append((i, "Hash mismatch"))
                    else:
                        integrity_violations.append((i, "Missing integrity hash"))
                    
                    # Store event for master hash tracking
                    log_entries.append(event)
                except Exception as e:
                    integrity_violations.append((i, f"Error: {str(e)}"))
        
        # Compute master hash
        master_hash = hashlib.sha256(json.dumps(log_entries, sort_keys=True).encode()).hexdigest()
        
        # Compare with stored master hash
        if os.path.exists(master_hash_file):
            try:
                with open(master_hash_file, 'r') as f:
                    stored_master_hash = json.load(f).get("master_hash")
                if stored_master_hash and stored_master_hash != master_hash:
                    integrity_violations.append(("Master Hash Mismatch", "Possible full log tampering!"))
            except Exception as e:
                integrity_violations.append(("Master Hash Check", f"Error checking master hash: {str(e)}"))
        
        # Update master hash file
        try:
            with open(master_hash_file, 'w') as f:
                json.dump({"master_hash": master_hash, "last_verified": datetime.now(timezone.utc).isoformat()}, f)
            # Secure the master hash file
            if os.name != 'nt':  # Skip on Windows
                os.chmod(master_hash_file, 0o600)
        except Exception as e:
            integrity_violations.append(("Master Hash Update", f"Failed to update master hash: {str(e)}"))
        
        return integrity_violations


# Utility functions
def setup_logging(app_name='manus', log_dir=None):
    """Set up and configure logging with all security features"""
    log_manager = LoggingManager(app_name, log_dir)
    return log_manager.get_logger(), log_manager.get_audit_logger()


# Example usage
if __name__ == "__main__":
    # Set up logging
    logger, audit = setup_logging()
    
    # Log some messages
    logger.debug("Debug message")
    logger.info("Information message")
    logger.warning("Warning message with password=secret123")
    logger.error("Error occurred with api_key=abcdef123456")
    
    # Log an audit event
    audit.log_event("user123", "LOGIN", "/api/auth", {"success": True, "ip": "192.168.1.1"})
