import uuid
import time
import threading
import logging
from typing import Dict, Tuple, Optional
from app.utils.config import load_config
from app.agent.complex_chat_engine import ComplexChatEngine

class SessionManager:
    """Manages multiple chat sessions."""
    def __init__(self, config_path: str = "app/config/config.yaml"):
        self.config = load_config(config_path)
        self.sessions: Dict[str, ComplexChatEngine] = {}
        self.session_timestamps: Dict[str, float] = {}
        self.session_locks: Dict[str, threading.Lock] = {}
        self.max_sessions = self.config.max_concurrent_sessions

    def get_session(self, session_id: Optional[str] = None) -> Tuple[str, ComplexChatEngine]:
        """Get or create a session."""
        if session_id not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                oldest_id = min(self.session_timestamps, key=self.session_timestamps.get)
                del self.sessions[oldest_id]
                del self.session_timestamps[oldest_id]
                del self.session_locks[oldest_id]
            new_id = str(uuid.uuid4())
            self.sessions[new_id] = ComplexChatEngine(self.config)
            self.session_timestamps[new_id] = time.time()
            self.session_locks[new_id] = threading.Lock()
            return new_id, self.sessions[new_id]
        self.session_timestamps[session_id] = time.time()
        return session_id, self.sessions[session_id]

    def process_message(self, message: str, session_id: Optional[str] = None, ip_address: str = "unknown") -> Tuple[str, str]:
        """Process a message with session management."""
        sid, session = self.get_session(session_id)
        with self.session_locks[sid]:
            response = session.process_message(message, ip_address)
        return response, sid
