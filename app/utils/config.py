from dataclasses import dataclass
import yaml
import os
import logging

@dataclass
class Config:
    """Configuration class with default values for the AI system."""
    # LLM parameters
    model_name: str = "gpt2"
    device: str = "auto"
    max_tokens: int = 8192
    max_new_tokens: int = 1000
    temperature: float = 0.8
    top_k: int = 40
    top_p: float = 0.9
    repetition_penalty: float = 1.2
    no_repeat_ngram_size: int = 3
    # Memory parameters
    max_memories: int = 20000
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_batch_size: int = 32
    similarity_threshold: float = 0.25
    memory_decay_rate: float = 0.001
    memory_favorites_boost: float = 0.7
    # System behavior parameters
    response_depth: float = 0.8
    curiosity_level: float = 0.7
    formality: float = 0.5
    adaptation_rate: float = 0.05
    # System parameters
    retry_attempts: int = 3
    retry_delay: float = 1.0
    log_level: str = "INFO"
    max_input_length: int = 2000
    session_timeout: int = 3600
    max_worker_threads: int = 8
    task_queue_size: int = 200
    request_timeout: int = 45
    max_concurrent_sessions: int = 20

    def validate(self) -> tuple[bool, str]:
        """Validate configuration parameters."""
        if not 0 <= self.temperature <= 2.0:
            return False, f"Temperature must be between 0 and 2.0, got {self.temperature}"
        if not 0 <= self.top_p <= 1.0:
            return False, f"Top_p must be between 0 and 1.0, got {self.top_p}"
        if self.device not in ["auto", "cpu", "cuda", "mps"]:
            return False, f"Device must be one of 'auto', 'cpu', 'cuda', or 'mps', got {self.device}"
        if self.max_worker_threads < 1:
            return False, f"Max worker threads must be at least 1, got {self.max_worker_threads}"
        if self.task_queue_size < 1:
            return False, f"Task queue size must be at least 1, got {self.task_queue_size}"
        return True, "Configuration valid"

def load_config(file_path: str = "app/config/config.yaml") -> Config:
    """
    Load configuration from YAML with fallback to defaults.
    
    Args:
        file_path: Path to the YAML configuration file.
    Returns:
        Config object with loaded or default values.
    """
    config = Config()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
            for k, v in data.items():
                if hasattr(config, k):
                    setattr(config, k, v)
                else:
                    logging.warning(f"Unknown configuration parameter: {k}")
            valid, message = config.validate()
            if not valid:
                logging.error(f"Configuration validation failed: {message}")
                logging.warning("Using default configuration")
                config = Config()
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            logging.warning("Using default configuration")
    else:
        logging.info(f"Configuration file {file_path} not found, using defaults")
    return config
