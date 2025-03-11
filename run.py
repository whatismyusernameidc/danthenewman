#!/usr/bin/env python3
import argparse
import logging
import os
import signal
import sys
import threading
from app.utils.logging import setup_logging
from app.utils.config import load_config
from app.api.web_service import WebService
from app.agent.complex_chat_engine import ComplexChatEngine

def main():
    """Main execution function for the AI system."""
    # Initial minimal logging setup (console only) to catch early errors
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.StreamHandler()])

    parser = argparse.ArgumentParser(description="Manus AI System")
    parser.add_argument("--config", type=str, default="app/config/config.yaml", help="Path to configuration file")
    parser.add_argument("--web", action="store_true", help="Run as web service")
    parser.add_argument("--port", type=int, default=5000, help="Port for web service")
    parser.add_argument("--env", type=str, default="development", choices=["development", "testing", "production"], 
                        help="Deployment environment")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Reconfigure logging based on loaded config
    setup_logging(config)  # Pass config to update log file handlers
    logging.getLogger().setLevel(getattr(logging, config.get('logging', {}).get('level', 'INFO').upper()))

    # Override config with environment variables
    for param_name in dir(config):
        if param_name.startswith('_'):
            continue
        env_var_name = f"AILOCAL_{param_name.upper()}"
        if env_var_name in os.environ:
            env_value = os.environ[env_var_name]
            param_type = type(getattr(config, param_name, str))  # Default to str if not found
            try:
                if param_type == bool:
                    value = env_value.lower() in ('true', 'yes', '1')
                else:
                    value = param_type(env_value)
                setattr(config, param_name, value)
                logging.info(f"Overriding {param_name} from environment variable: {value}")
            except ValueError:
                logging.warning(f"Could not convert {env_var_name}={env_value} to {param_type}")

    # Set up signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logging.info(f"Received signal {sig}, shutting down gracefully")
        if 'web_service' in locals():
            web_service._shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Optional: Monitor system resources if psutil is available
    try:
        import psutil
        def monitor_resources():
            while True:
                try:
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory_percent = psutil.virtual_memory().percent
                    if cpu_percent > 90 or memory_percent > 90:
                        logging.warning(f"High resource usage: CPU {cpu_percent}%, Memory {memory_percent}%")
                    time.sleep(60)
                except Exception as e:
                    logging.error(f"Resource monitoring error: {e}")
                    break
        monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
        monitor_thread.start()
    except ImportError:
        logging.info("psutil not available, resource monitoring disabled")

    if args.web:
        web_service = WebService(config, args.port)
        web_service.start()
    else:
        engine = ComplexChatEngine(config)
        engine.chat()

if __name__ == "__main__":
    main()
