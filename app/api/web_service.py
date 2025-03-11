from flask import Flask, request, jsonify
import queue
import threading
import logging
from typing import Optional
from app.utils.config import load_config
from app.api.session_manager import SessionManager

class WebService:
    """Web service with task queue for scalable request handling."""
    def __init__(self, config_path: str = "app/config/config.yaml", port: int = 5000):
        self.config = load_config(config_path)
        self.port = port
        self.session_manager = SessionManager(config_path)
        self.task_queue = queue.Queue(maxsize=self.config.task_queue_size)
        self.workers = []
        self.running = False

    def _worker(self):
        """Worker thread for processing tasks."""
        while self.running:
            try:
                task = self.task_queue.get(timeout=1.0)
                message, session_id, ip_address, result_queue = task
                response, sid = self.session_manager.process_message(message, session_id, ip_address)
                result_queue.put((response, sid))
                self.task_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Worker error: {str(e)}")
                result_queue.put((f"Error: {str(e)}", None))

    def start(self):
        """Start the web service."""
        self.running = True
        for i in range(self.config.max_worker_threads):
            t = threading.Thread(target=self._worker, daemon=True, name=f"worker-{i}")
            t.start()
            self.workers.append(t)

        app = Flask(__name__)

        @app.route("/api/chat", methods=["POST"])
        def chat():
            data = request.json
            message = data.get("message", "")
            session_id = data.get("session_id")
            ip_address = request.remote_addr
            if not message:
                return jsonify({"error": "No message provided"}), 400
            result_queue = queue.Queue()
            self.task_queue.put((message, session_id, ip_address, result_queue))
            response, sid = result_queue.get(timeout=self.config.request_timeout)
            return jsonify({"response": response, "session_id": sid})

        app.run(host="0.0.0.0", port=self.port, threaded=True)
