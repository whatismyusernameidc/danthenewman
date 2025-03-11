import uuid
import time
import logging
from typing import List, Dict, Any
from app.utils.config import Config
from app.llm.mistral import LLM as TransformersLocalLLM
from app.llm.memory_vector_store import MemoryVectorStore
from app.security.input_security import InputSecurityManager

GLOBAL_INSTRUCTION = """
You are a local AI system designed to:
1. Understand the user's context, intent, and interaction patterns
2. Provide valuable, contextually relevant information
3. Maintain a coherent memory of past interactions
4. Adapt your response style and depth to match user preferences
"""

class ComplexChatEngine:
    """Core chat engine with context management."""
    def __init__(self, config: Config):
        self.config = config
        self.llm = TransformersLocalLLM(config)
        self.memory = MemoryVectorStore(config)
        self.security = InputSecurityManager(config)
        self.history: List[Dict[str, Any]] = []
        self.session_id = str(uuid.uuid4())
        self.last_activity = time.time()
        self.memory.add(GLOBAL_INSTRUCTION, "system", {"relevance": 1.0, "mood": "neutral"})
        logging.info(f"Chat engine initialized with session ID: {self.session_id}")

    def _build_prompt(self, user_input: str) -> str:
        """Build a prompt with context and memory."""
        prompt_parts = [GLOBAL_INSTRUCTION, "\nRecent Conversation:"]
        for msg in self.history[-10:]:
            role_display = "User" if msg["role"] == "user" else "System"
            prompt_parts.append(f"{role_display}: {msg['text']}")
        memories = self.memory.retrieve(user_input)
        if memories["long"]:
            prompt_parts.append("\nRelevant Past Context:")
            for mem in memories["long"][:3]:
                prompt_parts.append(f"- {mem['text']} (Relevance: {mem['similarity']:.2f})")
        prompt_parts.append(f"\nUser: {user_input}\nSystem: ")
        return "\n".join(prompt_parts)

    def process_message(self, user_input: str, ip_address: str = "unknown") -> str:
        """Process a user message and generate a response."""
        valid, message = self.security.validate_input(user_input, ip_address)
        if not valid:
            return f"I couldn't process that input: {message}"
        clean_input = self.security.sanitize_input(user_input)
        self.history.append({"role": "user", "text": clean_input, "timestamp": time.time()})
        self.memory.add(clean_input, "user", {"mood": "neutral", "relevance": 0.9})
        prompt = self._build_prompt(clean_input)
        response = self.llm.generate_response(prompt, stop_sequences=["User:"])
        self.history.append({"role": "assistant", "text": response, "timestamp": time.time()})
        self.memory.add(response, "assistant", {"mood": "response", "relevance": 0.8})
        return response

    def chat(self):
        """Start an interactive CLI chat session."""
        print("System: Ready for interaction. How can I help you today?")
        while True:
            user_input = input("You: ").strip()
            if user_input.lower() in ["exit", "quit"]:
                print("System: Goodbye.")
                break
            if user_input:
                response = self.process_message(user_input)
                print(f"System: {response}")
