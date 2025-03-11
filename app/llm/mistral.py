from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import logging
import os
from app.utils.config import config  # Corrected import path

class LLM:
    """Mistral 7B Local Model Wrapper"""
    def __init__(self):
        try:
            # Safely access Mistral configuration with defaults
            mistral_config = config.llm.get("mistral", {})
            self.model_name = mistral_config.get("model", "mistralai/Mixtral-8x7B-Instruct-v0.1")  # Default model
            self.model_path = mistral_config.get("model_path", None) or self.model_name

            # Validate local model path if provided
            if self.model_path != self.model_name and not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Local model path '{self.model_path}' does not exist.")

            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForCausalLM.from_pretrained(self.model_path)

            # Set device and data type
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            dtype = torch.float16 if self.device == "cuda" else torch.float32
            self.model.to(self.device, dtype=dtype)
            logging.info(f"Initialized Mistral 7B on {self.device} with dtype {dtype}")
        except Exception as e:
            logging.error(f"Failed to initialize Mistral 7B: {e}")
            raise

    def ask(self, prompt: str) -> str:
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=config.llm["mistral"].get("max_tokens", 1024),  # Default if key missing
                temperature=config.llm["mistral"].get("temperature", 0.7)      # Default if key missing
            )
            return self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        except Exception as e:
            logging.error(f"Error generating response from Mistral 7B: {e}")
            raise
