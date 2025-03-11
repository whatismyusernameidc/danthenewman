import logging
from .mistral import LLM as MistralLLM
from .openai import LLM as OpenAILLM
from app.utils.config import config  # Corrected import path

logger = logging.getLogger(__name__)

if config.llm.get("use_openai_api", False):
    LLM = OpenAILLM
    logger.info("Using OpenAI API-based LLM")
else:
    LLM = MistralLLM
    logger.info("Using local Mistral 7B LLM")
