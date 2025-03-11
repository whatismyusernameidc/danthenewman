from typing import Dict, List, Literal, Optional, Union
from openai import AsyncAzureOpenAI, AsyncOpenAI, AuthenticationError, OpenAIError
from tenacity import retry, stop_after_attempt, wait_random_exponential
from app.utils.config import config  # Corrected path
from app.logger import logger
from app.utils.schema import Message  # Corrected path
from app.security.vault_manager import get_secret

class LLM:
    """OpenAI API LLM Wrapper"""
    _instances: Dict[str, "LLM"] = {}

    def __new__(cls, config_name: str = "default"):
        if config_name not in cls._instances:
            instance = super().__new__(cls)
            instance.__init__(config_name)
            cls._instances[config_name] = instance
        return cls._instances[config_name]

    def __init__(self, config_name: str = "default"):
        if not hasattr(self, "client"):
            llm_config = config.llm.get(config_name, config.llm["default"])
            self.api_type = llm_config["openai"].get("api_type", "openai")
            
            # Fetch API key from Vault with fallback to config.yaml
            try:
                self.api_key = get_secret(llm_config["openai"]["vault_api_key"])
                if not self.api_key:
                    raise ValueError("Vault API key is empty")
            except Exception as e:
                logger.warning(f"Vault access failed: {e}. Using config API key as fallback.")
                self.api_key = llm_config["openai"].get("api_key")
                if not self.api_key:
                    raise ValueError("API key is missing. Check Vault or config.yaml.")
            
            self.api_version = llm_config["openai"].get("api_version", None)
            self.base_url = llm_config["openai"].get("base_url", None)
            self.model = llm_config["openai"]["model"]
            self.max_tokens = llm_config["openai"]["max_tokens"]
            self.temperature = llm_config["openai"]["temperature"]
            
            if self.api_type == "azure":
                self.client = AsyncAzureOpenAI(
                    base_url=self.base_url,
                    api_key=self.api_key,
                    api_version=self.api_version,
                )
            else:
                self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
            logger.info("Initialized OpenAI API-based LLM")

    @staticmethod
    def format_messages(messages: List[Union[dict, Message]]) -> List[dict]:
        formatted_messages = []
        for message in messages:
            if isinstance(message, dict):
                if "role" not in message:
                    raise ValueError("Message dict must contain 'role' field")
                formatted_messages.append(message)
            elif isinstance(message, Message):
                formatted_messages.append(message.to_dict())
            else:
                raise TypeError(f"Unsupported message type: {type(message)}")
        for msg in formatted_messages:
            if msg["role"] not in ["system", "user", "assistant", "tool"]:
                raise ValueError(f"Invalid role: {msg['role']}")
            if "content" not in msg and "tool_calls" not in msg:
                raise ValueError("Message must contain either 'content' or 'tool_calls'")
        return formatted_messages

    @retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(6))
    async def ask(self, messages: List[Union[dict, Message]], system_msgs: Optional[List[Union[dict, Message]]] = None, stream: bool = True, temperature: Optional[float] = None) -> str:
        try:
            if system_msgs:
                messages = self.format_messages(system_msgs) + self.format_messages(messages)
            else:
                messages = self.format_messages(messages)
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=temperature or self.temperature,
                stream=stream,
            )
            if not stream:
                if not response.choices or not response.choices[0].message.content:
                    raise ValueError("Empty or invalid response from LLM")
                return response.choices[0].message.content
            collected_messages = []
            async for chunk in response:
                chunk_message = chunk.choices[0].delta.content or ""
                collected_messages.append(chunk_message)
            full_response = "".join(collected_messages).strip()
            if not full_response:
                raise ValueError("Empty response from streaming LLM")
            return full_response
        except AuthenticationError:
            logger.error("OpenAI authentication failed. Attempting to refresh API key.")
            try:
                self.api_key = get_secret(config.llm["openai"]["vault_api_key"])
                if not self.api_key:
                    raise ValueError("Vault API key is empty")
            except Exception as vault_error:
                logger.warning(f"Vault refresh failed: {vault_error}. Using config API key.")
                self.api_key = config.llm["openai"].get("api_key")
                if not self.api_key:
                    raise ValueError("API key is missing after refresh attempt.")
            self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
            raise
        except OpenAIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in ask: {e}")
            raise
