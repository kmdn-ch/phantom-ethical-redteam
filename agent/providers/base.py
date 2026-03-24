import time
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):

    # Subclasses can override these defaults
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0
    TIMEOUT = 120  # seconds — used by subclasses that support it

    @abstractmethod
    def convert_tools(self, tools: list) -> list:
        """Convert Anthropic-format tool specs to this provider's format."""

    @abstractmethod
    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        """
        Make one API call.
        Args:
            messages: conversation in standard (Anthropic-compatible) format
            system_prompt: system string
            tools: tools already converted by convert_tools()
        Returns:
            (text_blocks: list[str], tool_calls: list[dict])
            tool_calls items: {"id": str, "name": str, "input": dict}
        """

    def call_with_retry(self, messages: list, system_prompt: str, tools: list) -> tuple:
        """Retry wrapper with exponential backoff for transient failures."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                return self.call(messages, system_prompt, tools)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    wait = self.RETRY_BACKOFF ** attempt
                    logger.warning(
                        "LLM API call failed (attempt %d/%d): %s — retrying in %.0fs (timeout was %ds)",
                        attempt + 1, self.MAX_RETRIES, e, wait, self.TIMEOUT,
                    )
                    time.sleep(wait)
                else:
                    logger.error(
                        "LLM API call failed after %d attempts: %s",
                        self.MAX_RETRIES, e,
                    )
        raise last_error
