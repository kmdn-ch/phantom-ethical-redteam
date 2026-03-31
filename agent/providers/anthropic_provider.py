from anthropic import Anthropic
from .base import BaseLLMProvider


class AnthropicProvider(BaseLLMProvider):
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: str = None):
        self.client = Anthropic(api_key=api_key, timeout=self.TIMEOUT)
        self.model = model or self.DEFAULT_MODEL

    def convert_tools(self, tools: list) -> list:
        return tools  # already in Anthropic format

    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            temperature=0.0,
            system=system_prompt,
            messages=messages,
            tools=tools,
            tool_choice={"type": "auto"},
        )

        text_blocks = []
        tool_calls = []

        for content in response.content:
            if content.type == "text":
                text_blocks.append(content.text)
            elif content.type == "tool_use":
                tool_calls.append(
                    {
                        "id": content.id,
                        "name": content.name,
                        "input": content.input,
                    }
                )

        return text_blocks, tool_calls
