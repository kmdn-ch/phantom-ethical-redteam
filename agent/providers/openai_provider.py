import json
import logging
from openai import OpenAI
from .base import BaseLLMProvider

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """Handles OpenAI (ChatGPT), xAI (Grok), and DeepSeek — all OpenAI-compatible APIs."""

    OPENAI_DEFAULT = "gpt-5.4"
    GROK_DEFAULT = "grok-4-20-beta"
    DEEPSEEK_DEFAULT = "deepseek-chat-v3.2"
    GROK_BASE_URL = "https://api.x.ai/v1"
    DEEPSEEK_BASE_URL = "https://api.deepseek.com"

    def __init__(self, api_key: str, model: str = None, base_url: str = None):
        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=self.TIMEOUT)
        if base_url == self.GROK_BASE_URL:
            default = self.GROK_DEFAULT
        elif base_url == self.DEEPSEEK_BASE_URL:
            default = self.DEEPSEEK_DEFAULT
        else:
            default = self.OPENAI_DEFAULT
        self.model = model or default

    def convert_tools(self, tools: list) -> list:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    def _to_provider_messages(self, messages: list, system_prompt: str) -> list:
        converted = [{"role": "system", "content": system_prompt}]
        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if role == "user":
                if isinstance(content, str):
                    converted.append({"role": "user", "content": content})
                elif isinstance(content, list):
                    for block in content:
                        if block.get("type") == "tool_result":
                            converted.append(
                                {
                                    "role": "tool",
                                    "tool_call_id": block["tool_use_id"],
                                    "content": block["content"],
                                }
                            )

            elif role == "assistant":
                if isinstance(content, str):
                    converted.append({"role": "assistant", "content": content})
                elif isinstance(content, list):
                    text = " ".join(
                        b.get("text", "") for b in content if b.get("type") == "text"
                    )
                    tool_calls = [
                        {
                            "id": b["id"],
                            "type": "function",
                            "function": {
                                "name": b["name"],
                                "arguments": json.dumps(b["input"]),
                            },
                        }
                        for b in content
                        if b.get("type") == "tool_use"
                    ]
                    entry = {"role": "assistant", "content": text or None}
                    if tool_calls:
                        entry["tool_calls"] = tool_calls
                    converted.append(entry)

        return converted

    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=self._to_provider_messages(messages, system_prompt),
            tools=tools,
            tool_choice="auto",
            temperature=0.0,
        )

        if not response.choices:
            logger.error("API returned no choices")
            return [], []

        choice = response.choices[0].message
        text_blocks = [choice.content] if choice.content else []
        tool_calls = []

        if choice.tool_calls:
            for tc in choice.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError) as e:
                    logger.error(
                        "Malformed tool arguments for %s: %s", tc.function.name, e
                    )
                    args = {}
                tool_calls.append(
                    {
                        "id": tc.id,
                        "name": tc.function.name,
                        "input": args,
                    }
                )

        return text_blocks, tool_calls
