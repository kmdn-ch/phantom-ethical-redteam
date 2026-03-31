import json
import logging
from mistralai import Mistral
from .base import BaseLLMProvider

logger = logging.getLogger(__name__)


class MistralProvider(BaseLLMProvider):
    DEFAULT_MODEL = "mistral-large-latest"

    def __init__(self, api_key: str, model: str = None):
        self.client = Mistral(api_key=api_key, timeout=self.TIMEOUT)
        self.model = model or self.DEFAULT_MODEL

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
                if isinstance(content, list):
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
                    entry = {"role": "assistant", "content": text}
                    if tool_calls:
                        entry["tool_calls"] = tool_calls
                    converted.append(entry)
                else:
                    converted.append({"role": "assistant", "content": str(content)})

        return converted

    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        response = self.client.chat.complete(
            model=self.model,
            messages=self._to_provider_messages(messages, system_prompt),
            tools=tools,
            tool_choice="auto",
            temperature=0.0,
        )

        if not response.choices:
            logger.error("Mistral API returned no choices")
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
