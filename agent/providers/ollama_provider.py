import json
import logging
import ollama as ollama_client
from .base import BaseLLMProvider

logger = logging.getLogger(__name__)


class OllamaProvider(BaseLLMProvider):
    """Local inference via Ollama (llama3.1, mistral, qwen2.5, etc.)."""

    DEFAULT_MODEL = "llama3.1"

    def __init__(self, model: str = None, host: str = "http://localhost:11434", timeout: int = None):
        self.model = model or self.DEFAULT_MODEL
        self.host = host
        # Local models need more time — default to 300s for Ollama
        self._timeout = timeout or 300
        self._client = ollama_client.Client(host=host, timeout=self._timeout)

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
                            converted.append({
                                "role": "tool",
                                "content": block["content"],
                            })

            elif role == "assistant":
                if isinstance(content, list):
                    text = " ".join(
                        b.get("text", "") for b in content if b.get("type") == "text"
                    )
                    tool_calls = [
                        {
                            "function": {
                                "name": b["name"],
                                "arguments": b["input"],
                            }
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
        response = self._client.chat(
            model=self.model,
            messages=self._to_provider_messages(messages, system_prompt),
            tools=tools,
        )

        msg = response.message
        text_blocks = [msg.content] if msg.content else []
        tool_calls = []

        if msg.tool_calls:
            for i, tc in enumerate(msg.tool_calls):
                args = tc.function.arguments
                if not isinstance(args, dict):
                    try:
                        args = json.loads(args)
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.error("Malformed tool arguments for %s: %s", tc.function.name, e)
                        args = {}
                tool_calls.append({
                    "id": f"ollama-{tc.function.name}-{i}",
                    "name": tc.function.name,
                    "input": args,
                })

        # Fallback: if no structured tool calls but text contains XML-style calls
        if not tool_calls and text_blocks:
            full_text = " ".join(text_blocks)
            if "<invoke" in full_text:
                tool_calls = self._parse_xml_tool_calls(full_text)
                if tool_calls:
                    logger.info("Parsed %d XML-style tool call(s) from model output", len(tool_calls))
                    import re
                    cleaned = re.sub(
                        r'<function_calls>.*?</function_calls>',
                        '',
                        full_text,
                        flags=re.DOTALL,
                    ).strip()
                    text_blocks = [cleaned] if cleaned else []

        return text_blocks, tool_calls

    def _parse_xml_tool_calls(self, text: str) -> list[dict]:
        """Fallback: parse XML-style tool calls that some models emit instead of structured calls."""
        import re
        tool_calls = []
        invoke_pattern = re.compile(
            r'<invoke\s+name="([^"]+)">\s*(.*?)\s*</invoke>',
            re.DOTALL,
        )
        param_pattern = re.compile(
            r'<parameter\s+name="([^"]+)"[^>]*>([^<]*)</parameter>'
        )
        for i, match in enumerate(invoke_pattern.finditer(text)):
            tool_name = match.group(1)
            params_block = match.group(2)
            params = {}
            for pm in param_pattern.finditer(params_block):
                key = pm.group(1)
                value = pm.group(2).strip()
                if value.lower() in ("true", "false"):
                    params[key] = value.lower() == "true"
                else:
                    try:
                        params[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        params[key] = value
            tool_calls.append({
                "id": f"ollama-xml-{tool_name}-{i}",
                "name": tool_name,
                "input": params,
            })
        return tool_calls
