from google import genai
from google.genai import types
from .base import BaseLLMProvider

# Map JSON Schema types to Gemini types
_TYPE_MAP = {
    "string": types.Type.STRING,
    "integer": types.Type.INTEGER,
    "number": types.Type.NUMBER,
    "boolean": types.Type.BOOLEAN,
    "array": types.Type.ARRAY,
    "object": types.Type.OBJECT,
}


class GeminiProvider(BaseLLMProvider):
    DEFAULT_MODEL = "gemini-3.0-pro"

    def __init__(self, api_key: str, model: str = None):
        self.client = genai.Client(api_key=api_key)
        self.model_name = model or self.DEFAULT_MODEL

    def _convert_schema(self, prop: dict) -> types.Schema:
        """Convert a JSON Schema property to a Gemini Schema."""
        json_type = prop.get("type", "string")
        gemini_type = _TYPE_MAP.get(json_type, types.Type.STRING)

        kwargs = {"type": gemini_type}
        if "description" in prop:
            kwargs["description"] = prop["description"]

        # Handle array items
        if json_type == "array" and "items" in prop:
            kwargs["items"] = self._convert_schema(prop["items"])

        return types.Schema(**kwargs)

    def convert_tools(self, tools: list) -> list:
        declarations = []
        for t in tools:
            props = {}
            for k, v in t["input_schema"].get("properties", {}).items():
                props[k] = self._convert_schema(v)

            declarations.append(
                types.FunctionDeclaration(
                    name=t["name"],
                    description=t["description"],
                    parameters=types.Schema(
                        type=types.Type.OBJECT,
                        properties=props,
                        required=t["input_schema"].get("required", []),
                    ),
                )
            )
        return [types.Tool(function_declarations=declarations)]

    def _to_provider_contents(self, messages: list) -> list:
        id_to_name: dict = {}
        for msg in messages:
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if block.get("type") == "tool_use":
                        id_to_name[block["id"]] = block["name"]

        contents = []
        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if role == "user":
                if isinstance(content, str):
                    contents.append(
                        types.Content(role="user", parts=[types.Part(text=content)])
                    )
                elif isinstance(content, list):
                    parts = []
                    for block in content:
                        if block.get("type") == "tool_result":
                            fn_name = id_to_name.get(block["tool_use_id"], "tool")
                            parts.append(
                                types.Part(
                                    function_response=types.FunctionResponse(
                                        name=fn_name,
                                        response={"result": block["content"]},
                                    )
                                )
                            )
                    if parts:
                        contents.append(types.Content(role="user", parts=parts))

            elif role == "assistant":
                parts = []
                if isinstance(content, str):
                    parts.append(types.Part(text=content))
                elif isinstance(content, list):
                    for block in content:
                        if block.get("type") == "text":
                            parts.append(types.Part(text=block["text"]))
                        elif block.get("type") == "tool_use":
                            parts.append(
                                types.Part(
                                    function_call=types.FunctionCall(
                                        name=block["name"],
                                        args=block["input"],
                                    )
                                )
                            )
                if parts:
                    contents.append(types.Content(role="model", parts=parts))

        return contents

    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        contents = self._to_provider_contents(messages)

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                tools=tools,
                temperature=0.0,
            ),
        )

        text_blocks = []
        tool_calls = []

        try:
            parts = response.candidates[0].content.parts
        except (IndexError, AttributeError):
            import logging

            logging.getLogger(__name__).error("Gemini returned no candidates")
            return [], []

        for i, part in enumerate(parts):
            if hasattr(part, "text") and part.text:
                text_blocks.append(part.text)
            if (
                hasattr(part, "function_call")
                and part.function_call
                and part.function_call.name
            ):
                fc = part.function_call
                tool_calls.append(
                    {
                        "id": f"gemini-{fc.name}-{i}",
                        "name": fc.name,
                        "input": dict(fc.args),
                    }
                )

        return text_blocks, tool_calls
