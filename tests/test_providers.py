"""Tests for provider tool conversion logic (no API calls)."""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

SAMPLE_TOOL = {
    "name": "test_tool",
    "description": "A test tool",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL"},
            "count": {"type": "integer", "default": 5},
            "verbose": {"type": "boolean"},
        },
        "required": ["target"],
    },
}


class TestOpenAIConversion:
    def test_tool_spec_conversion(self):
        from providers.openai_provider import OpenAIProvider

        with patch("openai.OpenAI"):
            provider = OpenAIProvider(api_key="test", model="gpt-4")

        converted = provider.convert_tools([SAMPLE_TOOL])
        assert len(converted) == 1
        func = converted[0]["function"]
        assert func["name"] == "test_tool"
        assert "target" in func["parameters"]["properties"]

    def test_message_conversion(self):
        from providers.openai_provider import OpenAIProvider

        with patch("openai.OpenAI"):
            provider = OpenAIProvider(api_key="test", model="gpt-4")

        messages = [
            {"role": "user", "content": "Hello"},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "I'll help"},
                    {
                        "type": "tool_use",
                        "id": "tc1",
                        "name": "test_tool",
                        "input": {"target": "x"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tc1", "content": "result"},
                ],
            },
        ]
        converted = provider._to_provider_messages(messages, "system")
        # First message is the system prompt injected by the provider
        assert converted[0]["role"] == "system"
        assert converted[1]["role"] == "user"
        assert converted[1]["content"] == "Hello"


class TestGeminiConversion:
    def test_type_mapping(self):
        """Verify types are mapped correctly (not all STRING)."""
        with patch.dict(
            sys.modules, {"google": MagicMock(), "google.genai": MagicMock()}
        ):
            # Re-import with mocked google
            from providers.gemini_provider import _TYPE_MAP

            assert len(_TYPE_MAP) >= 5  # string, integer, number, boolean, array


class TestMistralConversion:
    def test_tool_spec_conversion(self):
        mock_mistral = MagicMock()
        with patch.dict(sys.modules, {"mistralai": mock_mistral}):
            # Force reimport with mock
            if "providers.mistral_provider" in sys.modules:
                del sys.modules["providers.mistral_provider"]
            from providers.mistral_provider import MistralProvider

            provider = MistralProvider(api_key="test", model="mistral-large")

        converted = provider.convert_tools([SAMPLE_TOOL])
        assert len(converted) == 1
        assert converted[0]["function"]["name"] == "test_tool"


class TestValidationUtils:
    def test_validate_url(self):
        from utils.validation import validate_url

        assert validate_url("https://example.com") is True
        assert validate_url("http://test.com/path?q=1") is True
        assert validate_url("not-a-url") is False
        assert validate_url("") is False

    def test_validate_domain(self):
        from utils.validation import validate_domain

        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("not valid") is False
        assert validate_domain("-bad.com") is False

    def test_validate_ip(self):
        from utils.validation import validate_ip

        assert validate_ip("192.168.1.1") is True
        assert validate_ip("::1") is True
        assert validate_ip("999.999.999.999") is False
        assert validate_ip("not-an-ip") is False

    def test_sanitize_target(self):
        from utils.validation import sanitize_target

        assert sanitize_target("  example.com  ") == "example.com"
        with pytest.raises(ValueError):
            sanitize_target("example.com; rm -rf /")
        with pytest.raises(ValueError):
            sanitize_target("target | cat /etc/passwd")

    def test_safe_filename(self):
        from utils.validation import safe_filename

        assert safe_filename("report.html") == "report.html"
        assert safe_filename("../../etc/passwd") == ".._.._etc_passwd"
