import os
from .base import BaseLLMProvider

PROVIDERS = ["anthropic", "openai", "grok", "gemini", "ollama", "mistral", "deepseek"]


def get_provider(config: dict) -> BaseLLMProvider:
    """
    Factory — imports ONLY the selected provider's module.
    This prevents ImportError when other SDKs are not installed.
    """
    name = config.get("provider", "anthropic").lower()
    model = config.get("model") or None

    if name == "anthropic":
        from .anthropic_provider import AnthropicProvider
        api_key = os.environ.get("ANTHROPIC_API_KEY") or config.get("api_key", "")
        return AnthropicProvider(api_key=api_key, model=model or "claude-sonnet-4-6")

    if name == "openai":
        from .openai_provider import OpenAIProvider
        api_key = os.environ.get("OPENAI_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(api_key=api_key, model=model or "gpt-5.4")

    if name == "grok":
        from .openai_provider import OpenAIProvider
        api_key = os.environ.get("XAI_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(
            api_key=api_key,
            model=model or "grok-4-20-beta",
            base_url=OpenAIProvider.GROK_BASE_URL,
        )

    if name == "gemini":
        from .gemini_provider import GeminiProvider
        api_key = os.environ.get("GEMINI_API_KEY") or config.get("api_key", "")
        return GeminiProvider(api_key=api_key, model=model or "gemini-3.0-pro")

    if name == "ollama":
        from .ollama_provider import OllamaProvider
        host = config.get("ollama_host", "http://localhost:11434")
        return OllamaProvider(model=model or "deepseek-r1:3.2", host=host)

    if name == "mistral":
        from .mistral_provider import MistralProvider
        api_key = os.environ.get("MISTRAL_API_KEY") or config.get("api_key", "")
        return MistralProvider(api_key=api_key, model=model or "mistral-large-latest")

    if name == "deepseek":
        from .openai_provider import OpenAIProvider
        api_key = os.environ.get("DEEPSEEK_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(
            api_key=api_key,
            model=model or "deepseek-chat-v3.2",
            base_url=OpenAIProvider.DEEPSEEK_BASE_URL,
        )

    raise ValueError(
        f"Unknown provider '{name}'. Choose from: {', '.join(PROVIDERS)}"
    )
