# agent/claude_client.py
import logging
from anthropic import Anthropic
from tools import ALL_TOOLS

class ClaudeClient:
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.client = Anthropic(api_key=api_key)
        self.model = model
        self.tools = ALL_TOOLS

    def think(self, messages: list, system_prompt: str, max_tokens: int = 8192):
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0.0,
            system=system_prompt,
            messages=messages,
            tools=self.tools,
            tool_choice={"type": "auto"}
        )

        new_messages = messages.copy()

        for content in response.content:
            if content.type == "text":
                print("🤖 Phantom :", content.text)
                new_messages.append({"role": "assistant", "content": content.text})
                logging.info(f"Claude reasoning: {content.text[:300]}...")

            elif content.type == "tool_use":
                tool_name = content.name
                tool_input = content.input
                tool_id = content.id

                logging.info(f"🔧 Execution : {tool_name}")

                # Mapping to real fonctions
                from tools import nuclei, sqlmap, ffuf, recon, set_phish, cleanup
                mapping = {
                    "run_bettercap": bettercap.run,  # from tools import bettercap
                    "generate_zphisher_template": zphisher.run,
                    "run_cyberstrike": cyberstrike.run
                    "run_nuclei": nuclei.run,
                    "run_sqlmap": sqlmap.run,
                    "run_ffuf": ffuf.run,
                    "run_recon": recon.run,
                    "generate_phish_template": set_phish.run,
                    "cleanup_temp": cleanup.run    
                }
                tool_func = mapping.get(tool_name)

                if tool_func:
                    try:
                        result = tool_func(**tool_input)
                        tool_result = {
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": str(result)
                        }
                        new_messages.append({"role": "user", "content": [tool_result]})
                    except Exception as e:
                        error_msg = f"Erreur {tool_name}: {str(e)}"
                        new_messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": error_msg}]})
                        logging.error(error_msg)
                else:
                    logging.warning(f"Tool inconnu : {tool_name}")

        return new_messages
