"""Agentic loop with parallel tool execution and state persistence."""

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools import ALL_TOOLS, get_tool_mapping
from providers import get_provider

logger = logging.getLogger(__name__)

# Severity keywords for finding detection
_SEVERITY_RE = re.compile(
    r"\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", re.IGNORECASE
)


class AgentClient:

    def __init__(self, config: dict):
        self.provider = get_provider(config)
        self.raw_tools = ALL_TOOLS
        self.tools = self.provider.convert_tools(ALL_TOOLS)
        self.mapping = get_tool_mapping()
        self.max_parallel = config.get("max_parallel_tools", 4)
        self.compact_after = config.get("context_compact_after", 5)
        # Stall detection
        self._stall_count = 0
        self._stall_threshold = config.get("stall_threshold", 3)
        self._total_findings = 0

    def _compact_old_tool_results(self, messages: list, keep_last_n: int = 3) -> list:
        """Truncate content of old tool_result blocks to avoid context overflow."""
        tool_result_indices = [
            i for i, m in enumerate(messages)
            if m.get("role") == "user"
            and isinstance(m.get("content"), list)
            and any(b.get("type") == "tool_result" for b in m["content"])
        ]
        to_compact = set(tool_result_indices[:-keep_last_n]) if len(tool_result_indices) > keep_last_n else set()
        if not to_compact:
            return messages

        result = []
        for i, msg in enumerate(messages):
            if i in to_compact:
                compacted = []
                for block in msg["content"]:
                    if block.get("type") == "tool_result":
                        content = str(block.get("content", ""))
                        if len(content) > 400:
                            block = {**block, "content": content[:400] + " [...compacted]"}
                    compacted.append(block)
                result.append({**msg, "content": compacted})
            else:
                result.append(msg)
        return result

    def _execute_tool(self, tc: dict) -> dict:
        """Execute a single tool call and return the result block."""
        tool_func = self.mapping.get(tc["name"])
        if not tool_func:
            logger.warning("Unknown tool: %s", tc["name"])
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": f"Unknown tool: {tc['name']}",
            }

        # Validate input is a dict (LLM may return malformed arguments)
        tool_input = tc.get("input")
        if not isinstance(tool_input, dict):
            logger.warning("Tool %s received non-dict input: %s", tc["name"], type(tool_input))
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": f"Error: tool input must be a dict, got {type(tool_input).__name__}",
            }

        try:
            result = tool_func(**tool_input)
            logger.debug("AUDIT tool=%s params=%s status=ok", tc["name"], list(tool_input.keys()))
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": str(result),
            }
        except Exception as e:
            error_msg = f"Error {tc['name']}: {str(e)}"
            logger.error("AUDIT tool=%s status=error error=%s", tc["name"], e)
            return {
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": error_msg,
            }

    def _execute_tools_parallel(self, tool_calls: list) -> list:
        """Execute multiple tool calls in parallel."""
        if len(tool_calls) == 1:
            return [self._execute_tool(tool_calls[0])]

        results = [None] * len(tool_calls)
        with ThreadPoolExecutor(max_workers=min(len(tool_calls), self.max_parallel)) as executor:
            future_to_idx = {
                executor.submit(self._execute_tool, tc): i
                for i, tc in enumerate(tool_calls)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        "type": "tool_result",
                        "tool_use_id": tool_calls[idx]["id"],
                        "content": f"Execution error: {str(e)}",
                    }
        return results

    def _estimate_tokens(self, messages: list) -> int:
        """Rough token estimate (1 token ~ 4 chars)."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                for block in content:
                    total += len(str(block.get("content", "") or block.get("text", "")))
            else:
                total += len(str(content))
        return total // 4

    def _count_findings_in_text(self, text: str) -> int:
        """Count severity-tagged findings in agent text."""
        return len(_SEVERITY_RE.findall(text))

    def think(self, messages: list, system_prompt: str) -> list:
        # Proactive context compaction based on estimated size
        estimated_tokens = self._estimate_tokens(messages) + len(system_prompt) // 4
        if estimated_tokens > 50000:
            logger.info("Context large (~%dk tokens), aggressive compaction", estimated_tokens // 1000)
            messages = self._compact_old_tool_results(messages, keep_last_n=2)
        else:
            messages = self._compact_old_tool_results(messages)

        text_blocks, tool_calls = self.provider.call_with_retry(messages, system_prompt, self.tools)

        new_messages = messages.copy()

        # Build assistant message + count findings for stall detection
        assistant_blocks = []
        turn_findings = 0
        for text in text_blocks:
            print("Phantom:", text)
            logger.info("Reasoning: %s", text[:300])
            assistant_blocks.append({"type": "text", "text": text})
            turn_findings += self._count_findings_in_text(text)

        for tc in tool_calls:
            assistant_blocks.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": tc["name"],
                "input": tc["input"],
            })

        if assistant_blocks:
            new_messages.append({"role": "assistant", "content": assistant_blocks})

        # Execute tools (parallel if multiple)
        if tool_calls:
            logger.info("Executing %d tool(s): %s",
                       len(tool_calls), [tc["name"] for tc in tool_calls])
            tool_results = self._execute_tools_parallel(tool_calls)

            # Count findings in tool results
            for tr in tool_results:
                turn_findings += self._count_findings_in_text(str(tr.get("content", "")))

            if tool_results:
                new_messages.append({"role": "user", "content": tool_results})

        # Stall detection: inject guidance if no new findings for N consecutive turns
        if turn_findings > 0:
            self._stall_count = 0
            self._total_findings += turn_findings
        else:
            self._stall_count += 1

        if self._stall_count >= self._stall_threshold:
            stall_msg = (
                f"[SYSTEM] Stall detected: {self._stall_count} consecutive turns with no new findings. "
                f"Total findings so far: {self._total_findings}. "
                "Options: (1) Pivot to untested attack vectors or techniques. "
                "(2) Try different tool parameters or scan modes. "
                "(3) If all vectors exhausted, proceed to reporting phase. "
                "Do NOT repeat the same scans. Adapt or complete the mission."
            )
            logger.warning("Stall detected: %d turns without findings", self._stall_count)
            new_messages.append({"role": "user", "content": stall_msg})
            self._stall_count = 0  # Reset after injection

        return new_messages

    def save_state(self, messages: list, turn: int, session_dir: str):
        """Persist mission state for resume capability (atomic write)."""
        import os
        import tempfile
        try:
            state = {"turn": turn, "messages": messages}
            state_path = os.path.join(session_dir, "state.json")
            # Atomic write: temp file then rename — prevents corruption on crash
            fd, tmp_path = tempfile.mkstemp(dir=session_dir, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=1)
                os.replace(tmp_path, state_path)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            logger.debug("State saved at turn %d", turn)
        except Exception as e:
            logger.error("Failed to save state at turn %d: %s", turn, e)

    @staticmethod
    def load_state(session_dir: str) -> dict | None:
        """Load mission state from a session directory (with validation)."""
        import os
        state_path = os.path.join(session_dir, "state.json")
        if not os.path.exists(state_path):
            return None
        try:
            with open(state_path, encoding="utf-8") as f:
                state = json.load(f)
            if not isinstance(state, dict) or "turn" not in state or "messages" not in state:
                logger.warning("Corrupted state.json — missing required keys")
                return None
            return state
        except (json.JSONDecodeError, IOError) as e:
            logger.error("Failed to load state: %s", e)
            return None
