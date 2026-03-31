"""Ultra-fast directory and endpoint fuzzing (ffuf)."""

import os
import glob
import json
import logging
import platform
import subprocess
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)
WORDLISTS_DIR = "wordlists"


def _find_wordlist() -> str:
    if platform.system() == "Windows":
        default = os.path.join(WORDLISTS_DIR, "directory-list-2.3-medium.txt")
        if os.path.exists(default):
            return default
        patt_lists = sorted(glob.glob(os.path.join(WORDLISTS_DIR, "patt_*.txt")))
        if patt_lists:
            return patt_lists[0]
        return default
    return "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"


# Allowed base directories for wordlists — prevent reading arbitrary files
_ALLOWED_WORDLIST_DIRS = (
    os.path.abspath(WORDLISTS_DIR),
    "/usr/share/wordlists",
    "/usr/share/seclists",
)


def _is_safe_wordlist(path: str) -> bool:
    """Check that a wordlist path resolves inside an allowed directory."""
    resolved = os.path.abspath(path)
    return any(resolved.startswith(d) for d in _ALLOWED_WORDLIST_DIRS)


def run(url: str, wordlist: str = "") -> str:
    # Validate URL scheme to prevent argument injection
    if not url.startswith(("http://", "https://")):
        return "Invalid URL: must start with http:// or https://"

    guard = scope_guard(url)
    if guard:
        return guard

    if not wordlist:
        wordlist = _find_wordlist()
    else:
        # Validate user-supplied wordlist against path traversal
        if not _is_safe_wordlist(wordlist):
            return (
                f"BLOCKED: Wordlist path '{wordlist}' is outside allowed directories. "
                f"Allowed: {', '.join(_ALLOWED_WORDLIST_DIRS)}. "
                "This prevents reading arbitrary system files."
            )

    output_path = log_path("ffuf.json")
    cmd = [
        "ffuf",
        "-u",
        url,
        "-w",
        wordlist,
        "-mc",
        "200,204,301,302,307,403",
        "-o",
        output_path,
        "-of",
        "json",
    ]

    logger.info("Running ffuf: %s (wordlist=%s)", url, wordlist)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return f"ffuf exited with code {result.returncode}\n{result.stderr[-300:]}"

        try:
            with open(output_path, encoding="utf-8") as f:
                data = json.load(f)
            results = data.get("results", [])

            if not results:
                return "ffuf done \u2013 0 endpoints found"

            summary = f"ffuf done \u2013 {len(results)} endpoints found:\n"
            for r in results[:15]:
                status = r.get("status", "?")
                found_url = r.get("url", "")
                if not found_url:
                    fuzz_val = (r.get("input") or {}).get("FUZZ", "?")
                    found_url = url.replace("FUZZ", fuzz_val)
                length = r.get("length", "?")
                summary += f"  [{status}] {found_url} ({length}b)\n"

            if len(results) > 15:
                summary += f"  ... +{len(results) - 15} more (use read_log 'ffuf.json')"

            logger.info("ffuf found %d endpoints", len(results))
            return summary.strip()
        except Exception:
            return f"ffuf done \u2013 results saved to {output_path}"

    except FileNotFoundError:
        return "[TOOL OK, BINARY MISSING] ffuf CLI is not installed on this system. Run the installer or download from github.com/ffuf/ffuf. This does NOT mean the run_ffuf tool is unavailable — it just needs the ffuf binary."
    except Exception as e:
        logger.error("ffuf error: %s", e)
        return f"ffuf error: {str(e)}"


TOOL_SPEC = {
    "name": "run_ffuf",
    "description": "Ultra-fast directory and endpoint fuzzing (ffuf). Auto-selects wordlist if not specified.",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "wordlist": {
                "type": "string",
                "description": "Wordlist path. Leave empty for auto-select.",
            },
        },
        "required": ["url"],
    },
}
