"""PayloadsAllTheThings integration with retry support."""

import os
import logging
import requests
from pathlib import Path
from .http_utils import retry_request

logger = logging.getLogger(__name__)

# Absolute path anchored to project root — immune to launch-directory variation
_HERE = Path(__file__).parent
WORDLISTS_DIR = str(_HERE.parent.parent / "wordlists")

PATT_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

# Note: verify paths against https://github.com/swisskyrepo/PayloadsAllTheThings
# if a category returns 404, the upstream repo may have reorganized.
CATEGORIES = {
    "sqli":           "SQL%20Injection/Intruder/SQL-Injection.txt",
    "sqli-error":     "SQL%20Injection/Intruder/SQL-Injection-Error-Based.txt",
    "xss":            "XSS%20Injection/Intruder/XSS-without-HTML.txt",
    "xss-html":       "XSS%20Injection/Intruder/XSS-with-HTML.txt",
    "lfi":            "Path%20Traversal/Intruder/Linux-path-traversal.txt",
    "lfi-windows":    "Path%20Traversal/Intruder/Windows-path-traversal.txt",
    "cmdi":           "Command%20Injection/Intruder/command-execution-unix.txt",
    "cmdi-windows":   "Command%20Injection/Intruder/command-execution-windows.txt",
    "ssrf":           "Server%20Side%20Request%20Forgery/Intruder/SSRF.txt",
    "ssti":           "Server%20Side%20Template%20Injection/Intruder/Generic.txt",
    "open-redirect":  "Open%20Redirect/Intruder/Open-Redirect.txt",
    "xxe":            "XXE%20Injection/Intruder/xxe.txt",
    "path-traversal": "Path%20Traversal/Intruder/path-traversal.txt",
}


def run(category: str, for_ffuf: bool = False, ffuf_url: str = "") -> str:
    if category.lower() == "list":
        lines = "\n".join(f"  - {k}" for k in CATEGORIES)
        return f"Available PATT categories:\n{lines}"

    path = CATEGORIES.get(category.lower())
    if not path:
        keys = ", ".join(CATEGORIES)
        return f"Unknown category '{category}'. Available: {keys}"

    url = f"{PATT_BASE}/{path}"
    try:
        r = retry_request(url, timeout=15)
        payloads = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            logger.error("PATT URL 404 — path may be stale for category '%s': %s", category, url)
            return (
                f"[ERROR] PATT fetch failed (404) for category '{category}'.\n"
                f"The upstream path may have moved: {url}\n"
                "Check https://github.com/swisskyrepo/PayloadsAllTheThings for the current structure\n"
                "and update CATEGORIES in agent/tools/payloads.py."
            )
        logger.error("Failed to fetch PATT payloads: %s", exc)
        return f"Failed to fetch PATT payloads: {str(exc)}"
    except Exception as e:
        logger.error("Failed to fetch PATT payloads: %s", e)
        return f"Failed to fetch PATT payloads: {str(e)}"

    if not payloads:
        return f"No payloads found for category '{category}'"

    os.makedirs(WORDLISTS_DIR, exist_ok=True)
    wordlist_path = os.path.join(WORDLISTS_DIR, f"patt_{category}.txt")
    with open(wordlist_path, "w", encoding="utf-8") as f:
        f.write("\n".join(payloads))

    preview = "\n".join(f"  {p}" for p in payloads[:10])
    result = (
        f"PATT '{category}' \u2013 {len(payloads)} payloads fetched\n"
        f"Saved: {wordlist_path}\n"
        f"Preview:\n{preview}"
        + (f"\n  ... +{len(payloads) - 10} more" if len(payloads) > 10 else "")
    )

    if for_ffuf and ffuf_url:
        from .ffuf import run as ffuf_run
        ffuf_result = ffuf_run(url=ffuf_url, wordlist=wordlist_path)
        result += f"\n\n--- ffuf with PATT {category} payloads ---\n{ffuf_result}"

    logger.info("Fetched %d payloads for category '%s'", len(payloads), category)
    return result


TOOL_SPEC = {
    "name": "run_payloads",
    "description": (
        "Fetch payload lists from PayloadsAllTheThings (PATT) by attack category. "
        "Use category='list' to see all available categories."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "description": "Attack category or 'list' to see all",
            },
            "for_ffuf": {
                "type": "boolean",
                "description": "If true, run ffuf immediately with the fetched payloads",
            },
            "ffuf_url": {
                "type": "string",
                "description": "Target URL with FUZZ placeholder (required when for_ffuf=true)",
            },
        },
        "required": ["category"],
    },
}
