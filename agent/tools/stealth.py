"""Stealth profiles — User-Agent rotation, timing randomization, proxy support."""

import os
import random
import time
import logging

logger = logging.getLogger(__name__)

# --- User-Agent pool ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

# --- Stealth profiles ---
PROFILES = {
    "silent": {
        "description": "Passive only — no active scanning, recon only",
        "delay_range": (3.0, 8.0),
        "rotate_ua": True,
        "nmap_timing": "-T1",
        "nmap_flags": ["-sn"],  # Ping only
        "nuclei_rate": 5,
        "ffuf_rate": 10,
    },
    "stealthy": {
        "description": "Low and slow — minimal footprint",
        "delay_range": (1.0, 4.0),
        "rotate_ua": True,
        "nmap_timing": "-T2",
        "nmap_flags": [],
        "nuclei_rate": 20,
        "ffuf_rate": 30,
    },
    "normal": {
        "description": "Standard scan speed — balanced",
        "delay_range": (0.2, 1.0),
        "rotate_ua": True,
        "nmap_timing": "-T3",
        "nmap_flags": [],
        "nuclei_rate": 100,
        "ffuf_rate": 100,
    },
    "aggressive": {
        "description": "Maximum speed — no stealth considerations",
        "delay_range": (0.0, 0.0),
        "rotate_ua": False,
        "nmap_timing": "-T4",
        "nmap_flags": [],
        "nuclei_rate": 500,
        "ffuf_rate": 500,
    },
}

# Active profile — loaded from config or set by agent
_active_profile = "normal"


def set_profile(name: str) -> str:
    """Set the active stealth profile."""
    global _active_profile
    name = name.lower()
    if name not in PROFILES:
        return f"Unknown profile '{name}'. Available: {', '.join(PROFILES.keys())}"
    _active_profile = name
    logger.info("Stealth profile set to: %s", name)
    return f"Stealth profile: {name} — {PROFILES[name]['description']}"


def get_profile() -> dict:
    """Return the current stealth profile settings."""
    return PROFILES.get(_active_profile, PROFILES["normal"])


def get_profile_name() -> str:
    return _active_profile


def random_ua() -> str:
    """Return a random User-Agent string."""
    profile = get_profile()
    if profile["rotate_ua"]:
        return random.choice(USER_AGENTS)
    return USER_AGENTS[0]


_MIN_DELAY_SECONDS = 0.05  # 50ms absolute floor — prevents wire-speed flooding


def stealth_delay():
    """Apply random delay based on current profile (minimum 50ms always enforced)."""
    profile = get_profile()
    lo, hi = profile["delay_range"]
    delay = random.uniform(lo, hi) if hi > 0 else 0.0
    delay = max(delay, _MIN_DELAY_SECONDS)
    time.sleep(delay)


def get_proxy() -> dict | None:
    """Return proxy config from environment or None."""
    proxy_url = os.environ.get("PHANTOM_PROXY", "")
    if proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    return None


def stealth_headers() -> dict:
    """Return HTTP headers with rotated User-Agent and common browser headers."""
    return {
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }


def run(profile: str = "") -> str:
    """Set or display the current stealth profile."""
    if profile:
        return set_profile(profile)
    p = get_profile()
    name = get_profile_name()
    lines = [
        f"Active stealth profile: {name}",
        f"  Description: {p['description']}",
        f"  Delay: {p['delay_range'][0]:.1f}-{p['delay_range'][1]:.1f}s between requests",
        f"  UA rotation: {'on' if p['rotate_ua'] else 'off'}",
        f"  Nmap timing: {p['nmap_timing']}",
        f"  Nuclei rate: {p['nuclei_rate']} req/s",
        f"  Ffuf rate: {p['ffuf_rate']} req/s",
    ]
    proxy = get_proxy()
    if proxy:
        lines.append(f"  Proxy: {proxy['http']}")
    else:
        lines.append("  Proxy: none (set PHANTOM_PROXY env var)")
    return "\n".join(lines)


TOOL_SPEC = {
    "name": "set_stealth_profile",
    "description": (
        "Set the OPSEC stealth profile. Profiles: silent (passive only), "
        "stealthy (low and slow), normal (balanced), aggressive (max speed). "
        "Affects all tools: timing, User-Agent rotation, scan rates."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "profile": {
                "type": "string",
                "description": "Profile name: silent, stealthy, normal, aggressive. Empty to show current.",
            },
        },
        "required": [],
    },
}
