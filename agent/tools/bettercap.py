"""Network MITM, probing, WiFi/BT reconnaissance (Bettercap)."""

import logging
import platform
import subprocess

from .scope_checker import scope_guard

logger = logging.getLogger(__name__)


def _default_interface() -> str:
    if platform.system() == "Windows":
        return "Ethernet"
    return "eth0"


def run(
    target: str = "", interface: str = "", module: str = "net.probe", duration: int = 30
) -> str:
    if platform.system() == "Windows":
        return "Bettercap is not supported on Windows. Use WSL2 for network MITM."

    # Scope enforcement — target is optional for net.probe but required for targeted attacks
    if target:
        guard = scope_guard(target)
        if guard:
            return guard

    if not interface:
        interface = _default_interface()

    cmd = [
        "bettercap",
        "-iface",
        interface,
        "-caplet",
        module,
        "-timeout",
        str(duration),
    ]
    logger.info("Running bettercap: %s on %s (%ds)", module, interface, duration)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=duration + 30
        )
        logger.info("Bettercap %s completed on %s", module, interface)
        return f"Bettercap ({module}) on {interface}\n{result.stdout[-300:]}"
    except FileNotFoundError:
        return "Bettercap not found. Install with: apt install bettercap"
    except Exception as e:
        logger.error("Bettercap error: %s", e)
        return f"Bettercap error: {str(e)}"


TOOL_SPEC = {
    "name": "run_bettercap",
    "description": "MITM, network probe, WiFi, Bluetooth (only in authorized lab). Requires target in scope.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or network (must be in scope)",
            },
            "interface": {"type": "string", "default": "eth0"},
            "module": {"type": "string", "default": "net.probe"},
            "duration": {"type": "integer", "default": 30},
        },
        "required": ["interface"],
    },
}
