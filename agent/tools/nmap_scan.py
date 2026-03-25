"""Nmap port scanning and service detection."""

import re
import logging
import subprocess
from datetime import datetime

from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)

SCAN_TYPES = {
    "quick": ["-T4", "-F"],
    "service": ["-sV", "-sC"],
    "full": ["-A", "-T4"],
    "vuln": ["--script", "vuln"],
}

# Target: IP addresses, hostnames, CIDRs — no shell metacharacters or nmap flags
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")
# Ports: digits, commas, hyphens only (e.g. "80,443", "1-1000")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


def run(target: str, ports: str = "-", scan_type: str = "service", timeout: int = 300) -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    if scan_type not in SCAN_TYPES:
        return f"Unknown scan_type '{scan_type}'. Available: {', '.join(SCAN_TYPES)}"

    # Validate target to prevent argument injection (e.g. "--script=malicious")
    if not _TARGET_RE.match(target):
        return (
            f"Invalid target '{target}'. Target must be an IP, hostname, or CIDR. "
            "No flags, spaces, or special characters allowed."
        )
    if target.startswith("-"):
        return f"Invalid target '{target}'. Target must not start with a dash."

    # Validate ports to prevent argument injection
    if ports != "-" and not _PORTS_RE.match(ports):
        return (
            f"Invalid ports '{ports}'. Ports must be digits, commas, and hyphens only "
            "(e.g. '80,443' or '1-1000')."
        )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = log_path(f"nmap_{ts}.txt")

    cmd = ["nmap"] + SCAN_TYPES[scan_type] + [target]
    if ports != "-":
        cmd += ["-p", ports]
    cmd += ["-oN", output_path]

    logger.info("Running nmap %s scan on %s", scan_type, target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout

        # Parse results
        open_ports = re.findall(r"(\d+/\w+)\s+open\s+(\S+)\s*(.*)", output)
        os_match = re.search(r"OS details:\s*(.+)", output)
        time_match = re.search(r"scanned in\s+([\d.]+)\s*s", output)

        summary = f"Nmap {scan_type} scan -- {target} -- {len(open_ports)} open ports:\n"

        if open_ports:
            # Build aligned table
            header = ("PORT", "SERVICE", "VERSION")
            col_port = max(len(header[0]), max(len(p) for p, _, _ in open_ports[:30])) + 2
            col_svc = max(len(header[1]), max(len(s) for _, s, _ in open_ports[:30])) + 2

            summary += f"\n  {header[0]:<{col_port}}{header[1]:<{col_svc}}{header[2]}\n"
            summary += f"  {'-' * col_port}{'-' * col_svc}{'-' * 20}\n"
            for port, service, version in open_ports[:30]:
                summary += f"  {port:<{col_port}}{service:<{col_svc}}{version.strip()}\n"
            if len(open_ports) > 30:
                summary += f"\n  ... +{len(open_ports) - 30} more\n"
        else:
            summary += "\n  No open ports found (host may be filtered or down)\n"
            summary += f"  Raw output tail: {output[-300:]}"

        if os_match:
            summary += f"\n  OS Detection: {os_match.group(1)}"
        if time_match:
            summary += f"\n  Scan time: {time_match.group(1)}s"

        logger.info("Nmap found %d open ports on %s", len(open_ports), target)
        return summary.strip()

    except subprocess.TimeoutExpired:
        return f"Nmap timed out after {timeout}s. Try 'quick' scan_type or narrower port range."
    except FileNotFoundError:
        return "[TOOL OK, BINARY MISSING] Nmap CLI is not installed on this system. Install with: apt install nmap (Linux) or download from nmap.org. This does NOT mean the run_nmap tool is unavailable — it just needs the nmap binary."
    except Exception as e:
        logger.error("Nmap error: %s", e)
        return f"Nmap error: {str(e)}"


TOOL_SPEC = {
    "name": "run_nmap",
    "description": (
        "Port scanning and service detection with Nmap. "
        "Scan types: quick (fast -F), service (version+scripts), full (-A), vuln (vulnerability scripts)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target IP, domain, or CIDR"},
            "ports": {
                "type": "string",
                "default": "-",
                "description": "Port specification (e.g. '80,443', '1-1000', '-' for default)",
            },
            "scan_type": {
                "type": "string",
                "default": "service",
                "description": "Scan type: quick, service, full, vuln",
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Timeout in seconds",
            },
        },
        "required": ["target"],
    },
}
