"""WordPress vulnerability scanner — wraps wpscan CLI or Python fallback."""

import json
import logging
import subprocess
import re

from .scope_checker import scope_guard
from .logs_helper import log_path
from .http_utils import retry_request
from .stealth import stealth_headers, stealth_delay

logger = logging.getLogger(__name__)

# Common WordPress paths to probe
WP_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/wp-json/wp/v2/users",
    "/wp-json/",
    "/xmlrpc.php",
    "/wp-cron.php",
    "/wp-content/debug.log",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/.wp-config.php.swp",
    "/wp-includes/version.php",
    "/readme.html",
    "/license.txt",
]

# Known vulnerable endpoints
WP_CHECKS = {
    "/xmlrpc.php": "XML-RPC enabled — brute force and pingback amplification risk",
    "/wp-json/wp/v2/users": "User enumeration via REST API",
    "/wp-content/debug.log": "Debug log exposed — may contain sensitive data",
    "/wp-config.php.bak": "Backup config file — may contain database credentials",
    "/readme.html": "WordPress version disclosure",
}


def _python_wpscan(target: str) -> str:
    """Pure Python WordPress scanner — no external deps."""
    findings = []
    wp_version = None
    users = []

    for path in WP_PATHS:
        stealth_delay()
        url = target.rstrip("/") + path
        try:
            resp = retry_request(
                url, headers=stealth_headers(), timeout=10, max_retries=1
            )
            status = resp.status_code

            if status == 200:
                body = resp.text[:5000]

                # Version detection from readme.html or version.php
                if path == "/readme.html":
                    m = re.search(r"Version\s+([\d.]+)", body)
                    if m:
                        wp_version = m.group(1)
                        findings.append(f"[INFO] WordPress version: {wp_version}")

                if path == "/wp-includes/version.php":
                    m = re.search(r"\$wp_version\s*=\s*'([\d.]+)'", body)
                    if m:
                        wp_version = m.group(1)
                        findings.append(
                            f"[INFO] WordPress version: {wp_version} (from version.php)"
                        )

                # User enumeration
                if path == "/wp-json/wp/v2/users":
                    try:
                        user_data = resp.json()
                        if isinstance(user_data, list):
                            users = [
                                u.get("slug", u.get("name", "?"))
                                for u in user_data[:10]
                            ]
                            findings.append(
                                f"[HIGH] User enumeration via REST API: {users}"
                            )
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Check known vulnerable paths
                if path in WP_CHECKS:
                    sev = (
                        "[HIGH]"
                        if "credential" in WP_CHECKS[path]
                        or "sensitive" in WP_CHECKS[path]
                        else "[MEDIUM]"
                    )
                    findings.append(f"{sev} {path} accessible: {WP_CHECKS[path]}")

                # Debug log
                if path == "/wp-content/debug.log" and len(body) > 50:
                    findings.append(
                        f"[HIGH] Debug log exposed ({len(resp.text)} bytes)"
                    )

            elif status == 403 and path in ("/wp-admin/", "/wp-content/uploads/"):
                findings.append(f"[INFO] {path} exists (403 Forbidden)")

        except Exception:
            continue

    # Check for wp-login brute force protection
    try:
        stealth_delay()
        resp = retry_request(
            target.rstrip("/") + "/wp-login.php",
            method="POST",
            headers=stealth_headers(),
            data={"log": "admin", "pwd": "test", "wp-submit": "Log In"},
            timeout=10,
            max_retries=1,
        )
        if "incorrect" in resp.text.lower() or "error" in resp.text.lower():
            findings.append(
                "[INFO] wp-login.php accepts POST — no CAPTCHA/lockout detected"
            )
    except Exception:
        pass

    if not findings:
        return "WordPress scan done — 0 findings (target may not be WordPress)"

    header = f"WordPress scan — {len(findings)} findings"
    if wp_version:
        header += f" (version {wp_version})"
    if users:
        header += f" | Users: {', '.join(users)}"
    result = header + "\n" + "\n".join(f"  {f}" for f in findings)
    if len(result) > 5000:
        result = result[:5000] + "\n... (use read_log to see full output)"
    return result


def run(target: str, api_token: str = "") -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("wpscan.json")

    # Try wpscan CLI first
    cmd = [
        "wpscan",
        "--url",
        target,
        "--format",
        "json",
        "-o",
        output_path,
        "--no-banner",
    ]
    if api_token:
        cmd.extend(["--api-token", api_token])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode in (0, 5) and output_path:
            import os

            if os.path.exists(output_path):
                with open(output_path, encoding="utf-8") as f:
                    data = json.load(f)

                findings = []
                # Version
                if data.get("version", {}).get("number"):
                    findings.append(f"[INFO] WordPress {data['version']['number']}")
                    if data["version"].get("status") == "insecure":
                        findings.append(
                            f"[HIGH] WordPress version {data['version']['number']} is INSECURE"
                        )

                # Plugins
                for name, info in data.get("plugins", {}).items():
                    vulns = info.get("vulnerabilities", [])
                    if vulns:
                        for v in vulns[:3]:
                            sev = v.get("cvss", {}).get("severity", "medium").upper()
                            findings.append(
                                f"[{sev}] Plugin '{name}': {v.get('title', 'vuln')}"
                            )

                # Users
                users = [u.get("username", "?") for u in data.get("users", [])]
                if users:
                    findings.append(f"[MEDIUM] Enumerated users: {users}")

                if findings:
                    cli_result = f"WPScan — {len(findings)} findings:\n" + "\n".join(
                        f"  {f}" for f in findings
                    )
                    if len(cli_result) > 5000:
                        cli_result = (
                            cli_result[:5000]
                            + "\n... (use read_log 'wpscan.json' to see full output)"
                        )
                    return cli_result
                return "WPScan done — 0 findings"

        # wpscan ran but no output
        return _python_wpscan(target)

    except FileNotFoundError:
        logger.info("wpscan CLI not found — using Python fallback")
        fallback = _python_wpscan(target)
        return (
            "[WARN] wpscan CLI not found — running degraded Python fallback.\n"
            "  Install wpscan for full CVE scanning: https://github.com/wpscanteam/wpscan\n"
            "  Fallback covers: path probing, version detection, user enum, xmlrpc check.\n"
            "  Missing: plugin CVE database, theme scanning, TimThumb detection.\n\n"
        ) + fallback
    except subprocess.TimeoutExpired:
        return _python_wpscan(target)
    except Exception as e:
        logger.error("WPScan error: %s", e)
        return _python_wpscan(target)


TOOL_SPEC = {
    "name": "run_wpscan",
    "description": (
        "WordPress vulnerability scanner. Detects WP version, enumerates users, "
        "checks plugins for CVEs, tests xmlrpc.php, debug.log, config backups. "
        "Uses wpscan CLI if available, otherwise pure Python fallback."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target WordPress URL"},
            "api_token": {
                "type": "string",
                "description": "WPScan API token (optional, for vuln DB)",
            },
        },
        "required": ["target"],
    },
}
