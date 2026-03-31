"""Brute force authentication — wraps Hydra CLI with Python HTTP fallback."""

import logging
import os
import stat
import subprocess
import re
import tempfile
import time

from .scope_checker import scope_guard
from .logs_helper import log_path
from .stealth import stealth_headers, stealth_delay

logger = logging.getLogger(__name__)

# Minimal default credentials (common across services)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", ""),
    ("root", ""),
    ("administrator", "administrator"),
    ("admin", "changeme"),
    ("admin", "letmein"),
    ("admin", "welcome"),
]

# Service-specific defaults
SERVICE_DEFAULTS = {
    "tomcat": [
        ("tomcat", "tomcat"),
        ("admin", "tomcat"),
        ("tomcat", "s3cret"),
        ("admin", "admin"),
    ],
    "jenkins": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins")],
    "joomla": [("admin", "admin"), ("admin", "joomla"), ("admin", "password")],
    "wordpress": [("admin", "admin"), ("admin", "password"), ("admin", "wordpress")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("root", "password")],
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin")],
    "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    "mysql": [("root", ""), ("root", "root"), ("root", "password")],
}


_MAX_CONSECUTIVE_429 = 3  # Abort after this many consecutive 429 responses


def _python_http_brute(
    target: str, usernames: list, passwords: list, form_params: dict
) -> list:
    """Pure Python HTTP form brute force (fallback when Hydra unavailable)."""
    import requests as _requests
    from .http_utils import retry_request

    results = []
    login_url = target
    user_field = form_params.get("user_field", "username")
    pass_field = form_params.get("pass_field", "password")
    fail_string = form_params.get("fail_string", "invalid")

    tested = 0
    consecutive_429 = 0

    for user in usernames:
        for passwd in passwords:
            if tested >= 50:  # Safety limit
                results.append(f"[INFO] Stopped after {tested} attempts (safety limit)")
                return results
            if consecutive_429 >= _MAX_CONSECUTIVE_429:
                results.append(
                    f"[WARN] Aborted after {consecutive_429} consecutive 429 responses "
                    f"({tested} attempts completed). Target is rate-limiting this IP — "
                    "stopping to avoid site-wide block."
                )
                return results
            stealth_delay()
            try:
                resp = retry_request(
                    login_url,
                    method="POST",
                    headers=stealth_headers(),
                    data={user_field: user, pass_field: passwd},
                    timeout=10,
                    max_retries=1,
                )
                tested += 1
                consecutive_429 = 0  # reset on any successful response
                body = resp.text.lower()
                # Check for success (no fail string, or redirect, or 302)
                if fail_string.lower() not in body and resp.status_code in (
                    200,
                    301,
                    302,
                    303,
                ):
                    if (
                        resp.status_code in (301, 302, 303)
                        or "dashboard" in body
                        or "welcome" in body
                    ):
                        results.append(f"[CRITICAL] Valid credentials: {user}:{passwd}")
                        logger.info("CREDENTIAL FOUND: %s on %s", user, target)
            except _requests.exceptions.HTTPError as exc:
                tested += 1
                if exc.response is not None and exc.response.status_code == 429:
                    consecutive_429 += 1
                    wait = 5.0 * consecutive_429
                    logger.warning(
                        "429 received (%d consecutive) on %s — backing off %.0fs",
                        consecutive_429,
                        target,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    consecutive_429 = 0
            except Exception:
                tested += 1
                consecutive_429 = 0
                continue

    if not results:
        results.append(
            f"[INFO] Tested {tested} combinations — no valid credentials found"
        )
    return results


def run(
    target: str,
    service: str = "http-form",
    userlist: str = "",
    passlist: str = "",
    form_params: str = "",
) -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("hydra_results.txt")

    # Parse target for hostname/port
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    port_match = re.search(r":(\d+)", host)
    port = port_match.group(1) if port_match else ""
    hostname = host.split(":")[0]

    # Build credential lists
    svc_key = service.split("-")[0].lower() if "-" in service else service.lower()
    extra_creds = SERVICE_DEFAULTS.get(svc_key, [])
    all_creds = extra_creds + DEFAULT_CREDS

    usernames = list(dict.fromkeys([c[0] for c in all_creds]))
    passwords = list(dict.fromkeys([c[1] for c in all_creds]))

    # Validate hostname to prevent argument injection into hydra
    _HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
    if not _HOSTNAME_RE.match(hostname):
        return f"Invalid hostname '{hostname}'. Only alphanumeric, dots, hyphens, underscores allowed."
    if hostname.startswith("-"):
        return f"Invalid hostname '{hostname}'. Must not start with a dash."

    # Validate service against allowlist to prevent argument injection
    ALLOWED_SERVICES = {
        "ssh",
        "ftp",
        "mysql",
        "rdp",
        "smb",
        "telnet",
        "vnc",
        "http-form",
    }
    if service not in ALLOWED_SERVICES:
        return f"Invalid service '{service}'. Allowed: {', '.join(sorted(ALLOWED_SERVICES))}"

    # Try Hydra CLI first
    if service in ("ssh", "ftp", "mysql", "rdp", "smb", "telnet", "vnc"):
        user_file = None
        pass_file = None
        try:
            # Write temp credential files with restricted permissions (owner-only read/write)
            fd_u, user_file = tempfile.mkstemp(suffix=".txt", prefix="phantom_users_")
            fd_p, pass_file = tempfile.mkstemp(suffix=".txt", prefix="phantom_pass_")

            # Set restrictive permissions before writing content (owner read/write only)
            os.chmod(user_file, stat.S_IRUSR | stat.S_IWUSR)
            os.chmod(pass_file, stat.S_IRUSR | stat.S_IWUSR)

            with os.fdopen(fd_u, "w") as uf:
                uf.write("\n".join(usernames[:20]))
            with os.fdopen(fd_p, "w") as pf:
                pf.write("\n".join(passwords[:20]))

            cmd = [
                "hydra",
                "-L",
                user_file,
                "-P",
                pass_file,
                hostname,
                service,
            ]
            if port:
                cmd.extend(["-s", port])
            cmd.extend(["-o", output_path, "-t", "4", "-f"])

            logger.info("Running hydra: %s %s", hostname, service)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            output = result.stdout + result.stderr
            found = re.findall(
                r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)",
                output,
            )

            findings = []
            for port_n, svc, h, login, passwd in found:
                findings.append(f"[CRITICAL] {svc}://{login}:{passwd}@{h}:{port_n}")

            if findings:
                return f"Hydra — {len(findings)} credentials found:\n" + "\n".join(
                    f"  {f}" for f in findings
                )
            return f"Hydra — 0 credentials found ({len(usernames)}x{len(passwords)} tested)"

        except FileNotFoundError:
            logger.info("Hydra not found — using Python fallback for HTTP")
        except Exception as e:
            logger.error("Hydra error: %s", e)
        finally:
            # Always clean up temp files, even on error or timeout
            for fpath in (user_file, pass_file):
                if fpath:
                    try:
                        os.unlink(fpath)
                    except OSError:
                        logger.warning("Could not delete temp file: %s", fpath)

    # Python HTTP fallback
    params = {}
    if form_params:
        for part in form_params.split(","):
            if "=" in part:
                k, _, v = part.partition("=")
                params[k.strip()] = v.strip()

    findings = _python_http_brute(target, usernames, passwords, params)
    return f"Brute force — {len(findings)} results:\n" + "\n".join(
        f"  {f}" for f in findings
    )


TOOL_SPEC = {
    "name": "run_hydra",
    "description": (
        "Brute force authentication testing. Tests default/common credentials against "
        "HTTP forms, SSH, FTP, MySQL, RDP, etc. Uses Hydra CLI if available, "
        "otherwise Python HTTP fallback. Includes service-specific credential lists "
        "(Tomcat, Jenkins, WordPress, phpMyAdmin). Safety-limited to 50 attempts."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL or host"},
            "service": {
                "type": "string",
                "description": "Service: http-form (default), ssh, ftp, mysql, rdp, smb",
            },
            "form_params": {
                "type": "string",
                "description": "HTTP form params: user_field=username,pass_field=password,fail_string=invalid",
            },
        },
        "required": ["target"],
    },
}
