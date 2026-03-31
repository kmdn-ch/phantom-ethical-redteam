"""Privilege escalation enumeration — LinPEAS/WinPEAS wrapper + Python checks."""

import logging
import os
import platform
import re
import subprocess

from .logs_helper import log_path

logger = logging.getLogger(__name__)


def _check_linux_privesc() -> list:
    """Run Linux privilege escalation checks (pure Python)."""
    findings = []

    # SUID binaries
    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        suid_bins = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        # Known exploitable SUID binaries
        exploitable = [
            "nmap",
            "vim",
            "find",
            "bash",
            "more",
            "less",
            "nano",
            "cp",
            "mv",
            "awk",
            "python",
            "perl",
            "ruby",
            "lua",
            "php",
            "env",
            "wget",
            "curl",
            "pkexec",
            "mount",
        ]
        dangerous = [
            b for b in suid_bins if any(e in os.path.basename(b) for e in exploitable)
        ]
        if dangerous:
            findings.append(f"[HIGH] Exploitable SUID binaries ({len(dangerous)}):")
            for b in dangerous[:10]:
                findings.append(f"    {b}")
        else:
            findings.append(
                f"[INFO] {len(suid_bins)} SUID binaries found (none obviously exploitable)"
            )
    except Exception:
        findings.append("[INFO] Cannot enumerate SUID binaries")

    # Writable /etc/passwd
    try:
        if os.access("/etc/passwd", os.W_OK):
            findings.append("[CRITICAL] /etc/passwd is WRITABLE — trivial root")
        if os.access("/etc/shadow", os.R_OK):
            findings.append(
                "[CRITICAL] /etc/shadow is READABLE — password hash extraction"
            )
    except Exception:
        pass

    # Sudo permissions
    try:
        result = subprocess.run(
            ["sudo", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            input="",  # Non-interactive
        )
        if "NOPASSWD" in result.stdout:
            nopasswd = [
                l.strip() for l in result.stdout.splitlines() if "NOPASSWD" in l
            ]
            findings.append(f"[HIGH] NOPASSWD sudo entries:")
            for entry in nopasswd[:5]:
                findings.append(f"    {entry}")
        elif result.stdout.strip():
            findings.append(f"[MEDIUM] Sudo permissions available (password required)")
    except Exception:
        findings.append("[INFO] Cannot check sudo permissions")

    # Cron jobs
    try:
        cron_files = []
        for cron_dir in ["/etc/cron.d/", "/etc/crontab", "/var/spool/cron/"]:
            if os.path.exists(cron_dir):
                if os.path.isdir(cron_dir):
                    for f in os.listdir(cron_dir):
                        cron_files.append(os.path.join(cron_dir, f))
                else:
                    cron_files.append(cron_dir)

        writable_crons = [f for f in cron_files if os.access(f, os.W_OK)]
        if writable_crons:
            findings.append(f"[HIGH] Writable cron files: {writable_crons}")
        else:
            findings.append(
                f"[INFO] {len(cron_files)} cron entries found (none writable)"
            )
    except Exception:
        pass

    # Kernel version
    try:
        result = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, timeout=5
        )
        kernel = result.stdout.strip()
        findings.append(f"[INFO] Kernel: {kernel}")
    except Exception:
        pass

    # Docker socket
    if os.path.exists("/var/run/docker.sock"):
        if os.access("/var/run/docker.sock", os.W_OK):
            findings.append(
                "[CRITICAL] Docker socket writable — container escape possible"
            )
        else:
            findings.append("[MEDIUM] Docker socket exists (check group membership)")

    # SSH keys
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir):
        keys = [
            f
            for f in os.listdir(ssh_dir)
            if f.startswith("id_") and not f.endswith(".pub")
        ]
        if keys:
            findings.append(f"[MEDIUM] SSH private keys found: {keys}")
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        if os.path.exists(auth_keys) and os.access(auth_keys, os.W_OK):
            findings.append(
                "[HIGH] authorized_keys is writable — SSH persistence possible"
            )

    # World-writable directories in PATH
    path_dirs = os.environ.get("PATH", "").split(":")
    writable_path = [d for d in path_dirs if os.path.isdir(d) and os.access(d, os.W_OK)]
    if writable_path:
        findings.append(f"[HIGH] Writable PATH directories: {writable_path[:5]}")

    return findings


def _check_windows_privesc() -> list:
    """Run Windows privilege escalation checks."""
    findings = []

    # Current user info
    try:
        result = subprocess.run(
            ["whoami", "/all"], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        if "SeImpersonatePrivilege" in output:
            findings.append(
                "[HIGH] SeImpersonatePrivilege enabled — potato attacks possible"
            )
        if "SeDebugPrivilege" in output:
            findings.append(
                "[CRITICAL] SeDebugPrivilege enabled — process injection possible"
            )
        if "SeBackupPrivilege" in output:
            findings.append("[HIGH] SeBackupPrivilege enabled — file read bypass")
        if "BUILTIN\\Administrators" in output:
            findings.append("[INFO] User is in Administrators group")

        # Extract username
        for line in output.splitlines():
            if "\\   " not in line and "\\" in line:
                findings.append(f"[INFO] Current user: {line.strip()}")
                break
    except Exception:
        findings.append("[INFO] Cannot enumerate current user privileges")

    # Unquoted service paths
    try:
        result = subprocess.run(
            ["wmic", "service", "get", "name,displayname,pathname,startmode"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            if (
                "C:\\" in line
                and '"' not in line
                and " " in line.split("C:\\")[1].split(".exe")[0]
            ):
                findings.append(f"[HIGH] Unquoted service path: {line.strip()[:100]}")
    except Exception:
        pass

    # AlwaysInstallElevated
    try:
        result = subprocess.run(
            [
                "reg",
                "query",
                "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                "/v",
                "AlwaysInstallElevated",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if "0x1" in result.stdout:
            findings.append(
                "[CRITICAL] AlwaysInstallElevated is ON — MSI privilege escalation"
            )
    except Exception:
        pass

    # Stored WiFi passwords
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        profiles = re.findall(r":\s+(.+)", result.stdout)
        if profiles:
            findings.append(f"[INFO] WiFi profiles stored: {len(profiles)}")
    except Exception:
        pass

    return findings


def run(check: str = "auto") -> str:
    """
    Run privilege escalation enumeration.

    check: auto (detect OS), linux, windows, or linpeas/winpeas (use external tool)
    """
    findings = []
    os_type = platform.system()

    if check == "auto":
        check = "linux" if os_type != "Windows" else "windows"

    # Try LinPEAS/WinPEAS external tool first
    if check == "linpeas":
        try:
            result = subprocess.run(
                ["bash", "linpeas.sh"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            output_path = log_path("linpeas_output.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            # Extract key findings
            for line in result.stdout.splitlines():
                if any(tag in line for tag in ["95%", "99%", "RED/YELLOW"]):
                    findings.append(f"[HIGH] {line.strip()[:120]}")
            if findings:
                return (
                    f"LinPEAS — {len(findings)} high-priority findings:\n"
                    + "\n".join(f"  {f}" for f in findings[:20])
                )
            return f"LinPEAS complete — output saved to {output_path}"
        except FileNotFoundError:
            logger.info("linpeas.sh not found — using built-in checks")
            check = "linux"
        except Exception as e:
            return f"LinPEAS error: {e}"

    if check == "winpeas":
        try:
            result = subprocess.run(
                ["winPEASany.exe"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            output_path = log_path("winpeas_output.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return f"WinPEAS complete — output saved to {output_path}"
        except FileNotFoundError:
            logger.info("winPEASany.exe not found — using built-in checks")
            check = "windows"
        except Exception as e:
            return f"WinPEAS error: {e}"

    # Built-in checks
    if check == "linux":
        findings = _check_linux_privesc()
    elif check == "windows":
        findings = _check_windows_privesc()
    else:
        return (
            f"Unknown check type: {check}. Use: auto, linux, windows, linpeas, winpeas"
        )

    if not findings:
        return "Privilege escalation check — no findings"

    return f"PrivEsc check ({check}) — {len(findings)} findings:\n" + "\n".join(
        f"  {f}" for f in findings
    )


TOOL_SPEC = {
    "name": "run_privesc_check",
    "description": (
        "Privilege escalation enumeration. Checks SUID binaries, sudo NOPASSWD, writable crons, "
        "Docker socket, SSH keys, kernel version (Linux) or SeImpersonate, unquoted service paths, "
        "AlwaysInstallElevated (Windows). Uses LinPEAS/WinPEAS if available, otherwise built-in checks."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "check": {
                "type": "string",
                "description": "Check type: auto (detect OS), linux, windows, linpeas, winpeas",
            },
        },
        "required": [],
    },
}
