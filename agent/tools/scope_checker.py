"""Scope enforcement — the gatekeeper for all tools."""

import re
import ipaddress
import logging
from urllib.parse import urlparse

from tools import register_tool

logger = logging.getLogger(__name__)

TOOL_SPEC = {
    "name": "check_scope",
    "description": (
        "Verify whether a target (URL, domain, IP, or CIDR) is within the authorized scope. "
        "Use this before any offensive action to confirm authorization."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target to verify (URL, domain, IP, or CIDR)",
            },
        },
        "required": ["target"],
    },
}


@register_tool(TOOL_SPEC)
def run(target: str = "", **kwargs) -> str:
    """Check if a target is in scope."""
    if not target:
        return "No target provided."
    result = scope_guard(target)
    if result:
        return result
    authorized = load_scope_targets()
    return f"IN SCOPE: '{target}' is authorized.\nAll scope targets: {authorized}"


def load_scope_targets(scope_file: str = "scopes/current_scope.md") -> list:
    """Extract all URLs, domains, IPs, and CIDRs from the scope file."""
    try:
        with open(scope_file, encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return []

    targets = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Extract URLs -> keep netloc
        for url in re.findall(r'https?://[^\s\'"<>\]]+', line):
            netloc = urlparse(url).netloc
            if netloc:
                targets.append(netloc.lower().split(":")[0])

        # Extract CIDRs (e.g. 192.168.1.0/24)
        for cidr in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d+\b", line):
            targets.append(cidr)

        # Extract bare IPs (not part of CIDR)
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?!/)", line):
            if ip not in targets:
                targets.append(ip)

    return list(set(targets))


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check if an IP address falls within a CIDR range."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(
            cidr_str, strict=False
        )
    except ValueError:
        return False


def _extract_hostname(target: str) -> str | None:
    """Safely extract hostname from a target string, rejecting ambiguous inputs.

    Returns the normalized hostname/IP, or None if the input is malformed or
    contains userinfo (user@host) which could cause scope check vs actual request
    mismatch.
    """
    t = target.strip()

    if t.startswith(("http://", "https://")):
        parsed = urlparse(t)
        # Reject URLs with userinfo — these cause scope check mismatch:
        # http://in-scope.com@evil.com actually requests evil.com
        if "@" in (parsed.netloc or ""):
            return None
        hostname = parsed.hostname  # urlparse.hostname strips port and lowercases
        if not hostname:
            return None
        return hostname

    # Non-URL target: IP, hostname, or CIDR
    # Strip port if present, reject anything with @ or other URL-like components
    if "@" in t:
        return None
    # Remove port
    host = t.lower().split(":")[0].split("/")[0]
    return host if host else None


def is_in_scope(target: str, scope_file: str = "scopes/current_scope.md") -> bool:
    """Return True if target is within the authorized scope."""
    scope_targets = load_scope_targets(scope_file)
    if not scope_targets:
        # SECURITY: Default deny when no scope is configured.
        # An empty or missing scope file means NO targets are authorized.
        logger.warning("No scope targets loaded — denying by default")
        return False

    t = _extract_hostname(target)
    if not t:
        # Could not parse a clean hostname — reject to prevent bypass
        logger.warning("Could not extract clean hostname from target: %s", target)
        return False

    for s in scope_targets:
        s_clean = s.split(":")[0].lower()

        # Exact match
        if t == s_clean:
            return True

        # Subdomain match: target is a subdomain of a scope entry
        # e.g., target=sub.example.com matches scope=example.com
        if t.endswith("." + s_clean):
            return True

        # NOTE: The reverse check (s_clean.endswith("." + t)) was removed.
        # It allowed overly broad matching: target="com" would match scope "example.com".
        # Scope entries should be specific; if a subdomain is in scope, list it explicitly.

        # CIDR match
        if "/" in s:
            if _ip_in_cidr(t, s):
                return True

    return False


def scope_guard(target: str, scope_file: str = "scopes/current_scope.md") -> str | None:
    """Return an error string if target is out of scope, None if OK."""
    if not is_in_scope(target, scope_file):
        authorized = load_scope_targets(scope_file)
        logger.warning("SCOPE VIOLATION: %s (authorized: %s)", target, authorized)
        return (
            f"SCOPE VIOLATION: '{target}' is not in the authorized scope.\n"
            f"   Authorized targets: {authorized}\n"
            f"   Check scopes/current_scope.md."
        )
    return None
