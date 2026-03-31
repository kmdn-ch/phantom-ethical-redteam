"""Shared input validation utilities for Phantom tools."""

import re
import ipaddress


_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_DANGEROUS_CHARS = re.compile(r"[;&|`$(){}]")


def sanitize_target(target: str) -> str:
    """Strip whitespace and reject shell-dangerous characters."""
    target = target.strip()
    if _DANGEROUS_CHARS.search(target):
        raise ValueError(f"Target contains dangerous characters: {target!r}")
    return target


def validate_url(url: str) -> bool:
    return bool(_URL_RE.match(url))


def validate_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def safe_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r"[^\w.\-]", "_", name)[:200]
