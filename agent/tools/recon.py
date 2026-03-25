"""Passive subdomain reconnaissance — multi-source, with retry."""

import logging
from .scope_checker import scope_guard
from .http_utils import retry_request

logger = logging.getLogger(__name__)


def _fetch_crtsh(domain: str) -> set:
    r = retry_request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
    return {entry["name_value"].lower() for entry in r.json()}


def _fetch_hackertarget(domain: str) -> set:
    r = retry_request(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
    subs = set()
    for line in r.text.strip().splitlines():
        if "," in line:
            subs.add(line.split(",")[0].lower().strip())
    return subs


def _fetch_securitytrails_free(domain: str) -> set:
    """DNS recon via SecurityTrails public/guest API (no auth, rate-limited)."""
    import requests

    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            params={"apikey": "guest"},
            timeout=10,
            verify=False,
        )
        if r.status_code in (401, 403):
            logger.debug("SecurityTrails returned %d — skipping", r.status_code)
            return set()
        if r.status_code != 200:
            logger.warning("SecurityTrails unexpected status %d for %s", r.status_code, domain)
            return set()
        data = r.json()
        subs = set()
        for sub in data.get("subdomains", []):
            subs.add(f"{sub}.{domain}".lower())
        return subs
    except Exception as exc:
        logger.warning("SecurityTrails request failed for %s: %s", domain, exc)
        return set()


_SOURCES = {
    "crt.sh": _fetch_crtsh,
    "hackertarget": _fetch_hackertarget,
    "securitytrails": _fetch_securitytrails_free,
}


def run(domain: str) -> str:
    guard = scope_guard(domain)
    if guard:
        return guard

    all_subs: set = set()
    source_results = []

    for name, fetcher in _SOURCES.items():
        try:
            subs = fetcher(domain)
            all_subs |= subs
            source_results.append(f"{name}({len(subs)})")
            logger.info("Recon %s: %d subdomains for %s", name, len(subs), domain)
        except Exception as e:
            source_results.append(f"{name}(failed)")
            logger.warning("Recon %s failed for %s: %s", name, domain, e)

    if not all_subs:
        return f"Recon failed on all sources: {', '.join(source_results)}"

    sorted_subs = sorted(all_subs)

    # Identify potentially interesting subdomains
    interesting_keywords = {"dev", "staging", "admin", "test", "internal", "vpn", "uat",
                            "debug", "api-dev", "beta", "preprod", "stage", "jenkins",
                            "gitlab", "ci", "docker", "k8s", "kube"}
    notable = []
    for sub in sorted_subs:
        prefix = sub.split(".")[0].lower()
        if prefix in interesting_keywords:
            notable.append(prefix)

    summary = f"Subdomain reconnaissance -- {domain} -- {len(all_subs)} unique subdomains:\n"
    summary += f"\n  Sources: {' + '.join(source_results)}\n"
    summary += "\n  SUBDOMAINS:\n"
    for s in sorted_subs[:25]:
        summary += f"    {s}\n"
    if len(sorted_subs) > 25:
        summary += f"    ... +{len(sorted_subs) - 25} more\n"

    if notable:
        summary += f"\n  Notable: {len(notable)} potentially interesting ({', '.join(sorted(notable))})"

    return summary.strip()


TOOL_SPEC = {
    "name": "run_recon",
    "description": "Passive subdomain reconnaissance \u2014 crt.sh + HackerTarget + SecurityTrails (multi-source, deduped, with retry)",
    "input_schema": {
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"],
    },
}
