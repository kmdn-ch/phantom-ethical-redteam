"""Web technology fingerprinting (WhatWeb + fallback)."""

import json
import logging
import subprocess

from .http_utils import retry_request
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# Signatures for Python-based fallback fingerprinting
CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["Drupal", "sites/default", "drupal.js"],
    "Joomla": ["Joomla", "/administrator/", "com_content"],
    "Magento": ["Magento", "mage/", "varien"],
    "Laravel": ["laravel_session", "csrf-token"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "React": ["react-root", "data-reactroot", "__REACT"],
    "Vue.js": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "ng-app"],
    "Express.js": [],  # Detected via X-Powered-By header
    "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION"],
    "Ruby on Rails": ["authenticity_token"],
    "Spring Boot": ["Whitelabel Error Page", "X-Application-Context"],
}

# Header-based framework signatures (header-name -> header-value-substring -> label)
HEADER_SIGNATURES = {
    "X-Powered-By": {
        "Express": "Express.js",
        "ASP.NET": "ASP.NET",
        "PHP": "PHP",
    },
    "X-Request-Id": {"": "Ruby on Rails (probable)"},
    "X-Runtime": {"": "Ruby on Rails (probable)"},
    "X-Application-Context": {"": "Spring Boot"},
}

# Server header fingerprints
SERVER_SIGNATURES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "microsoft-iis": "IIS",
    "cloudflare": "Cloudflare",
    "litespeed": "LiteSpeed",
}

# Interesting files to probe for information disclosure
INTERESTING_FILES = {
    ".env": "Environment file exposed — may contain secrets",
    ".git/HEAD": "Git repository exposed — source code leak risk",
    "/.well-known/security.txt": "security.txt present",
}


def _fallback_fingerprint(target: str) -> str:
    """Python-based fingerprinting when whatweb is not available."""
    if not target.startswith("http"):
        target = f"https://{target}"

    results = []

    try:
        resp = retry_request(target, timeout=10, allow_redirects=True, max_retries=1)
        headers = resp.headers
        body = resp.text[:50000]

        # Server header detection
        server = headers.get("Server", "")
        if server:
            results.append(f"Server: {server}")
            server_lower = server.lower()
            for sig, label in SERVER_SIGNATURES.items():
                if sig in server_lower:
                    results.append(f"Web server: {label}")
                    break

        # Header-based framework detection
        detected_frameworks = set()
        for header_name, sig_map in HEADER_SIGNATURES.items():
            header_val = headers.get(header_name, "")
            if not header_val:
                continue
            for substring, label in sig_map.items():
                if substring == "" or substring.lower() in header_val.lower():
                    detected_frameworks.add(label)

        if headers.get("X-Powered-By"):
            results.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if headers.get("X-Generator"):
            results.append(f"X-Generator: {headers['X-Generator']}")
        if headers.get("X-AspNet-Version"):
            results.append(f"ASP.NET: {headers['X-AspNet-Version']}")

        for fw in sorted(detected_frameworks):
            results.append(f"Framework (header): {fw}")

        # CMS / body-based detection
        for cms, sigs in CMS_SIGNATURES.items():
            if sigs and any(sig.lower() in body.lower() for sig in sigs):
                results.append(f"CMS/Framework: {cms}")

        # Rails-specific: check for authenticity_token + X-Runtime combo
        if "authenticity_token" in body and headers.get("X-Runtime"):
            if "Ruby on Rails (probable)" not in detected_frameworks:
                results.append("CMS/Framework: Ruby on Rails")

        # Security headers
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
        ]
        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]
        if present:
            results.append(f"Security headers present: {', '.join(present)}")
        if missing:
            results.append(f"Security headers MISSING: {', '.join(missing)}")

    except Exception as e:
        results.append(f"Main page error: {e}")

    # Check robots.txt
    try:
        r = retry_request(f"{target}/robots.txt", timeout=5, max_retries=0)
        if r.status_code == 200 and len(r.text) > 10:
            results.append(f"robots.txt: found ({len(r.text)} bytes)")
    except Exception:
        pass

    # Check sitemap.xml
    try:
        r = retry_request(f"{target}/sitemap.xml", timeout=5, max_retries=0)
        if r.status_code == 200 and "xml" in r.text[:200].lower():
            results.append(f"sitemap.xml: found ({len(r.text)} bytes)")
    except Exception:
        pass

    # Check interesting files for information disclosure
    for path, description in INTERESTING_FILES.items():
        try:
            url = f"{target}/{path}" if not path.startswith("/") else f"{target}{path}"
            r = retry_request(url, timeout=5, max_retries=0)
            if r.status_code == 200 and len(r.text.strip()) > 0:
                results.append(f"Sensitive file: {path} — {description}")
        except Exception:
            pass

    if not results:
        return "No technology fingerprints detected."

    # Log summary of detected technologies
    tech_items = [
        r
        for r in results
        if r.startswith(("Server:", "CMS/Framework:", "Framework (header):", "Web server:"))
    ]
    if tech_items:
        logger.info(
            "Fallback fingerprint for %s — detected: %s",
            target,
            "; ".join(tech_items),
        )
    else:
        logger.info("Fallback fingerprint for %s — no technologies positively identified", target)

    return "Technology fingerprint (Python fallback):\n" + "\n".join(f"  {r}" for r in results)


def run(target: str, aggression: int = 1) -> str:
    # URL validation
    if not target.startswith("http://") and not target.startswith("https://"):
        return (
            f"Invalid target URL: {target!r} — "
            "target must start with http:// or https://"
        )

    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("whatweb.json")

    try:
        cmd = ["whatweb", f"-a{aggression}", f"--log-json={output_path}", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 and result.stdout.strip():
            logger.info("WhatWeb scan completed for %s", target)
            return f"WhatWeb scan ({target}):\n{result.stdout[:2000]}"

        # Try parsing JSON output
        try:
            with open(output_path, encoding="utf-8") as f:
                data = json.load(f)
            return f"WhatWeb scan ({target}):\n{json.dumps(data, indent=2)[:2000]}"
        except Exception:
            pass

        return f"WhatWeb returned no results.\n{result.stderr[:300]}"

    except FileNotFoundError:
        logger.debug("WhatWeb not found, using Python fallback for %s", target)
        return _fallback_fingerprint(target)
    except Exception as e:
        logger.warning("WhatWeb failed (%s), using fallback: %s", target, e)
        return _fallback_fingerprint(target)


TOOL_SPEC = {
    "name": "run_whatweb",
    "description": (
        "Web technology fingerprinting — detect CMS, frameworks, server software, "
        "security headers. Uses WhatWeb if available, otherwise Python-based fallback."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL or domain"},
            "aggression": {
                "type": "integer",
                "default": 1,
                "description": "Aggression level 1-4 (1=stealthy, 4=aggressive)",
            },
        },
        "required": ["target"],
    },
}
