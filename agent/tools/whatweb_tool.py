"""Web technology fingerprinting (WhatWeb + comprehensive Python fallback)."""

import json
import logging
import subprocess
from urllib.parse import urljoin

import requests

from .http_utils import retry_request
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Body-based CMS / framework signatures
# ---------------------------------------------------------------------------
CMS_SIGNATURES = {
    # CMS platforms
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["Drupal", "sites/default", "drupal.js"],
    "Joomla": ["Joomla", "/administrator/", "com_content"],
    "Magento": ["Magento", "mage/", "varien"],
    "Shopify": ["Shopify.theme", "cdn.shopify.com"],
    "PrestaShop": ["prestashop", "presta"],
    "Ghost CMS": ["ghost-"],
    "Craft CMS": ["craft/"],
    "Typo3": ["typo3"],
    "Moodle": ["moodle"],
    "phpBB": ["phpBB"],
    "MediaWiki": ["mediawiki", "wikitext"],
    "Confluence": ["ajs-version-number", "confluence"],
    # Frameworks — backend
    "Laravel": ["laravel_session", "csrf-token"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Ruby on Rails": ["authenticity_token"],
    "Spring Boot": ["Whitelabel Error Page", "X-Application-Context"],
    "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION"],
    "Strapi": ["strapi"],
    "Express.js": [],  # Detected via X-Powered-By header
    # Frameworks — frontend / SSR
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js": ["__NUXT__", "_nuxt/"],
    "React": ["react-root", "data-reactroot", "__REACT"],
    "Vue.js": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "ng-app"],
    "Svelte / SvelteKit": ["__sveltekit"],
    "Remix": ["__remixContext"],
    # Static site generators
    "Hugo": ["hugo-"],
    "Gatsby": ["gatsby-"],
}

# ---------------------------------------------------------------------------
# Header-based framework / technology signatures
# header-name -> { value-substring: label }   (empty string = any value)
# ---------------------------------------------------------------------------
HEADER_SIGNATURES = {
    "X-Powered-By": {
        "Express": "Express.js",
        "ASP.NET": "ASP.NET",
        "PHP": "PHP",
        "Servlet": "Java Servlet",
        "JSP": "JSP",
        "Phusion Passenger": "Phusion Passenger (Ruby/Python)",
        "PleskLin": "Plesk (Linux)",
        "PleskWin": "Plesk (Windows)",
    },
    "X-Request-Id": {"": "Ruby on Rails (probable)"},
    "X-Runtime": {"": "Ruby on Rails (probable)"},
    "X-Application-Context": {"": "Spring Boot"},
    # Drupal-specific
    "X-Drupal-Cache": {"": "Drupal"},
    "X-Drupal-Dynamic-Cache": {"": "Drupal"},
    # Shopify
    "X-Shopify-Stage": {"": "Shopify"},
    # Magento
    "X-Magento-Cache-Debug": {"": "Magento"},
}

# WordPress headers are matched by prefix separately (X-WordPress-*)

# ---------------------------------------------------------------------------
# Server header fingerprints
# ---------------------------------------------------------------------------
SERVER_SIGNATURES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "microsoft-iis": "IIS",
    "cloudflare": "Cloudflare",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty (Nginx)",
    "gunicorn": "Gunicorn (Python)",
    "uvicorn": "Uvicorn (Python ASGI)",
    "cowboy": "Cowboy (Erlang)",
    "caddy": "Caddy",
    "envoy": "Envoy Proxy",
    "tengine": "Tengine (Alibaba Nginx)",
}

# ---------------------------------------------------------------------------
# CDN / Cloud / Caching headers  ->  (header_name, label)
# ---------------------------------------------------------------------------
INFRA_HEADERS = {
    # Cloudflare
    "CF-Cache-Status": "Cloudflare CDN",
    "CF-RAY": "Cloudflare",
    # AWS
    "X-Amz-Cf-Id": "Amazon CloudFront",
    "X-Amz-Request-Id": "AWS (S3 / API Gateway)",
    # Azure
    "X-Azure-Ref": "Microsoft Azure",
    # Google Cloud
    "X-GUploader-UploadID": "Google Cloud Storage",
    # Fastly
    "X-Fastly-Request-ID": "Fastly CDN",
    # Varnish / generic caching
    "X-Varnish": "Varnish Cache",
    "X-Cache": "Caching layer",
    "X-Cache-Hit": "Caching layer (hit indicator)",
    "X-Served-By": "Fastly / Varnish",
}

# ---------------------------------------------------------------------------
# Security headers — what we expect and their severity if missing
# Severity: MEDIUM or LOW
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": "MEDIUM",
    "Content-Security-Policy": "MEDIUM",
    "X-Frame-Options": "LOW",
    "X-Content-Type-Options": "LOW",
    "X-XSS-Protection": "LOW",
    "Permissions-Policy": "LOW",
    "Referrer-Policy": "LOW",
    "Cross-Origin-Opener-Policy": "LOW",
    "Cross-Origin-Embedder-Policy": "LOW",
    "Cross-Origin-Resource-Policy": "LOW",
    "X-Permitted-Cross-Domain-Policies": "LOW",
    "X-DNS-Prefetch-Control": "LOW",
}

# ---------------------------------------------------------------------------
# Interesting / sensitive files to probe
# (path, description, severity)
# ---------------------------------------------------------------------------
INTERESTING_FILES = [
    # Secrets / source-code exposure
    ("/.env", "Environment file — may contain secrets", "HIGH"),
    ("/.git/HEAD", "Git repository exposed — source code leak", "HIGH"),
    ("/.htaccess", "Apache config exposed", "HIGH"),
    ("/web.config", "IIS config exposed", "HIGH"),
    ("/.DS_Store", "macOS directory listing leak", "MEDIUM"),
    # Server diagnostics
    ("/server-status", "Apache server-status exposed", "HIGH"),
    ("/nginx.conf", "Nginx config exposed", "HIGH"),
    ("/phpinfo.php", "PHP info page exposed", "HIGH"),
    ("/elmah.axd", "ASP.NET error log exposed", "HIGH"),
    ("/trace.axd", "ASP.NET trace exposed", "HIGH"),
    # CMS admin panels
    ("/wp-login.php", "WordPress login page", "MEDIUM"),
    ("/administrator/", "Joomla admin panel", "MEDIUM"),
    ("/user/login", "Drupal login page", "MEDIUM"),
    # API / developer endpoints
    ("/actuator/health", "Spring Boot actuator exposed", "HIGH"),
    ("/swagger-ui.html", "Swagger UI exposed", "MEDIUM"),
    ("/swagger.json", "Swagger JSON spec exposed", "MEDIUM"),
    ("/graphql", "GraphQL endpoint (check introspection)", "MEDIUM"),
    # Policy files
    ("/crossdomain.xml", "Flash cross-domain policy", "LOW"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain policy", "LOW"),
    # Discovery
    ("/.well-known/security.txt", "security.txt present", "INFO"),
]


# ===================================================================
#  PYTHON FALLBACK FINGERPRINTING ENGINE
# ===================================================================


def _safe_get(url: str, timeout: int = 8):
    """GET that silently returns None on any error (including 4xx)."""
    try:
        return retry_request(url, timeout=timeout, max_retries=0)
    except Exception:
        return None


def _check_cookies(headers) -> list[dict]:
    """Analyse Set-Cookie headers for missing security flags."""
    findings = []
    raw_cookies = headers.get("Set-Cookie", "")
    if not raw_cookies:
        return findings

    # requests collapses multiple Set-Cookie into one comma-separated value,
    # but we also handle the raw header list when available.
    cookie_strings = []
    if hasattr(headers, "getlist"):
        cookie_strings = headers.getlist("Set-Cookie")
    else:
        # Fall back to splitting on comma followed by a cookie-name pattern.
        # This is imperfect but catches most cases.
        cookie_strings = [raw_cookies]

    for cookie in cookie_strings:
        cookie_lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        missing_flags = []
        if "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")
        if missing_flags:
            findings.append({
                "cookie": name,
                "missing": missing_flags,
            })
    return findings


def _detect_server_infra(headers) -> list[str]:
    """Detect server software, CDN, cloud provider, caching layers."""
    results = []
    server = headers.get("Server", "")
    if server:
        results.append(f"[INFO] Server header: {server}")
        server_lower = server.lower()
        for sig, label in SERVER_SIGNATURES.items():
            if sig in server_lower:
                results.append(f"[INFO] Web server: {label}")
                break

    # Via header — proxy / CDN detection
    via = headers.get("Via", "")
    if via:
        results.append(f"[INFO] Via (proxy/CDN): {via}")

    # Infrastructure headers
    for header_name, label in INFRA_HEADERS.items():
        val = headers.get(header_name, "")
        if val:
            results.append(f"[INFO] {label} detected (header: {header_name})")

    # GCP catch-all
    for key in headers:
        if key.lower().startswith("x-gcp-"):
            results.append(f"[INFO] Google Cloud Platform detected (header: {key})")
            break

    return results


def _detect_technologies(headers, body: str) -> list[str]:
    """Detect CMS, languages, and frameworks from headers and body."""
    results = []
    detected = set()
    body_lower = body.lower()

    # --- Header-based detection ---
    for header_name, sig_map in HEADER_SIGNATURES.items():
        header_val = headers.get(header_name, "")
        if not header_val:
            continue
        for substring, label in sig_map.items():
            if substring == "" or substring.lower() in header_val.lower():
                if label not in detected:
                    detected.add(label)
                    results.append(f"[INFO] {label} (header: {header_name}: {header_val})")

    # X-Powered-By raw value (always log it)
    xpb = headers.get("X-Powered-By", "")
    if xpb and not any("X-Powered-By" in r for r in results):
        results.append(f"[INFO] X-Powered-By: {xpb}")

    # X-Generator
    xgen = headers.get("X-Generator", "")
    if xgen:
        results.append(f"[INFO] X-Generator: {xgen}")

    # ASP.NET version header
    aspnet_ver = headers.get("X-AspNet-Version", "")
    if aspnet_ver:
        results.append(f"[INFO] ASP.NET version: {aspnet_ver}")

    # WordPress wildcard headers (X-WordPress-*)
    for key in headers:
        if key.lower().startswith("x-wordpress"):
            results.append(f"[INFO] WordPress detected (header: {key}: {headers[key]})")
            detected.add("WordPress")
            break

    # --- Body-based detection ---
    for tech, sigs in CMS_SIGNATURES.items():
        if tech in detected:
            continue
        if sigs and any(sig.lower() in body_lower for sig in sigs):
            detected.add(tech)
            results.append(f"[INFO] {tech} detected (body signature)")

    # Rails combo heuristic
    if "authenticity_token" in body and headers.get("X-Runtime"):
        if "Ruby on Rails" not in detected and "Ruby on Rails (probable)" not in detected:
            results.append("[INFO] Ruby on Rails detected (body + X-Runtime header)")

    return results


def _check_security_headers(headers) -> list[str]:
    """Audit security headers — report present and missing with severity."""
    present = []
    missing = []

    for header_name, severity in SECURITY_HEADERS.items():
        val = headers.get(header_name, "")
        if val:
            present.append(f"[INFO] {header_name}: {val}")
        else:
            missing.append(f"[{severity}] Missing security header: {header_name}")

    # Cache-Control on the main page (informational)
    cc = headers.get("Cache-Control", "")
    if cc:
        present.append(f"[INFO] Cache-Control: {cc}")
        if "no-store" not in cc.lower():
            missing.append(
                "[LOW] Cache-Control missing 'no-store' — "
                "sensitive responses may be cached by intermediaries"
            )
    else:
        missing.append("[LOW] Missing Cache-Control header")

    return present, missing


def _probe_sensitive_files(target: str) -> list[str]:
    """Probe for sensitive / interesting files."""
    results = []
    for path, description, severity in INTERESTING_FILES:
        url = f"{target}{path}"
        resp = _safe_get(url, timeout=6)
        if resp is None:
            continue
        if resp.status_code == 200 and len(resp.text.strip()) > 0:
            # Extra validation to reduce false positives:
            # Many servers return a custom 200 page for missing paths.
            text = resp.text.strip()

            # .git/HEAD should start with "ref:"
            if path == "/.git/HEAD" and not text.startswith("ref:"):
                continue
            # .env should contain = (key=value pairs)
            if path == "/.env" and "=" not in text[:500]:
                continue
            # phpinfo should contain "phpinfo()"
            if path == "/phpinfo.php" and "phpinfo()" not in text[:5000].lower():
                continue
            # actuator/health returns JSON with "status"
            if path == "/actuator/health" and "status" not in text[:500].lower():
                continue
            # swagger.json should be JSON
            if path == "/swagger.json" and not text.lstrip().startswith("{"):
                continue
            # graphql — check if introspection works
            if path == "/graphql":
                # Just note the endpoint exists; introspection is a separate test
                pass

            results.append(f"[{severity}] {path} — {description}")

    return results


def _check_robots_sitemap(target: str) -> list[str]:
    """Check for robots.txt and sitemap.xml."""
    results = []

    resp = _safe_get(f"{target}/robots.txt", timeout=5)
    if resp and resp.status_code == 200 and len(resp.text) > 10:
        results.append(f"[INFO] robots.txt found ({len(resp.text)} bytes)")
        # Check for Disallow entries that hint at hidden paths
        interesting_disallows = []
        for line in resp.text.splitlines():
            line_stripped = line.strip().lower()
            if line_stripped.startswith("disallow:"):
                path = line_stripped.split(":", 1)[1].strip()
                if path and path != "/":
                    interesting_disallows.append(path)
        if interesting_disallows:
            results.append(
                f"[INFO] robots.txt disallowed paths: {', '.join(interesting_disallows[:15])}"
            )

    resp = _safe_get(f"{target}/sitemap.xml", timeout=5)
    if resp and resp.status_code == 200 and "xml" in resp.text[:200].lower():
        results.append(f"[INFO] sitemap.xml found ({len(resp.text)} bytes)")

    return results


def _fallback_fingerprint(target: str) -> str:
    """Comprehensive Python-based fingerprinting when WhatWeb is not available."""
    if not target.startswith("http"):
        target = f"https://{target}"

    # ---- Sections (populated below) ----
    sec_server: list[str] = []
    sec_tech: list[str] = []
    sec_headers_present: list[str] = []
    sec_headers_missing: list[str] = []
    sec_cookies: list[str] = []
    sec_files: list[str] = []
    sec_discovery: list[str] = []

    # ===================== Main page fetch =====================
    try:
        resp = retry_request(target, timeout=12, allow_redirects=True, max_retries=1)
        headers = resp.headers
        body = resp.text[:80_000]

        # 1. Server & Infrastructure
        sec_server = _detect_server_infra(headers)

        # 2. Technologies & Frameworks
        sec_tech = _detect_technologies(headers, body)

        # 3. Security Headers
        sec_headers_present, sec_headers_missing = _check_security_headers(headers)

        # 4. Cookies
        cookie_issues = _check_cookies(headers)
        for ci in cookie_issues:
            sec_cookies.append(
                f"[LOW] Cookie '{ci['cookie']}' missing flags: "
                f"{', '.join(ci['missing'])}"
            )

    except Exception as e:
        sec_server.append(f"[INFO] Main page fetch error: {e}")

    # ===================== Discovery probes =====================
    sec_discovery = _check_robots_sitemap(target)

    # ===================== Sensitive file probes =====================
    sec_files = _probe_sensitive_files(target)

    # ===================== Build formatted output =====================
    sections = []

    if sec_server:
        sections.append(
            "=== Server & Infrastructure ===\n" + "\n".join(f"  {r}" for r in sec_server)
        )

    if sec_tech:
        sections.append(
            "=== Technologies & Frameworks ===\n" + "\n".join(f"  {r}" for r in sec_tech)
        )

    header_lines = sec_headers_present + sec_headers_missing
    if header_lines:
        sections.append(
            "=== Security Headers ===\n" + "\n".join(f"  {r}" for r in header_lines)
        )

    if sec_files:
        sections.append(
            "=== Sensitive Files ===\n" + "\n".join(f"  {r}" for r in sec_files)
        )

    if sec_cookies:
        sections.append(
            "=== Cookies ===\n" + "\n".join(f"  {r}" for r in sec_cookies)
        )

    if sec_discovery:
        sections.append(
            "=== Discovery ===\n" + "\n".join(f"  {r}" for r in sec_discovery)
        )

    if not sections:
        return "No technology fingerprints detected."

    # Summary log for internal tracing
    tech_labels = [r for r in (sec_server + sec_tech) if "[INFO]" in r]
    if tech_labels:
        logger.info(
            "Fallback fingerprint for %s — detected: %s",
            target,
            "; ".join(t.replace("[INFO] ", "") for t in tech_labels[:12]),
        )
    else:
        logger.info(
            "Fallback fingerprint for %s — no technologies positively identified", target
        )

    output = "Technology fingerprint (Python fallback):\n\n" + "\n\n".join(sections)
    return output


# ===================================================================
#  PUBLIC API
# ===================================================================


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
