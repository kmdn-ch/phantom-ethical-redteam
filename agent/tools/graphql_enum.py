"""GraphQL introspection and enumeration tool."""

import json
import logging

from .scope_checker import scope_guard
from .http_utils import retry_request
from .stealth import stealth_headers, stealth_delay
from .logs_helper import log_path

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
""".strip()

# Common GraphQL endpoints
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/graphiql",
    "/graphql/console",
    "/api/graphql",
    "/api/v1/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/playground",
]

# Dangerous operations to flag
SENSITIVE_FIELDS = [
    "password",
    "token",
    "secret",
    "apikey",
    "api_key",
    "credential",
    "ssn",
    "credit_card",
    "creditcard",
    "bank",
    "salary",
    "admin",
    "role",
    "permission",
    "delete",
    "drop",
    "reset",
]


def _find_graphql_endpoint(base_url: str) -> str | None:
    """Probe common GraphQL endpoint paths."""
    base = base_url.rstrip("/")
    for path in GRAPHQL_PATHS:
        stealth_delay()
        url = base + path
        try:
            resp = retry_request(
                url,
                method="POST",
                headers={**stealth_headers(), "Content-Type": "application/json"},
                json={"query": "{__typename}"},
                timeout=8,
                max_retries=1,
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        return url
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            continue
    return None


def _run_introspection(endpoint: str) -> dict | None:
    """Run full introspection query."""
    stealth_delay()
    try:
        resp = retry_request(
            endpoint,
            method="POST",
            headers={**stealth_headers(), "Content-Type": "application/json"},
            json={"query": INTROSPECTION_QUERY},
            timeout=15,
        )
        data = resp.json()
        if "data" in data and data["data"].get("__schema"):
            return data["data"]["__schema"]
    except Exception as e:
        logger.error("Introspection failed: %s", e)
    return None


def run(target: str, endpoint: str = "", depth: str = "full") -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    findings = []

    # Find GraphQL endpoint
    gql_url = endpoint or _find_graphql_endpoint(target)
    if not gql_url:
        return f"No GraphQL endpoint found at {target} (tested {len(GRAPHQL_PATHS)} common paths)"

    findings.append(f"[INFO] GraphQL endpoint: {gql_url}")

    # Run introspection
    schema = _run_introspection(gql_url)
    if not schema:
        findings.append("[MEDIUM] Introspection query failed or disabled")
        # Try alternative introspection bypass
        stealth_delay()
        try:
            resp = retry_request(
                gql_url,
                method="POST",
                headers={**stealth_headers(), "Content-Type": "application/json"},
                json={"query": '{__type(name:"Query"){name fields{name}}}'},
                timeout=10,
            )
            data = resp.json()
            if "data" in data and data["data"]:
                findings.append("[HIGH] Partial introspection possible (type-level)")
        except Exception:
            pass

        return f"GraphQL scan — {len(findings)} findings:\n" + "\n".join(
            f"  {f}" for f in findings
        )

    findings.append("[HIGH] Introspection is ENABLED — full schema exposed")

    # Analyze schema
    types = schema.get("types", [])
    query_type = schema.get("queryType", {}).get("name", "Query")
    mutation_type = (schema.get("mutationType") or {}).get("name", "")

    # Filter user-defined types (exclude __*)
    user_types = [t for t in types if not t["name"].startswith("__")]
    object_types = [t for t in user_types if t["kind"] == "OBJECT"]

    findings.append(
        f"[INFO] Schema: {len(user_types)} types, {len(object_types)} objects"
    )
    if mutation_type:
        findings.append(f"[MEDIUM] Mutations available (type: {mutation_type})")

    # List queries and mutations
    queries = []
    mutations = []
    for t in types:
        if t["name"] == query_type and t.get("fields"):
            queries = [f["name"] for f in t["fields"]]
        if mutation_type and t["name"] == mutation_type and t.get("fields"):
            mutations = [f["name"] for f in t["fields"]]

    if queries:
        findings.append(f"[INFO] Queries ({len(queries)}): {', '.join(queries[:15])}")
        if len(queries) > 15:
            findings.append(f"  ... +{len(queries) - 15} more")
    if mutations:
        findings.append(
            f"[MEDIUM] Mutations ({len(mutations)}): {', '.join(mutations[:15])}"
        )
        if len(mutations) > 15:
            findings.append(f"  ... +{len(mutations) - 15} more")

    # Check for sensitive fields
    sensitive_found = []
    for t in object_types:
        for field in t.get("fields") or []:
            fname = field["name"].lower()
            for keyword in SENSITIVE_FIELDS:
                if keyword in fname:
                    sensitive_found.append(f"{t['name']}.{field['name']}")
                    break

    if sensitive_found:
        findings.append(f"[HIGH] Sensitive fields exposed ({len(sensitive_found)}):")
        for sf in sensitive_found[:10]:
            findings.append(f"    {sf}")
        if len(sensitive_found) > 10:
            findings.append(f"    ... +{len(sensitive_found) - 10} more")

    # Check for dangerous mutations
    dangerous_mutations = []
    for m in mutations:
        ml = m.lower()
        if any(
            kw in ml for kw in ("delete", "remove", "drop", "reset", "admin", "role")
        ):
            dangerous_mutations.append(m)

    if dangerous_mutations:
        findings.append(f"[HIGH] Dangerous mutations: {', '.join(dangerous_mutations)}")

    # Save full schema
    result_path = log_path("graphql_schema.json")
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
        findings.append(f"[INFO] Full schema saved to {result_path}")
    except Exception:
        pass

    result = f"GraphQL scan — {len(findings)} findings:\n" + "\n".join(
        f"  {f}" for f in findings
    )
    if len(result) > 5000:
        result = (
            result[:5000]
            + "\n... (use read_log 'graphql_schema.json' to see full schema)"
        )
    return result


TOOL_SPEC = {
    "name": "run_graphql_enum",
    "description": (
        "GraphQL introspection and enumeration. Discovers endpoints, runs introspection, "
        "enumerates queries/mutations, identifies sensitive fields (password, token, admin), "
        "flags dangerous mutations (delete, reset). Pure Python — no external deps."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base URL of the target"},
            "endpoint": {
                "type": "string",
                "description": "Exact GraphQL endpoint URL (optional)",
            },
            "depth": {
                "type": "string",
                "description": "Scan depth: quick or full (default: full)",
            },
        },
        "required": ["target"],
    },
}
