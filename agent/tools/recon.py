import requests

def run(domain: str) -> str:
    # Recon subdomains via crt.sh (public & free)
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        subs = {entry["name_value"] for entry in r.json()}
        return f"✅ {len(subs)} sub-domains found (crt.sh)\n" + "\n".join(list(subs)[:15])
    except:
        return "⚠️ Recon crt.sh failed – fallback possible later"

TOOL_SPEC = {
    "name": "run_recon",
    "description": "Sub domain passive Reconnaissance (crt.sh)",
    "input_schema": {
        "type": "object",
        "properties": {"domain": {"type": "string"}},
        "required": ["domain"]
    }
}
