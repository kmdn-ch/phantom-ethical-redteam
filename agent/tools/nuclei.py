import subprocess
import json


def run(target: str, templates: str = "http/cves", severity: str = "critical") -> str:
    cmd = [
        "nuclei", "-u", target, "-t", templates,
        "-severity", severity, "-json", "-silent", "-o", "logs/nuclei.json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            # Nuclei outputs JSONL (one JSON object per line), not a JSON array
            findings = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return f"✅ Nuclei done – {len(findings)} findings"
        return f"⚠️ Nuclei ended with warnings\n{result.stderr}"
    except Exception as e:
        return f"❌ Error Nuclei : {str(e)}"


TOOL_SPEC = {
    "name": "run_nuclei",
    "description": "Launch a fast Nuclei scan and targeted (CVEs, misconfigs, etc.)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "string", "default": "http/cves"},
            "severity": {"type": "string", "default": "critical"},
        },
        "required": ["target"],
    },
}
