"""Fast CVE and misconfiguration scanner (Nuclei)."""

import os
import json
import logging
import subprocess
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)


def run(
    target: str, templates: str = "http/cves", severity: str = "critical,high"
) -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("nuclei.json")
    cmd = [
        "nuclei",
        "-u",
        target,
        "-t",
        templates,
        "-severity",
        severity,
        "-json",
        "-silent",
        "-o",
        output_path,
    ]

    logger.info(
        "Running nuclei: %s (templates=%s, severity=%s)", target, templates, severity
    )

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        source = result.stdout.strip()
        if not source and os.path.exists(output_path):
            with open(output_path, encoding="utf-8", errors="replace") as f:
                source = f.read()

        findings = []
        for line in source.splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if not findings:
            return f"Nuclei scan -- {target} -- 0 findings"

        summary = f"Nuclei scan -- {len(findings)} findings on {target}:\n"
        for finding in findings[:15]:
            info = finding.get("info", {})
            classification = info.get("classification") or {}
            cve_list = classification.get("cve-id") or []
            cve = cve_list[0] if cve_list else ""
            template_id = finding.get("template-id", "")
            name = info.get("name", "unknown")
            sev = info.get("severity", "?").upper()
            matched = finding.get("matched-at", finding.get("host", ""))
            refs = info.get("reference") or classification.get("cvss-metrics") or []
            ref_url = ""
            if cve:
                ref_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
            elif isinstance(refs, list) and refs:
                ref_url = refs[0]

            label = f"{cve} -- {name}" if cve else name
            summary += f"\n  [{sev}] {label}\n"
            summary += f"     URL: {matched}\n"
            if template_id:
                summary += f"     Template: {template_id}\n"
            if ref_url:
                summary += f"     Reference: {ref_url}\n"

        if len(findings) > 15:
            summary += (
                f"\n  ... +{len(findings) - 15} more (use read_log 'nuclei.json')"
            )

        logger.info("Nuclei found %d findings on %s", len(findings), target)
        return summary.strip()

    except FileNotFoundError:
        return "[TOOL OK, BINARY MISSING] nuclei is not installed on this system. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest or download from github.com/projectdiscovery/nuclei/releases. This does NOT mean the run_nuclei tool is unavailable — it just needs the nuclei binary."
    except Exception as e:
        logger.error("Nuclei error: %s", e)
        return f"Nuclei error: {str(e)}"


TOOL_SPEC = {
    "name": "run_nuclei",
    "description": "Fast CVE and misconfiguration scanner (Nuclei)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "string", "default": "http/cves"},
            "severity": {
                "type": "string",
                "default": "critical,high",
                "description": "Comma-separated severities (e.g. critical,high,medium)",
            },
        },
        "required": ["target"],
    },
}
