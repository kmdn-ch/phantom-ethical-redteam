"""CVSS risk scoring utility for Phantom reports."""

from __future__ import annotations

from tools import register_tool

SEVERITY_SCORES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.5,
    "low": 0.5,
    "info": 0.1,
}

TOOL_SPEC = {
    "name": "calculate_risk_score",
    "description": (
        "Calculate aggregate CVSS risk score from collected findings. "
        "Pass a list of findings, each with a 'severity' field "
        "(critical/high/medium/low/info). Returns score, label, and breakdown."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of finding objects with 'severity' field",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "name": {"type": "string"},
                    },
                },
            },
        },
        "required": ["findings"],
    },
}


@register_tool(TOOL_SPEC)
def run(findings: list | None = None, **kwargs) -> str:
    """Calculate aggregate risk score."""
    if not findings:
        return "No findings provided."

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        # Support both flat {"severity": "high"} and nested {"info": {"severity": "high"}}
        sev = f.get("severity") or (f.get("info", {}) or {}).get("severity") or "info"
        sev = sev.lower()
        if sev in breakdown:
            breakdown[sev] += 1

    total = sum(breakdown.values())
    if total == 0:
        return "No valid findings. Score: 0.0/10 (None)"

    weighted_sum = sum(
        breakdown[sev] * SEVERITY_WEIGHTS[sev] * SEVERITY_SCORES[sev]
        for sev in breakdown
    )
    weight_total = sum(breakdown[sev] * SEVERITY_WEIGHTS[sev] for sev in breakdown)
    score = round(min(10.0, weighted_sum / max(weight_total, 1.0)), 1)

    if score >= 9.0:
        label = "Critical"
    elif score >= 7.0:
        label = "High"
    elif score >= 4.0:
        label = "Medium"
    elif score >= 1.0:
        label = "Low"
    else:
        label = "Informational"

    # Build ASCII table
    rows = [
        ("Critical", breakdown["critical"]),
        ("High", breakdown["high"]),
        ("Medium", breakdown["medium"]),
        ("Low", breakdown["low"]),
        ("Info", breakdown["info"]),
    ]

    lines = [
        "=== RISK ASSESSMENT ===",
        "",
        f"  Overall Score: {score}/10 ({label.upper()})",
        "",
        "  +----------+-------+",
        "  | Severity | Count |",
        "  +----------+-------+",
    ]
    for sev_name, count in rows:
        lines.append(f"  | {sev_name:<8s} | {count:>5d} |")
    lines.append("  +----------+-------+")
    lines.append(f"  Total: {total} findings")

    # Top risk factors analysis
    risk_factors = []
    if breakdown["critical"] > 0:
        risk_factors.append(
            f"{breakdown['critical']} Critical finding{'s' if breakdown['critical'] > 1 else ''} "
            f"dominate{'s' if breakdown['critical'] == 1 else ''} the score"
        )
    if breakdown["high"] > 0:
        risk_factors.append(
            f"{breakdown['high']} High-severity finding{'s' if breakdown['high'] > 1 else ''} "
            f"contribute significantly"
        )
    high_weight = breakdown["critical"] + breakdown["high"]
    low_weight = breakdown["medium"] + breakdown["low"] + breakdown["info"]
    if high_weight > 0 and low_weight > high_weight:
        risk_factors.append(
            "Weighted average skewed by high-severity items despite more low-severity findings"
        )
    elif high_weight > low_weight and low_weight > 0:
        risk_factors.append("High-severity findings outnumber lower-severity ones")
    if not risk_factors:
        risk_factors.append("All findings are low severity or informational")

    lines.append("")
    lines.append("  Top risk factors:")
    for factor in risk_factors:
        lines.append(f"    - {factor}")

    return "\n".join(lines)
