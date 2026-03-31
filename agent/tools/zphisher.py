import os
import logging

logger = logging.getLogger(__name__)
ZPHISHER_DIR = os.path.join("tools", "zphisher_repo", "sites")


def _list_available_templates() -> list[str]:
    """Scan the zphisher sites directory for available templates."""
    if not os.path.isdir(ZPHISHER_DIR):
        return []
    return sorted(
        d
        for d in os.listdir(ZPHISHER_DIR)
        if os.path.isdir(os.path.join(ZPHISHER_DIR, d))
    )


def run(target: str, template: str = "instagram") -> str:
    if template == "list":
        templates = _list_available_templates()
        if not templates:
            return f"No Zphisher templates found. Directory: {ZPHISHER_DIR}"
        return "Available Zphisher templates:\n" + "\n".join(
            f"  - {t}" for t in templates
        )

    template_path = os.path.join(ZPHISHER_DIR, template)
    if not os.path.isdir(template_path):
        available = _list_available_templates()
        hint = (
            f" Available: {', '.join(available)}"
            if available
            else " Run installer to download templates."
        )
        return f"Template '{template}' not found.{hint}"

    login_file = os.path.join(template_path, "login.html")
    if not os.path.isfile(login_file):
        return f"Template '{template}' exists but login.html is missing."

    try:
        with open(login_file, encoding="utf-8", errors="replace") as f:
            content = f.read()[:500]
    except PermissionError:
        return f"Permission denied reading template '{template}'."

    logger.info("Zphisher template '%s' loaded for %s", template, target)
    return (
        f"Template {template} for {target} generated (NO REAL SEND POSSIBLE)\n"
        f"Template Zphisher loaded (ethical):\n{content}"
    )


TOOL_SPEC = {
    "name": "generate_zphisher_template",
    "description": (
        "Generate a phishing page template with Zphisher (educational only). "
        "Use template='list' to see all available templates."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "template": {
                "type": "string",
                "default": "instagram",
                "description": "Template name (instagram, facebook, etc.) or 'list' to see all",
            },
        },
        "required": ["target"],
    },
}
