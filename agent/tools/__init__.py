"""Tool registry with auto-discovery."""

from __future__ import annotations

import importlib
import logging

__all__ = [
    "register_tool",
    "ALL_TOOLS",
    "get_tool_mapping",
    "TOOL_REGISTRY",
    "TOOL_SPECS",
]

logger = logging.getLogger(__name__)

# Global registry
TOOL_REGISTRY: dict[str, callable] = {}
TOOL_SPECS: list[dict] = []


def register_tool(spec: dict):
    """Decorator to register a tool function with its spec."""

    def decorator(func):
        TOOL_REGISTRY[spec["name"]] = func
        TOOL_SPECS.append(spec)
        return func

    return decorator


def _import_all_tools():
    """Import all tool modules and register them."""

    # --- Core tools (no decorator — manual registration) ---
    from .nuclei import run as run_nuclei, TOOL_SPEC as nuclei_spec
    from .sqlmap import run as run_sqlmap, TOOL_SPEC as sqlmap_spec
    from .ffuf import run as run_ffuf, TOOL_SPEC as ffuf_spec
    from .recon import run as run_recon, TOOL_SPEC as recon_spec
    from .set_phish import run as generate_phish_template, TOOL_SPEC as phish_spec
    from .cleanup import run as cleanup_temp, TOOL_SPEC as cleanup_spec
    from .bettercap import run as run_bettercap, TOOL_SPEC as bettercap_spec
    from .zphisher import run as generate_zphisher_template, TOOL_SPEC as zphisher_spec
    from .read_log import run as read_log, TOOL_SPEC as read_log_spec
    from .payloads import run as run_payloads, TOOL_SPEC as payloads_spec
    from .human_input import run as request_human_input, TOOL_SPEC as human_input_spec
    from .report import run as generate_report, TOOL_SPEC as report_spec

    _core_specs = [
        nuclei_spec,
        sqlmap_spec,
        ffuf_spec,
        recon_spec,
        phish_spec,
        cleanup_spec,
        bettercap_spec,
        zphisher_spec,
        read_log_spec,
        payloads_spec,
        human_input_spec,
        report_spec,
    ]
    _core_funcs = {
        "run_nuclei": run_nuclei,
        "run_sqlmap": run_sqlmap,
        "run_ffuf": run_ffuf,
        "run_recon": run_recon,
        "generate_phish_template": generate_phish_template,
        "cleanup_temp": cleanup_temp,
        "run_bettercap": run_bettercap,
        "generate_zphisher_template": generate_zphisher_template,
        "read_log": read_log,
        "run_payloads": run_payloads,
        "request_human_input": request_human_input,
        "generate_report": generate_report,
    }
    TOOL_SPECS.extend(_core_specs)
    TOOL_REGISTRY.update(_core_funcs)

    # --- Optional tools (use @register_tool decorator or manual fallback) ---
    _optional = [
        "nmap_scan",
        "whatweb_tool",
        "screenshot",
        "auth_manager",
        "mission_diff",
        "cvss_scorer",
        "scope_checker",
        "wpscan",
        "jwt_tool",
        "graphql_enum",
        "hydra_tool",
        "privesc",
        "stealth",
        "metasploit",
    ]
    for mod_name in _optional:
        try:
            mod = importlib.import_module(f".{mod_name}", package="tools")
            # If the module uses @register_tool, it's already registered.
            # If not, try manual registration from TOOL_SPEC + run.
            spec = getattr(mod, "TOOL_SPEC", None)
            run_fn = getattr(mod, "run", None)
            if spec and run_fn and spec["name"] not in TOOL_REGISTRY:
                TOOL_SPECS.append(spec)
                TOOL_REGISTRY[spec["name"]] = run_fn
        except ImportError as e:
            logger.warning("Optional tool '%s' not available: %s", mod_name, e)


# Auto-register all tools on import
_import_all_tools()

# Public API
ALL_TOOLS = TOOL_SPECS


def get_tool_mapping() -> dict[str, callable]:
    """Return {tool_name: function} mapping for all registered tools."""
    return dict(TOOL_REGISTRY)
