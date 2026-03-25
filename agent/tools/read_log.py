import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)
LOGS_DIR = Path("logs")


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def run(filename: str = "") -> str:
    """Read a result file from logs/ or list all available log files."""
    logs_abs = LOGS_DIR.resolve()

    if not filename:
        files_by_ext: dict[str, list] = {}
        for path in sorted(logs_abs.rglob("*")):
            if path.is_file():
                rel = str(path.relative_to(logs_abs))
                stat = path.stat()
                size = _human_size(stat.st_size)
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                ext = path.suffix.lstrip(".").upper() or "OTHER"
                files_by_ext.setdefault(ext, []).append((rel, size, mtime))
        if not files_by_ext:
            return "logs/ is empty"

        total = sum(len(v) for v in files_by_ext.values())
        summary = f"Available logs -- {total} files:\n"
        for ext in sorted(files_by_ext):
            group = files_by_ext[ext]
            summary += f"\n  [{ext}] ({len(group)} files)\n"
            for rel, size, mtime in group:
                summary += f"    {rel:<40s} {size:>8s}  {mtime}\n"
        return summary.strip()

    # Security: resolve symlinks and block path traversal
    try:
        target = (LOGS_DIR / filename).resolve(strict=True)
    except (OSError, ValueError):
        return f"File not found: {filename}"

    if not str(target).startswith(str(logs_abs)):
        return "Access denied: path outside logs/"

    try:
        content = target.read_text(encoding="utf-8", errors="replace")

        if not content.strip():
            return f"{filename}: (empty)"

        if filename.endswith(".json"):
            lines = [l.strip() for l in content.splitlines() if l.strip()]

            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            if len(parsed) > 1:
                # Detect nuclei JSON (has "info" key with severity)
                is_nuclei = any("info" in e and "severity" in (e.get("info") or {}) for e in parsed[:5])
                if is_nuclei:
                    summary = f"Nuclei results -- {filename} -- {len(parsed)} findings:\n"
                    for entry in parsed[:20]:
                        info = entry.get("info", {})
                        classification = info.get("classification") or {}
                        cve_list = classification.get("cve-id") or []
                        cve = cve_list[0] if cve_list else ""
                        template_id = entry.get("template-id", "")
                        name = info.get("name", "?")
                        sev = info.get("severity", "?").upper()
                        matched = entry.get("matched-at", entry.get("host", "?"))
                        ref_url = ""
                        if cve:
                            ref_url = f"https://nvd.nist.gov/vuln/detail/{cve}"

                        label = f"{cve} -- {name}" if cve else name
                        summary += f"\n  [{sev}] {label}\n"
                        summary += f"     URL: {matched}\n"
                        if template_id:
                            summary += f"     Template: {template_id}\n"
                        if ref_url:
                            summary += f"     Reference: {ref_url}\n"
                    if len(parsed) > 20:
                        summary += f"\n  ... +{len(parsed) - 20} more"
                    return summary.strip()
                else:
                    summary = f"{filename} -- {len(parsed)} entries:\n"
                    for entry in parsed[:20]:
                        summary += f"  {json.dumps(entry)[:120]}\n"
                    if len(parsed) > 20:
                        summary += f"  ... +{len(parsed) - 20} more"
                    return summary.strip()

            if len(parsed) == 1:
                data = parsed[0]
                results = data.get("results", [])
                if results:
                    summary = f"Ffuf results -- {filename} -- {len(results)} entries:\n\n"
                    # Build aligned table
                    col_status = 8
                    col_url = max(20, min(60, max(
                        len(str(r.get("url", (r.get("input") or {}).get("FUZZ", "?"))))
                        for r in results[:20]
                    ))) + 2
                    summary += f"  {'STATUS':<{col_status}}{'URL':<{col_url}}{'LENGTH':>8}\n"
                    summary += f"  {'-' * col_status}{'-' * col_url}{'-' * 8}\n"
                    for r in results[:20]:
                        status = str(r.get("status", "?"))
                        url = r.get("url", (r.get("input") or {}).get("FUZZ", "?"))
                        length = str(r.get("length", "?"))
                        summary += f"  {status:<{col_status}}{url:<{col_url}}{length:>8}\n"
                    if len(results) > 20:
                        summary += f"\n  ... +{len(results) - 20} more"
                    return summary.strip()
                return f"{filename}:\n{json.dumps(data, indent=2)[:3000]}"

        # Plain text
        line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        file_size = _human_size(len(content.encode("utf-8", errors="replace")))
        header = f"{filename} -- {file_size}, {line_count} lines:\n\n"
        if len(content) > 3000:
            return f"{header}{content[:3000]}\n\n  ... truncated (showing first 3000 chars)"
        return f"{header}{content}"

    except Exception as e:
        logger.error("Error reading %s: %s", filename, e)
        return f"Error reading {filename}: {str(e)}"


TOOL_SPEC = {
    "name": "read_log",
    "description": (
        "Read a result file from logs/ (nuclei, ffuf, sqlmap, recon, etc.) "
        "or list all available log files. Call with no argument to list files."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": (
                    "Filename to read (e.g. 'nuclei.json', 'ffuf.json', 'sqlmap/target/log'). "
                    "Leave empty to list all available log files."
                ),
            }
        },
        "required": [],
    },
}
