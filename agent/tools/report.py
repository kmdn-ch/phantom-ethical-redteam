import os
import re
import html
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phantom version (imported at call-time to avoid circular deps)
# ---------------------------------------------------------------------------


def _get_version() -> str:
    """Read version from the VERSION file at the project root (avoids circular imports)."""
    try:
        version_file = Path(__file__).parent.parent.parent / "VERSION"
        return version_file.read_text(encoding="utf-8").strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Severity badge definitions
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#dc2626", "fg": "#ffffff"},
    "HIGH": {"bg": "#ea580c", "fg": "#ffffff"},
    "MEDIUM": {"bg": "#ca8a04", "fg": "#ffffff"},
    "LOW": {"bg": "#2563eb", "fg": "#ffffff"},
    "INFO": {"bg": "#6b7280", "fg": "#ffffff"},
}


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

PHANTOM_BANNER = r"""
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
""".strip()


# ---------------------------------------------------------------------------
# Markdown -> HTML converter
# ---------------------------------------------------------------------------


def _inline_format(text: str) -> str:
    """Apply inline markdown formatting to already-escaped HTML text."""
    # Bold
    text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
    # Italic (single *)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<em>\1</em>", text)
    # Inline code
    text = re.sub(r"`(.*?)`", r"<code>\1</code>", text)
    # Links [text](url)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<a href="\2" target="_blank" rel="noopener">\1</a>',
        text,
    )
    # Severity badges: [CRITICAL], [HIGH], etc.
    for sev, colors in SEVERITY_COLORS.items():
        text = text.replace(
            f"[{sev}]",
            f'<span class="badge badge-{sev.lower()}">{sev}</span>',
        )
    return text


def _detect_table_block(lines: list[str], start: int) -> tuple[list[str], int]:
    """Detect a pipe-delimited markdown table starting at `start`.

    Returns (html_lines, next_index) or ([], start) if not a table.
    """
    if start >= len(lines):
        return [], start

    first = lines[start].strip()
    if not first.startswith("|") or not first.endswith("|"):
        return [], start

    # Collect contiguous table rows
    raw_rows: list[str] = []
    idx = start
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            raw_rows.append(stripped)
            idx += 1
        else:
            break

    if len(raw_rows) < 2:
        return [], start

    # Check for separator row (e.g. |---|---|)
    sep_row = raw_rows[1]
    cells = [c.strip() for c in sep_row.strip("|").split("|")]
    is_sep = all(re.match(r"^:?-{2,}:?$", c) for c in cells)

    out = ['<div class="table-wrapper"><table>']

    def parse_cells(row: str) -> list[str]:
        return [html.escape(c.strip()) for c in row.strip("|").split("|")]

    if is_sep:
        # Header row
        headers = parse_cells(raw_rows[0])
        out.append("<thead><tr>")
        for h in headers:
            out.append(f"<th>{_inline_format(h)}</th>")
        out.append("</tr></thead>")
        data_rows = raw_rows[2:]
    else:
        data_rows = raw_rows

    out.append("<tbody>")
    for row in data_rows:
        out.append("<tr>")
        for cell in parse_cells(row):
            out.append(f"<td>{_inline_format(cell)}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")

    return out, idx


def _md_to_html_body(content: str) -> tuple[str, list[tuple[str, str]]]:
    """Convert markdown content to HTML body.

    Returns (html_string, toc_entries) where toc_entries is a list of
    (id, heading_text) for h2 headings.
    """
    lines = content.split("\n")
    out: list[str] = []
    toc: list[tuple[str, str]] = []
    in_code = False
    list_stack: list[str] = []  # stack of 'ul' or 'ol'

    h2_counter = 0

    def _close_lists(to_depth: int = 0) -> None:
        while len(list_stack) > to_depth:
            tag = list_stack.pop()
            out.append(f"</{tag}>")

    i = 0
    while i < len(lines):
        line = lines[i]

        # --- Fenced code blocks ---
        if line.startswith("```"):
            _close_lists()
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                lang = html.escape(line[3:].strip())
                lang_attr = f' data-lang="{lang}"' if lang else ""
                out.append(f'<pre class="code-block"{lang_attr}><code>')
                in_code = True
            i += 1
            continue

        if in_code:
            out.append(html.escape(line))
            out.append("\n")
            i += 1
            continue

        # --- Table detection ---
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            _close_lists()
            table_html, i = _detect_table_block(lines, i)
            if table_html:
                out.extend(table_html)
                continue
            # fallthrough if not a valid table

        # --- Horizontal rule ---
        if re.match(r"^-{3,}$", stripped) or re.match(r"^\*{3,}$", stripped):
            _close_lists()
            out.append('<hr class="divider">')
            i += 1
            continue

        # Escape for non-code content
        escaped = html.escape(line)
        escaped = _inline_format(escaped)

        # --- Headings ---
        heading_match = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading_match:
            _close_lists()
            level = len(heading_match.group(1))
            text_raw = heading_match.group(2)
            text_esc = _inline_format(html.escape(text_raw))
            if level == 2:
                h2_counter += 1
                anchor = f"section-{h2_counter}"
                toc.append((anchor, text_raw))
                out.append(f'<h2 id="{anchor}">{text_esc}</h2>')
            elif level == 1:
                out.append(f"<h1>{text_esc}</h1>")
            elif level == 3:
                out.append(f"<h3>{text_esc}</h3>")
            elif level == 4:
                out.append(f"<h4>{text_esc}</h4>")
            i += 1
            continue

        # --- Ordered list items (1. 2. etc.) ---
        ol_match = re.match(r"^(\s*)\d+\.\s+(.+)$", line)
        if ol_match:
            indent = len(ol_match.group(1))
            depth = indent // 2 + 1
            item_text = _inline_format(html.escape(ol_match.group(2)))
            # Manage list nesting
            while len(list_stack) < depth:
                out.append("<ol>")
                list_stack.append("ol")
            while len(list_stack) > depth:
                tag = list_stack.pop()
                out.append(f"</{tag}>")
            out.append(f"<li>{item_text}</li>")
            i += 1
            continue

        # --- Unordered list items ---
        ul_match = re.match(r"^(\s*)[-*]\s+(.+)$", line)
        if ul_match:
            indent = len(ul_match.group(1))
            depth = indent // 2 + 1
            item_text = _inline_format(html.escape(ul_match.group(2)))
            while len(list_stack) < depth:
                out.append("<ul>")
                list_stack.append("ul")
            while len(list_stack) > depth:
                tag = list_stack.pop()
                out.append(f"</{tag}>")
            out.append(f"<li>{item_text}</li>")
            i += 1
            continue

        # --- Blank line ---
        if not stripped:
            _close_lists()
            i += 1
            continue

        # --- Paragraph ---
        _close_lists()
        out.append(f"<p>{escaped}</p>")
        i += 1

    # Close any remaining open lists / code blocks
    _close_lists()
    if in_code:
        out.append("</code></pre>")

    return "\n".join(out), toc


# ---------------------------------------------------------------------------
# Severity stats extraction
# ---------------------------------------------------------------------------


def _count_severities(content: str) -> dict[str, int]:
    """Count occurrences of [CRITICAL], [HIGH], etc. in the content."""
    counts: dict[str, int] = {}
    for sev in SEVERITY_COLORS:
        n = content.count(f"[{sev}]")
        if n > 0:
            counts[sev] = n
    return counts


def _build_stats_bar(counts: dict[str, int]) -> str:
    """Build an HTML stats bar with severity pill counts."""
    if not counts:
        return ""
    total = sum(counts.values())
    pills = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n > 0:
            colors = SEVERITY_COLORS[sev]
            pills.append(
                f'<span class="stat-pill" style="background:{colors["bg"]}; '
                f'color:{colors["fg"]}">{sev}: {n}</span>'
            )
    return f"""<div class="stats-bar">
  <div class="stats-label">Findings Summary</div>
  <div class="stats-pills">
    {"".join(pills)}
    <span class="stat-pill stat-total">TOTAL: {total}</span>
  </div>
</div>"""


# ---------------------------------------------------------------------------
# Table of contents builder
# ---------------------------------------------------------------------------


def _build_toc(toc_entries: list[tuple[str, str]]) -> str:
    """Build an HTML table of contents from h2 entries."""
    if not toc_entries:
        return ""
    items = []
    for anchor, text in toc_entries:
        safe = html.escape(text)
        items.append(f'<li><a href="#{anchor}">{safe}</a></li>')
    return f"""<nav class="toc">
  <div class="toc-title">Table of Contents</div>
  <ol>
    {"".join(items)}
  </ol>
</nav>"""


# ---------------------------------------------------------------------------
# CSS stylesheet
# ---------------------------------------------------------------------------

CSS = """
:root {
  --bg-primary: #1a1f2e;
  --bg-secondary: #232838;
  --bg-tertiary: #2a3042;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent-primary: #3b82f6;
  --accent-red: #f85149;
  --border-color: #334155;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
               'Helvetica Neue', Arial, sans-serif;
  --font-mono: 'Cascadia Code', 'Fira Code', 'JetBrains Mono',
               'Consolas', 'Monaco', monospace;
}

*, *::before, *::after { box-sizing: border-box; }

body {
  font-family: var(--font-sans);
  background: var(--bg-primary);
  color: var(--text-primary);
  max-width: 1000px;
  margin: 0 auto;
  padding: 40px 32px 60px;
  line-height: 1.7;
  font-size: 15px;
  -webkit-font-smoothing: antialiased;
}

/* ---- Banner / Header ---- */
.report-header {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 24px 28px;
  margin-bottom: 28px;
  text-align: center;
}
.ascii-banner {
  font-family: var(--font-mono);
  font-size: 10px;
  line-height: 1.15;
  color: var(--accent-red);
  white-space: pre;
  margin-bottom: 8px;
  overflow-x: auto;
}
.header-subtitle {
  font-size: 13px;
  color: var(--text-muted);
  letter-spacing: 3px;
  text-transform: uppercase;
  margin-top: 4px;
}

/* ---- Title ---- */
h1 {
  color: var(--text-primary);
  font-size: 1.8em;
  font-weight: 700;
  border-bottom: 2px solid var(--accent-red);
  padding-bottom: 12px;
  margin-top: 0;
  margin-bottom: 8px;
}

.report-meta {
  color: var(--text-muted);
  font-size: 0.85em;
  margin-bottom: 28px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border-color);
}

/* ---- Stats bar ---- */
.stats-bar {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px 20px;
  margin-bottom: 28px;
}
.stats-label {
  font-size: 0.8em;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  margin-bottom: 10px;
}
.stats-pills { display: flex; flex-wrap: wrap; gap: 8px; }
.stat-pill {
  display: inline-block;
  padding: 4px 14px;
  border-radius: 20px;
  font-size: 0.8em;
  font-weight: 600;
  letter-spacing: 0.5px;
}
.stat-total {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
}

/* ---- Table of contents ---- */
.toc {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 32px;
}
.toc-title {
  font-size: 0.8em;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  margin-bottom: 12px;
}
.toc ol {
  margin: 0;
  padding-left: 20px;
}
.toc li {
  margin: 6px 0;
  font-size: 0.95em;
}
.toc a {
  color: var(--accent-primary);
  text-decoration: none;
  transition: color 0.2s;
}
.toc a:hover { color: #60a5fa; text-decoration: underline; }

/* ---- Headings ---- */
h2 {
  color: var(--text-primary);
  font-size: 1.35em;
  font-weight: 600;
  background: var(--bg-secondary);
  padding: 10px 16px;
  border-left: 4px solid var(--accent-red);
  border-radius: 0 6px 6px 0;
  margin-top: 36px;
  margin-bottom: 16px;
}
h3 {
  color: #93c5fd;
  font-size: 1.1em;
  font-weight: 600;
  margin-top: 24px;
  margin-bottom: 10px;
}
h4 {
  color: var(--text-secondary);
  font-size: 1em;
  font-weight: 600;
  margin-top: 20px;
  margin-bottom: 8px;
}

/* ---- Text ---- */
p {
  margin: 8px 0;
  color: var(--text-primary);
}
strong { color: #f1f5f9; }
em { color: var(--text-secondary); font-style: italic; }
a { color: var(--accent-primary); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ---- Code ---- */
code {
  font-family: var(--font-mono);
  background: var(--bg-tertiary);
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 0.88em;
  color: #f97316;
}
.code-block {
  font-family: var(--font-mono);
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  padding: 18px 20px;
  border-radius: 8px;
  overflow-x: auto;
  font-size: 0.88em;
  line-height: 1.5;
  color: #a5d6ff;
  margin: 12px 0;
}
.code-block code {
  background: none;
  padding: 0;
  border-radius: 0;
  font-size: inherit;
  color: inherit;
}

/* ---- Lists ---- */
ul, ol {
  padding-left: 24px;
  margin: 8px 0;
}
li {
  margin: 5px 0;
  line-height: 1.6;
}

/* ---- Severity badges ---- */
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 4px;
  font-size: 0.75em;
  font-weight: 700;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  vertical-align: middle;
  margin-right: 4px;
}
.badge-critical { background: #dc2626; color: #fff; }
.badge-high     { background: #ea580c; color: #fff; }
.badge-medium   { background: #ca8a04; color: #fff; }
.badge-low      { background: #2563eb; color: #fff; }
.badge-info     { background: #6b7280; color: #fff; }

/* ---- Tables ---- */
.table-wrapper {
  overflow-x: auto;
  margin: 12px 0;
  border-radius: 8px;
  border: 1px solid var(--border-color);
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
}
thead {
  background: var(--bg-tertiary);
}
th {
  padding: 10px 14px;
  text-align: left;
  font-weight: 600;
  color: var(--text-secondary);
  border-bottom: 2px solid var(--border-color);
  font-size: 0.85em;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
td {
  padding: 8px 14px;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-primary);
}
tbody tr:hover { background: var(--bg-secondary); }
tbody tr:last-child td { border-bottom: none; }

/* ---- Horizontal rule ---- */
.divider {
  border: none;
  height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    var(--border-color) 20%,
    var(--border-color) 80%,
    transparent
  );
  margin: 28px 0;
}

/* ---- Footer ---- */
.report-footer {
  margin-top: 48px;
  padding-top: 20px;
  border-top: 1px solid var(--border-color);
  text-align: center;
  color: var(--text-muted);
  font-size: 0.8em;
}
.report-footer .phantom-mark {
  color: var(--accent-red);
  font-weight: 600;
}

/* ---- Print styles ---- */
@media print {
  :root {
    --bg-primary: #ffffff;
    --bg-secondary: #f8fafc;
    --bg-tertiary: #f1f5f9;
    --text-primary: #1e293b;
    --text-secondary: #475569;
    --text-muted: #64748b;
    --border-color: #cbd5e1;
  }

  body {
    background: #ffffff;
    color: #1e293b;
    max-width: none;
    padding: 20px;
    font-size: 12pt;
  }

  .report-header {
    border-color: #cbd5e1;
    break-after: avoid;
  }
  .ascii-banner { color: #1e293b; font-size: 8px; }

  h1 { border-bottom-color: #1e293b; }
  h2 {
    background: #f1f5f9;
    border-left-color: #1e293b;
    break-after: avoid;
  }

  .code-block {
    background: #f8fafc;
    border-color: #cbd5e1;
    color: #1e293b;
    white-space: pre-wrap;
    word-break: break-all;
  }
  code { background: #f1f5f9; color: #c2410c; }

  .stats-bar, .toc {
    background: #f8fafc;
    border-color: #cbd5e1;
  }

  table { font-size: 10pt; }
  thead { background: #f1f5f9; }
  th, td { border-color: #cbd5e1; }

  a { color: #1e293b; text-decoration: underline; }
  a::after { content: " (" attr(href) ")"; font-size: 0.8em; color: #64748b; }

  .badge { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  .stat-pill { print-color-adjust: exact; -webkit-print-color-adjust: exact; }

  .report-footer { break-before: avoid; }
}
"""


# ---------------------------------------------------------------------------
# HTML document builder
# ---------------------------------------------------------------------------


def _build_html_document(title: str, content: str, timestamp: str) -> str:
    """Assemble the complete HTML report document."""
    safe_title = html.escape(title)
    version = _get_version()
    body_html, toc_entries = _md_to_html_body(content)
    severity_counts = _count_severities(content)
    stats_bar = _build_stats_bar(severity_counts)
    toc_html = _build_toc(toc_entries)
    banner_escaped = html.escape(PHANTOM_BANNER)

    display_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="Phantom Ethical RedTeam v{html.escape(version)}">
  <title>Phantom \u2014 {safe_title}</title>
  <style>{CSS}</style>
</head>
<body>

  <div class="report-header">
    <div class="ascii-banner">{banner_escaped}</div>
    <div class="header-subtitle">Ethical RedTeam \u2014 Mission Report</div>
  </div>

  <h1>{safe_title}</h1>
  <div class="report-meta">
    Generated: {html.escape(display_ts)} &nbsp;\u2022&nbsp;
    Phantom v{html.escape(version)} &nbsp;\u2022&nbsp;
    Ethical RedTeam Assessment
  </div>

  {stats_bar}
  {toc_html}

  <div class="report-body">
    {body_html}
  </div>

  <div class="report-footer">
    <p>
      Generated by <span class="phantom-mark">Phantom Ethical RedTeam</span>
      v{html.escape(version)}
    </p>
    <p>{html.escape(display_ts)}</p>
  </div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run(title: str, content: str, generate_pdf: bool = False) -> str:
    """Generate a formatted mission report (Markdown + HTML, optional PDF)."""
    version = _get_version()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    display_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md_path = log_path(f"report_{ts}.md")
    html_path = log_path(f"report_{ts}.html")

    # -- Write Markdown --
    md_header = (
        f"# {title}\n\n"
        f"> **Phantom Ethical RedTeam** v{version}  \n"
        f"> Generated: {display_date}  \n"
        f"> Classification: Confidential\n\n"
        f"---\n\n"
    )
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_header + content)

    # -- Write HTML --
    html_doc = _build_html_document(title, content, ts)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    result = f"Report saved:\n  Markdown : {md_path}\n  HTML     : {html_path}"

    # -- Optional PDF --
    if generate_pdf:
        pdf_path = log_path(f"report_{ts}.pdf")
        try:
            subprocess.run(
                ["wkhtmltopdf", "--quiet", html_path, pdf_path],
                capture_output=True,
                timeout=60,
            )
            if os.path.exists(pdf_path):
                result += f"\n  PDF      : {pdf_path}"
            else:
                result += "\n  PDF      : wkhtmltopdf ran but produced no output"
        except FileNotFoundError:
            result += "\n  PDF      : skipped (wkhtmltopdf not installed)"
        except Exception as e:
            result += f"\n  PDF      : failed ({e})"

    logger.info("Report generated: %s", md_path)
    return result


# ---------------------------------------------------------------------------
# Tool specification (unchanged API contract)
# ---------------------------------------------------------------------------

TOOL_SPEC = {
    "name": "generate_report",
    "description": (
        "Generate a formatted mission report (Markdown + HTML, optional PDF). "
        "Call at the end of the mission, before cleanup_temp, "
        "with the full executive summary, findings, PoC, and recommendations."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Report title, e.g. 'Pentest Report \u2014 dummytarget.com \u2014 2026-03-18'",
            },
            "content": {
                "type": "string",
                "description": "Full report body in Markdown format",
            },
            "generate_pdf": {
                "type": "boolean",
                "description": "Generate PDF via wkhtmltopdf (default false)",
            },
        },
        "required": ["title", "content"],
    },
}
