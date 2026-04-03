"""Tests for agent/tools/report.py — HTML generation, markdown conversion, severity counting."""

import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

from tools.report import (
    _inline_format,
    _md_to_html_body,
    _count_severities,
    _build_stats_bar,
    _build_toc,
    _build_html_document,
    _detect_table_block,
    SEVERITY_COLORS,
)


class TestInlineFormat:
    def test_bold(self):
        result = _inline_format("**bold text**")
        assert "<strong>bold text</strong>" in result

    def test_italic(self):
        result = _inline_format("*italic text*")
        assert "<em>italic text</em>" in result

    def test_inline_code(self):
        result = _inline_format("`code`")
        assert "<code>code</code>" in result

    def test_link(self):
        result = _inline_format("[label](https://example.com)")
        assert 'href="https://example.com"' in result
        assert "label" in result

    def test_severity_badge_critical(self):
        result = _inline_format("[CRITICAL]")
        assert "badge-critical" in result
        assert "CRITICAL" in result

    def test_severity_badge_high(self):
        result = _inline_format("[HIGH]")
        assert "badge-high" in result

    def test_severity_badge_medium(self):
        result = _inline_format("[MEDIUM]")
        assert "badge-medium" in result


class TestMdToHtmlBody:
    def test_heading_h1(self):
        html, toc = _md_to_html_body("# Title")
        assert "<h1>" in html

    def test_heading_h2_in_toc(self):
        html, toc = _md_to_html_body("## Section One")
        assert len(toc) == 1
        assert toc[0][1] == "Section One"
        assert "section-1" in toc[0][0]

    def test_multiple_h2_sections(self):
        content = "## First\n\nsome text\n\n## Second\n\nmore text"
        html, toc = _md_to_html_body(content)
        assert len(toc) == 2

    def test_code_block(self):
        content = "```python\nprint('hello')\n```"
        html, toc = _md_to_html_body(content)
        assert "<pre" in html
        assert "<code>" in html
        # Code content is HTML-escaped
        assert "print" in html

    def test_unordered_list(self):
        html, _ = _md_to_html_body("- item one\n- item two")
        assert "<ul>" in html
        assert "<li>" in html

    def test_ordered_list(self):
        html, _ = _md_to_html_body("1. first\n2. second")
        assert "<ol>" in html
        assert "<li>" in html

    def test_horizontal_rule(self):
        html, _ = _md_to_html_body("---")
        assert '<hr class="divider">' in html

    def test_paragraph(self):
        html, _ = _md_to_html_body("Just a paragraph.")
        assert "<p>" in html

    def test_blank_line_no_paragraph(self):
        html, _ = _md_to_html_body("\n\n")
        # Blank lines should not produce paragraph tags
        assert html.strip() == "" or "<p>" not in html


class TestCountSeverities:
    def test_counts_critical(self):
        text = "Found [CRITICAL] issue"
        counts = _count_severities(text)
        assert counts.get("CRITICAL") == 1

    def test_counts_multiple(self):
        text = "[HIGH] one\n[HIGH] two\n[MEDIUM] three"
        counts = _count_severities(text)
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1

    def test_empty_text(self):
        counts = _count_severities("")
        assert counts == {}

    def test_no_match(self):
        counts = _count_severities("No severity markers here.")
        assert counts == {}

    def test_all_severities(self):
        text = "[CRITICAL] [HIGH] [MEDIUM] [LOW] [INFO]"
        counts = _count_severities(text)
        assert set(counts.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class TestBuildStatsBar:
    def test_empty_counts_returns_empty(self):
        result = _build_stats_bar({})
        assert result == ""

    def test_produces_stats_bar_div(self):
        result = _build_stats_bar({"CRITICAL": 2, "HIGH": 5})
        assert "stats-bar" in result
        assert "CRITICAL: 2" in result
        assert "HIGH: 5" in result

    def test_shows_total(self):
        result = _build_stats_bar({"CRITICAL": 1, "HIGH": 2})
        assert "TOTAL: 3" in result


class TestBuildToc:
    def test_empty_toc(self):
        result = _build_toc([])
        assert result == ""

    def test_single_entry(self):
        result = _build_toc([("section-1", "Executive Summary")])
        assert "Executive Summary" in result
        assert "section-1" in result
        assert "<nav" in result

    def test_multiple_entries_ordered(self):
        entries = [("section-1", "Recon"), ("section-2", "Scanning"), ("section-3", "Reporting")]
        result = _build_toc(entries)
        assert result.index("Recon") < result.index("Scanning") < result.index("Reporting")


class TestBuildHtmlDocument:
    def test_produces_valid_html_structure(self):
        html = _build_html_document("Test Report", "## Section\n\nContent here.", "20260101_120000")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "</html>" in html

    def test_title_in_document(self):
        html = _build_html_document("My Pentest Report", "", "20260101_120000")
        assert "My Pentest Report" in html

    def test_has_phantom_branding(self):
        html = _build_html_document("Report", "", "20260101_120000")
        assert "Phantom" in html or "PHANTOM" in html

    def test_xss_title_escaped(self):
        malicious_title = '<script>alert("xss")</script>'
        html = _build_html_document(malicious_title, "", "20260101_120000")
        # The raw script tag must not appear unescaped
        assert "<script>alert" not in html

    def test_severity_stats_shown_when_present(self):
        content = "[CRITICAL] SQL injection found\n[HIGH] XSS vulnerability"
        html = _build_html_document("Report", content, "20260101_120000")
        assert "stats-bar" in html


class TestDetectTableBlock:
    def test_valid_table_detected(self):
        lines = [
            "| Col1 | Col2 |",
            "|------|------|",
            "| A    | B    |",
        ]
        html_lines, next_idx = _detect_table_block(lines, 0)
        assert len(html_lines) > 0
        assert next_idx == 3
        combined = "\n".join(html_lines)
        assert "<table>" in combined
        assert "<thead>" in combined

    def test_no_table_returns_empty(self):
        lines = ["Just a plain line", "Another line"]
        html_lines, next_idx = _detect_table_block(lines, 0)
        assert html_lines == []
        assert next_idx == 0

    def test_table_cells_escaped(self):
        lines = [
            "| <script> | Data |",
            "|-----------|------|",
            "| value     | x    |",
        ]
        html_lines, _ = _detect_table_block(lines, 0)
        combined = "\n".join(html_lines)
        assert "<script>" not in combined
