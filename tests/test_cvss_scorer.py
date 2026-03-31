"""Tests for CVSS risk scoring utility."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

# Patch the register_tool decorator before importing so it works standalone
from unittest.mock import MagicMock, patch
import importlib

# We need to load the module with the registry available
import tools  # noqa — triggers auto-registration


class TestCVSSScorer:
    def test_no_findings_returns_none_score(self):
        from tools.cvss_scorer import run

        result = run(findings=[])
        assert "0.0/10" in result or "No valid findings" in result

    def test_none_findings(self):
        from tools.cvss_scorer import run

        result = run(findings=None)
        assert "No findings" in result

    def test_critical_finding_gives_high_score(self):
        from tools.cvss_scorer import run

        result = run(findings=[{"severity": "critical"}, {"severity": "critical"}])
        assert "Critical" in result or "High" in result
        # Score must be numeric and present
        assert "/10" in result

    def test_mixed_severities(self):
        from tools.cvss_scorer import run

        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        result = run(findings=findings)
        assert "Total findings: 5" in result
        assert "Critical: 1" in result
        assert "High: 1" in result

    def test_score_capped_at_10(self):
        from tools.cvss_scorer import run

        # Many critical findings — score should not exceed 10
        findings = [{"severity": "critical"}] * 50
        result = run(findings=findings)
        # Extract score
        import re

        m = re.search(r"Risk Score: ([\d.]+)/10", result)
        assert m is not None
        assert float(m.group(1)) <= 10.0

    def test_info_only_gives_low_score(self):
        from tools.cvss_scorer import run

        findings = [{"severity": "info"}] * 5
        result = run(findings=findings)
        import re

        m = re.search(r"Risk Score: ([\d.]+)/10", result)
        assert m is not None
        assert float(m.group(1)) < 3.0

    def test_nested_severity_format(self):
        """Support Nuclei-style nested {'info': {'severity': 'high'}} format."""
        from tools.cvss_scorer import run

        findings = [{"info": {"severity": "high"}, "template-id": "test"}]
        result = run(findings=findings)
        assert "High: 1" in result

    def test_unknown_severity_counted_as_info(self):
        from tools.cvss_scorer import run

        findings = [{"severity": "unknown_level"}]
        result = run(findings=findings)
        # Should not crash; unknown severity falls through as info
        assert "/10" in result

    def test_label_thresholds(self):
        from tools.cvss_scorer import run
        import re

        # High severity batch
        result_high = run(findings=[{"severity": "high"}] * 3)
        m = re.search(r"Risk Score: ([\d.]+)/10 \((\w+)\)", result_high)
        assert m is not None
        score = float(m.group(1))
        assert score >= 7.0

        # Low severity batch
        result_low = run(findings=[{"severity": "low"}] * 3)
        m = re.search(r"Risk Score: ([\d.]+)/10 \((\w+)\)", result_low)
        assert m is not None
        assert m.group(2) in ("Low", "Informational")
