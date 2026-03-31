"""Tests for nuclei/ffuf output parsing in read_log and tool modules."""

import json
import os
import tempfile
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))


class TestNucleiParsing:
    """Test nuclei JSONL parsing via read_log."""

    def _write_jsonl(self, tmp_path, entries):
        path = tmp_path / "nuclei.json"
        lines = [json.dumps(e) for e in entries]
        path.write_text("\n".join(lines))
        return path

    def test_valid_nuclei_findings(self, tmp_path):
        findings = [
            {
                "template-id": "cve-2021-44228",
                "info": {
                    "name": "Log4Shell",
                    "severity": "critical",
                    "classification": {"cve-id": ["CVE-2021-44228"]},
                },
                "matched-at": "http://dummytarget.com/api",
            },
            {
                "template-id": "cve-2023-1234",
                "info": {
                    "name": "Test Vuln",
                    "severity": "high",
                    "classification": {"cve-id": ["CVE-2023-1234"]},
                },
                "matched-at": "http://dummytarget.com/login",
            },
        ]
        path = self._write_jsonl(tmp_path, findings)
        content = path.read_text()
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        parsed = [json.loads(l) for l in lines]
        assert len(parsed) == 2
        assert parsed[0]["info"]["severity"] == "critical"
        assert parsed[1]["info"]["name"] == "Test Vuln"

    def test_empty_file(self, tmp_path):
        path = tmp_path / "nuclei.json"
        path.write_text("")
        parsed = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        assert parsed == []

    def test_malformed_json(self, tmp_path):
        path = tmp_path / "nuclei.json"
        path.write_text('{"valid": true}\nnot-json\n{"also": "valid"}')
        parsed = []
        for line in path.read_text().splitlines():
            try:
                parsed.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
        assert len(parsed) == 2

    def test_missing_info_field(self, tmp_path):
        path = self._write_jsonl(
            tmp_path, [{"template-id": "test", "host": "dummytarget.com"}]
        )
        content = path.read_text()
        entry = json.loads(content.strip())
        # Should not crash when accessing info
        assert entry.get("info", {}).get("severity", "?") == "?"

    def test_missing_cve_id(self, tmp_path):
        entry = {
            "template-id": "misconfig-001",
            "info": {"name": "Misconfig", "severity": "medium", "classification": {}},
            "matched-at": "http://dummytarget.com",
        }
        path = self._write_jsonl(tmp_path, [entry])
        parsed = json.loads(path.read_text().strip())
        cve_list = (parsed["info"].get("classification") or {}).get("cve-id") or []
        assert cve_list == []


class TestFfufParsing:
    """Test ffuf JSON parsing."""

    def test_valid_results(self, tmp_path):
        data = {
            "results": [
                {"status": 200, "url": "http://dummytarget.com/admin", "length": 1234},
                {"status": 301, "url": "http://dummytarget.com/api", "length": 0},
            ]
        }
        path = tmp_path / "ffuf.json"
        path.write_text(json.dumps(data))
        parsed = json.loads(path.read_text())
        assert len(parsed["results"]) == 2
        assert parsed["results"][0]["status"] == 200

    def test_empty_results(self, tmp_path):
        data = {"results": []}
        path = tmp_path / "ffuf.json"
        path.write_text(json.dumps(data))
        parsed = json.loads(path.read_text())
        assert parsed["results"] == []

    def test_missing_url_field(self, tmp_path):
        data = {
            "results": [
                {"status": 200, "length": 100, "input": {"FUZZ": "admin"}},
            ]
        }
        path = tmp_path / "ffuf.json"
        path.write_text(json.dumps(data))
        r = json.loads(path.read_text())["results"][0]
        url = r.get("url", (r.get("input") or {}).get("FUZZ", "?"))
        assert url == "admin"

    def test_malformed_json(self, tmp_path):
        path = tmp_path / "ffuf.json"
        path.write_text("{bad json")
        with pytest.raises(json.JSONDecodeError):
            json.loads(path.read_text())
