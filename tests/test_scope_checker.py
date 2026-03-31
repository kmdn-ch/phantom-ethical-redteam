"""Comprehensive tests for scope_checker.py."""

import os
import tempfile
import pytest

# Add agent/ to path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

from tools.scope_checker import load_scope_targets, is_in_scope, scope_guard


@pytest.fixture
def scope_file(tmp_path):
    """Create a temporary scope file and return its path."""

    def _create(content: str) -> str:
        p = tmp_path / "scope.md"
        p.write_text(content)
        return str(p)

    return _create


class TestLoadScopeTargets:
    def test_single_url(self, scope_file):
        f = scope_file("**Scope:** http://dummytarget.com")
        targets = load_scope_targets(f)
        assert "dummytarget.com" in targets

    def test_multiple_urls(self, scope_file):
        f = scope_file("https://a.com\nhttps://b.com\nhttps://c.com")
        targets = load_scope_targets(f)
        assert "a.com" in targets
        assert "b.com" in targets
        assert "c.com" in targets

    def test_ip_address(self, scope_file):
        f = scope_file("Target: 192.168.1.1")
        targets = load_scope_targets(f)
        assert "192.168.1.1" in targets

    def test_cidr(self, scope_file):
        f = scope_file("Range: 10.0.0.0/24")
        targets = load_scope_targets(f)
        assert "10.0.0.0/24" in targets

    def test_comments_ignored(self, scope_file):
        f = scope_file("# This is a comment\nhttp://dummytarget.com")
        targets = load_scope_targets(f)
        assert "dummytarget.com" in targets

    def test_empty_file(self, scope_file):
        f = scope_file("")
        targets = load_scope_targets(f)
        assert targets == []

    def test_file_not_found(self):
        targets = load_scope_targets("/nonexistent/scope.md")
        assert targets == []

    def test_strips_port(self, scope_file):
        f = scope_file("http://dummytarget.com:8443/path")
        targets = load_scope_targets(f)
        assert "dummytarget.com" in targets

    def test_deduplication(self, scope_file):
        f = scope_file("http://dummytarget.com\nhttp://dummytarget.com/admin")
        targets = load_scope_targets(f)
        assert targets.count("dummytarget.com") == 1


class TestIsInScope:
    def test_exact_match(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("dummytarget.com", f) is True

    def test_exact_match_url(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("http://dummytarget.com/admin", f) is True

    def test_subdomain_in_scope(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("sub.dummytarget.com", f) is True

    def test_deep_subdomain(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("deep.sub.dummytarget.com", f) is True

    def test_out_of_scope(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("evil.com", f) is False

    def test_similar_but_different(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("nottarget.com", f) is False

    def test_case_insensitive(self, scope_file):
        f = scope_file("https://Target.COM")
        assert is_in_scope("TARGET.com", f) is True

    def test_ip_match(self, scope_file):
        f = scope_file("192.168.1.1")
        assert is_in_scope("192.168.1.1", f) is True

    def test_ip_no_match(self, scope_file):
        f = scope_file("192.168.1.1")
        assert is_in_scope("192.168.1.2", f) is False

    def test_cidr_match(self, scope_file):
        f = scope_file("10.0.0.0/24")
        assert is_in_scope("10.0.0.42", f) is True

    def test_cidr_no_match(self, scope_file):
        f = scope_file("10.0.0.0/24")
        assert is_in_scope("10.0.1.1", f) is False

    def test_empty_scope_permissive(self, scope_file):
        f = scope_file("")
        assert is_in_scope("anything.com", f) is True

    def test_url_with_port(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("http://dummytarget.com:8080", f) is True

    def test_whitespace_target(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert is_in_scope("  dummytarget.com  ", f) is True


class TestScopeGuard:
    def test_in_scope_returns_none(self, scope_file):
        f = scope_file("http://dummytarget.com")
        assert scope_guard("dummytarget.com", f) is None

    def test_out_of_scope_returns_error(self, scope_file):
        f = scope_file("http://dummytarget.com")
        result = scope_guard("evil.com", f)
        assert result is not None
        assert "SCOPE VIOLATION" in result
        assert "evil.com" in result

    def test_error_contains_authorized_targets(self, scope_file):
        f = scope_file("http://dummytarget.com")
        result = scope_guard("evil.com", f)
        assert "dummytarget.com" in result
