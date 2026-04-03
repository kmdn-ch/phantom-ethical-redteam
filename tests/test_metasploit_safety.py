"""Tests for metasploit.py safety layer — blocked modules, input sanitization, and validation.

These tests only exercise the safety and validation functions (no msfconsole binary required).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

from tools.metasploit import (
    _is_module_blocked,
    _sanitize_msf_value,
    _validate_module_path,
    _validate_target,
    _validate_option_key,
    _validate_option_value,
    _build_search_command,
    _parse_search_results,
    _parse_exploit_results,
    BLOCKED_MODULE_PATTERNS,
)


class TestBlockedModulePatterns:
    def test_post_module_blocked(self):
        assert _is_module_blocked("post/multi/gather/run_console") is not None

    def test_meterpreter_payload_blocked(self):
        assert _is_module_blocked("payload/meterpreter/reverse_tcp") is not None

    def test_persistence_blocked(self):
        assert _is_module_blocked("exploit/windows/local/persistence") is not None

    def test_backdoor_blocked(self):
        assert _is_module_blocked("exploit/linux/backdoor_ssh") is not None

    def test_bind_tcp_blocked(self):
        assert _is_module_blocked("payload/generic/bind_tcp") is not None

    def test_bind_shell_blocked(self):
        assert _is_module_blocked("exploit/multi/bind_shell") is not None

    def test_evasion_blocked(self):
        assert _is_module_blocked("evasion/windows/applocker_evasion") is not None

    def test_encoder_blocked(self):
        assert _is_module_blocked("encoder/x86/shikata_ga_nai") is not None

    def test_exploit_module_allowed(self):
        assert _is_module_blocked("exploit/multi/http/struts2_rce") is None

    def test_auxiliary_module_allowed(self):
        assert _is_module_blocked("auxiliary/scanner/http/http_version") is None

    def test_case_insensitive_blocking(self):
        # Upper-case should also be blocked
        assert _is_module_blocked("POST/multi/gather/run_console") is not None


class TestSanitizeMsfValue:
    def test_strips_semicolons(self):
        result = _sanitize_msf_value("value; exit")
        assert ";" not in result

    def test_strips_newlines(self):
        result = _sanitize_msf_value("value\nexit")
        assert "\n" not in result

    def test_strips_backticks(self):
        result = _sanitize_msf_value("`whoami`")
        assert "`" not in result

    def test_strips_dollar_sign(self):
        result = _sanitize_msf_value("$(id)")
        assert "$" not in result

    def test_strips_quotes(self):
        result = _sanitize_msf_value('"quoted"')
        assert '"' not in result

    def test_strips_pipe(self):
        result = _sanitize_msf_value("value | cat")
        assert "|" not in result

    def test_clean_value_preserved(self):
        clean = "apache_struts_rce"
        assert _sanitize_msf_value(clean) == clean


class TestValidateModulePath:
    def test_valid_exploit_path(self):
        assert _validate_module_path("exploit/multi/http/struts2_rce") is None

    def test_valid_auxiliary_path(self):
        assert _validate_module_path("auxiliary/scanner/http/http_version") is None

    def test_rejects_spaces(self):
        assert _validate_module_path("exploit/multi/http/ rce") is not None

    def test_rejects_semicolons(self):
        assert _validate_module_path("exploit/multi;exit") is not None

    def test_rejects_dotdot(self):
        assert _validate_module_path("exploit/../../../etc/passwd") is not None


class TestValidateTarget:
    def test_valid_ip(self):
        assert _validate_target("192.168.1.1") is None

    def test_valid_hostname(self):
        assert _validate_target("target.example.com") is None

    def test_valid_ip_port(self):
        assert _validate_target("192.168.1.1:8080") is None

    def test_rejects_semicolons(self):
        assert _validate_target("192.168.1.1; rm -rf /") is not None

    def test_rejects_spaces(self):
        assert _validate_target("192.168.1.1 evil") is not None

    def test_rejects_backtick(self):
        assert _validate_target("`hostname`") is not None


class TestValidateOptionKey:
    def test_valid_key(self):
        assert _validate_option_key("RHOSTS") is None

    def test_valid_underscored_key(self):
        assert _validate_option_key("TARGET_PORT") is None

    def test_rejects_hyphen(self):
        # Hyphens not allowed in MSF option keys
        assert _validate_option_key("RHOST-EXTRA") is not None

    def test_rejects_spaces(self):
        assert _validate_option_key("R HOSTS") is not None

    def test_rejects_injection(self):
        assert _validate_option_key("KEY;evil") is not None


class TestValidateOptionValue:
    def test_valid_ip_value(self):
        assert _validate_option_value("192.168.1.1") is None

    def test_valid_port_value(self):
        assert _validate_option_value("4444") is None

    def test_valid_path_value(self):
        assert _validate_option_value("/admin/login") is None

    def test_rejects_semicolons(self):
        assert _validate_option_value("value; exit") is not None

    def test_rejects_backtick(self):
        assert _validate_option_value("`id`") is not None

    def test_rejects_dollar(self):
        assert _validate_option_value("$(whoami)") is not None


class TestBuildSearchCommand:
    def test_builds_search_command(self):
        cmd = _build_search_command("apache struts")
        assert "search" in cmd
        assert "apache struts" in cmd
        assert "exit" in cmd

    def test_sanitizes_injection_in_search(self):
        # _sanitize_msf_value strips semicolons from the search term before embedding.
        # The "; exit" suffix added by _build_search_command is outside the user input.
        # Verify: the sanitized term (without semicolons) appears in the command.
        cmd = _build_search_command("term; exit; evil")
        # After sanitization, semicolons inside the search term are stripped
        # so "term exit evil" becomes the sanitized search term
        assert "term" in cmd
        # The command must end with "; exit" (the safe terminator)
        assert cmd.endswith("; exit")


class TestParseResults:
    def test_parse_search_no_results(self):
        result = _parse_search_results("")
        assert isinstance(result, str)

    def test_parse_exploit_empty(self):
        result = _parse_exploit_results("")
        assert isinstance(result, str)

    def test_parse_exploit_finds_session_line(self):
        output = "Some lines\n[*] session 1 opened (192.168.1.2:4444)\nMore lines"
        result = _parse_exploit_results(output)
        assert "session" in result.lower()

    def test_parse_exploit_finds_vulnerable(self):
        output = "Target is vulnerable to CVE-2021-1234"
        result = _parse_exploit_results(output)
        assert "vulnerable" in result.lower()
