# tests/test_security.py
"""
Pytest test suite for ThreatLens security-critical functions.
Run with:  pytest tests/ -v
"""
import os
import sys

# Ensure the project root is importable without installation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Force dev mode so private targets are blocked (default)
os.environ.setdefault("ALLOW_PRIVATE_TARGETS", "false")

import pytest
from scan import (
    SSRFError,
    validate_target,
    check_security_headers,
    build_summary,
)


# ══════════════════════════════════════════════════════════════════════════════
# validate_target — SSRF blocking
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateTargetBlocked:
    """All of these must raise SSRFError."""

    def test_blocks_loopback_ipv4(self):
        with pytest.raises(SSRFError):
            validate_target("http://127.0.0.1")

    def test_blocks_loopback_ipv4_port(self):
        with pytest.raises(SSRFError):
            validate_target("http://127.0.0.1:8080")

    def test_blocks_localhost(self):
        with pytest.raises(SSRFError):
            validate_target("http://localhost")

    def test_blocks_private_10x(self):
        with pytest.raises(SSRFError):
            validate_target("http://10.0.0.1")

    def test_blocks_private_172x(self):
        with pytest.raises(SSRFError):
            validate_target("http://172.16.0.1")

    def test_blocks_private_192168(self):
        with pytest.raises(SSRFError):
            validate_target("http://192.168.1.1")

    def test_blocks_aws_metadata_ip(self):
        """169.254.169.254 is link-local and must be blocked."""
        with pytest.raises(SSRFError):
            validate_target("http://169.254.169.254")

    def test_blocks_ipv6_loopback(self):
        with pytest.raises(SSRFError):
            validate_target("http://[::1]")

    def test_blocks_file_scheme(self):
        with pytest.raises(SSRFError):
            validate_target("file:///etc/passwd")

    def test_blocks_ftp_scheme(self):
        with pytest.raises(SSRFError):
            validate_target("ftp://example.com")

    def test_blocks_credentials_in_url(self):
        with pytest.raises(SSRFError):
            validate_target("http://user:pass@example.com")

    def test_blocks_username_only(self):
        with pytest.raises(SSRFError):
            validate_target("http://admin@example.com")

    def test_blocks_non_standard_port(self):
        with pytest.raises(SSRFError):
            validate_target("http://example.com:9999")

    def test_blocks_port_22(self):
        with pytest.raises(SSRFError):
            validate_target("http://example.com:22")

    def test_blocks_port_3306(self):
        with pytest.raises(SSRFError):
            validate_target("http://example.com:3306")


class TestValidateTargetAllowed:
    """These must NOT raise SSRFError."""

    def test_allows_public_http(self):
        validate_target("http://example.com")

    def test_allows_public_https(self):
        validate_target("https://example.com")

    def test_allows_port_8080(self):
        validate_target("http://example.com:8080")

    def test_allows_port_443(self):
        validate_target("https://example.com:443")

    def test_allows_port_8443(self):
        validate_target("https://example.com:8443")


# ══════════════════════════════════════════════════════════════════════════════
# check_security_headers
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckSecurityHeaders:

    def test_all_missing(self):
        findings = check_security_headers({})
        assert len(findings) == 5
        assert all(f["severity"] == "MEDIUM" for f in findings)
        assert all(f["source"] == "security_headers" for f in findings)

    def test_all_present(self):
        headers = {
            "Content-Security-Policy":   "default-src 'self'",
            "X-Frame-Options":           "SAMEORIGIN",
            "X-Content-Type-Options":    "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy":           "strict-origin-when-cross-origin",
        }
        assert check_security_headers(headers) == []

    def test_partial_missing(self):
        headers = {
            "X-Frame-Options":        "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
        }
        findings = check_security_headers(headers)
        assert len(findings) == 3

    def test_case_insensitive(self):
        """Headers are matched case-insensitively."""
        headers = {
            "content-security-policy":   "default-src 'self'",
            "x-frame-options":           "SAMEORIGIN",
            "x-content-type-options":    "nosniff",
            "strict-transport-security": "max-age=31536000",
            "referrer-policy":           "no-referrer",
        }
        assert check_security_headers(headers) == []


# ══════════════════════════════════════════════════════════════════════════════
# build_summary — severity capping (confirmed vs possible)
# ══════════════════════════════════════════════════════════════════════════════

def _make_cve(severity: str, confidence: str, score: float = 7.5) -> dict:
    return {
        "id":          "CVE-2024-TEST",
        "description": "A test vulnerability",
        "severity":    severity,
        "score":       score,
        "confidence":  confidence,
    }


def _run_summary(cve: dict) -> str:
    tech_stack = {"jQuery": ["3.0"]}
    vulns = {"jQuery 3.0": [cve]}
    result = build_summary(tech_stack, vulns, [])
    return result["overall_risk"]


class TestBuildSummary:

    def test_confirmed_critical_gives_critical(self):
        assert _run_summary(_make_cve("CRITICAL", "confirmed", 9.8)) == "Critical"

    def test_confirmed_high_gives_high(self):
        assert _run_summary(_make_cve("HIGH", "confirmed", 8.0)) == "High"

    def test_possible_critical_capped_at_medium(self):
        """Possible CVEs, even CRITICAL, must not push risk above Medium."""
        risk = _run_summary(_make_cve("CRITICAL", "possible", 9.8))
        assert risk in ("Medium", "Low"), f"Expected Medium or Low, got {risk}"

    def test_possible_high_capped_at_medium(self):
        risk = _run_summary(_make_cve("HIGH", "possible", 8.5))
        assert risk in ("Medium", "Low"), f"Expected Medium or Low, got {risk}"

    def test_confirmed_medium_gives_medium(self):
        assert _run_summary(_make_cve("MEDIUM", "confirmed", 5.0)) == "Medium"

    def test_no_vulns_no_headers_gives_low(self):
        result = build_summary({}, {}, [])
        assert result["overall_risk"] == "Low"

    def test_three_missing_headers_gives_medium(self):
        header_findings = [
            {
                "title": f"Missing security header: H{i}",
                "severity": "MEDIUM",
                "confidence": "confirmed",
                "source": "security_headers",
                "plain_explanation": "",
                "recommended_fix": "",
            }
            for i in range(3)
        ]
        result = build_summary({}, {}, header_findings)
        assert result["overall_risk"] == "Medium"

    def test_two_missing_headers_gives_medium(self):
        """Even 2 confirmed MEDIUM header findings push risk to Medium."""
        header_findings = [
            {
                "title": f"Missing security header: H{i}",
                "severity": "MEDIUM",
                "confidence": "confirmed",
                "source": "security_headers",
                "plain_explanation": "",
                "recommended_fix": "",
            }
            for i in range(2)
        ]
        result = build_summary({}, {}, header_findings)
        assert result["overall_risk"] == "Medium"


    def test_top_findings_capped_at_five(self):
        cves = [_make_cve("HIGH", "confirmed", 8.0) for _ in range(10)]
        result = build_summary({"Lib": ["1.0"]}, {"Lib 1.0": cves}, [])
        assert len(result["findings"]) <= 5

    def test_what_we_checked_line_present(self):
        result = build_summary({"jQuery": ["3.0"]}, {}, [])
        assert "Checked" in result["what_we_checked"]
