# tests/test_nuclei_engine.py
"""
Test suite for Nuclei-inspired declarative template and matching engine.
Verifies Matchers, Extractors, Template evaluation, and scan_tech integration.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.matcher import Matcher, ResponseContext
from engine.extractor import Extractor
from engine.template import Template
from engine.runner import NucleiEngine
from scan import scan_tech, nuclei_engine


# ══════════════════════════════════════════════════════════════════════════════
# Matcher Unit Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNucleiMatcher:
    def test_word_matcher_or_condition(self):
        ctx = ResponseContext(status_code=200, headers={"Server": "nginx/1.24"}, body="Hello World from WordPress")
        matcher = Matcher({
            "type": "word",
            "part": "body",
            "words": ["Joomla", "WordPress"],
            "condition": "or",
        })
        assert matcher.matches(ctx) is True

    def test_word_matcher_and_condition(self):
        ctx = ResponseContext(status_code=200, headers={}, body="jQuery is included with React")
        matcher_pass = Matcher({
            "type": "word",
            "part": "body",
            "words": ["jquery", "react"],
            "condition": "and",
        })
        assert matcher_pass.matches(ctx) is True

        matcher_fail = Matcher({
            "type": "word",
            "part": "body",
            "words": ["jquery", "angular"],
            "condition": "and",
        })
        assert matcher_fail.matches(ctx) is False

    def test_regex_matcher(self):
        ctx = ResponseContext(status_code=200, headers={}, body='<script src="/js/jquery-3.6.0.min.js"></script>')
        matcher = Matcher({
            "type": "regex",
            "part": "body",
            "regex": [r"jquery[./-]([\d.]+)"],
        })
        assert matcher.matches(ctx) is True

    def test_status_matcher(self):
        ctx_200 = ResponseContext(status_code=200, headers={}, body="")
        ctx_404 = ResponseContext(status_code=404, headers={}, body="")
        matcher = Matcher({
            "type": "status",
            "status": [200, 301],
        })
        assert matcher.matches(ctx_200) is True
        assert matcher.matches(ctx_404) is False

    def test_dsl_matcher(self):
        ctx = ResponseContext(status_code=200, headers={"Server": "Apache"}, body="Admin Dashboard")
        matcher = Matcher({
            "type": "dsl",
            "dsl": ['status_code == 200 and contains(body, "Dashboard") and contains(header, "Apache")'],
        })
        assert matcher.matches(ctx) is True

    def test_negative_matcher(self):
        ctx = ResponseContext(status_code=200, headers={}, body="No sensitive data")
        matcher = Matcher({
            "type": "word",
            "part": "body",
            "words": ["secret_token"],
            "negative": True,
        })
        assert matcher.matches(ctx) is True

    def test_header_part_targeting(self):
        ctx = ResponseContext(status_code=200, headers={"X-Powered-By": "PHP/8.1.0"}, body="")
        matcher = Matcher({
            "type": "word",
            "part": "header.x-powered-by",
            "words": ["PHP"],
        })
        assert matcher.matches(ctx) is True


# ══════════════════════════════════════════════════════════════════════════════
# Extractor Unit Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNucleiExtractor:
    def test_regex_version_extractor(self):
        ctx = ResponseContext(status_code=200, headers={}, body='<script src="bootstrap-5.2.3.min.js"></script>')
        extractor = Extractor({
            "type": "regex",
            "name": "version",
            "part": "body",
            "group": 1,
            "regex": [r"bootstrap[./-]([\d.]+)"],
        })
        extracted = extractor.extract(ctx)
        assert extracted == ["5.2.3"]

    def test_kval_header_extractor(self):
        ctx = ResponseContext(status_code=200, headers={"Server": "nginx/1.22.0"}, body="")
        extractor = Extractor({
            "type": "kval",
            "name": "server_hdr",
            "part": "header",
            "kval": ["server"],
        })
        extracted = extractor.extract(ctx)
        assert extracted == ["nginx/1.22.0"]


# ══════════════════════════════════════════════════════════════════════════════
# Template & Engine Integration Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestNucleiTemplateEngine:
    def test_templates_loaded(self):
        assert len(nuclei_engine.templates) > 0
        template_ids = [t.id for t in nuclei_engine.templates]
        assert "jquery-detect" in template_ids
        assert "wordpress-detect" in template_ids
        assert "react-detect" in template_ids
        assert "bootstrap-detect" in template_ids

    def test_scan_response_matches_jquery(self):
        html = '<html><head><script src="/assets/jquery-3.5.1.min.js"></script></head><body>Home</body></html>'
        results = nuclei_engine.scan_response(status_code=200, headers={}, body=html)
        matched_techs = [r.tech for r in results]
        assert "jQuery" in matched_techs

        # Verify extracted version
        jquery_res = next(r for r in results if r.tech == "jQuery")
        assert jquery_res.detected_version == "3.5.1"
        assert jquery_res.cpe == "cpe:2.3:a:jquery:jquery"

    def test_scan_response_matches_wordpress(self):
        html = '<html><head><meta name="generator" content="WordPress 6.2"></head><body><link rel="stylesheet" href="/wp-content/themes/style.css"></body></html>'
        results = nuclei_engine.scan_response(status_code=200, headers={}, body=html)
        matched_techs = [r.tech for r in results]
        assert "WordPress" in matched_techs

        wp_res = next(r for r in results if r.tech == "WordPress")
        assert wp_res.detected_version == "6.2"

    def test_to_tech_stack_conversion(self):
        html = '<html><head><script src="jquery-3.6.0.min.js"></script><script src="bootstrap-5.1.0.min.js"></script></head></html>'
        results = nuclei_engine.scan_response(status_code=200, headers={}, body=html)
        tech_stack = nuclei_engine.to_tech_stack(results)

        assert "jQuery" in tech_stack
        assert tech_stack["jQuery"] == ["3.6.0"]
        assert "Bootstrap" in tech_stack
        assert tech_stack["Bootstrap"] == ["5.1.0"]

    def test_header_based_matching(self):
        results = nuclei_engine.scan_response(
            status_code=200,
            headers={
                "Server": "nginx/1.24.0",
                "X-Powered-By": "PHP/8.1.2",
                "Set-Cookie": "PHPSESSID=abcdef12345; path=/",
            },
            body="Hello",
        )
        tech_stack = nuclei_engine.to_tech_stack(results)
        assert "nginx" in tech_stack
        assert tech_stack["nginx"] == ["1.24.0"]
        assert "PHP" in tech_stack

    def test_search_templates(self):
        # Search by query
        query_matches = nuclei_engine.search_templates(query="git")
        assert any(t.id == "git-config-exposure" for t in query_matches)

        # Search by severity
        critical_matches = nuclei_engine.search_templates(severity="CRITICAL")
        assert any(t.id == "env-file-exposure" for t in critical_matches)

        # Search by category
        exposure_matches = nuclei_engine.search_templates(category="exposures")
        assert len(exposure_matches) >= 4

    def test_multi_path_scan_target(self):
        class MockResponse:
            def __init__(self, status_code, body, headers=None):
                self.status_code = status_code
                self.text = body
                self.headers = headers or {}

        def mock_requester(url: str):
            if url.endswith("/.env"):
                return MockResponse(200, "APP_ENV=production\nDB_PASSWORD=SuperSecretKey123\n")
            elif url.endswith("/robots.txt"):
                return MockResponse(200, "User-agent: *\nDisallow: /admin\n")
            return MockResponse(404, "Not Found")

        matches = nuclei_engine.scan_target(
            base_url="https://testsite.com",
            request_fn=mock_requester,
        )
        matched_ids = [m.template_id for m in matches]
        assert "env-file-exposure" in matched_ids
        assert "robots-txt-disclosure" in matched_ids

    def test_build_summary_escalates_on_nuclei_critical(self):
        from scan import build_summary
        mock_nuclei_findings = [
            {
                "template_id": "env-file-exposure",
                "name": "Environment Variables File (.env) Exposure",
                "severity": "CRITICAL",
                "description": "Leaked credentials",
                "matched_at": "https://testsite.com/.env",
            }
        ]
        summary = build_summary(
            tech_stack={},
            vulnerabilities={},
            security_header_findings=[],
            nuclei_findings=mock_nuclei_findings,
        )
        assert summary["overall_risk"] == "Critical"
        assert len(summary["findings"]) >= 1
        assert summary["findings"][0]["severity"] == "CRITICAL"

    def test_clean_tech_name_normalization(self):
        from scan import _clean_tech_name
        assert _clean_tech_name("WordPress", "wordpress-detect", "", {}) == "WordPress"
        assert _clean_tech_name("nginxgeneric", "waf-detect", "nginxgeneric", {}) == "nginx"
        assert _clean_tech_name("akismet", "wordpress-akismet", "", {}) == "Akismet"
        assert _clean_tech_name("Gutenberg Detection", "wordpress-gutenberg", "", {}) == "Gutenberg"
        assert _clean_tech_name("waf", "waf-detect", "", {}) is None

    def test_run_nuclei_cli_graceful_missing_binary(self, monkeypatch):
        import scan
        monkeypatch.setattr(scan, "NUCLEI_BIN_PATH", "/nonexistent/nuclei")
        monkeypatch.setattr(scan.shutil, "which", lambda x: None)
        tech, matches, vulns = scan.run_nuclei_cli("https://example.com")
        assert tech == {}
        assert matches == []
        assert vulns == {}

