# scan.py
import re
import json
import os
import requests
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load .env if present (python-dotenv is optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NVD_API_KEY = os.environ.get("NVD_API_KEY", "DA5D6095-66E2-420C-B83F-0860ED78E9B1")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Security headers that should be present on every site
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "plain": "Your site may lack a Content Security Policy, which could allow attackers to inject malicious scripts into your pages.",
        "fix": "Add a Content-Security-Policy header to your web server to restrict which scripts and resources browsers are allowed to load."
    },
    "X-Frame-Options": {
        "plain": "Your site may be missing a header that prevents it from being embedded in other websites, which could expose users to clickjacking attacks.",
        "fix": "Add the X-Frame-Options: SAMEORIGIN header to stop your pages from being loaded inside iframes on other domains."
    },
    "X-Content-Type-Options": {
        "plain": "Your site may be missing a header that prevents browsers from guessing the file type of responses, which could allow certain attacks.",
        "fix": "Add the X-Content-Type-Options: nosniff header to stop browsers from interpreting files as a different type than declared."
    },
    "Strict-Transport-Security": {
        "plain": "Your site may not be enforcing secure HTTPS connections, which could allow attackers to intercept traffic on unsecured networks.",
        "fix": "Add the Strict-Transport-Security header (HSTS) to force browsers to always use HTTPS when connecting to your site."
    },
    "Referrer-Policy": {
        "plain": "Your site may be sharing full page URLs with third-party sites when users click links, which could expose sensitive paths.",
        "fix": "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin) to control how much referrer information is shared."
    },
}


class _TechHTMLParser(HTMLParser):
    """Lightweight HTML parser that collects script/link srcs and meta tags."""
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.links   = []
        self.meta    = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta":
            name = a.get("name", "").lower()
            if name == "generator":
                self.meta["generator"] = a.get("content", "")


def scan_tech(url):
    """Detect tech stack using HTTP headers + HTML parsing (no external tools)."""
    try:
        resp = requests.get(
            url, timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (ThreatLens Scanner)"},
            allow_redirects=True
        )
        hdrs = resp.headers
        html = resp.text
        tech = {}

        # ── Header-based detection ──────────────────────────────────────────
        server = hdrs.get("Server") or hdrs.get("server", "")
        if server:
            tech["Server"] = [server]

        powered = hdrs.get("X-Powered-By") or hdrs.get("x-powered-by", "")
        if powered:
            tech["X-Powered-By"] = [powered]

        aspnet = hdrs.get("X-AspNet-Version", "")
        if aspnet:
            tech["ASP.NET"] = [aspnet]

        # Cookie-based detection
        cookies = hdrs.get("Set-Cookie", "")
        if "PHPSESSID" in cookies:
            tech.setdefault("PHP", ["detected"])
        if "ASP.NET_SessionId" in cookies or "ASPSESSIONID" in cookies:
            tech.setdefault("ASP.NET", ["detected"])

        # ── HTML parsing ────────────────────────────────────────────────────
        parser = _TechHTMLParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        generator = parser.meta.get("generator", "")
        if generator:
            tech["Generator"] = [generator]

        # Combine all text sources for pattern matching
        sources = " ".join(parser.scripts + parser.links) + " " + html[:50000]

        PATTERNS = {
            "jQuery":    r"jquery[./-]([\d.]+)",
            "React":     r"react[./-]([\d.]+)|['\"]react['\"]",
            "Vue":       r"vue[./-]([\d.]+)|Vue\.js",
            "Angular":   r"angular[./-]([\d.]+)|@angular",
            "Bootstrap": r"bootstrap[./-]([\d.]+)",
            "WordPress": r"/wp-content/|/wp-includes/",
            "Drupal":    r"Drupal\.settings|/sites/default/files",
            "Joomla":    r"/media/jui/|Joomla!",
            "Next.js":   r"/_next/static/|__NEXT_DATA__",
            "Laravel":   r"laravel_session|Laravel",
            "Django":    r"csrfmiddlewaretoken|django",
            "Node.js":   r"Express|node\.js",
        }

        for name, pattern in PATTERNS.items():
            m = re.search(pattern, sources, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else "detected"
                tech[name] = [version]

        return {
            "target": url,
            "status": resp.status_code,
            "tech_stack": tech
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e), "tech_stack": {}}


def get_headers(url):
    resp = requests.get(url, timeout=5)
    return dict(resp.headers)


def check_security_headers(headers):
    """
    Check for missing security headers.
    Returns a list of findings, each with title, plain_explanation,
    severity, and recommended_fix.
    """
    findings = []
    # Normalize header names to lowercase for comparison
    normalized = {k.lower(): v for k, v in headers.items()}
    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in normalized:
            findings.append({
                "title": f"Missing security header: {header_name}",
                "plain_explanation": info["plain"],
                "severity": "MEDIUM",
                "recommended_fix": info["fix"],
                "source": "security_headers"
            })
    return findings


def search_cves(keyword, max_results=5):
    """Query NVD API for CVEs matching a tech keyword (e.g. 'Apache 2.4.29')"""
    headers = {"apiKey": NVD_API_KEY}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            severity = "UNKNOWN"
            score = None
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore")

            cves.append({
                "id": cve_id,
                "description": description,
                "severity": severity,
                "score": score
            })

        return cves

    except requests.exceptions.RequestException as e:
        return [{"error": str(e)}]


def map_vulnerabilities(tech_stack, max_workers=6):
    """Fetch CVEs for all detected tech concurrently using a thread pool."""
    # Build the flat list of (keyword) to look up
    keywords = []
    for tech_name, tech_values in tech_stack.items():
        for val in tech_values:
            keyword = f"{tech_name} {val}" if val != "detected" else tech_name
            keywords.append(keyword)

    vuln_map = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_kw = {executor.submit(search_cves, kw): kw for kw in keywords}
        for future in as_completed(future_to_kw):
            kw = future_to_kw[future]
            try:
                vuln_map[kw] = future.result()
            except Exception as exc:
                vuln_map[kw] = [{"error": str(exc)}]
    return vuln_map


def _cve_to_finding(cve, tech_key):
    """Convert a raw CVE dict into a plain-language finding."""
    sev = (cve.get("severity") or "UNKNOWN").upper()
    cve_id = cve.get("id", "Unknown CVE")
    score = cve.get("score")
    desc = cve.get("description", "")

    # Truncate description to first sentence for the plain explanation
    first_sentence = desc.split(". ")[0].rstrip(".")
    if len(first_sentence) > 200:
        first_sentence = first_sentence[:197] + "…"

    plain = (
        f"A known security issue ({cve_id}) may affect {tech_key} — "
        f"it could allow attackers to {first_sentence.lower() if first_sentence else 'exploit this component'}."
    )

    fix = (
        f"Update {tech_key} to the latest stable version and review "
        f"the vendor's advisory for {cve_id}."
    )

    return {
        "title": f"{cve_id} in {tech_key}",
        "plain_explanation": plain,
        "severity": sev,
        "recommended_fix": fix,
        "cve_score": score,
        "source": "cve"
    }


_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def build_summary(tech_stack, vulnerabilities, security_header_findings):
    """
    Compute overall_risk and top findings for the /scan summary object.
    """
    all_findings = list(security_header_findings)  # copy

    # Collect CVE findings
    for tech_key, cves in vulnerabilities.items():
        for cve in cves:
            if cve.get("error"):
                continue
            all_findings.append(_cve_to_finding(cve, tech_key))

    # Sort findings: CVE CRITICAL/HIGH first, then by severity order descending
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 0), reverse=True)

    top_findings = all_findings[:5]

    # Compute overall risk
    highest_sev = 0
    highest_score = 0.0
    for f in all_findings:
        highest_sev = max(highest_sev, _SEV_ORDER.get(f["severity"], 0))
        score = f.get("cve_score") or 0
        try:
            highest_score = max(highest_score, float(score))
        except (TypeError, ValueError):
            pass

    missing_header_count = sum(1 for f in all_findings if f.get("source") == "security_headers")

    # Risk ladder
    if highest_sev >= 4 or highest_score >= 9.0:
        overall_risk = "Critical"
    elif highest_sev >= 3 or highest_score >= 7.0:
        overall_risk = "High"
    elif highest_sev >= 2 or missing_header_count >= 3 or highest_score >= 4.0:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    # Build "what we checked" line
    tech_count = len(tech_stack)
    cve_count = sum(
        1 for cves in vulnerabilities.values()
        for c in cves if not c.get("error")
    )
    checked_line = (
        f"Checked {tech_count} technolog{'ies' if tech_count != 1 else 'y'}, "
        f"{len(SECURITY_HEADERS)} security headers, "
        f"and found {cve_count} potential CVE{'s' if cve_count != 1 else ''} from the NVD database."
    )

    return {
        "overall_risk": overall_risk,
        "findings": top_findings,
        "what_we_checked": checked_line,
    }


if __name__ == "__main__":
    target_url = "http://zero.webappsecurity.com"
    scan_result = scan_tech(target_url)
    print("=== Tech Stack ===")
    print(json.dumps(scan_result, indent=2))

    if "tech_stack" in scan_result and scan_result["tech_stack"]:
        print("\n=== Vulnerabilities ===")
        vulns = map_vulnerabilities(scan_result["tech_stack"])
        print(json.dumps(vulns, indent=2))