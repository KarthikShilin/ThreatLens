# scan.py
import re
import json
import requests
from html.parser import HTMLParser

NVD_API_KEY = "DA5D6095-66E2-420C-B83F-0860ED78E9B1"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

def map_vulnerabilities(tech_stack):
    """Loop through detected tech and pull CVEs for each"""
    vuln_map = {}
    for tech_name, tech_values in tech_stack.items():
        for val in tech_values:
            keyword = f"{tech_name} {val}" if val != "detected" else tech_name
            vuln_map[keyword] = search_cves(keyword)
    return vuln_map

if __name__ == "__main__":
    target_url = "http://zero.webappsecurity.com"
    scan_result = scan_tech(target_url)
    print("=== Tech Stack ===")
    print(json.dumps(scan_result, indent=2))

    if "tech_stack" in scan_result and scan_result["tech_stack"]:
        print("\n=== Vulnerabilities ===")
        vulns = map_vulnerabilities(scan_result["tech_stack"])
        print(json.dumps(vulns, indent=2))