# scan.py
import subprocess
import json
import requests

NVD_API_KEY = "DA5D6095-66E2-420C-B83F-0860ED78E9B1"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def parse_relevant_tech(raw_data):
    if "plugins" not in raw_data:
        return {"error": "no plugins found", "raw": raw_data}

    plugins = raw_data["plugins"]

    relevant_keys = [
        "HTTPServer", "X-Powered-By", "Script", "JQuery", "Bootstrap",
        "WordPress", "PHP", "ASP", "Angular", "React", "Vue",
        "nginx", "Apache", "IIS", "Node.js"
    ]

    filtered = {}
    for key, value in plugins.items():
        if any(rk.lower() in key.lower() for rk in relevant_keys):
            filtered[key] = value.get("string", value.get("version", "detected"))

    return {
        "target": raw_data.get("target"),
        "status": raw_data.get("http_status"),
        "tech_stack": filtered
    }

def scan_tech(url):
    try:
        result = subprocess.run(
            ["whatweb", "--log-json=-", "-q", "--color=never", url],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        raw = data[0] if isinstance(data, list) and data else data
        return parse_relevant_tech(raw)
    except FileNotFoundError:
        return {"error": "whatweb not installed", "tech_stack": {}}
    except json.JSONDecodeError:
        return {"error": "parse failed", "tech_stack": {}}

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