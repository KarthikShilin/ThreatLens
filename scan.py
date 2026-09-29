# scan.py
import re
import json
import os
import socket
import ipaddress
import time
import requests
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

# Load .env if present (python-dotenv is optional — graceful fallback if not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Configuration ──────────────────────────────────────────────────────────────
# No hardcoded key. See .env.example. Without a key, NVD applies stricter rate
# limits (5 req/30s) but the app still functions.
NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Set ALLOW_PRIVATE_TARGETS=true in .env to scan local targets (e.g. Juice Shop / DVWA).
ALLOW_PRIVATE_TARGETS = os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"

ALLOWED_SCHEMES    = {"http", "https"}
ALLOWED_PORTS      = {80, 443, 8080, 8443}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024   # 2 MB body cap
MAX_REDIRECTS      = 5
REQUEST_TIMEOUT    = 10

# ── Generic / versionless server identifiers ─────────────────────────────────
# When a Server header (or other tech value) matches one of these names AND
# carries no version number, skip the CVE keyword-fallback entirely.
# Keyword searches against CDN / proxy names produce highly unrelated matches
# (e.g. a Crafatar CVE appearing for "cloudflare").
GENERIC_SERVER_NAMES = {
    "cloudflare", "nginx", "apache", "apache httpd",
    "microsoft-iis", "iis", "openresty", "caddy", "lighttpd",
    "litespeed", "gunicorn", "uvicorn", "werkzeug", "tornado",
    "jetty", "tomcat", "server", "web server",
}

# Regex: does the value contain at least one digit group that looks like a
# version number?  e.g. "nginx/1.24.0" → yes; "cloudflare" → no.
_VERSION_RE = re.compile(r"\d")


def _is_generic_server_value(value: str) -> bool:
    """
    Return True when `value` is a generic server identifier with no usable
    version string — i.e. the CVE keyword-fallback should be skipped.

    Examples that return True  : "cloudflare", "nginx", "Apache"
    Examples that return False : "nginx/1.24.0", "Apache/2.4.51"
    """
    stripped = value.strip().lower()
    # If there is ANY digit in the value, treat it as a versioned string
    # (the caller already skips lookup when version == "detected" / "").
    if _VERSION_RE.search(stripped):
        return False
    # Match against the known-generic list
    # Also treat any single bare word that has no slash/dot as generic.
    if stripped in GENERIC_SERVER_NAMES:
        return True
    # Bare server name with no slash and no digits (e.g. "LiteSpeed", "Server")
    if "/" not in stripped and "." not in stripped:
        return True
    return False


# ── CPE prefix table for known products ───────────────────────────────────────
# Used to perform accurate NVD CPE queries instead of free-text keyword search.
# Keys must match the tech names emitted by scan_tech().
CPE_PREFIX = {
    "jQuery":    "cpe:2.3:a:jquery:jquery",
    "Bootstrap": "cpe:2.3:a:getbootstrap:bootstrap",
    "Angular":   "cpe:2.3:a:google:angular.js",
    "Vue":       "cpe:2.3:a:vuejs:vue.js",
    "React":     "cpe:2.3:a:facebook:react",
    "WordPress": "cpe:2.3:a:wordpress:wordpress",
    "Drupal":    "cpe:2.3:a:drupal:drupal",
    "Joomla":    "cpe:2.3:a:joomla:joomla\\!",
    "Next.js":   "cpe:2.3:a:vercel:next.js",
    "Laravel":   "cpe:2.3:a:laravel:laravel",
    "Django":    "cpe:2.3:a:djangoproject:django",
    "nginx":     "cpe:2.3:a:nginx:nginx",
    "Apache":    "cpe:2.3:a:apache:http_server",
}

# ── Security headers ──────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "plain": "Your site may lack a Content Security Policy, which could allow attackers to inject malicious scripts into your pages.",
        "fix":   "Add a Content-Security-Policy header to your web server to restrict which scripts and resources browsers are allowed to load."
    },
    "X-Frame-Options": {
        "plain": "Your site may be missing a header that prevents it from being embedded in other websites, which could expose users to clickjacking attacks.",
        "fix":   "Add the X-Frame-Options: SAMEORIGIN header to stop your pages from being loaded inside iframes on other domains."
    },
    "X-Content-Type-Options": {
        "plain": "Your site may be missing a header that prevents browsers from guessing the file type of responses, which could allow certain attacks.",
        "fix":   "Add the X-Content-Type-Options: nosniff header to stop browsers from interpreting files as a different type than declared."
    },
    "Strict-Transport-Security": {
        "plain": "Your site may not be enforcing secure HTTPS connections, which could allow attackers to intercept traffic on unsecured networks.",
        "fix":   "Add the Strict-Transport-Security header (HSTS) to force browsers to always use HTTPS when connecting to your site."
    },
    "Referrer-Policy": {
        "plain": "Your site may be sharing full page URLs with third-party sites when users click links, which could expose sensitive paths.",
        "fix":   "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin) to control how much referrer information is shared."
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# FIX 2 — SSRF PROTECTION
# ══════════════════════════════════════════════════════════════════════════════

class SSRFError(ValueError):
    """Raised when a URL fails SSRF validation."""


def validate_target(url: str) -> str:
    """
    Validate a user-supplied URL against SSRF risks.
    Returns the (unchanged) URL when safe; raises SSRFError otherwise.

    Checks performed:
      - Scheme must be http or https.
      - No embedded credentials (user:pass@host).
      - Port must be in ALLOWED_PORTS.
      - Every IP address returned by DNS must be public (not private, loopback,
        link-local — including 169.254.169.254 AWS metadata — reserved,
        multicast, or unspecified), for both IPv4 and IPv6.

    Known residual risk — DNS rebinding: an attacker can serve a valid public
    IP during this validation, then switch to an internal IP for the actual TCP
    connection. Mitigation: enforce egress filtering at the network/firewall
    level in production. ALLOW_PRIVATE_TARGETS bypasses all checks (dev only).
    """
    if ALLOW_PRIVATE_TARGETS:
        return url

    try:
        parsed = urlparse(url)
    except Exception:
        raise SSRFError("Invalid URL format.")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"Scheme '{parsed.scheme}' is not allowed. Only http and https are supported."
        )

    if parsed.username or parsed.password:
        raise SSRFError("URLs with embedded credentials are not allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Could not determine hostname from URL.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFError(
            f"Port {port} is not allowed. Allowed ports: {sorted(ALLOWED_PORTS)}."
        )

    # Resolve all addresses and validate every one
    try:
        addr_infos = socket.getaddrinfo(hostname, port)
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve hostname '{hostname}': {exc}")

    for _af, _type, _proto, _canon, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFError(f"Unrecognised IP returned by DNS: {ip_str}")

        if (
            ip.is_private      # RFC1918 / ULA
            or ip.is_loopback  # 127.x / ::1
            or ip.is_link_local  # 169.254.x.x (incl. AWS metadata) / fe80::/10
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise SSRFError("This address can't be scanned (private or reserved IP).")

    return url


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (ThreatLens Scanner)"})
    return s


def _safe_get(
    url: str,
    session: requests.Session | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> requests.Response:
    """
    SSRF-safe GET: validates every redirect hop and caps response body at
    MAX_RESPONSE_BYTES. Never follows a redirect to a blocked address.
    """
    sess = session or _make_session()
    current_url = url

    for _hop in range(MAX_REDIRECTS + 1):
        validate_target(current_url)

        resp = sess.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )

        # Cap response body
        chunks, total = [], 0
        for chunk in resp.iter_content(chunk_size=8192):
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_RESPONSE_BYTES:
                break
        resp._content = b"".join(chunks)

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if not location:
                return resp
            current_url = urljoin(current_url, location)
            continue

        return resp

    return resp  # max redirects exhausted — return last response


# ══════════════════════════════════════════════════════════════════════════════
# TECH FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

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


def scan_tech(url: str) -> dict:
    """Detect tech stack using SSRF-safe HTTP request + HTML parsing."""
    try:
        validate_target(url)
    except SSRFError as e:
        return {"error": str(e), "ssrf_blocked": True, "tech_stack": {}}

    try:
        sess = _make_session()
        resp = _safe_get(url, sess)
        hdrs = resp.headers
        html = resp.text
        tech: dict[str, list[str]] = {}

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
            "target":     url,
            "status":     resp.status_code,
            "tech_stack": tech,
        }

    except SSRFError as e:
        return {"error": str(e), "ssrf_blocked": True, "tech_stack": {}}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "tech_stack": {}}


def get_headers(url: str) -> dict:
    validate_target(url)
    sess = _make_session()
    resp = _safe_get(url, sess, timeout=5)
    return dict(resp.headers)


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADER AUDIT
# ══════════════════════════════════════════════════════════════════════════════

def check_security_headers(headers: dict) -> list[dict]:
    """
    Check for missing security headers.
    Returns a list of findings, each with title, plain_explanation,
    severity, and recommended_fix.
    """
    findings = []
    normalized = {k.lower(): v for k, v in headers.items()}
    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in normalized:
            findings.append({
                "title":             f"Missing security header: {header_name}",
                "plain_explanation": info["plain"],
                "severity":          "MEDIUM",
                "confidence":        "confirmed",   # header absence is definitive
                "recommended_fix":   info["fix"],
                "source":            "security_headers",
            })
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# FIX 3 — CVE LOOKUP: CPE accuracy + confidence tags + retry/backoff
# ══════════════════════════════════════════════════════════════════════════════

def _nvd_request_with_retry(params: dict, max_retries: int = 3) -> dict:
    """Query NVD API with exponential backoff on 429 / timeouts."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    # Without a key, NVD allows 5 requests per 30s — slow down on 429
    base_wait = 1 if NVD_API_KEY else 6

    for attempt in range(max_retries):
        try:
            resp = requests.get(
                NVD_BASE_URL, headers=headers, params=params, timeout=15
            )
            if resp.status_code == 429:
                wait = base_wait * (2 ** attempt)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
        except requests.exceptions.RequestException:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise

    return {"vulnerabilities": [], "_rate_limited": True}


def _parse_nvd_response(data: dict, confidence: str) -> list[dict]:
    """Convert raw NVD API response into our CVE list format."""
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity, score = "UNKNOWN", None
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss     = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore")
        elif "cvssMetricV30" in metrics:
            cvss     = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore")
        elif "cvssMetricV2" in metrics:
            cvss     = metrics["cvssMetricV2"][0]["cvssData"]
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
            score    = cvss.get("baseScore")

        cves.append({
            "id":          cve_id,
            "description": description,
            "severity":    severity,
            "score":       score,
            "confidence":  confidence,   # "confirmed" | "possible"
        })
    return cves


def _search_cves_by_keyword(keyword: str, max_results: int = 5) -> list[dict]:
    """Keyword fallback — returns confidence='possible'."""
    try:
        data = _nvd_request_with_retry(
            {"keywordSearch": keyword, "resultsPerPage": max_results}
        )
    except Exception as e:
        return [{"error": "CVE data temporarily unavailable", "detail": str(e)}]

    if data.get("_rate_limited"):
        return [{"error": "CVE data temporarily unavailable (rate limit)"}]

    return _parse_nvd_response(data, confidence="possible")


def _search_cves_by_cpe(cpe_prefix: str, version: str, max_results: int = 5) -> list[dict]:
    """CPE virtualMatchString lookup — returns confidence='confirmed'."""
    virtual_match = f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"
    try:
        data = _nvd_request_with_retry(
            {"virtualMatchString": virtual_match, "resultsPerPage": max_results}
        )
    except Exception as e:
        return [{"error": "CVE data temporarily unavailable", "detail": str(e)}]

    if data.get("_rate_limited"):
        return [{"error": "CVE data temporarily unavailable (rate limit)"}]

    results = _parse_nvd_response(data, confidence="confirmed")
    # If CPE returns nothing, fall back to keyword (possible)
    if not results:
        return _search_cves_by_keyword(f"{cpe_prefix.split(':')[-1]} {version}")
    return results


def map_vulnerabilities(tech_stack: dict, max_workers: int = 6) -> dict:
    """
    Fetch CVEs concurrently for detected technologies.

    Rules:
      - Skip lookup when no version was detected (avoids noisy false positives).
      - Use CPE-based query (confidence='confirmed') when tech is in CPE_PREFIX.
      - Fall back to keyword search (confidence='possible') otherwise.
    """

    def _lookup(tech_name: str, version: str) -> tuple[str, list]:
        has_version = version not in ("detected", "")
        label = f"{tech_name} {version}".strip() if has_version else tech_name

        if not has_version:
            # No version → skip to avoid high false-positive rate
            return label, []

        # Skip keyword fallback for generic / versionless server identifiers
        # (e.g. "Server: cloudflare", "Server: nginx" with no version number).
        # These produce highly unrelated NVD matches.
        if _is_generic_server_value(version):
            return label, []

        cpe_prefix = CPE_PREFIX.get(tech_name)
        if cpe_prefix:
            return label, _search_cves_by_cpe(cpe_prefix, version)
        else:
            return label, _search_cves_by_keyword(label)

    tasks: list[tuple[str, str]] = []
    for tech_name, tech_values in tech_stack.items():
        for val in (tech_values if isinstance(tech_values, list) else [tech_values]):
            tasks.append((tech_name, val))

    vuln_map: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {
            executor.submit(_lookup, name, val): (name, val)
            for name, val in tasks
        }
        for future in as_completed(future_to_task):
            try:
                key, result = future.result()
                vuln_map[key] = result
            except Exception as exc:
                name, val = future_to_task[future]
                vuln_map[f"{name} {val}".strip()] = [{"error": str(exc)}]

    return vuln_map


# ══════════════════════════════════════════════════════════════════════════════
# RISK SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# Severity levels that are capped for "possible" confidence CVEs.
# Only "confirmed" (CPE + version matched) CVEs may display HIGH or CRITICAL.
_POSSIBLE_MAX_SEV = "MEDIUM"
_POSSIBLE_MAX_SEV_ORDER = _SEV_ORDER[_POSSIBLE_MAX_SEV]  # = 2


def _clamp_severity(sev: str, confidence: str) -> str:
    """
    Apply the confidence-based severity cap:
      - confidence == 'confirmed' → use raw severity unchanged.
      - confidence == 'possible'  → clamp to at most MEDIUM.
    """
    if confidence != "confirmed":
        if _SEV_ORDER.get(sev, 0) > _POSSIBLE_MAX_SEV_ORDER:
            return _POSSIBLE_MAX_SEV
    return sev


def _cve_to_finding(cve: dict, tech_key: str) -> dict:
    """Convert a raw CVE dict into a plain-language finding."""
    raw_sev    = (cve.get("severity") or "UNKNOWN").upper()
    confidence = cve.get("confidence", "possible")
    cve_id     = cve.get("id", "Unknown CVE")
    score      = cve.get("score")
    desc       = cve.get("description", "")

    # Cap severity: possible CVEs may not display above MEDIUM
    sev = _clamp_severity(raw_sev, confidence)

    first_sentence = desc.split(". ")[0].rstrip(".")
    if len(first_sentence) > 200:
        first_sentence = first_sentence[:197] + "…"

    # Cautious wording for possible; direct for confirmed
    verb = "may be affected by" if confidence == "possible" else "is affected by"
    plain = (
        f"A known security issue ({cve_id}) — this component {verb} a vulnerability "
        f"that could allow attackers to "
        f"{first_sentence.lower() if first_sentence else 'exploit this component'}."
    )

    return {
        "title":             f"{cve_id} in {tech_key}",
        "plain_explanation": plain,
        "severity":          sev,
        "confidence":        confidence,
        "recommended_fix":   (
            f"Update {tech_key} to the latest stable version and review "
            f"the vendor's advisory for {cve_id}."
        ),
        "cve_score":         score,
        "source":            "cve",
    }


def build_summary(
    tech_stack: dict,
    vulnerabilities: dict,
    security_header_findings: list,
) -> dict:
    """
    Compute overall_risk and top findings.

    Severity capping rule:
      - 'confirmed' CVEs (CPE-matched) can push risk to High or Critical.
      - 'possible' CVEs (keyword fallback) cap the risk contribution at Medium.
    """
    all_findings = list(security_header_findings)

    for tech_key, cves in vulnerabilities.items():
        for cve in cves:
            if cve.get("error"):
                continue
            all_findings.append(_cve_to_finding(cve, tech_key))

    all_findings.sort(
        key=lambda f: _SEV_ORDER.get(f.get("severity", "UNKNOWN"), 0),
        reverse=True,
    )
    top_findings = all_findings[:5]

    # Separate confirmed vs possible contributions
    highest_confirmed_sev = 0
    highest_possible_sev  = 0
    highest_score         = 0.0
    missing_header_count  = 0

    for f in all_findings:
        sev_val    = _SEV_ORDER.get(f.get("severity", "UNKNOWN"), 0)
        confidence = f.get("confidence", "possible")
        source     = f.get("source", "")

        if source == "security_headers":
            # Header absence is certain — treat as confirmed medium
            missing_header_count += 1
            highest_confirmed_sev = max(highest_confirmed_sev, sev_val)
        elif confidence == "confirmed":
            highest_confirmed_sev = max(highest_confirmed_sev, sev_val)
        else:
            highest_possible_sev = max(highest_possible_sev, sev_val)

        try:
            highest_score = max(highest_score, float(f.get("cve_score") or 0))
        except (TypeError, ValueError):
            pass

    # Risk ladder — only confirmed evidence drives High/Critical
    if highest_confirmed_sev >= 4:
        overall_risk = "Critical"
    elif highest_confirmed_sev >= 3:
        overall_risk = "High"
    elif (
        highest_confirmed_sev >= 2
        or highest_possible_sev >= 2
        or missing_header_count >= 3
    ):
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    tech_count = len(tech_stack)
    cve_count  = sum(
        1 for cves in vulnerabilities.values()
        for c in cves if not c.get("error")
    )
    checked_line = (
        f"Checked {tech_count} technolog{'ies' if tech_count != 1 else 'y'}, "
        f"{len(SECURITY_HEADERS)} security headers, "
        f"and found {cve_count} potential CVE{'s' if cve_count != 1 else ''} "
        f"from the NVD database."
    )

    return {
        "overall_risk":    overall_risk,
        "findings":        top_findings,
        "what_we_checked": checked_line,
    }


# ── Quick smoke test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    target_url = "http://zero.webappsecurity.com"
    scan_result = scan_tech(target_url)
    print("=== Tech Stack ===")
    print(json.dumps(scan_result, indent=2))

    if "tech_stack" in scan_result and scan_result["tech_stack"]:
        print("\n=== Vulnerabilities ===")
        vulns = map_vulnerabilities(scan_result["tech_stack"])
        print(json.dumps(vulns, indent=2))