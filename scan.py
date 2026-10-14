# scan.py
import re
import json
import os
import socket
import ipaddress
import time
import subprocess
import shutil
import tempfile
import requests
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

from engine import NucleiEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

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

# ── Nuclei Template Engine Instance ───────────────────────────────────────────
nuclei_engine = NucleiEngine(template_dirs=[
    os.path.join(TEMPLATES_DIR, "technologies"),
    os.path.join(TEMPLATES_DIR, "exposures"),
    os.path.join(TEMPLATES_DIR, "misconfigurations"),
    os.path.join(TEMPLATES_DIR, "headers"),
    TEMPLATES_DIR,
])
try:
    nuclei_engine.load_templates()
    for _tpl in nuclei_engine.templates:
        if _tpl.cpe and _tpl.tech not in CPE_PREFIX:
            CPE_PREFIX[_tpl.tech] = _tpl.cpe
except Exception:
    pass

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


NUCLEI_BIN_PATH = os.environ.get(
    "NUCLEI_BIN_PATH",
    os.path.join(BASE_DIR, "bin", "nuclei.exe" if os.name == "nt" else "nuclei"),
)
COMMUNITY_TEMPLATES_DIR = os.environ.get(
    "NUCLEI_TEMPLATES_DIR",
    os.path.expanduser("~/nuclei-templates"),
)
USE_NUCLEI_CLI = os.environ.get("USE_NUCLEI_CLI", "true").lower() in ("true", "1", "yes")

KNOWN_CANONICAL = {
    "wordpress": "WordPress",
    "nginx": "nginx",
    "apache": "Apache",
    "apache httpd": "Apache",
    "php": "PHP",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "next.js": "Next.js",
    "nextjs": "Next.js",
    "react": "React",
    "vue": "Vue",
    "angular": "Angular",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "laravel": "Laravel",
    "django": "Django",
    "cloudflare": "Cloudflare",
    "google-tag-manager": "Google Tag Manager",
    "google-font-api": "Google Fonts",
    "akismet": "Akismet",
    "gutenberg": "Gutenberg",
    "jetpack": "Jetpack",
    "translatepress": "TranslatePress",
}


def _clean_tech_name(raw_name: str, tpl_id: str, matcher_name: str, metadata: dict, tags: list | None = None) -> str | None:
    if not raw_name:
        return None
    tags = tags or []
    t_lower = tpl_id.lower()
    if any(k in t_lower for k in ("exposure", "disclosure", "leak", "misconfig", "robots", "security-txt", "policy", "tls", "ssl")):
        return None

    raw_lower = raw_name.lower().strip()
    if raw_lower in KNOWN_CANONICAL:
        return KNOWN_CANONICAL[raw_lower]

    if "product" in metadata and metadata["product"]:
        prod = str(metadata["product"]).strip()
        if prod.lower() in KNOWN_CANONICAL:
            return KNOWN_CANONICAL[prod.lower()]
        return prod.title()

    if matcher_name:
        mn_lower = matcher_name.lower().replace("generic", "").strip()
        if mn_lower in KNOWN_CANONICAL:
            return KNOWN_CANONICAL[mn_lower]

    cleaned = re.sub(
        r"\s+(?:Detection|Detect|CMS|Framework|Server|Protection|Service|Disclosure|Exposure|Information|File|Policy)\b.*$",
        "",
        raw_name,
        flags=re.IGNORECASE,
    ).strip()
    cleaned = re.sub(r"['\"]", "", cleaned)
    if cleaned.lower() in KNOWN_CANONICAL:
        return KNOWN_CANONICAL[cleaned.lower()]

    if cleaned.lower() in ("waf", "metatag", "tech", "plugin", "general", "matcher", "robots", "security", "policy", "file"):
        return None

    return cleaned.title() if len(cleaned) > 2 else cleaned.upper()


def run_nuclei_cli(url: str, timeout: int = 35) -> tuple[dict, list, dict]:
    """
    Execute the official Nuclei CLI engine against `url`.
    Returns:
        (tech_stack, security_matches, vulnerabilities)
    """
    bin_path = NUCLEI_BIN_PATH
    if not (bin_path and os.path.exists(bin_path)):
        bin_path = shutil.which("nuclei")
    if not bin_path or not os.path.exists(bin_path):
        return {}, [], {}

    phase1_dirs: list[str] = []
    if os.path.isdir(COMMUNITY_TEMPLATES_DIR):
        for sub in ["http/technologies", "ssl"]:
            full_sub = os.path.join(COMMUNITY_TEMPLATES_DIR, sub)
            if os.path.exists(full_sub):
                phase1_dirs.append(full_sub)
    if os.path.isdir(TEMPLATES_DIR):
        phase1_dirs.append(TEMPLATES_DIR)

    phase2_dirs: list[str] = []
    if os.path.isdir(COMMUNITY_TEMPLATES_DIR):
        for sub in ["http/misconfiguration", "http/exposures", "http/vulnerabilities", "http/default-logins"]:
            full_sub = os.path.join(COMMUNITY_TEMPLATES_DIR, sub)
            if os.path.exists(full_sub):
                phase2_dirs.append(full_sub)

    if not phase1_dirs and not phase2_dirs:
        return {}, [], {}

    lines: list[str] = []
    out_file = None
    try:
        # ── Phase 1: Rapid Technology, SSL & Custom Templates ─────────────
        if phase1_dirs:
            fd, out_file = tempfile.mkstemp(suffix=".jsonl")
            os.close(fd)

            cmd1 = [
                bin_path,
                "-target", url,
                "-jsonl",
                "-silent",
                "-no-stdin",
                "-duc",
                "-ni",
                "-nmhe",
                "-c", "30",
                "-rl", "50",
                "-timeout", "4",
                "-o", out_file,
            ]
            for tpl in phase1_dirs:
                cmd1.extend(["-t", tpl])

            proc1 = subprocess.Popen(
                cmd1,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                proc1.wait(timeout=min(20, timeout))
            except subprocess.TimeoutExpired:
                proc1.kill()
                try:
                    proc1.wait(timeout=2)
                except Exception:
                    pass

            if os.path.exists(out_file):
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    lines.extend([l.strip() for l in f if l.strip()])
                try:
                    os.remove(out_file)
                except Exception:
                    pass
                out_file = None

        # ── Phase 2: Misconfigurations & Exposures ────────────────────────
        if phase2_dirs and timeout > 20:
            fd, out_file = tempfile.mkstemp(suffix=".jsonl")
            os.close(fd)

            cmd2 = [
                bin_path,
                "-target", url,
                "-jsonl",
                "-silent",
                "-no-stdin",
                "-duc",
                "-ni",
                "-nmhe",
                "-c", "30",
                "-rl", "50",
                "-timeout", "4",
                "-o", out_file,
            ]
            for tpl in phase2_dirs:
                cmd2.extend(["-t", tpl])

            proc2 = subprocess.Popen(
                cmd2,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                proc2.wait(timeout=timeout - 20)
            except subprocess.TimeoutExpired:
                proc2.kill()
                try:
                    proc2.wait(timeout=2)
                except Exception:
                    pass

            if os.path.exists(out_file):
                with open(out_file, "r", encoding="utf-8", errors="replace") as f:
                    lines.extend([l.strip() for l in f if l.strip()])

        tech_stack: dict[str, list[str]] = {}
        security_matches: list[dict] = []
        vulnerabilities: dict[str, list[dict]] = {}
        seen_template_ids: set[str] = set()

        for line in lines:
            try:
                item = json.loads(line)
            except Exception:
                continue

            tpl_id = item.get("template-id", "")
            info = item.get("info", {})
            name = info.get("name", tpl_id)
            severity = (info.get("severity") or "INFO").upper()
            desc = info.get("description", "")
            tags = info.get("tags", [])
            matched_at = item.get("matched-at", item.get("url", url))
            extracted = item.get("extracted-results", [])
            version = str(extracted[0]).strip() if extracted else "detected"
            matcher_name = item.get("matcher-name", "")
            metadata = info.get("metadata", {})

            # Tech detection
            raw = None
            if tpl_id.startswith("wordpress-"):
                parts = tpl_id.split("-")
                sub = parts[1] if len(parts) > 1 else "wordpress"
                raw = "WordPress" if sub in ("detect", "passive") else sub
            elif matcher_name and "waf-detect" in tpl_id:
                raw = matcher_name
            elif matcher_name and "tech-detect" in tpl_id:
                raw = matcher_name
            else:
                raw = name

            canon_tech = _clean_tech_name(raw, tpl_id, matcher_name, metadata, tags=tags)
            if canon_tech:
                has_digits = bool(re.search(r"\d", version))
                if canon_tech not in tech_stack:
                    tech_stack[canon_tech] = [version]
                else:
                    existing = tech_stack[canon_tech]
                    if existing == ["detected"] and has_digits:
                        tech_stack[canon_tech] = [version]
                    elif has_digits and version not in existing:
                        tech_stack[canon_tech].append(version)

            cpe = None
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("cpe:"):
                    cpe = tag
                    break

            classification = info.get("classification", {})
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]

            match_item = {
                "template_id": tpl_id,
                "name": name,
                "tech": canon_tech or "General",
                "severity": severity,
                "category": item.get("type", "http"),
                "tags": tags,
                "matched_at": matched_at,
                "description": desc,
                "version": version,
                "cpe": cpe,
                "reference": info.get("reference", []),
            }
            if tpl_id not in seen_template_ids:
                security_matches.append(match_item)
                seen_template_ids.add(tpl_id)

            if severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL") or cve_ids:
                vuln_component = canon_tech or "Security Findings"
                if vuln_component not in vulnerabilities:
                    vulnerabilities[vuln_component] = []
                cve_id_str = cve_ids[0] if cve_ids else tpl_id.upper()
                cvss_score = classification.get("cvss-score")
                if not cvss_score:
                    scores = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}
                    cvss_score = scores.get(severity, 5.0)

                vulnerabilities[vuln_component].append({
                    "id": cve_id_str,
                    "severity": severity,
                    "score": cvss_score,
                    "description": desc or name,
                    "confidence": "confirmed",
                    "source": "scanner",
                    "matched_at": matched_at,
                })

        return tech_stack, security_matches, vulnerabilities

    except Exception:
        return {}, [], {}
    finally:
        if out_file and os.path.exists(out_file):
            try:
                os.remove(out_file)
            except Exception:
                pass


def scan_tech(url: str, enable_multi_path: bool = True) -> dict:
    """Detect tech stack & exposures using official Nuclei engine + SSRF-safe request."""
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
        matches_payload: list[dict] = []
        direct_vulnerabilities: dict[str, list[dict]] = {}

        # ── 1. Official Nuclei Engine execution (if available) ─────────────
        cli_tech, cli_matches, cli_vulns = {}, [], {}
        if USE_NUCLEI_CLI:
            cli_tech, cli_matches, cli_vulns = run_nuclei_cli(url, timeout=30)

        if cli_matches or cli_tech:
            tech.update(cli_tech)
            matches_payload.extend(cli_matches)
            direct_vulnerabilities.update(cli_vulns)
        else:
            # ── Fallback to Python in-memory engine ────────────────────────
            template_matches = nuclei_engine.scan_response(
                status_code=resp.status_code,
                headers=dict(hdrs),
                body=html,
            )

            if enable_multi_path:
                exposure_templates = [
                    t for t in nuclei_engine.templates
                    if t.category in ("exposures", "misconfigurations")
                ]
                if exposure_templates:
                    def _req(target_url: str):
                        return _safe_get(target_url, sess, timeout=5)

                    path_matches = nuclei_engine.scan_target(
                        base_url=url,
                        request_fn=_req,
                        templates=exposure_templates,
                        max_paths=12,
                    )
                    seen_ids = {m.template_id for m in template_matches}
                    for pm in path_matches:
                        if pm.template_id not in seen_ids:
                            template_matches.append(pm)
                            seen_ids.add(pm.template_id)

            tech = nuclei_engine.to_tech_stack(template_matches)
            matches_payload = [
                {
                    "template_id": m.template_id,
                    "name":        m.name,
                    "tech":        m.tech,
                    "severity":    m.severity,
                    "category":    m.category,
                    "tags":        m.tags,
                    "matched_at":  m.matched_at or url,
                    "description": m.description,
                    "version":     m.detected_version,
                    "cpe":         m.cpe,
                }
                for m in template_matches
            ]

        # ── Header-based detection & Fallbacks ──────────────────────────────
        server = hdrs.get("Server") or hdrs.get("server", "")
        if server and "Server" not in tech:
            tech["Server"] = [server]

        powered = hdrs.get("X-Powered-By") or hdrs.get("x-powered-by", "")
        if powered and "X-Powered-By" not in tech:
            tech["X-Powered-By"] = [powered]

        aspnet = hdrs.get("X-AspNet-Version", "")
        if aspnet and "ASP.NET" not in tech:
            tech["ASP.NET"] = [aspnet]

        # HTML parsing fallback for generator meta
        parser = _TechHTMLParser()
        try:
            parser.feed(html)
        except Exception:
            pass

        generator = parser.meta.get("generator", "")
        if generator and "Generator" not in tech:
            tech["Generator"] = [generator]

        return {
            "target":                 url,
            "status":                 resp.status_code,
            "tech_stack":             tech,
            "security_matches":       matches_payload,
            "nuclei_matches":         matches_payload,
            "direct_vulnerabilities": direct_vulnerabilities,
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
    nuclei_findings: list | None = None,
) -> dict:
    """
    Compute overall_risk and top findings.

    Severity capping rule:
      - 'confirmed' CVEs (CPE-matched) & verified Nuclei findings can push risk to High or Critical.
      - 'possible' CVEs (keyword fallback) cap the risk contribution at Medium.
    """
    all_findings = list(security_header_findings)

    # Convert significant engine matches (exposures / misconfigs with severity > INFO) into confirmed findings
    if nuclei_findings:
        for nf in nuclei_findings:
            sev = str(nf.get("severity", "INFO")).upper()
            if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                all_findings.append({
                    "title":             f"[{sev}] {nf.get('name', nf.get('template_id', 'Security Finding'))}",
                    "plain_explanation": nf.get("description", "Potential exposure or misconfiguration detected by template."),
                    "severity":          sev,
                    "confidence":        "confirmed",
                    "recommended_fix":   f"Review endpoint ({nf.get('matched_at', 'target')}) and restrict public exposure.",
                    "source":            "engine",
                })

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
    sec_count = len(nuclei_findings) if nuclei_findings else 0
    checked_parts = [
        f"Checked {tech_count} technolog{'ies' if tech_count != 1 else 'y'}",
    ]
    if sec_count > 0:
        checked_parts.append(f"{sec_count} security check{'s' if sec_count != 1 else ''}")
    checked_parts.append(f"{len(SECURITY_HEADERS)} security headers")

    checked_line = (
        f"{', '.join(checked_parts)}, and found {cve_count} potential CVE{'s' if cve_count != 1 else ''} "
        f"from the vulnerability database."
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