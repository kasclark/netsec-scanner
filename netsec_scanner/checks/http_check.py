"""HTTP/HTTPS security checks."""

import json
import os
import re
import ssl
import socket
import datetime
import uuid
from typing import List
from html.parser import HTMLParser

import requests

from netsec_scanner import Finding, Severity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

DEFAULT_PAGES = [
    ("Apache", re.compile(r"Apache.*Test Page|It works!", re.I)),
    ("Nginx", re.compile(r"Welcome to nginx", re.I)),
    ("IIS", re.compile(r"IIS Windows Server|Internet Information Services", re.I)),
]


def _load_security_headers():
    path = os.path.join(DATA_DIR, "security_headers.json")
    with open(path) as f:
        return json.load(f)


def check_http(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check HTTP/HTTPS service."""
    findings = []
    is_https = port in (443, 8443) or "ssl" in port_info.get("service", "").lower() or "https" in port_info.get("service", "").lower()
    scheme = "https" if is_https else "http"
    base_url = f"{scheme}://{ip}:{port}"

    # Flag plain HTTP
    if not is_https:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"HTTP (cleartext) on port {port}",
            description="Service is running over unencrypted HTTP. Credentials and data transmitted in cleartext.",
            module="checks/http",
            remediation="Enable HTTPS/TLS and redirect HTTP to HTTPS.",
            port=port,
            service="http",
        ))

    # TLS checks
    if is_https:
        findings.extend(_check_tls(ip, port))

    # HTTP response checks
    try:
        resp = requests.get(base_url, timeout=10, verify=False, allow_redirects=True,
                           headers={"User-Agent": "netsec-scanner/1.0"})

        # Security headers
        headers_config = _load_security_headers()
        for header_info in headers_config:
            name = header_info["header"]
            if name.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                sev = Severity[header_info.get("severity_if_missing", "LOW")]
                findings.append(Finding(
                    severity=sev,
                    title=f"Missing security header: {name}",
                    description=header_info.get("description", f"The {name} header is not set."),
                    module="checks/http",
                    remediation=header_info.get("remediation", f"Add {name} header to server responses."),
                    port=port,
                    service="http",
                ))

        # Server header info leak
        server = resp.headers.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"Server version disclosed: {server}",
                description=f"The Server header reveals version information: '{server}'.",
                module="checks/http",
                remediation="Configure the web server to suppress version information in the Server header.",
                port=port,
                service="http",
            ))

        # X-Powered-By
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"X-Powered-By disclosed: {powered}",
                description=f"Technology stack disclosed via X-Powered-By: '{powered}'.",
                module="checks/http",
                remediation="Remove the X-Powered-By header.",
                port=port,
                service="http",
            ))

        # Default page detection
        body = resp.text[:5000]
        for name, pattern in DEFAULT_PAGES:
            if pattern.search(body):
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Default {name} page detected",
                    description=f"The server is showing the default {name} page, indicating default configuration.",
                    module="checks/http",
                    remediation="Replace the default page with your application or remove the default content.",
                    port=port,
                    service="http",
                ))
                break

        # Check robots.txt
        try:
            robots = requests.get(f"{base_url}/robots.txt", timeout=5, verify=False,
                                 headers={"User-Agent": "netsec-scanner/1.0"})
            if robots.status_code == 200 and len(robots.text) > 10:
                sensitive = [line for line in robots.text.splitlines()
                            if "disallow" in line.lower() and any(
                                kw in line.lower() for kw in ["admin", "config", "backup", "secret", "private", "api", ".env"])]
                if sensitive:
                    findings.append(Finding(
                        severity=Severity.LOW,
                        title="Sensitive paths in robots.txt",
                        description=f"robots.txt reveals potentially sensitive paths: {'; '.join(sensitive[:5])}",
                        module="checks/http",
                        remediation="Review robots.txt entries; sensitive paths should be protected by authentication, not just hidden.",
                        port=port,
                        service="http",
                    ))
        except Exception:
            pass

        # OWASP Top 10 passive checks
        findings.extend(_check_owasp(ip, port, base_url, is_https, resp))

    except requests.exceptions.RequestException as e:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"HTTP request failed on port {port}",
            description=str(e)[:200],
            module="checks/http",
            port=port,
            service="http",
        ))

    return findings


def _check_tls(ip: str, port: int) -> List[Finding]:
    """Check TLS configuration."""
    findings = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert(binary_form=True)

                # Protocol version
                if version and "TLSv1.0" in version:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="TLS 1.0 in use",
                        description="TLS 1.0 is deprecated and has known vulnerabilities.",
                        module="checks/http",
                        remediation="Disable TLS 1.0; use TLS 1.2 or 1.3.",
                        port=port, service="https",
                    ))
                elif version and "TLSv1.1" in version:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="TLS 1.1 in use",
                        description="TLS 1.1 is deprecated.",
                        module="checks/http",
                        remediation="Disable TLS 1.1; use TLS 1.2 or 1.3.",
                        port=port, service="https",
                    ))

                # Cipher info
                if cipher:
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"TLS: {version}, cipher: {cipher[0]}",
                        description=f"Protocol: {version}, Cipher: {cipher[0]}, Bits: {cipher[2]}",
                        module="checks/http",
                        port=port, service="https",
                    ))

                # Certificate checks
                try:
                    cert_decoded = ssock.getpeercert()
                    if cert_decoded:
                        # Check expiry
                        not_after = cert_decoded.get("notAfter", "")
                        if not_after:
                            try:
                                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                if expiry < datetime.datetime.utcnow():
                                    findings.append(Finding(
                                        severity=Severity.HIGH,
                                        title="TLS certificate expired",
                                        description=f"Certificate expired on {not_after}.",
                                        module="checks/http",
                                        remediation="Renew the TLS certificate.",
                                        port=port, service="https",
                                    ))
                                elif expiry < datetime.datetime.utcnow() + datetime.timedelta(days=30):
                                    findings.append(Finding(
                                        severity=Severity.MEDIUM,
                                        title="TLS certificate expiring soon",
                                        description=f"Certificate expires on {not_after}.",
                                        module="checks/http",
                                        remediation="Renew the TLS certificate before expiry.",
                                        port=port, service="https",
                                    ))
                            except ValueError:
                                pass
                except Exception:
                    pass

    except ssl.SSLError as e:
        if "self-signed" in str(e).lower() or "self signed" in str(e).lower():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Self-signed TLS certificate",
                description="The server uses a self-signed certificate not trusted by standard CAs.",
                module="checks/http",
                remediation="Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                port=port, service="https",
            ))
    except Exception:
        pass

    return findings


def _load_owasp_paths():
    path = os.path.join(DATA_DIR, "owasp_paths.json")
    with open(path) as f:
        return json.load(f)


class _ScriptSrcParser(HTMLParser):
    """Extract external script src attributes and check for integrity."""
    def __init__(self):
        super().__init__()
        self.scripts_missing_sri = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs_dict = dict(attrs)
        src = attrs_dict.get("src", "")
        if src and (src.startswith("http://") or src.startswith("https://") or src.startswith("//")):
            if "integrity" not in attrs_dict:
                self.scripts_missing_sri.append(src)


def _check_owasp(ip: str, port: int, base_url: str, is_https: bool, initial_resp: requests.Response) -> List[Finding]:
    """Run OWASP Top 10 passive/safe checks. Returns list of Findings."""
    findings = []
    hdrs = {"User-Agent": "netsec-scanner/1.0"}
    req_kw = dict(timeout=10, verify=False, headers=hdrs, allow_redirects=True)
    body = initial_resp.text[:10000]
    resp_headers = initial_resp.headers
    owasp = _load_owasp_paths()

    # ── A01: Broken Access Control ──────────────────────────────────

    # Directory listing
    for path in ["/", "/icons/", "/images/"]:
        try:
            r = requests.get(base_url + path, **req_kw)
            if r.status_code == 200 and "Index of" in r.text[:2000]:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"OWASP A01: Directory listing enabled ({path})",
                    description=f"Directory listing is enabled at {path}, exposing file structure.",
                    module="checks/http",
                    remediation="Disable directory listing in the web server configuration.",
                    port=port, service="http",
                ))
                break  # one finding is enough
        except Exception:
            pass

    # CORS wildcard
    try:
        r = requests.get(base_url, timeout=10, verify=False,
                         headers={**hdrs, "Origin": "https://evil.example.com"}, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="OWASP A01: CORS wildcard Access-Control-Allow-Origin",
                description="Server returns Access-Control-Allow-Origin: * allowing any origin.",
                module="checks/http",
                remediation="Restrict CORS to trusted origins instead of using wildcard.",
                port=port, service="http",
            ))
        elif acao == "https://evil.example.com":
            findings.append(Finding(
                severity=Severity.HIGH,
                title="OWASP A01: CORS reflects arbitrary Origin",
                description="Server reflects the Origin header in Access-Control-Allow-Origin, allowing any origin.",
                module="checks/http",
                remediation="Validate and whitelist allowed origins for CORS.",
                port=port, service="http",
            ))
    except Exception:
        pass

    # Admin/API path exposure (batch — count toward ~20 request budget)
    exposed_paths = []
    all_paths = owasp.get("admin_paths", []) + owasp.get("api_paths", [])
    for path in all_paths[:12]:  # limit requests
        try:
            r = requests.get(base_url + path, **req_kw)
            if r.status_code < 400:
                exposed_paths.append(path)
        except Exception:
            pass
    if exposed_paths:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="OWASP A01: Accessible admin/API paths",
            description=f"The following paths returned non-error responses: {', '.join(exposed_paths)}",
            module="checks/http",
            remediation="Restrict access to administrative and API endpoints via authentication and network controls.",
            port=port, service="http",
        ))

    # ── A02: Cryptographic Failures ─────────────────────────────────

    cookies = initial_resp.headers.get("Set-Cookie", "")
    if cookies:
        if is_https and "secure" not in cookies.lower():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="OWASP A02: Cookie missing Secure flag",
                description="Set-Cookie header on HTTPS lacks the Secure flag.",
                module="checks/http",
                remediation="Add the Secure flag to all cookies served over HTTPS.",
                port=port, service="http",
            ))
        if "httponly" not in cookies.lower():
            findings.append(Finding(
                severity=Severity.LOW,
                title="OWASP A02: Cookie missing HttpOnly flag",
                description="Set-Cookie header lacks the HttpOnly flag, making cookies accessible to JavaScript.",
                module="checks/http",
                remediation="Add the HttpOnly flag to session cookies.",
                port=port, service="http",
            ))

    # ── A03: Injection — error message disclosure ───────────────────

    error_patterns = [
        "SQL syntax", "mysql_", "pg_query", "ORA-", "Microsoft OLE DB",
        "Traceback (most recent call last)", "Exception in thread",
        "Parse error", "Fatal error", "Warning:", "stack trace",
    ]
    for pat in error_patterns:
        if pat.lower() in body.lower():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="OWASP A03: Error message / stack trace disclosure",
                description=f"Response body contains error pattern: '{pat}'",
                module="checks/http",
                remediation="Configure custom error pages; never expose stack traces or database errors to users.",
                port=port, service="http",
            ))
            break

    # Reflected input canary
    canary = f"netseccanary{uuid.uuid4().hex[:8]}"
    try:
        r = requests.get(f"{base_url}/?q={canary}", **req_kw)
        if canary in r.text:
            findings.append(Finding(
                severity=Severity.LOW,
                title="OWASP A03: Input reflected in response",
                description="A unique canary string sent as a query parameter was reflected in the response body.",
                module="checks/http",
                remediation="Sanitize and encode all user input before including it in responses.",
                port=port, service="http",
            ))
    except Exception:
        pass

    # ── A04: Insecure Design ────────────────────────────────────────

    # OPTIONS method enumeration
    try:
        r = requests.options(base_url, **req_kw)
        allow = r.headers.get("Allow", "")
        risky = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow.upper()]
        if risky:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"OWASP A04: Risky HTTP methods enabled ({', '.join(risky)})",
                description=f"OPTIONS response reveals enabled methods: {allow}",
                module="checks/http",
                remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE).",
                port=port, service="http",
            ))
    except Exception:
        pass

    # TRACE enabled
    try:
        r = requests.request("TRACE", base_url, **req_kw)
        if r.status_code == 200 and "TRACE" in r.text[:500].upper():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="OWASP A04: TRACE method enabled",
                description="The server responds to TRACE requests, which can enable Cross-Site Tracing (XST).",
                module="checks/http",
                remediation="Disable the TRACE HTTP method.",
                port=port, service="http",
            ))
    except Exception:
        pass

    # ── A05: Security Misconfiguration ──────────────────────────────

    # Sensitive file exposure
    sensitive = owasp.get("sensitive_files", [])
    exposed_files = []
    for path in sensitive[:8]:  # limit requests
        try:
            r = requests.get(base_url + path, timeout=10, verify=False,
                             headers=hdrs, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 5:
                exposed_files.append(path)
        except Exception:
            pass
    if exposed_files:
        findings.append(Finding(
            severity=Severity.HIGH,
            title="OWASP A05: Sensitive files exposed",
            description=f"The following sensitive files are publicly accessible: {', '.join(exposed_files)}",
            module="checks/http",
            remediation="Block access to sensitive files via web server configuration.",
            port=port, service="http",
        ))

    # Debug indicators
    debug_indicators = []
    if "X-Debug" in resp_headers or "X-Debug-Token" in resp_headers:
        debug_indicators.append("X-Debug header present")
    debug_body_patterns = ["Django", "Debugger", "FLASK_DEBUG", "WEB_DEBUG", "Whoops!"]
    for pat in debug_body_patterns:
        if pat.lower() in body.lower():
            debug_indicators.append(f"'{pat}' found in response")
            break
    if debug_indicators:
        findings.append(Finding(
            severity=Severity.HIGH,
            title="OWASP A05: Debug mode indicators detected",
            description=f"Debug indicators found: {'; '.join(debug_indicators)}",
            module="checks/http",
            remediation="Disable debug mode in production environments.",
            port=port, service="http",
        ))

    # ── A06: Vulnerable & Outdated Components ──────────────────────

    # CMS detection from body
    cms_patterns = [
        (r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)', "WordPress"),
        (r'<meta[^>]+generator[^>]+Drupal\s*([\d.]+)', "Drupal"),
        (r'<meta[^>]+generator[^>]+Joomla[^\d]*([\d.]+)', "Joomla"),
    ]
    for pattern, cms_name in cms_patterns:
        m = re.search(pattern, body, re.I)
        if m:
            ver = m.group(1)
            findings.append(Finding(
                severity=Severity.LOW,
                title=f"OWASP A06: {cms_name} version detected ({ver})",
                description=f"{cms_name} {ver} detected via meta generator tag.",
                module="checks/http",
                remediation=f"Keep {cms_name} updated and remove version info from HTML.",
                port=port, service="http",
            ))
            break

    # ── A07: Identification & Authentication Failures ──────────────

    login_indicators = ["login", "log in", "sign in", "username", "password"]
    has_login = any(kw in body.lower() for kw in login_indicators)
    if has_login:
        if not is_https:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="OWASP A07: Login form over unencrypted HTTP",
                description="A login form was detected on a page served over HTTP (no TLS).",
                module="checks/http",
                remediation="Serve login pages exclusively over HTTPS.",
                port=port, service="http",
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                title="OWASP A07: Login form detected",
                description="A login form was detected. Verify it is protected against brute force and enumeration.",
                module="checks/http",
                port=port, service="http",
            ))

    # ── A08: Software & Data Integrity ─────────────────────────────

    # SRI check on external scripts
    try:
        parser = _ScriptSrcParser()
        parser.feed(body)
        if parser.scripts_missing_sri:
            scripts_sample = parser.scripts_missing_sri[:5]
            findings.append(Finding(
                severity=Severity.LOW,
                title="OWASP A08: External scripts without Subresource Integrity",
                description=f"{len(parser.scripts_missing_sri)} external script(s) lack SRI: {', '.join(scripts_sample)}",
                module="checks/http",
                remediation="Add integrity attributes to external script tags for Subresource Integrity.",
                port=port, service="http",
            ))
    except Exception:
        pass

    return findings
