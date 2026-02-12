"""HTTP/HTTPS security checks."""

import json
import os
import re
import ssl
import socket
import datetime
from typing import List

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
