"""SMTP security checks."""

import socket
from typing import List

from netsec_scanner import Finding, Severity


def check_smtp(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check SMTP service for security issues."""
    findings = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((ip, port))
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()

            if banner:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"SMTP banner: {banner[:100]}",
                    description=f"SMTP server banner: {banner}",
                    module="checks/smtp",
                    port=port,
                    service="smtp",
                ))

            # EHLO
            s.sendall(b"EHLO netsec-scanner\r\n")
            ehlo_resp = s.recv(2048).decode("utf-8", errors="replace")

            # Check STARTTLS
            if "STARTTLS" in ehlo_resp.upper():
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="SMTP STARTTLS supported",
                    description="The SMTP server supports STARTTLS encryption.",
                    module="checks/smtp",
                    port=port,
                    service="smtp",
                ))
            elif port == 25:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="SMTP STARTTLS not supported",
                    description="The SMTP server on port 25 does not advertise STARTTLS support.",
                    module="checks/smtp",
                    remediation="Enable STARTTLS on the SMTP server.",
                    port=port,
                    service="smtp",
                ))

            # VRFY test
            s.sendall(b"VRFY root\r\n")
            vrfy_resp = s.recv(1024).decode("utf-8", errors="replace").strip()
            if vrfy_resp.startswith("2"):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="SMTP VRFY command enabled",
                    description="The SMTP server allows VRFY commands, which can be used to enumerate valid users.",
                    module="checks/smtp",
                    remediation="Disable VRFY command in SMTP server configuration.",
                    port=port,
                    service="smtp",
                ))

            # Basic open relay test (don't actually send mail)
            s.sendall(b"MAIL FROM:<test@netsec-scanner.local>\r\n")
            mail_resp = s.recv(1024).decode("utf-8", errors="replace").strip()
            if mail_resp.startswith("2"):
                s.sendall(b"RCPT TO:<test@example.com>\r\n")
                rcpt_resp = s.recv(1024).decode("utf-8", errors="replace").strip()
                if rcpt_resp.startswith("2"):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="SMTP open relay detected",
                        description="The SMTP server appears to accept mail for external domains without authentication. "
                                    "This can be abused for spam and phishing.",
                        module="checks/smtp",
                        remediation="Configure SMTP relay restrictions to require authentication.",
                        port=port,
                        service="smtp",
                    ))
                # Reset
                s.sendall(b"RSET\r\n")
                s.recv(1024)

            s.sendall(b"QUIT\r\n")

    except Exception as e:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"SMTP check error on port {port}",
            description=str(e)[:200],
            module="checks/smtp",
            port=port,
            service="smtp",
        ))

    return findings
