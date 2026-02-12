"""Telnet security checks."""

import socket
from typing import List

from netsec_scanner import Finding, Severity


def check_telnet(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check telnet service — flag as critical cleartext protocol."""
    findings = []

    findings.append(Finding(
        severity=Severity.CRITICAL,
        title=f"Telnet service active on port {port}",
        description="Telnet transmits all data including credentials in cleartext. "
                    "This protocol should not be used under any circumstances.",
        module="checks/telnet",
        remediation="Disable Telnet and replace with SSH.",
        port=port,
        service="telnet",
    ))

    # Grab banner
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            if banner:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Telnet banner: {banner[:100]}",
                    description=f"Telnet server banner: {banner[:300]}",
                    module="checks/telnet",
                    port=port,
                    service="telnet",
                ))
    except Exception:
        pass

    return findings
