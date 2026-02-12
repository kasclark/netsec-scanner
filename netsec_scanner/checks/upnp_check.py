"""UPnP/SSDP security checks."""

import socket
from typing import List

import requests

from netsec_scanner import Finding, Severity

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def check_upnp(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check for UPnP/SSDP services."""
    findings = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(SSDP_SEARCH.encode(), (ip, SSDP_PORT))

            responses = []
            try:
                while True:
                    data, addr = s.recvfrom(4096)
                    if addr[0] == ip:
                        responses.append(data.decode("utf-8", errors="replace"))
            except socket.timeout:
                pass

            if responses:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"UPnP/SSDP active on {ip}",
                    description=f"UPnP is enabled and responding to SSDP discovery. "
                                f"Found {len(responses)} service(s). UPnP can expose internal services to the network.",
                    module="checks/upnp",
                    remediation="Disable UPnP unless explicitly needed. UPnP can be exploited for port forwarding abuse.",
                    port=1900,
                    service="upnp",
                ))

                # Try to fetch device descriptions
                for resp in responses[:5]:
                    for line in resp.splitlines():
                        if line.upper().startswith("LOCATION:"):
                            url = line.split(":", 1)[1].strip()
                            try:
                                desc = requests.get(url, timeout=3)
                                if desc.status_code == 200:
                                    findings.append(Finding(
                                        severity=Severity.INFO,
                                        title=f"UPnP device description: {url}",
                                        description=desc.text[:300],
                                        module="checks/upnp",
                                        port=1900,
                                        service="upnp",
                                    ))
                            except Exception:
                                pass
                            break

    except Exception:
        pass

    return findings
