"""RDP security checks."""

import socket
import struct
from typing import List

from netsec_scanner import Finding, Severity


def check_rdp(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check RDP service for security issues."""
    findings = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((ip, port))

            findings.append(Finding(
                severity=Severity.MEDIUM,
                title=f"RDP service exposed on port {port}",
                description="Remote Desktop Protocol is accessible from the network. "
                            "RDP is a common target for brute-force and credential stuffing attacks.",
                module="checks/rdp",
                remediation="Restrict RDP access via VPN or firewall. Enable Network Level Authentication (NLA). "
                            "Use strong passwords and account lockout policies.",
                port=port,
                service="rdp",
            ))

            # Send RDP negotiation request to detect NLA
            # X.224 Connection Request with NLA (CredSSP)
            cookie = b"Cookie: mstshash=netsec\r\n"
            neg_req = struct.pack("<BBH", 0x01, 0x00, 0x08) + struct.pack("<I", 0x03)  # PROTOCOL_SSL | PROTOCOL_HYBRID
            x224_data = cookie + neg_req
            x224_header = bytes([len(x224_data) + 6, 0xe0, 0x00, 0x00, 0x00, 0x00])

            tpkt = struct.pack("!BBH", 3, 0, len(x224_header) + len(x224_data) + 4)
            s.sendall(tpkt + x224_header + x224_data)

            resp = s.recv(1024)
            if len(resp) > 11:
                # Check negotiation response
                # Look for PROTOCOL_HYBRID (NLA) support
                if len(resp) >= 19:
                    neg_type = resp[11]
                    if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                        selected_protocol = struct.unpack("<I", resp[15:19])[0] if len(resp) >= 19 else 0
                        if selected_protocol & 0x02:  # PROTOCOL_HYBRID (NLA)
                            findings.append(Finding(
                                severity=Severity.INFO,
                                title="RDP NLA (Network Level Authentication) supported",
                                description="The RDP server supports NLA/CredSSP.",
                                module="checks/rdp",
                                port=port,
                                service="rdp",
                            ))
                        elif selected_protocol == 0:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="RDP without NLA — classic RDP security",
                                description="The RDP server does not require NLA. This allows connection before authentication, "
                                            "increasing the attack surface (e.g., BlueKeep CVE-2019-0708).",
                                module="checks/rdp",
                                remediation="Enable Network Level Authentication (NLA) on the RDP server.",
                                port=port,
                                service="rdp",
                            ))
                    elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="RDP NLA not supported",
                            description="The RDP server rejected NLA negotiation, suggesting NLA is not enabled.",
                            module="checks/rdp",
                            remediation="Enable Network Level Authentication (NLA) on the RDP server.",
                            port=port,
                            service="rdp",
                        ))

    except socket.timeout:
        pass
    except Exception as e:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"RDP check error on port {port}",
            description=str(e)[:200],
            module="checks/rdp",
            port=port,
            service="rdp",
        ))

    return findings
