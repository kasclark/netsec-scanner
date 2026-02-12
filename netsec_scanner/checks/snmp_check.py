"""SNMP security checks."""

import socket
import struct
from typing import List

from netsec_scanner import Finding, Severity

DEFAULT_COMMUNITIES = ["public", "private", "community", "default", "admin", "snmp"]


def check_snmp(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check SNMP service for default community strings and version."""
    findings = []

    for community in DEFAULT_COMMUNITIES:
        try:
            response = _snmp_get(ip, port, community)
            if response:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"SNMP default community string: '{community}'",
                    description=f"The SNMP service responds to the default community string '{community}'. "
                                "This allows unauthorized read access to device information.",
                    module="checks/snmp",
                    remediation=f"Change the SNMP community string from '{community}' to a strong, unique value. "
                                "Consider migrating to SNMPv3 with authentication and encryption.",
                    port=port,
                    service="snmp",
                    details={"community": community, "response": response[:200]},
                ))
                break  # Found one, no need to continue
        except Exception:
            pass

    # SNMPv1/v2c warning
    findings.append(Finding(
        severity=Severity.MEDIUM,
        title="SNMP v1/v2c detected (no encryption)",
        description="SNMPv1 and v2c transmit community strings in cleartext and lack authentication.",
        module="checks/snmp",
        remediation="Upgrade to SNMPv3 with authentication (authPriv) and encryption.",
        port=port,
        service="snmp",
    ))

    return findings


def _snmp_get(ip: str, port: int, community: str, timeout: float = 3.0) -> str:
    """Send SNMPv2c GET request for sysDescr.0 and return response string."""
    # Build SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0)
    oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])  # OID
    null_val = bytes([0x05, 0x00])  # NULL
    varbind = bytes([0x30, len(oid) + len(null_val)]) + oid + null_val
    varbind_list = bytes([0x30, len(varbind)]) + varbind

    request_id = bytes([0x02, 0x01, 0x01])  # INTEGER 1
    error_status = bytes([0x02, 0x01, 0x00])
    error_index = bytes([0x02, 0x01, 0x00])

    pdu_content = request_id + error_status + error_index + varbind_list
    pdu = bytes([0xa0, len(pdu_content)]) + pdu_content  # GetRequest PDU

    version = bytes([0x02, 0x01, 0x01])  # INTEGER 1 (SNMPv2c)
    comm = community.encode()
    comm_tlv = bytes([0x04, len(comm)]) + comm

    message_content = version + comm_tlv + pdu
    message = bytes([0x30, len(message_content)]) + message_content

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(message, (ip, port))
        data = s.recv(4096)
        return data.hex()[:200] if data else ""
