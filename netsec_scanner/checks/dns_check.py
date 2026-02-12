"""DNS security checks."""

import socket
import struct
import subprocess
import shutil
from typing import List

from netsec_scanner import Finding, Severity


def check_dns(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check DNS service for security issues."""
    findings = []

    # Zone transfer attempt (AXFR)
    dig = shutil.which("dig")
    if dig:
        try:
            result = subprocess.run(
                [dig, f"@{ip}", "AXFR", ".", "+short", "+time=5", "+tries=1"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip() and "Transfer failed" not in result.stdout:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="DNS zone transfer (AXFR) allowed",
                    description="The DNS server allows zone transfers, which can expose all DNS records.",
                    module="checks/dns",
                    remediation="Restrict zone transfers to authorized secondary DNS servers only.",
                    port=port,
                    service="dns",
                ))
        except (subprocess.TimeoutExpired, Exception):
            pass

    # Open resolver check
    try:
        # Build a DNS query for google.com A record with recursion desired
        query = _build_dns_query("google.com", recurse=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(query, (ip, port))
            response = s.recv(1024)
            if len(response) > 12:
                flags = struct.unpack("!H", response[2:4])[0]
                rcode = flags & 0x0F
                answer_count = struct.unpack("!H", response[6:8])[0]
                if rcode == 0 and answer_count > 0:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="DNS open resolver detected",
                        description="The DNS server responds to recursive queries from external sources. "
                                    "Open resolvers can be abused for DNS amplification attacks.",
                        module="checks/dns",
                        remediation="Restrict recursive queries to trusted networks only.",
                        port=port,
                        service="dns",
                    ))
    except Exception:
        pass

    # Version query (version.bind)
    try:
        query = _build_dns_query("version.bind", qtype=16, qclass=3)  # TXT, CH
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(query, (ip, port))
            response = s.recv(1024)
            if len(response) > 12:
                answer_count = struct.unpack("!H", response[6:8])[0]
                if answer_count > 0:
                    # Try to extract version string
                    version_str = _extract_txt(response)
                    if version_str:
                        findings.append(Finding(
                            severity=Severity.LOW,
                            title=f"DNS version disclosed: {version_str}",
                            description=f"The DNS server reveals its version: {version_str}",
                            module="checks/dns",
                            remediation="Hide the DNS server version (e.g., 'version none;' in BIND config).",
                            port=port,
                            service="dns",
                        ))
    except Exception:
        pass

    return findings


def _build_dns_query(name: str, qtype: int = 1, qclass: int = 1, recurse: bool = False) -> bytes:
    """Build a minimal DNS query packet."""
    import random
    txid = random.randint(0, 65535)
    flags = 0x0100 if recurse else 0x0000
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)

    qname = b""
    for part in name.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"

    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question


def _extract_txt(response: bytes) -> str:
    """Try to extract TXT record from DNS response."""
    try:
        # Skip header (12 bytes) and question section
        offset = 12
        # Skip question
        while offset < len(response) and response[offset] != 0:
            offset += response[offset] + 1
        offset += 5  # null byte + qtype + qclass

        # Skip to answer data
        # Answer: name(2 ptr) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
        offset += 2 + 2 + 2 + 4  # name ptr + type + class + ttl
        rdlen = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2
        if rdlen > 1:
            txt_len = response[offset]
            txt = response[offset+1:offset+1+txt_len].decode("utf-8", errors="replace")
            return txt
    except Exception:
        pass
    return ""
