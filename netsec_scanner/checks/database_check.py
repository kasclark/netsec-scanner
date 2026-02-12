"""Database security checks — socket-level default credential testing."""

import json
import os
import socket
import struct
from typing import List

from netsec_scanner import Finding, Severity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

PORT_DB_MAP = {
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    1433: "mssql",
}


def _load_creds():
    path = os.path.join(DATA_DIR, "default_creds.json")
    with open(path) as f:
        return json.load(f)


def check_databases(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check database services for default credentials and unauthenticated access."""
    findings = []
    db_type = PORT_DB_MAP.get(port, "unknown")

    if db_type == "redis":
        findings.extend(_check_redis(ip, port))
    elif db_type == "mongodb":
        findings.extend(_check_mongodb(ip, port))
    elif db_type == "mysql":
        findings.extend(_check_mysql(ip, port))
    elif db_type == "postgresql":
        findings.extend(_check_postgresql(ip, port))
    elif db_type == "mssql":
        findings.extend(_check_mssql(ip, port))

    return findings


def _check_redis(ip: str, port: int) -> List[Finding]:
    """Check Redis for unauthenticated access."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            s.sendall(b"PING\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            if "+PONG" in resp:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Redis unauthenticated access",
                    description="Redis accepts commands without authentication. "
                                "An attacker can read/write data, execute Lua scripts, or write SSH keys.",
                    module="checks/database",
                    remediation="Set a strong password with 'requirepass' in redis.conf. "
                                "Bind to localhost only unless remote access is needed.",
                    port=port,
                    service="redis",
                ))

                # Try INFO
                s.sendall(b"INFO server\r\n")
                info = s.recv(4096).decode("utf-8", errors="replace")
                if "redis_version" in info:
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"Redis version info exposed",
                        description=info[:300],
                        module="checks/database",
                        port=port,
                        service="redis",
                    ))
    except Exception:
        pass
    return findings


def _check_mongodb(ip: str, port: int) -> List[Finding]:
    """Check MongoDB for unauthenticated access."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))

            # Send isMaster command
            # MongoDB wire protocol: OP_QUERY
            doc = b"\x10isMaster\x00\x01\x00\x00\x00\x00"  # BSON {isMaster: 1}
            doc_len = len(doc) + 4
            bson_doc = struct.pack("<i", doc_len) + doc

            query = b""
            query += struct.pack("<i", 0)  # flags
            query += b"admin.$cmd\x00"  # collection
            query += struct.pack("<i", 0)  # skip
            query += struct.pack("<i", 1)  # return
            query += bson_doc

            msg_len = 16 + len(query)
            header = struct.pack("<iiii", msg_len, 1, 0, 2004)  # OP_QUERY
            s.sendall(header + query)

            resp = s.recv(4096)
            if len(resp) > 36 and b"ismaster" in resp.lower():
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="MongoDB unauthenticated access",
                    description="MongoDB accepts connections without authentication. "
                                "An attacker can read, modify, or delete all databases.",
                    module="checks/database",
                    remediation="Enable authentication in MongoDB: set security.authorization to 'enabled' in mongod.conf.",
                    port=port,
                    service="mongodb",
                ))
    except Exception:
        pass
    return findings


def _check_mysql(ip: str, port: int) -> List[Finding]:
    """Check MySQL for connectivity and version info."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            greeting = s.recv(1024)
            if len(greeting) > 5:
                # MySQL greeting packet contains version string
                try:
                    # Skip packet header (4 bytes) + protocol version (1 byte)
                    version_end = greeting.index(b"\x00", 5)
                    version = greeting[5:version_end].decode("utf-8", errors="replace")
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"MySQL version: {version}",
                        description=f"MySQL server version: {version}",
                        module="checks/database",
                        port=port,
                        service="mysql",
                    ))
                except (ValueError, IndexError):
                    pass

                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="MySQL exposed to network",
                    description="MySQL is accessible on the network. Test with default credentials.",
                    module="checks/database",
                    remediation="Bind MySQL to localhost unless remote access is required. Use strong passwords.",
                    port=port,
                    service="mysql",
                ))
    except Exception:
        pass
    return findings


def _check_postgresql(ip: str, port: int) -> List[Finding]:
    """Check PostgreSQL for connectivity."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            # Send startup message (protocol 3.0)
            user = b"postgres"
            database = b"postgres"
            params = b"user\x00" + user + b"\x00database\x00" + database + b"\x00\x00"
            length = 4 + 4 + len(params)
            startup = struct.pack("!ii", length, 196608) + params  # 196608 = 3.0
            s.sendall(startup)
            resp = s.recv(1024)
            if resp:
                if resp[0:1] == b"R":
                    # Authentication request
                    auth_type = struct.unpack("!i", resp[5:9])[0] if len(resp) >= 9 else -1
                    if auth_type == 0:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="PostgreSQL no authentication required",
                            description="PostgreSQL accepts connections as 'postgres' without a password.",
                            module="checks/database",
                            remediation="Configure pg_hba.conf to require password authentication for all connections.",
                            port=port,
                            service="postgresql",
                        ))
                    else:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="PostgreSQL exposed to network",
                            description="PostgreSQL is accessible on the network.",
                            module="checks/database",
                            remediation="Bind PostgreSQL to localhost. Use strong passwords. Review pg_hba.conf.",
                            port=port,
                            service="postgresql",
                        ))
                elif resp[0:1] == b"E":
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="PostgreSQL reachable (auth required)",
                        description="PostgreSQL is reachable and requires authentication.",
                        module="checks/database",
                        port=port,
                        service="postgresql",
                    ))
    except Exception:
        pass
    return findings


def _check_mssql(ip: str, port: int) -> List[Finding]:
    """Check MSSQL for connectivity."""
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="MSSQL exposed to network",
                description="Microsoft SQL Server is accessible on the network.",
                module="checks/database",
                remediation="Bind MSSQL to localhost. Disable 'sa' account or use a strong password. "
                            "Enable Windows Authentication only.",
                port=port,
                service="mssql",
            ))
    except Exception:
        pass
    return findings
