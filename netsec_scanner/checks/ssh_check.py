"""SSH security checks using paramiko."""

import json
import os
from typing import List

from netsec_scanner import Finding, Severity

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _load_weak_algos():
    path = os.path.join(DATA_DIR, "weak_ssh_algos.json")
    with open(path) as f:
        return json.load(f)


def check_ssh(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check SSH service for security issues."""
    findings = []

    try:
        import paramiko
    except ImportError:
        findings.append(Finding(
            severity=Severity.INFO,
            title="SSH check skipped — paramiko not installed",
            description="Install paramiko to enable SSH security checks.",
            module="checks/ssh",
            port=port,
            service="ssh",
        ))
        return findings

    weak_algos = _load_weak_algos()
    transport = None

    try:
        sock = paramiko.Transport((ip, port))
        sock.connect()
        transport = sock

        # Get security options
        sec_opts = transport.get_security_options()

        # Check key exchange algorithms
        for kex in sec_opts.kex:
            if kex in weak_algos.get("kex", []):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Weak SSH key exchange: {kex}",
                    description=f"The SSH server supports weak key exchange algorithm '{kex}'.",
                    module="checks/ssh",
                    remediation=f"Disable {kex} in sshd_config KexAlgorithms directive.",
                    port=port,
                    service="ssh",
                ))

        # Check ciphers
        for cipher in sec_opts.ciphers:
            if cipher in weak_algos.get("ciphers", []):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Weak SSH cipher: {cipher}",
                    description=f"The SSH server supports weak cipher '{cipher}'.",
                    module="checks/ssh",
                    remediation=f"Disable {cipher} in sshd_config Ciphers directive.",
                    port=port,
                    service="ssh",
                ))

        # Check MACs
        for mac in sec_opts.digests:
            if mac in weak_algos.get("macs", []):
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Weak SSH MAC: {mac}",
                    description=f"The SSH server supports weak MAC algorithm '{mac}'.",
                    module="checks/ssh",
                    remediation=f"Disable {mac} in sshd_config MACs directive.",
                    port=port,
                    service="ssh",
                ))

        # Check host key types
        for key_type in sec_opts.key_types:
            if key_type in weak_algos.get("host_keys", []):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"Weak SSH host key type: {key_type}",
                    description=f"The SSH server supports deprecated host key type '{key_type}'.",
                    module="checks/ssh",
                    remediation="Remove DSA keys and disable ssh-dss in HostKeyAlgorithms.",
                    port=port,
                    service="ssh",
                ))

        # Check banner for version
        banner = transport.remote_version or ""
        if banner:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"SSH banner: {banner}",
                description=f"SSH server identifies as: {banner}",
                module="checks/ssh",
                port=port,
                service="ssh",
            ))

        # Check if password auth might be enabled
        try:
            transport.auth_none("")
        except paramiko.BadAuthenticationType as e:
            auth_methods = e.allowed_types
            if "password" in auth_methods:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="SSH password authentication enabled",
                    description="The SSH server allows password authentication, which is less secure than key-based auth.",
                    module="checks/ssh",
                    remediation="Set 'PasswordAuthentication no' in sshd_config.",
                    port=port,
                    service="ssh",
                ))
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"SSH auth methods: {', '.join(auth_methods)}",
                description=f"Supported authentication methods: {', '.join(auth_methods)}",
                module="checks/ssh",
                port=port,
                service="ssh",
            ))
        except Exception:
            pass

    except Exception as e:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"SSH check error on port {port}",
            description=str(e)[:200],
            module="checks/ssh",
            port=port,
            service="ssh",
        ))
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass

    return findings
