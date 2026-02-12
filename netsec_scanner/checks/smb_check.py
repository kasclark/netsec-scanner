"""SMB security checks using smbclient subprocess."""

import subprocess
import shutil
from typing import List

from netsec_scanner import Finding, Severity


def check_smb(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check SMB service for security issues."""
    findings = []

    smbclient = shutil.which("smbclient")
    if not smbclient:
        findings.append(Finding(
            severity=Severity.INFO,
            title="SMB check limited — smbclient not installed",
            description="Install smbclient for full SMB security checks.",
            module="checks/smb",
            port=port,
            service="smb",
        ))
        # Still do basic socket check
        return findings + _basic_smb_check(ip, port)

    # Test null session / anonymous access
    try:
        result = subprocess.run(
            [smbclient, "-L", f"//{ip}", "-N", "-p", str(port)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="SMB null session allowed",
                description=f"The SMB server at {ip}:{port} allows anonymous/null session listing of shares.",
                module="checks/smb",
                remediation="Disable null sessions: set 'restrict anonymous = 2' or equivalent.",
                port=port,
                service="smb",
                details={"shares": result.stdout[:500]},
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass

    # Test guest access
    try:
        result = subprocess.run(
            [smbclient, "-L", f"//{ip}", "-U", "guest%", "-p", str(port)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and "Sharename" in result.stdout:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="SMB guest access allowed",
                description="The SMB server allows guest access to list shares.",
                module="checks/smb",
                remediation="Disable guest access in SMB configuration.",
                port=port,
                service="smb",
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass

    # Check for SMBv1 using smbclient
    try:
        result = subprocess.run(
            [smbclient, "-L", f"//{ip}", "-N", "-m", "NT1", "-p", str(port)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="SMBv1 (NT LM 0.12) enabled",
                description="SMBv1 is enabled. This protocol has critical vulnerabilities including EternalBlue (MS17-010).",
                module="checks/smb",
                remediation="Disable SMBv1 immediately. Use SMBv2 or SMBv3 only.",
                port=port,
                service="smb",
            ))
    except (subprocess.TimeoutExpired, Exception):
        pass

    return findings


def _basic_smb_check(ip: str, port: int) -> List[Finding]:
    """Basic SMB check via raw socket."""
    import socket
    findings = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((ip, port))
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"SMB service accessible on port {port}",
                description="SMB service is reachable. Install smbclient for detailed security checks.",
                module="checks/smb",
                port=port,
                service="smb",
            ))
    except Exception:
        pass
    return findings
