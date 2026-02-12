"""FTP security checks."""

import ftplib
from typing import List

from netsec_scanner import Finding, Severity


def check_ftp(ip: str, port: int, port_info: dict) -> List[Finding]:
    """Check FTP service for security issues."""
    findings = []

    # Flag cleartext protocol
    findings.append(Finding(
        severity=Severity.MEDIUM,
        title=f"FTP cleartext protocol on port {port}",
        description="FTP transmits credentials and data in cleartext.",
        module="checks/ftp",
        remediation="Replace FTP with SFTP or FTPS. If FTP is required, ensure STARTTLS is supported.",
        port=port,
        service="ftp",
    ))

    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        banner = ftp.getwelcome()

        if banner:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"FTP banner: {banner[:100]}",
                description=f"FTP server banner: {banner}",
                module="checks/ftp",
                port=port,
                service="ftp",
            ))

        # Try anonymous login
        try:
            ftp.login("anonymous", "test@test.com")
            findings.append(Finding(
                severity=Severity.HIGH,
                title="FTP anonymous login allowed",
                description="The FTP server allows anonymous access, potentially exposing files.",
                module="checks/ftp",
                remediation="Disable anonymous FTP access unless explicitly required.",
                port=port,
                service="ftp",
            ))

            # Try to list files
            try:
                file_list = []
                ftp.retrlines("LIST", file_list.append)
                if file_list:
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"FTP anonymous: {len(file_list)} items visible",
                        description=f"Anonymous user can see {len(file_list)} files/directories.",
                        module="checks/ftp",
                        port=port,
                        service="ftp",
                        details={"files": file_list[:10]},
                    ))
            except Exception:
                pass

        except ftplib.error_perm:
            pass  # Anonymous login rejected — good

        # Check STARTTLS support
        try:
            ftp.sendcmd("AUTH TLS")
            findings.append(Finding(
                severity=Severity.INFO,
                title="FTP STARTTLS supported",
                description="The FTP server supports STARTTLS encryption.",
                module="checks/ftp",
                port=port,
                service="ftp",
            ))
        except ftplib.error_perm:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="FTP STARTTLS not supported",
                description="The FTP server does not support STARTTLS, all traffic is cleartext.",
                module="checks/ftp",
                remediation="Enable STARTTLS/FTPS on the FTP server.",
                port=port,
                service="ftp",
            ))
        except Exception:
            pass

        ftp.quit()
    except Exception as e:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"FTP connection error on port {port}",
            description=str(e)[:200],
            module="checks/ftp",
            port=port,
            service="ftp",
        ))

    return findings
