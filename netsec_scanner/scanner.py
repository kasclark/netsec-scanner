"""Main scan orchestrator."""

import ipaddress
import socket
from typing import List, Callable, Optional

from netsec_scanner import HostResult, Finding, Severity
from netsec_scanner.discovery.port_scan import scan_ports
from netsec_scanner.discovery.banner_grab import grab_banners
from netsec_scanner.vulns.nvd_lookup import lookup_cves
from netsec_scanner.vulns.cisa_kev import check_kev
from netsec_scanner.checks.ssh_check import check_ssh
from netsec_scanner.checks.http_check import check_http
from netsec_scanner.checks.smb_check import check_smb
from netsec_scanner.checks.ftp_check import check_ftp
from netsec_scanner.checks.telnet_check import check_telnet
from netsec_scanner.checks.dns_check import check_dns
from netsec_scanner.checks.snmp_check import check_snmp
from netsec_scanner.checks.smtp_check import check_smtp
from netsec_scanner.checks.database_check import check_databases
from netsec_scanner.checks.rdp_check import check_rdp
from netsec_scanner.checks.upnp_check import check_upnp

# Map service names / ports to check functions
SERVICE_CHECKS = {
    22: check_ssh,
    80: check_http,
    443: check_http,
    8080: check_http,
    8443: check_http,
    445: check_smb,
    139: check_smb,
    21: check_ftp,
    23: check_telnet,
    53: check_dns,
    161: check_snmp,
    25: check_smtp,
    587: check_smtp,
    465: check_smtp,
    3306: check_databases,
    5432: check_databases,
    6379: check_databases,
    27017: check_databases,
    1433: check_databases,
    3389: check_rdp,
    1900: check_upnp,
}


def resolve_targets(target: str) -> List[str]:
    """Resolve target string to list of IPs."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        pass

    # Hostname or single IP
    try:
        ip = socket.gethostbyname(target)
        return [ip]
    except socket.gaierror:
        return [target]


class NetworkScanner:
    def __init__(self, target: str, ports: str = "top-1000", deep: bool = False,
                 modules: List[str] = None, timeout: int = 300, is_root: bool = False):
        self.target = target
        self.ports = ports
        self.deep = deep
        self.modules = modules or ["discovery", "vulns", "checks"]
        self.timeout = timeout
        self.is_root = is_root

    def run(self, progress_callback: Optional[Callable] = None) -> List[HostResult]:
        def update(pct, msg):
            if progress_callback:
                progress_callback(pct, msg)

        targets = resolve_targets(self.target)
        results = []
        total = len(targets)

        for idx, ip in enumerate(targets):
            base_pct = int((idx / total) * 100)
            host = HostResult(ip=ip)

            # Try reverse DNS
            try:
                host.hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                pass

            # Phase 1: Discovery
            if "discovery" in self.modules:
                update(base_pct + 5, f"[{ip}] Port scanning...")
                port_data, os_guess = scan_ports(ip, self.ports, self.deep, self.is_root, self.timeout)
                host.ports = port_data
                host.os_guess = os_guess

                # Banner grab for ports missing version info
                update(base_pct + 15, f"[{ip}] Banner grabbing...")
                grab_banners(ip, host.ports)

            # Phase 2: Vulnerability lookup
            if "vulns" in self.modules and host.ports:
                update(base_pct + 25, f"[{ip}] CVE lookup...")
                kev_cves = set()
                try:
                    kev_cves = check_kev()
                except Exception:
                    pass

                for p in host.ports:
                    svc = p.get("service", "")
                    ver = p.get("version", "")
                    if svc and ver:
                        try:
                            cves = lookup_cves(svc, ver)
                            for cve in cves:
                                sev = Severity.MEDIUM
                                if cve.get("cvss", 0) >= 9.0:
                                    sev = Severity.CRITICAL
                                elif cve.get("cvss", 0) >= 7.0:
                                    sev = Severity.HIGH
                                elif cve.get("cvss", 0) >= 4.0:
                                    sev = Severity.MEDIUM
                                else:
                                    sev = Severity.LOW

                                # Escalate if in CISA KEV
                                if cve["id"] in kev_cves:
                                    sev = Severity.CRITICAL

                                host.findings.append(Finding(
                                    severity=sev,
                                    title=f"{cve['id']} — {svc} {ver}",
                                    description=cve.get("description", ""),
                                    module="vulns/nvd",
                                    cve=cve["id"],
                                    port=p.get("port", 0),
                                    service=svc,
                                    remediation=f"Update {svc} to latest version. CVSS: {cve.get('cvss', 'N/A')}",
                                    details={"cvss": cve.get("cvss"), "kev": cve["id"] in kev_cves},
                                ))
                        except Exception:
                            pass

            # Phase 3: Service checks
            if "checks" in self.modules and host.ports:
                update(base_pct + 40, f"[{ip}] Running service checks...")
                checked_funcs = set()
                for p in host.ports:
                    port_num = p.get("port", 0)
                    check_fn = SERVICE_CHECKS.get(port_num)
                    if check_fn and id(check_fn) not in checked_funcs:
                        checked_funcs.add(id(check_fn))
                        try:
                            findings = check_fn(ip, port_num, p)
                            host.findings.extend(findings)
                        except Exception:
                            pass

                # Always try UPnP (UDP-based)
                if check_upnp not in [SERVICE_CHECKS.get(p.get("port")) for p in host.ports]:
                    try:
                        host.findings.extend(check_upnp(ip, 1900, {}))
                    except Exception:
                        pass

            host.calculate_risk()
            results.append(host)
            update(base_pct + int(100 / total), f"[{ip}] Complete")

        update(100, "Scan complete")
        return results
