"""Port scanning via nmap."""

import shutil
from typing import List, Tuple

try:
    import nmap
except ImportError:
    nmap = None


def scan_ports(ip: str, ports: str = "top-1000", deep: bool = False,
               is_root: bool = False, timeout: int = 300) -> Tuple[List[dict], str]:
    """Run nmap scan. Returns (list of port dicts, os_guess string)."""
    if nmap is None or not shutil.which("nmap"):
        return [], ""

    nm = nmap.PortScanner()

    # Build arguments — do fast scan first, version detection separately
    if is_root:
        args = "-sS"  # SYN scan (fast)
        if deep:
            args += " -O --script=default"
    else:
        args = "-sT"  # Connect scan (no root)

    # Port specification
    if ports == "top-100":
        args += " --top-ports 100"
    elif ports == "top-1000":
        args += " --top-ports 1000"
    elif ports == "all":
        args += " -p-"
    else:
        args += f" -p {ports}"

    args += f" --host-timeout {timeout}s"
    args += " -T4"  # Aggressive timing

    try:
        nm.scan(ip, arguments=args)
    except nmap.PortScannerError:
        return [], ""
    except Exception:
        return [], ""

    if ip not in nm.all_hosts():
        return [], ""

    port_list = []
    for proto in nm[ip].all_protocols():
        for port in sorted(nm[ip][proto].keys()):
            info = nm[ip][proto][port]
            if info.get("state") == "open":
                port_list.append({
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state", ""),
                    "service": info.get("name", ""),
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                    "extra": info.get("extrainfo", ""),
                })

    os_guess = ""
    if "osmatch" in nm[ip]:
        matches = nm[ip]["osmatch"]
        if matches:
            os_guess = matches[0].get("name", "")

    # Phase 2: Targeted version detection on open ports (only in deep mode)
    if port_list and deep:
        open_ports = ",".join(str(p["port"]) for p in port_list)
        try:
            ver_args = f"-sV --version-intensity 2 -p {open_ports} --host-timeout {timeout}s -T4"
            if is_root:
                ver_args = f"-sS " + ver_args
            nm2 = nmap.PortScanner()
            nm2.scan(ip, arguments=ver_args)
            if ip in nm2.all_hosts():
                for proto in nm2[ip].all_protocols():
                    for port in nm2[ip][proto].keys():
                        info = nm2[ip][proto][port]
                        if info.get("state") == "open":
                            version = f"{info.get('product', '')} {info.get('version', '')}".strip()
                            extra = info.get("extrainfo", "")
                            for p in port_list:
                                if p["port"] == port and p["protocol"] == proto:
                                    if version:
                                        p["version"] = version
                                    if extra:
                                        p["extra"] = extra
                                    if info.get("name"):
                                        p["service"] = info["name"]
                                    break
        except Exception:
            pass  # Fall back to banner grabbing

    return port_list, os_guess
