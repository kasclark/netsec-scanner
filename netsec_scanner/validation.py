"""Input validation helpers for scan targets and port specifications."""

import ipaddress
import re
import socket
from typing import List

DEFAULT_MAX_HOSTS = 256
PORT_PRESETS = {"top-100", "top-1000", "all"}
_PORT_TOKEN = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")


def normalize_ports(ports: str) -> str:
    """Validate and normalize a user-supplied nmap port specification."""
    if not ports:
        raise ValueError("Port specification cannot be empty.")

    ports = ports.strip()
    if ports in PORT_PRESETS:
        return ports

    tokens = []
    for raw_token in ports.split(","):
        token = raw_token.strip()
        if not _PORT_TOKEN.match(token):
            raise ValueError(
                "Invalid port specification. Use top-100, top-1000, all, "
                "or comma-separated ports/ranges such as 22,80,443,8000-8100."
            )

        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"Invalid port range '{token}': start must be <= end.")
            if start < 1 or end > 65535:
                raise ValueError(f"Invalid port range '{token}': ports must be 1-65535.")
        else:
            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port '{token}': ports must be 1-65535.")

        tokens.append(token)

    return ",".join(tokens)


def resolve_targets(target: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> List[str]:
    """Resolve a target string to IPs, refusing accidental large-network scans."""
    if not target or not target.strip():
        raise ValueError("Target cannot be empty.")

    target = target.strip()
    try:
        network = ipaddress.ip_network(target, strict=False)
        usable_hosts = network.num_addresses if network.num_addresses <= 2 else network.num_addresses - 2
        if usable_hosts > max_hosts:
            raise ValueError(
                f"Target expands to {usable_hosts} hosts, which exceeds --max-hosts={max_hosts}. "
                "Use a narrower CIDR or raise --max-hosts if you are authorized to scan it."
            )
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError as exc:
        if "exceeds --max-hosts" in str(exc):
            raise

    try:
        ip = socket.gethostbyname(target)
        return [ip]
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target '{target}'.") from exc
