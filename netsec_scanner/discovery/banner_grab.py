"""Raw socket banner grabbing."""

import socket
from typing import List


def grab_banners(ip: str, ports: List[dict], timeout: float = 3.0):
    """Supplement port list with banner info where version is missing."""
    for p in ports:
        if p.get("version"):
            continue
        port_num = p.get("port", 0)
        proto = p.get("protocol", "tcp")
        if proto != "tcp":
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port_num))
                # Some services send banner on connect
                s.sendall(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                if banner:
                    p["version"] = banner[:128]
        except Exception:
            pass
