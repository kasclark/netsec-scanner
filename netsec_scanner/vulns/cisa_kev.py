"""CISA Known Exploited Vulnerabilities catalog check."""

import requests
from typing import Set

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_kev_cache: Set[str] = set()
_loaded = False


def check_kev() -> Set[str]:
    """Fetch CISA KEV catalog and return set of CVE IDs."""
    global _kev_cache, _loaded
    if _loaded:
        return _kev_cache

    try:
        resp = requests.get(KEV_URL, timeout=30,
                           headers={"User-Agent": "netsec-scanner/1.0"})
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                _kev_cache.add(cve_id)
    except Exception:
        pass

    _loaded = True
    return _kev_cache
