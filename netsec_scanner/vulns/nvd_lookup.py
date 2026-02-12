"""NVD API v2 CVE lookup."""

import time
import requests
from typing import List, Dict

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: Dict[str, List[dict]] = {}
_last_request = 0.0


def lookup_cves(service: str, version: str, max_results: int = 5) -> List[dict]:
    """Search NVD for CVEs matching service+version. Returns list of {id, description, cvss}."""
    key = f"{service} {version}"
    if key in _cache:
        return _cache[key]

    # Rate limiting: 5 requests per 30 seconds without API key
    global _last_request
    elapsed = time.time() - _last_request
    if elapsed < 6:
        time.sleep(6 - elapsed)

    params = {
        "keywordSearch": key,
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(NVD_API, params=params, timeout=30,
                           headers={"User-Agent": "netsec-scanner/1.0"})
        _last_request = time.time()
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        _cache[key] = []
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Get description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Get CVSS score
        cvss = 0.0
        metrics = cve.get("metrics", {})
        for key_name in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key_name, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                break

        results.append({
            "id": cve_id,
            "description": desc[:300],
            "cvss": cvss,
        })

    _cache[f"{service} {version}"] = results
    return results
