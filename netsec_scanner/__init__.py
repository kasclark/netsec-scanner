"""netsec-scanner — Network device security scanner."""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List

__version__ = "1.0.0"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    module: str
    remediation: str = ""
    details: dict = field(default_factory=dict)
    cve: str = ""
    port: int = 0
    service: str = ""


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    ports: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    risk_score: Severity = Severity.INFO

    @property
    def finding_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def calculate_risk(self):
        """Set risk_score to the highest severity finding."""
        if not self.findings:
            self.risk_score = Severity.INFO
            return
        best = Severity.INFO
        for f in self.findings:
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[best]:
                best = f.severity
        self.risk_score = best
