import pytest

from netsec_scanner import Finding, HostResult, Severity
from netsec_scanner.report import generate_report
from netsec_scanner.validation import normalize_ports, resolve_targets


class TestPortValidation:
    def test_accepts_presets_and_valid_ranges(self):
        assert normalize_ports("top-100") == "top-100"
        assert normalize_ports("top-1000") == "top-1000"
        assert normalize_ports("all") == "all"
        assert normalize_ports(" 22, 80, 8000-8100 ") == "22,80,8000-8100"

    @pytest.mark.parametrize("ports", ["", "0", "65536", "80-22", "22 --script vuln", "22, -sV"])
    def test_rejects_invalid_or_option_injection_ports(self, ports):
        with pytest.raises(ValueError):
            normalize_ports(ports)


class TestTargetValidation:
    def test_resolves_single_ip_without_dns(self):
        assert resolve_targets("192.0.2.10") == ["192.0.2.10"]

    def test_rejects_large_cidr_by_default(self):
        with pytest.raises(ValueError, match="exceeds --max-hosts"):
            resolve_targets("10.0.0.0/16")


class TestReportEscaping:
    def _malicious_result(self):
        host = HostResult(
            ip="192.0.2.10",
            hostname="<script>alert(1)</script>",
            os_guess="<b>FakeOS</b>",
        )
        host.ports.append({
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "version": "Apache | <img src=x onerror=alert(1)>",
        })
        host.findings.append(Finding(
            severity=Severity.HIGH,
            title="<script>alert(2)</script>",
            description="Injected <img src=x onerror=alert(3)>",
            module="test",
            remediation="Patch | now",
            port=80,
            service="http",
        ))
        host.calculate_risk()
        return [host]

    def test_html_report_escapes_untrusted_scan_output(self):
        report = generate_report(self._malicious_result(), "<script>target</script>", "html")

        assert "<script>alert" not in report
        assert "<img src=x onerror=alert" not in report
        assert "&lt;script&gt;alert" in report
        assert "&lt;img src=x onerror=alert" in report

    def test_markdown_report_escapes_html_and_table_pipes(self):
        report = generate_report(self._malicious_result(), "<script>target</script>", "md")

        assert "<script>alert" not in report
        assert "<img src=x onerror=alert" not in report
        assert "&lt;script&gt;alert" in report
        assert "Apache \\| &lt;img src=x onerror=alert" in report
        assert "Patch \\| now" in report
