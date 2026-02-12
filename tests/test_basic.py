"""Basic tests — imports, data files, models."""

import json
import os
import pytest

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "netsec_scanner", "data")


class TestImports:
    def test_main_package(self):
        from netsec_scanner import __version__, Severity, Finding, HostResult
        assert __version__ == "1.0.0"

    def test_cli_import(self):
        from netsec_scanner.cli import cli
        assert cli is not None

    def test_scanner_import(self):
        from netsec_scanner.scanner import NetworkScanner
        assert NetworkScanner is not None

    def test_report_import(self):
        from netsec_scanner.report import generate_report
        assert generate_report is not None

    def test_discovery_imports(self):
        from netsec_scanner.discovery.port_scan import scan_ports
        from netsec_scanner.discovery.banner_grab import grab_banners

    def test_vulns_imports(self):
        from netsec_scanner.vulns.nvd_lookup import lookup_cves
        from netsec_scanner.vulns.cisa_kev import check_kev

    def test_checks_imports(self):
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


class TestDataFiles:
    def test_default_creds_valid_json(self):
        with open(os.path.join(DATA_DIR, "default_creds.json")) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 30
        for entry in data:
            assert "service" in entry
            assert "username" in entry
            assert "password" in entry

    def test_weak_ssh_algos_valid_json(self):
        with open(os.path.join(DATA_DIR, "weak_ssh_algos.json")) as f:
            data = json.load(f)
        assert "kex" in data
        assert "ciphers" in data
        assert "macs" in data
        assert "host_keys" in data

    def test_security_headers_valid_json(self):
        with open(os.path.join(DATA_DIR, "security_headers.json")) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 7
        for entry in data:
            assert "header" in entry
            assert "severity_if_missing" in entry


class TestModels:
    def test_finding_creation(self):
        from netsec_scanner import Finding, Severity
        f = Finding(
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test finding",
            module="test",
            port=80,
            service="http",
        )
        assert f.severity == Severity.HIGH
        assert f.port == 80

    def test_host_result(self):
        from netsec_scanner import HostResult, Finding, Severity
        h = HostResult(ip="192.168.1.1")
        h.findings.append(Finding(
            severity=Severity.HIGH, title="Test", description="Test", module="test"
        ))
        h.findings.append(Finding(
            severity=Severity.LOW, title="Test2", description="Test2", module="test"
        ))
        assert h.finding_counts["HIGH"] == 1
        assert h.finding_counts["LOW"] == 1
        h.calculate_risk()
        assert h.risk_score == Severity.HIGH

    def test_host_result_empty(self):
        from netsec_scanner import HostResult, Severity
        h = HostResult(ip="10.0.0.1")
        h.calculate_risk()
        assert h.risk_score == Severity.INFO


class TestCLI:
    def test_cli_help(self):
        from click.testing import CliRunner
        from netsec_scanner.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "netsec-scanner" in result.output

    def test_scan_help(self):
        from click.testing import CliRunner
        from netsec_scanner.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--ports" in result.output
        assert "--deep" in result.output
        assert "--i-own-this" in result.output
