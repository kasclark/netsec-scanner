# netsec-scanner

**Network device security scanner with automated vulnerability assessment.**

A comprehensive CLI tool for assessing the security posture of network devices, services, and infrastructure. Performs port scanning, service detection, CVE lookup, and protocol-specific security checks with professional report generation.

## ⚠️ Legal Disclaimer

**Only scan networks and systems you own or have explicit written authorization to test.** Unauthorized scanning is illegal in most jurisdictions and may violate computer fraud laws (CFAA, Computer Misuse Act, etc.). The authors accept no liability for misuse.

## Features

- **Port Scanning** — SYN/connect scanning via nmap with service and OS detection
- **CVE Lookup** — Automated vulnerability search via NVD API + CISA KEV catalog
- **SSH Analysis** — Key exchange, cipher, MAC, and host key algorithm auditing
- **HTTP/TLS Security** — TLS version, certificate, security headers, server info leak detection
- **SMB Checks** — SMBv1, null sessions, guest access, signing requirements
- **FTP/Telnet** — Cleartext protocol detection, anonymous access, banner grabbing
- **DNS Security** — Zone transfer, open resolver, version disclosure checks
- **SNMP Auditing** — Default community strings, protocol version analysis
- **SMTP Checks** — Open relay testing, STARTTLS, VRFY enumeration
- **Database Security** — Default credentials and unauthenticated access for MySQL, PostgreSQL, Redis, MongoDB, MSSQL
- **RDP Analysis** — NLA detection, exposure assessment
- **UPnP Discovery** — SSDP enumeration of exposed services
- **Professional Reports** — Markdown, HTML, and JSON output formats

## Requirements

- **Python** 3.8+
- **nmap** must be installed on the system (`apt install nmap` / `brew install nmap`)
- Root/sudo recommended for SYN scanning and OS detection

## Installation

```bash
git clone https://github.com/kasclark/netsec-scanner.git
cd netsec-scanner
pip install -e .
```

Or without installing:

```bash
pip install -r requirements.txt
python -m netsec_scanner.cli scan <target>
```

## Usage

### Single Host Scan

```bash
netsec-scanner scan 192.168.1.1 --i-own-this
```

### Subnet Scan

```bash
sudo netsec-scanner scan 192.168.1.0/24 --i-own-this
```

### Deep Scan (All Ports + OS Detection)

```bash
sudo netsec-scanner scan 192.168.1.1 --deep --i-own-this
```

### Custom Port Range

```bash
netsec-scanner scan 192.168.1.1 --ports 22,80,443,8080 --i-own-this
```

### Specific Modules Only

```bash
netsec-scanner scan 192.168.1.1 --modules discovery,checks --i-own-this
```

### Generate Reports

```bash
# Markdown report
netsec-scanner scan 192.168.1.1 --format md -o report.md --i-own-this

# HTML report (professional format with CSS)
netsec-scanner scan 192.168.1.1 --format html -o report.html --i-own-this

# JSON (for automation)
netsec-scanner scan 192.168.1.1 --format json -o report.json --i-own-this
```

## Modules

| Module | Description |
|--------|-------------|
| `discovery/port_scan` | nmap-based port scanning with service detection |
| `discovery/banner_grab` | Raw socket banner grabbing supplement |
| `vulns/nvd_lookup` | NVD API v2 CVE search by service+version |
| `vulns/cisa_kev` | CISA Known Exploited Vulnerabilities cross-reference |
| `checks/ssh_check` | SSH algorithm and configuration auditing |
| `checks/http_check` | HTTP/HTTPS security headers and TLS analysis |
| `checks/smb_check` | SMB protocol security assessment |
| `checks/ftp_check` | FTP anonymous access and encryption checks |
| `checks/telnet_check` | Telnet cleartext protocol detection |
| `checks/dns_check` | DNS zone transfer and resolver checks |
| `checks/snmp_check` | SNMP community string and version checks |
| `checks/smtp_check` | SMTP relay and enumeration checks |
| `checks/database_check` | Database default credential testing |
| `checks/rdp_check` | RDP NLA and exposure assessment |
| `checks/upnp_check` | UPnP/SSDP service discovery |

## Severity Levels

| Level | Description |
|-------|-------------|
| **CRITICAL** | Actively exploited or trivially exploitable (telnet, open databases, KEV CVEs) |
| **HIGH** | Significant risk requiring immediate attention (anonymous access, missing NLA) |
| **MEDIUM** | Moderate risk (cleartext protocols, missing headers, weak config) |
| **LOW** | Minor issues (info leakage, deprecated features) |
| **INFO** | Informational (banners, versions, supported features) |

## License

MIT
