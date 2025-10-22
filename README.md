# 🔒 VulnScan Pro - Professional Bug Bounty Scanner

A comprehensive vulnerability scanner for bug bounty hunting.

## Features
- SQL Injection detection
- XSS detection
- CSRF detection
- XXE detection
- SSRF detection
- RCE detection
- Path traversal detection
- Professional reports (Text/JSON/HTML)

## Installation
```bash
go build -o vulnscan_pro vulnscan_pro.go
sudo cp vulnscan_pro /usr/local/bin/
```

## Usage
```bash
vulnscan_pro -url https://target.com
vulnscan_pro -url https://target.com -json report.json -html report.html
```

## License
MIT
