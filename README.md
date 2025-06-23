# Toolkit
A pure ethical hacking utility tool with over 15+ security assessment features, designed for penetration testers, security researchers, and developers.

## Features

**Network Analysis**
- IP information lookup (ISP, ASN, geo-data)
- Port scanning with service detection
- Reverse DNS lookup
- WHOIS domain/IP lookup
- DNS record analysis (A, MX, TXT, etc.)
- Subdomain enumeration

**Web Security**
- HTTP header analysis
- Security header checker
- CORS configuration tester
- HTTP methods checker
- robots.txt scanner
- Web technology detection
- SSL/TLS certificate inspection

**Privacy & Security**
- Password strength analyzer
- Password generator
- Hash generator (MD5, SHA1, SHA256, etc.)
- Base64 encoder/decoder
- Breach checker (simulated)
- DNS/IP leak tests

**Utilities**
- Live command logging
- Color-coded output
- Interactive help system
- Cross-platform support

## Installation

1. **Requirements**:
   - Python 3.6+
   - Required packages: `requests`, `python-whois`, `ipwhois`, `dnspython`, `pyOpenSSL`, `cryptography`

2. **Install dependencies**:
   ```bash
   pip install requests python-whois ipwhois dnspython pyOpenSSL cryptography
   ```

3. **Download the tool**:
   ```bash
   git clone https://github.com/starexx/toolkit.git
   cd toolkit
   ```

## Usage

Run the tool:
```bash
python cli.py
```

### Example Commands

1. **IP Information**:
   ```bash
   starexx@root ~$ ipinfo 8.8.8.8
   ```

2. **Port Scanning**:
   ```bash
   starexx@root ~$ portscan 192.168.1.1 80-100
   ```

3. **Web Security Analysis**:
   ```bash
   starexx@root ~$ httpheaders https://example.com
   starexx@root ~$ analyze https://example.com
   starexx@root ~$ cors https://example.com
   ```

4. **DNS Tools**:
   ```bash
   starexx@root ~$ dns example.com MX
   starexx@root ~$ subdomain example.com
   ```

5. **Password Tools**:
   ```bash
   starexx@root ~$ pwdgen 16 4
   starexx@root ~$ pwdstrength MyP@ssw0rd!
   ```

6. **View Command History**:
   ```bash
   starexx@root ~$ tracklog --live
   ```

## Command Reference

| Command | Description |
|---------|-------------|
| `ipinfo <ip>` | Get detailed IP information |
| `portscan <ip> <start>-<end>` | Scan ports on target IP |
| `httpheaders <url>` | Fetch HTTP headers |
| `whois <domain/ip>` | WHOIS lookup |
| `geoip <ip>` | Geolocation data |
| `dns <domain> [type]` | DNS record lookup |
| `subdomain <domain>` | Subdomain enumeration |
| `analyze <url>` | Security header analysis |
| `pwdgen [len] [complexity]` | Generate strong password |
| `tracklog [--live]` | View command history |

Full command list available via `help` in the tool.

## License & Disclaimer
This project released under MIT License and this tool is for **educational and ethical testing purposes only**. Always obtain proper authorization before scanning or testing any network or system.
