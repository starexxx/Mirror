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
   ```sh
   pip install requests python-whois ipwhois dnspython pyOpenSSL cryptography
   ```

3. **Download the tool**:
   ```sh
   git clone https://github.com/starexx/toolkit.git
   cd toolkit
   ```
3. **Run the tool**:
   ```sh
   python3 cli.py # help 
   ```

## License & Disclaimer
This project released under MIT License and this tool is for **educational and ethical testing purposes only**. Always obtain proper authorization before scanning or testing any network or system.
