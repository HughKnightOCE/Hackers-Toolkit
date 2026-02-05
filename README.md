# Hackers Toolkit

A professional cybersecurity analysis toolkit with a modern GUI for penetration testing and security auditing.

## Features

### 1. **Port Scanner**
   - Scan specific port ranges
   - Quick scan of common ports
   - Service identification
   - Real-time progress updates

### 2. **DNS Lookup**
   - A Record lookup
   - MX Record lookup
   - NS Record lookup
   - TXT Record lookup
   - Full DNS enumeration

### 3. **IP Geolocation**
   - IP address information
   - Geographic location
   - ISP and ASN information
   - IP reputation checking

### 4. **SSL/TLS Analyzer**
   - Certificate information extraction
   - Certificate validity checking
   - Supported protocol detection
   - Security vulnerability assessment

### 5. **Network Reconnaissance**
   - DNS record enumeration
   - Reverse DNS lookup
   - Host information gathering
   - Subnet scanning

### 6. **Password Analyzer**
   - Password strength evaluation
   - Entropy calculation
   - Character composition analysis
   - Secure password generation

### 7. **Hash Analyzer**
   - Hash type identification (MD5, SHA1, SHA256, SHA512)
   - Rainbow table lookup
   - Batch hash analysis
   - Hash generation utilities

### 8. **Vulnerability Scanner**
   - Port-based vulnerability detection
   - Service vulnerability assessment
   - CVE matching
   - Vulnerability reporting

## Installation

### Requirements
- Python 3.8+
- Windows/Linux/macOS

### Setup

1. Clone or download the toolkit:
```bash
cd "Hackers toolkit"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## Usage

### Basic Port Scan
1. Open the **Port Scanner** tab
2. Enter target hostname or IP address
3. Specify port range (e.g., 1-1000)
4. Click "Scan Ports"

### DNS Enumeration
1. Go to **DNS Lookup** tab
2. Enter domain name
3. Select record type or "All"
4. Click "Lookup"

### IP Geolocation
1. Open **IP Geolocation** tab
2. Enter IP address
3. Click "Lookup" for location info
4. Click "Check Reputation" for abuse reports

### SSL Certificate Analysis
1. Open **SSL Analyzer** tab
2. Enter hostname and port (default 443)
3. Click "Get Certificate" for details
4. Click "Test Protocols" for supported TLS versions

### Password Security
1. Go to **Password Analyzer** tab
2. Enter password to analyze strength
3. Use "Generate Strong Password" for secure passwords
4. View entropy and character composition

### Hash Analysis
1. Open **Hash Analyzer** tab
2. Enter hash to identify type
3. Click "Analyze Hash" for matching against databases
4. Generate hashes of text using various algorithms

## Configuration

Edit `config.py` to customize:
- API keys for external services
- Proxy settings
- Scanner timeouts
- Database location
- Logging level

## Security Notice

This toolkit is designed for **authorized security testing only**. Users are responsible for:
- Obtaining proper authorization before testing systems
- Complying with applicable laws and regulations
- Using the toolkit ethically and responsibly
- Following responsible disclosure practices

## Data Storage

- **Logs**: Stored in `logs/` directory
- **Database**: SQLite database at `data/toolkit.db`
- **Results**: Exported to CSV or JSON format

## Troubleshooting

### Port Scanner not working
- Ensure you have appropriate network permissions
- Check firewall settings
- Verify target is reachable

### DNS Lookup failing
- Confirm target domain exists
- Check internet connectivity
- Verify DNS server is accessible

### SSL Certificate errors
- Ensure SSL/TLS is enabled on target port
- Check certificate is valid
- Some certificates may not be accessible

## API Key Configuration

To enable advanced features, add API keys in `config.py`:
- **AbuseIPDB**: IP reputation checking
- **Shodan**: Advanced network scanning
- **VirusTotal**: Malware and vulnerability analysis
- **HaveIBeenPwned**: Password breach checking

## Advanced Features

### Database Export
Results are automatically stored in SQLite database for analysis and reporting.

### Batch Operations
Analyze multiple IPs, hashes, or domains simultaneously.

### Real-time Progress
Visual feedback during long-running scans.

### Result Logging
All activities logged for compliance and audit trails.

## System Requirements

- **RAM**: 4GB minimum
- **Disk Space**: 500MB for application and data
- **Network**: Internet connectivity for API services
- **OS**: Windows 10+, Ubuntu 18+, macOS 10.14+

## Support and Updates

For issues or feature requests, check the logs directory for detailed error information.

## License

Professional Security Analysis Tool - Educational and authorized testing use only.

## Disclaimer

This toolkit should only be used on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this software.

---

**Version**: 1.0.0  
**Last Updated**: 2026
