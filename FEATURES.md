# Hackers Toolkit - Complete Feature Guide

## Quick Start

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py

# Or on Windows:
run.bat

# Or on Linux/Mac:
bash run.sh
```

## Tools Overview

### 1. Port Scanner
**Purpose**: Network service discovery and port enumeration

**Features**:
- Range scanning (e.g., 1-1000)
- Common ports quick scan
- Service identification
- Real-time progress updates
- Threaded scanning (non-blocking UI)

**Usage**:
1. Enter target host (IP or hostname)
2. Specify port range or use "Common Ports"
3. Review results showing open/closed ports
4. Identify services running on open ports

**Common Ports Scanned**:
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 80 (HTTP), 443 (HTTPS)
- 3306 (MySQL), 5432 (PostgreSQL)
- 3389 (RDP), 445 (SMB)

---

### 2. DNS Lookup
**Purpose**: Domain name system enumeration and analysis

**Features**:
- A Record (IPv4 addresses)
- MX Records (mail servers)
- NS Records (nameservers)
- TXT Records (SPF, DKIM, etc.)
- Full DNS enumeration

**Usage**:
1. Enter domain name (e.g., example.com)
2. Select record type or "All"
3. View all DNS records associated with domain
4. Identify mail servers and nameservers

**Example Results**:
- A Record: 93.184.216.34
- MX: mail.example.com (priority 10)
- NS: ns1.example.com, ns2.example.com
- TXT: v=spf1 include:_spf.google.com ~all

---

### 3. IP Geolocation
**Purpose**: Geographic and organizational IP information

**Features**:
- IP address location (country, city)
- Latitude/longitude coordinates
- ISP and organization identification
- Timezone information
- IP reputation checking
- Batch IP lookup

**Usage**:
1. Enter IP address
2. Click "Lookup" for location data
3. Click "Check Reputation" for abuse reports
4. View location on coordinates

**Information Returned**:
- Country and region
- City coordinates
- ISP and AS Number
- Timezone
- Abuse confidence score

---

### 4. SSL/TLS Analyzer
**Purpose**: Certificate and encryption analysis

**Features**:
- Certificate extraction
- Validity checking (not expired)
- Subject and issuer information
- Alternative names (SANs)
- Protocol version detection
- Security assessment

**Usage**:
1. Enter hostname
2. Specify port (default 443)
3. Click "Get Certificate" for details
4. Click "Test Protocols" for TLS versions
5. Review certificate chain and validity

**Certificate Information**:
- Subject (CN, O, C)
- Issuer details
- Serial number
- Validity dates
- Supported protocols (TLS 1.0, 1.1, 1.2, 1.3)

---

### 5. Password Analyzer
**Purpose**: Password security evaluation

**Features**:
- Strength rating (Weak/Fair/Strong/Very Strong)
- Entropy calculation (bits)
- Character composition analysis
- Common password detection
- Secure password generation
- Batch analysis support

**Usage**:
1. Enter password to analyze
2. View strength score and entropy
3. Check character types included
4. Generate strong passwords with specifications

**Strength Criteria**:
- Length (8+ characters preferred)
- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Numbers (0-9)
- Special characters (!@#$%^&*)
- Not common passwords

**Password Generation**:
- Configurable length (default 16 chars)
- Include uppercase, numbers, special chars
- Instant entropy calculation

---

### 6. Hash Analyzer
**Purpose**: Hash identification and cracking

**Features**:
- Hash type identification
  - MD5 (32 hex characters)
  - SHA1 (40 hex characters)
  - SHA256 (64 hex characters)
  - SHA512 (128 hex characters)
  - Bcrypt, Scrypt, Argon2
- Rainbow table lookup
- Batch hash analysis
- Hash generation from text

**Usage**:
1. Enter hash value or text
2. Click "Analyze Hash" to identify
3. Check against known databases
4. Or generate hash of text using algorithms

**Hash Generation**:
- Select algorithm (MD5, SHA1, SHA256, SHA512)
- Enter text to hash
- Generate cryptographic hash
- Copy and use in applications

**Example**:
- Input: "password"
- MD5: 5f4dcc3b5aa765d61d8327deb882cf99
- SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

---

### 7. Network Reconnaissance
**Purpose**: Network mapping and host discovery

**Features**:
- Reverse DNS lookup
- Host information gathering
- Subnet scanning
- DNS record enumeration
- WHOIS-like information

**Usage**:
1. Perform reverse DNS for IPs
2. Get host information from hostname
3. Scan subnet for active hosts
4. Gather network topology

---

### 8. Vulnerability Scanner
**Purpose**: Identify known vulnerabilities

**Features**:
- Port-based vulnerability detection
- Service vulnerability mapping
- CVE matching
- Severity classification
- Vulnerability reporting

**Vulnerabilities Detected**:
- Outdated services
- Unencrypted protocols
- Known CVEs
- Brute force risks
- Default credentials

---

## Configuration

### API Keys (config_local.json)
Configure external service integrations:
```json
{
  "abuseipdb": "your_api_key",
  "shodan": "your_api_key",
  "virustotal": "your_api_key"
}
```

### Scanner Settings
- **Timeout**: Connection timeout (default 5 seconds)
- **Max Threads**: Parallel operations (default 10)
- **Retries**: Failed request retries (default 2)

### Proxy Configuration
- Enable/disable proxy
- Set proxy URL and port
- Authentication credentials

---

## Results and Logging

### Automatic Features
- **Logging**: All operations logged to `logs/` directory
- **Database**: Results stored in SQLite at `data/toolkit.db`
- **Timestamps**: All results timestamped
- **Error Tracking**: Full error logs for debugging

### Export Options
- Results displayed in GUI
- Copy to clipboard
- Export to CSV
- Export to JSON format

---

## Security Best Practices

### Before Testing
1. Obtain written authorization
2. Define scope clearly
3. Establish rules of engagement
4. Know applicable laws

### During Testing
1. Start with less invasive scans
2. Monitor system impact
3. Document all findings
4. Maintain secure communication channels

### After Testing
1. Compile comprehensive report
2. Include remediation recommendations
3. Follow responsible disclosure
4. Notify affected parties

---

## Troubleshooting

### Port Scanner Issues
**Problem**: No ports detected
- Check network connectivity
- Verify target is reachable (ping)
- Firewall may be blocking
- Try common ports first

**Problem**: Scan is slow
- Increase timeout sparingly
- Reduce port range
- Check network latency

### DNS Lookup Issues
**Problem**: Domain not found
- Verify domain exists
- Check spelling
- Ensure internet connectivity
- Domain may have expired

**Problem**: Incomplete records
- Some records may not be published
- Check with nslookup command
- Multiple DNS servers may have different records

### IP Geolocation Issues
**Problem**: Location inaccurate
- Geoip databases have limitations
- VPN/Proxy may affect results
- Update geoip database regularly

### SSL Certificate Issues
**Problem**: Certificate not found
- Ensure SSL/TLS is enabled on port
- Check certificate is valid
- Firewall may block connection
- Try port 443 (standard HTTPS)

---

## Advanced Usage

### Batch Operations
- Analyze multiple IPs at once
- Scan multiple targets sequentially
- Export batch results

### Database Queries
- Query historical results
- Track vulnerability trends
- Generate custom reports

### API Integration
- Connect to external services
- Automated scanning pipelines
- Result aggregation

---

## System Requirements

- **Python**: 3.8 or higher
- **RAM**: 4GB minimum
- **Disk**: 500MB free space
- **Network**: Internet connectivity
- **OS**: Windows 10+, Ubuntu 18+, macOS 10.14+

---

## Legal and Ethical Considerations

⚠️ **IMPORTANT**: This toolkit should only be used for authorized security testing on systems you own or have explicit written permission to test.

Unauthorized access to computer systems is **ILLEGAL** and subject to criminal prosecution under laws including:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act 1990 - UK
- Similar laws in other jurisdictions

The developers of this toolkit accept **NO LIABILITY** for:
- Unauthorized access
- Data loss or corruption
- System damage
- Legal consequences
- Misuse of the software

---

## Updates and Support

Check GitHub repository for:
- Latest versions
- Bug fixes
- Feature updates
- Security patches

---

**Version**: 1.0.0  
**Last Updated**: February 2026  
**Status**: Active Development
