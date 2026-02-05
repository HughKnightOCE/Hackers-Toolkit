# TOOL REFERENCE GUIDE

Quick reference for all 8 security tools included in Hackers Toolkit.

---

## 1️⃣ PORT SCANNER

### What it does
Identifies open ports and services on target hosts.

### Key Features
- Range scanning (1-65535)
- Common ports quick scan (15 ports)
- Service identification
- Real-time progress
- Threaded scanning

### How to use
1. Enter target (IP or hostname)
2. Specify port range (e.g., 1-1000) or click "Common Ports"
3. Click "Scan Ports" button
4. Wait for results
5. Review open ports and identified services

### Example
```
Target: example.com
Ports: 1-1000
Results:
  - Port 80 (HTTP) OPEN
  - Port 443 (HTTPS) OPEN
  - Port 22 (SSH) OPEN
```

### Common Ports Tested
- 21 (FTP), 22 (SSH), 23 (Telnet)
- 80 (HTTP), 443 (HTTPS)
- 3306 (MySQL), 5432 (PostgreSQL)
- 3389 (RDP), 445 (SMB)
- 8080, 8443 (HTTP/HTTPS alternatives)

### Tips
- Start with common ports for speed
- Reduce port range if scanning is slow
- Use for authorized targets only

---

## 2️⃣ DNS LOOKUP

### What it does
Retrieves and displays DNS records for domains.

### Key Features
- A Records (IPv4 addresses)
- MX Records (mail servers)
- NS Records (nameservers)
- TXT Records (SPF, DKIM, etc.)
- Full enumeration

### How to use
1. Enter domain name
2. Select record type (A, MX, NS, TXT, or All)
3. Click "Lookup"
4. View results

### Example
```
Domain: google.com
Record Type: All

Results:
A Records: 142.251.41.14
MX: aspmx.l.google.com (priority 10)
NS: ns1.google.com, ns2.google.com
TXT: v=spf1 include:_spf.google.com ~all
```

### Record Types Explained
- **A**: IPv4 address pointing
- **MX**: Mail server routing
- **NS**: Authoritative nameservers
- **TXT**: Text records (SPF, DKIM, verification)

### Tips
- Use "All" for complete picture
- Check MX for email infrastructure
- Verify TXT for email security (SPF/DKIM)

---

## 3️⃣ IP GEOLOCATION

### What it does
Provides geographic and organizational information about IP addresses.

### Key Features
- Geographic location (country, city)
- Coordinates (latitude, longitude)
- ISP and organization
- Timezone information
- IP reputation checking
- Batch lookup support

### How to use
1. Enter IP address
2. Click "Lookup" for location data
3. Or click "Check Reputation" for abuse reports
4. View complete information

### Example
```
IP: 8.8.8.8
Results:
  Country: United States
  City: Mountain View
  ISP: Google LLC
  Coordinates: (37.386, -122.084)
  Timezone: America/Los_Angeles
```

### Information Provided
- Country and region
- City and postal code
- Geographic coordinates
- ISP name and organization
- AS Number (Autonomous System)
- Timezone
- Connection type

### Tips
- VPN/Proxies may affect accuracy
- Google DNS (8.8.8.8) is easily identifiable
- Use for IP attribution and analysis

---

## 4️⃣ SSL/TLS ANALYZER

### What it does
Analyzes SSL/TLS certificates and security configuration.

### Key Features
- Certificate information extraction
- Subject and issuer details
- Serial number and validity
- Alternative names (SANs)
- Supported TLS protocol detection
- Security assessment

### How to use
1. Enter hostname
2. Specify port (default 443)
3. Click "Get Certificate" for details
4. Or click "Test Protocols" for TLS versions
5. Review results

### Example
```
Hostname: google.com
Port: 443

Results:
Subject: CN=google.com
Issuer: CN=Google Internet Authority
Valid Until: 2025-01-07
TLS Protocols: 1.2, 1.3 supported
Status: Valid
```

### Certificate Information
- Subject CN (common name)
- Issuer (certificate authority)
- Serial number
- Validity dates
- SANs (alternative domains)

### TLS Protocols
- TLS 1.0 (deprecated)
- TLS 1.1 (deprecated)
- TLS 1.2 (current standard)
- TLS 1.3 (modern)

### Tips
- Use for certificate verification
- Check expiration dates
- Flag deprecated TLS versions
- Verify certificate chain

---

## 5️⃣ NETWORK RECONNAISSANCE

### What it does
Gathers network mapping and host discovery information.

### Key Features
- Reverse DNS lookup
- Host information retrieval
- Subnet scanning
- DNS record enumeration
- Network topology mapping

### How to use
- Reverse DNS: Enter IP address
- Host info: Enter hostname
- Subnet scan: Enter CIDR notation
- View results

### Example
```
Reverse DNS: 8.8.8.8
Results: dns.google

Host Info: google.com
Results:
  FQDN: google.com
  IPs: 142.251.41.14, etc
  Aliases: www.google.com
```

### Information Gathered
- Hostname from IP (reverse lookup)
- IP addresses from hostname
- Host aliases
- FQDN (Fully Qualified Domain Name)
- Subnet information

### Tips
- Use for network discovery
- Reverse lookup confirms IP ownership
- Subnet scanning identifies active hosts
- Maps network structure

---

## 6️⃣ PASSWORD ANALYZER

### What it does
Evaluates password strength and security.

### Key Features
- Strength rating (Weak to Very Strong)
- Entropy calculation (bits)
- Character type analysis
- Common password detection
- Secure password generation
- Batch analysis

### How to use
1. Enter password to analyze
2. Click "Analyze"
3. View strength score and entropy
4. Or click "Generate Strong Password"
5. Copy generated password

### Example
```
Password: Test123!
Results:
  Strength: Strong
  Entropy: 52.24 bits
  Length: 8 characters
  Character Types:
    - Uppercase: ✓
    - Lowercase: ✓
    - Numbers: ✓
    - Special: ✓
  Common: ✗
```

### Strength Criteria
- **Weak**: Low entropy, predictable patterns
- **Fair**: Adequate but improvable
- **Strong**: Good mix of character types
- **Very Strong**: Excellent entropy (16+ chars)

### Password Generation
- Configurable length (default 16)
- Include uppercase letters
- Include numbers
- Include special characters
- Instant entropy calculation

### Tips
- Minimum 12 characters recommended
- Use all character types
- Avoid common passwords
- Use generated passwords for security

---

## 7️⃣ HASH ANALYZER

### What it does
Identifies hash types and attempts to crack them.

### Key Features
- Hash type identification (8 algorithms)
- Rainbow table lookup
- Batch analysis
- Hash generation from text
- Entropy calculation

### How to use
**For analysis:**
1. Enter hash value
2. Click "Analyze Hash"
3. View type and crack attempts

**For generation:**
1. Enter text to hash
2. Select algorithm
3. Click "Generate"
4. Copy generated hash

### Example
```
Analyze Hash:
Input: 5f4dcc3b5aa765d61d8327deb882cf99
Results:
  Type: MD5 (32 hex characters)
  Cracked: YES
  Plaintext: password

Generate Hash:
Input: MyPassword123!
Algorithm: SHA256
Output: a1b2c3d4e5f6g7h8...
```

### Supported Hash Types
- **MD5** (32 characters) - Legacy
- **SHA1** (40 characters) - Deprecated
- **SHA256** (64 characters) - Standard
- **SHA512** (128 characters) - Enhanced
- **Bcrypt** - Password hashing
- **Scrypt** - Key derivation
- **Argon2** - Modern password hashing

### Hash Usage
- File integrity verification
- Password storage
- Digital signatures
- Blockchain applications

### Tips
- Common passwords are in rainbow table
- Complex passwords unlikely to match
- SHA256+ more secure than MD5/SHA1
- Use Argon2/Bcrypt for password hashing

---

## 8️⃣ VULNERABILITY SCANNER

### What it does
Identifies known vulnerabilities in services and ports.

### Key Features
- Port-based vulnerability detection
- Service vulnerability mapping
- CVE matching
- Severity classification
- Vulnerability reporting
- Remediation guidance

### How to use
1. Enter IP address and port
2. Or enter service name
3. Click scan button
4. Review vulnerabilities
5. Check recommendations

### Example
```
Port: 22 (SSH)
Vulnerabilities:
  - SSH Version Enumeration
  - Brute Force Risk
  - Outdated version (check server logs)

Recommendation: Update OpenSSH to latest version
```

### Vulnerability Types
- Unencrypted communication
- Outdated software
- Default credentials
- Known CVEs
- Service exposure risks

### Common Port Vulnerabilities
| Port | Service | Risk |
|------|---------|------|
| 23 | Telnet | Unencrypted |
| 445 | SMB | Lateral movement |
| 3389 | RDP | Brute force |
| 3306 | MySQL | Database exposure |
| 5432 | PostgreSQL | Database exposure |

### Tips
- Focus on critical vulnerabilities first
- Patch promptly
- Reduce service exposure
- Use firewalls for access control

---

## 🔧 SETTINGS PANEL

### Configuration Options
- API Key management
- Proxy settings
- Scanner timeout
- Thread settings
- Retry policy

### API Keys (Optional)
- AbuseIPDB - IP reputation
- Shodan - Network information
- VirusTotal - File analysis

### Scanner Settings
- **Timeout**: 1-60 seconds (default 5)
- **Max Threads**: 1-100 (default 10)
- **Retries**: 0-10 (default 2)

### Proxy Configuration
- Enable/disable
- Set proxy URL
- Authentication support

---

## ⚡ QUICK COMMAND REFERENCE

| Task | Tool | Input | Button |
|------|------|-------|--------|
| Find open ports | Port Scanner | hostname | Scan Ports |
| Get mail servers | DNS Lookup | domain | Lookup (MX) |
| Find server location | IP Geolocation | IP | Lookup |
| Check HTTPS | SSL Analyzer | hostname | Get Certificate |
| Test password | Password Analyzer | password | Analyze |
| Crack hash | Hash Analyzer | hash | Analyze Hash |
| Identify service | Port Scanner | host | Scan Common |
| Generate password | Password Analyzer | - | Generate |

---

## 📊 TOOL SELECTION GUIDE

**Want to know...**

- **Which ports are open?** → Port Scanner
- **Which servers handle mail?** → DNS Lookup
- **Where is the server?** → IP Geolocation
- **Is the certificate valid?** → SSL Analyzer
- **What's the network layout?** → Network Recon
- **Is the password secure?** → Password Analyzer
- **What's this hash?** → Hash Analyzer
- **Are there vulnerabilities?** → Vulnerability Scanner

---

## 🎯 COMMON WORKFLOWS

### Infrastructure Mapping
1. Port Scanner → Find services
2. DNS Lookup → Map structure
3. IP Geolocation → Locate servers
4. SSL Analyzer → Check security

### Security Assessment
1. Port Scanner → Find open ports
2. Vulnerability Scanner → Identify risks
3. SSL Analyzer → Check certs
4. Password Analyzer → Verify policies

### Email Infrastructure
1. DNS Lookup (MX) → Find mail servers
2. Port Scanner → Test mail ports
3. SSL Analyzer → Check SMTP TLS
4. IP Geolocation → Locate mail servers

---

## ⚠️ TOOL REQUIREMENTS

| Tool | Internet | Permission | Time |
|------|----------|-----------|------|
| Port Scanner | Optional | Target | 1-5 min |
| DNS Lookup | Required | Domain | <1 min |
| IP Geolocation | Required | IP | <1 min |
| SSL Analyzer | Required | Host | 1-5 sec |
| Network Recon | Required | Target | <1 min |
| Password Analyzer | No | Text | Instant |
| Hash Analyzer | Optional | Hash | <1 sec |
| Vulnerability Scanner | Optional | Port | <1 min |

---

**Version**: 1.0.0
**Last Updated**: February 2026
