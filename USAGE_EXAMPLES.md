# USAGE EXAMPLES

## Real-World Security Testing Scenarios

This document provides practical examples of using the Hackers Toolkit for authorized security testing.

---

## 🔍 Scenario 1: Basic Infrastructure Reconnaissance

**Objective**: Map network infrastructure of authorized domain

### Step 1: Identify Web Servers
```
Tool: Port Scanner
Target: example.com
Ports: 80, 443, 8080, 8443
Expected: Find HTTP/HTTPS services
```

### Step 2: Get Server Certificates
```
Tool: SSL Analyzer
Hostname: example.com
Port: 443
Expected: Certificate details, validity, TLS versions
```

### Step 3: Enumerate DNS Records
```
Tool: DNS Lookup
Domain: example.com
Record Type: All
Expected: A, MX, NS, TXT records
Results: Mail servers, nameservers, SPF configuration
```

### Step 4: Identify Mail Infrastructure
```
Tool: DNS Lookup
Domain: example.com
Record Type: MX
Expected: Mail server hostnames
Next: Check those servers with Port Scanner
```

### Step 5: Check Mail Server Certificates
```
Tool: SSL Analyzer
Hostname: mail.example.com
Port: 25 or 587
Expected: SMTP TLS configuration
```

---

## 🔐 Scenario 2: Vulnerability Assessment

**Objective**: Identify known vulnerabilities in services

### Step 1: Scan Target Services
```
Tool: Port Scanner
Target: 192.168.1.100
Ports: 1-1000
Expected: List of open ports and services
```

### Step 2: Check Service Vulnerabilities
```
Tool: Vulnerability Scanner
Port: 22 (SSH)
Expected: Brute force risk, version enumeration
Action: Check for outdated OpenSSH versions
```

### Step 3: Test Additional Ports
```
Tool: Vulnerability Scanner
Port: 3306 (MySQL)
Expected: Database exposure risk
Action: Recommend access restriction
```

### Step 4: Review SSL/TLS Security
```
Tool: SSL Analyzer
Hostname: target.com
Protocols: Test TLS 1.0, 1.1, 1.2, 1.3
Expected: Supported versions
Action: Flag deprecated TLS versions
```

---

## 🔑 Scenario 3: Password Security Assessment

**Objective**: Evaluate password policies in organization

### Test User Passwords Against Strength
```
Tool: Password Analyzer
Test Cases:
  1. "Password123" → Weak
  2. "MyP@ssw0rd!" → Strong
  3. "SecureP@ss123!" → Very Strong
```

### Generate Secure Passwords
```
Tool: Password Analyzer
Click: Generate Strong Password
Result: 16-character password with mixed characters
Entropy: Calculate from output
```

### Identify Weak Patterns
```
Analyze:
  - "12345678" → Very Weak (sequential)
  - "qwerty" → Very Weak (keyboard pattern)
  - "password" → Very Weak (common)
  - "MyC0rp!2024" → Strong (mixed + special)
```

---

## 🔗 Scenario 4: Hash Analysis and Verification

**Objective**: Identify and crack password hashes

### Test Hash Type Identification
```
Tool: Hash Analyzer
Input: 5f4dcc3b5aa765d61d8327deb882cf99
Expected: MD5 (32 hex characters)
Crack: "password" (in rainbow table)
```

### Generate Hashes for Comparison
```
Tool: Hash Analyzer
Text: MySecurePassword123!
Algorithm: SHA256
Generate: 9e4c8...
Use: Compare against captured hashes
```

### Batch Analysis
```
Multiple hashes:
  1. 5f4dcc3b5aa765d61d8327deb882cf99 (MD5)
  2. e99a18c428cb38d5f260853678922e03 (MD5)
  3. 8f14e45fceea167a5a36dedd4bea2543 (MD5)

Results: 2 matched in rainbow table
```

---

## 🌍 Scenario 5: IP Reconnaissance

**Objective**: Gather intelligence on IP addresses

### Check Single IP
```
Tool: IP Geolocation
Target: 8.8.8.8 (Google DNS)
Expected Output:
  - Country: United States
  - City: Mountain View
  - ISP: Google LLC
  - Coordinates: (latitude, longitude)
```

### Batch IP Analysis
```
Tool: IP Geolocation
Targets: 
  - 8.8.8.8
  - 1.1.1.1
  - 208.67.222.222
Results: Compare ISPs and geographic locations
```

### Check IP Reputation
```
Tool: IP Geolocation
Target: 192.0.2.1
Check Reputation: Yes
Expected: Abuse confidence score
Action: Add to blocklist if malicious
```

---

## 🌐 Scenario 6: Complete Domain Assessment

**Objective**: Full reconnaissance of domain

### Phase 1: Domain Information
```
Step 1: DNS Lookup → Get all records
Step 2: IP Geolocation → Map server locations
Step 3: SSL Analyzer → Certificate analysis
```

### Phase 2: Web Services
```
Step 1: Port Scanner → Identify open ports
Step 2: Service Identification → Determine services
Step 3: Vulnerability Scanner → Check vulnerabilities
```

### Phase 3: Email Infrastructure
```
Step 1: DNS Lookup → Get MX records
Step 2: Port Scanner → Test mail server ports
Step 3: SSL Analyzer → Check SMTP TLS
```

### Phase 4: Documentation
```
Results Summary:
  - Web servers: example.com (IPs: 93.184.216.34)
  - Mail servers: mail.example.com
  - Nameservers: ns1.example.com, ns2.example.com
  - TLS Support: 1.2, 1.3 (1.0 deprecated)
  - Open Ports: 80, 443, 25, 587
```

---

## 🛡️ Scenario 7: Security Audit Preparation

**Objective**: Prepare comprehensive security audit report

### Pre-Audit Scanning
```
1. Port Scanner: Full range scan
2. Vulnerability Scanner: Identify risks
3. SSL Analyzer: Certificate review
4. Network Recon: Map infrastructure
5. Password Analyzer: Test policies
```

### Documentation Gathering
```
Collect:
- Open ports and services
- Certificate details (issuer, expiry, algorithms)
- DNS configuration (records, nameservers)
- IP locations (geographic distribution)
- Identified vulnerabilities (severity, remediation)
```

### Report Generation
```
Create report with:
- Executive summary
- Findings (critical, high, medium, low)
- Evidence from scans
- Remediation recommendations
- Timeline for fixes
```

---

## ⚡ Quick Reference: Common Tasks

### Port Scan Common Ports
```
Tool: Port Scanner
Input: hostname.com
Button: "Scan Common Ports"
Time: ~30 seconds
Ports: 15 most common ports
```

### Find Mail Servers
```
Tool: DNS Lookup
Input: example.com
Record Type: MX
Time: <5 seconds
Result: All mail server hostnames
```

### Check if HTTPS is Working
```
Tool: SSL Analyzer
Input: example.com
Port: 443
Time: ~5 seconds
Result: Certificate validity and TLS versions
```

### Generate Secure Password
```
Tool: Password Analyzer
Button: "Generate Strong Password"
Time: Instant
Result: 16-character password + entropy
```

### Identify Hash Type
```
Tool: Hash Analyzer
Input: [paste hash]
Button: "Analyze Hash"
Time: Instant
Result: Hash type + crack attempt
```

### Locate Server
```
Tool: IP Geolocation
Input: 93.184.216.34
Button: "Lookup"
Time: <1 second
Result: Country, city, ISP, coordinates
```

### Find Nameservers
```
Tool: DNS Lookup
Input: example.com
Record Type: NS
Time: <5 seconds
Result: Primary and secondary nameservers
```

---

## 📊 Scenario 8: Continuous Monitoring

**Objective**: Track changes over time

### Weekly Scan Schedule
```
Monday:
  - Port Scanner on all domains
  - SSL Analyzer on web servers
  
Wednesday:
  - DNS Lookup for all domains
  - IP Geolocation for IPs
  
Friday:
  - Vulnerability Scanner
  - Full infrastructure review
```

### Database Queries
```
Query: Port changes since last week
Query: New open ports detected
Query: Certificate expiring soon
Query: IP geolocation changes
```

### Reporting
```
Generate report showing:
- Services added/removed
- Configuration changes
- New vulnerabilities
- Expiring certificates
```

---

## ✅ Best Practices

### Pre-Scan Checklist
- [ ] Have written authorization
- [ ] Define scope clearly
- [ ] Know point of contact
- [ ] Understand rules of engagement
- [ ] Know emergency contacts

### During Scan
- [ ] Monitor system impact
- [ ] Stop if performance affected
- [ ] Document findings
- [ ] Communicate issues
- [ ] Maintain professional conduct

### Post-Scan
- [ ] Compile results
- [ ] Review findings
- [ ] Draft recommendations
- [ ] Follow responsible disclosure
- [ ] Schedule follow-up

---

## 🚨 Legal Reminders

⚠️ **AUTHORIZATION REQUIRED**
All testing must be on systems you own or have explicit written permission to test.

**Unauthorized access is ILLEGAL** and may result in:
- Criminal prosecution
- Significant fines
- Imprisonment
- Civil liability
- Employment termination

---

## 📞 Testing Support

### Troubleshooting Tests
If a test fails:
1. Check target is reachable (ping)
2. Verify firewall settings
3. Confirm proper credentials
4. Review logs for details
5. Try with different settings

### Performance Tips
- Reduce port range for faster scans
- Use "Common Ports" instead of full range
- Increase timeout if network is slow
- Run during off-peak hours

### Documentation
- Log all test results
- Note date and time
- Record test parameters
- Document findings
- Keep evidence

---

## 🎓 Learning Examples

### Example 1: Understanding Port Scan Output
```
Results:
  80 (http) - OPEN - Web server
  443 (https) - OPEN - Secure web
  22 (ssh) - OPEN - Remote access
  3306 (mysql) - CLOSED - Database
  
Interpretation:
- Web services accessible
- SSH enabled (verify necessary)
- MySQL not exposed (good)
```

### Example 2: Certificate Analysis
```
Certificate Info:
  Subject: CN=example.com
  Issuer: CN=Let's Encrypt
  Valid Until: 2025-06-15
  TLS 1.2: YES
  TLS 1.3: YES
  
Assessment:
- Certificate valid
- Modern TLS support
- Auto-renewal likely (Let's Encrypt)
```

### Example 3: DNS Records
```
A: 93.184.216.34
MX: mail.example.com
NS: ns1.example.com, ns2.example.com
TXT: v=spf1 include:_spf.google.com ~all

Assessment:
- IPv4 only (add IPv6?)
- Email hosted externally
- SPF configured
```

---

## 🎯 Summary

The Hackers Toolkit provides professional-grade security testing capabilities for:
- Infrastructure reconnaissance
- Vulnerability identification
- Security assessment
- Compliance verification
- Continuous monitoring

**Remember**: Always test responsibly and ethically.

---

**Last Updated**: February 2026  
**Version**: 1.0.0
