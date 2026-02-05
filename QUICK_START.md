# QUICK START GUIDE

## Installation (1 minute)

### Windows
```bash
# 1. Open Command Prompt
# 2. Navigate to toolkit folder
cd "path\to\Hackers toolkit"

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py
```

### Linux/Mac
```bash
# 1. Open Terminal
# 2. Navigate to toolkit folder
cd "path/to/Hackers toolkit"

# 3. Install dependencies
pip3 install -r requirements.txt

# 4. Run the application
python3 main.py
```

### Using Launcher Scripts
```bash
# Windows
run.bat

# Linux/Mac
bash run.sh
```

---

## First Run

1. **Application Loads**: GUI window opens with 7 tabs
2. **Check Logs**: Verify `logs/` folder created
3. **Database**: SQLite database created at `data/toolkit.db`
4. **Ready to Scan**: Start using tools immediately

---

## 5-Minute Tutorial

### Test 1: Port Scan
```
1. Click "Port Scanner" tab
2. Enter: google.com
3. Click "Scan Common Ports"
4. View results (ports 80, 443 should be open)
```

### Test 2: DNS Lookup
```
1. Click "DNS Lookup" tab
2. Enter: google.com
3. Select "All" for all records
4. Click "Lookup"
5. View A, MX, NS records
```

### Test 3: Password Check
```
1. Click "Password Analyzer" tab
2. Enter: Test123!
3. View strength: "Strong"
4. Generate: Click "Generate Strong Password"
5. Copy new password
```

### Test 4: Hash Analysis
```
1. Click "Hash Analyzer" tab
2. Enter: "password"
3. Select MD5 from dropdown
4. Click "Generate"
5. View generated MD5 hash
```

---

## Common Tasks

### Change API Keys
1. Click "Settings" tab
2. Enter API keys for:
   - AbuseIPDB
   - Shodan
   - VirusTotal
3. Click "Save Settings"

### Enable Proxy
1. Click "Settings" tab
2. Check "Enable Proxy"
3. Enter proxy URL: `http://proxy:8080`
4. Click "Save Settings"

### View Logs
1. Open `logs/` folder
2. View today's log file
3. Search for "ERROR" for issues

### Check Database
1. Open `data/toolkit.db` with SQLite browser
2. Query `scan_results` table
3. View historical scans

---

## Keyboard Shortcuts

- `Ctrl+Q`: Exit application
- `Tab`: Switch between tabs
- `Enter`: Run scan/lookup (in focused field)

---

## Tips & Tricks

### Speed Up Port Scans
- Use "Scan Common Ports" instead of full range
- Reduce port range (e.g., 1-100)
- Increase timeout only if needed

### Better DNS Results
- Use full domain (www.example.com)
- Check multiple record types
- Try "All" for complete picture

### Stronger Passwords
- Use "Generate Strong Password"
- Minimum 12 characters
- Include special characters (!@#$)

### Hash Cracking
- Common passwords are in rainbow table
- Complex passwords won't match
- Check plain text against hashes

---

## Troubleshooting

### Application Won't Start
```
Error: ModuleNotFoundError: No module named 'PyQt5'

Solution:
1. pip install -r requirements.txt
2. python main.py
```

### Can't Scan Target
```
Error: Could not connect to host

Solutions:
1. Check target is reachable: ping example.com
2. Firewall may block scans
3. Target may not exist
4. Try with IP instead of hostname
```

### DNS Lookup Returns No Results
```
Solutions:
1. Verify domain exists
2. Check internet connection
3. Try different record types
4. Domain may have no MX records
```

### SSL Certificate Error
```
Solutions:
1. Ensure target uses HTTPS (port 443)
2. Check hostname is correct
3. Certificate may be self-signed
4. Try different port (8443, etc)
```

---

## File Structure

```
Hackers toolkit/
├── main.py                 # Application launcher
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── README.md               # Full documentation
├── FEATURES.md             # Detailed feature guide
├── QUICK_START.md          # This file
├── run.bat                 # Windows launcher
├── run.sh                  # Linux/Mac launcher
├── logs/                   # Application logs
├── data/                   # Database and results
└── src/
    ├── tools/              # Security tools
    ├── gui/                # GUI components
    └── utils/              # Helper utilities
```

---

## Next Steps

1. **Read FEATURES.md** - Complete feature documentation
2. **Configure APIs** - Add API keys in Settings tab
3. **Run Scans** - Test on authorized targets only
4. **Review Logs** - Check logs/ for details
5. **Export Results** - Save results for reports

---

## Important Legal Notice

⚠️ **THIS TOOLKIT IS FOR AUTHORIZED TESTING ONLY**

Before testing any system:
1. Get **written permission** from system owner
2. Define **scope** clearly
3. Follow **all applicable laws**
4. Use **responsibly and ethically**

Unauthorized access is **ILLEGAL** and subject to prosecution.

---

## Getting Help

1. Check FEATURES.md for detailed guides
2. Review logs/ directory for errors
3. Verify target is reachable
4. Check internet connectivity
5. Ensure all dependencies installed

---

## Version Information

- **Version**: 1.0.0
- **Python Required**: 3.8+
- **Last Updated**: February 2026
- **Status**: Production Ready

---

Enjoy using Hackers Toolkit! 🔒
