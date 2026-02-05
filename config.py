# Hackers Toolkit Configuration

# API Keys (add your own)
API_KEYS = {
    "abuseipdb": "",
    "shodan": "",
    "virustotal": "",
    "haveibeenpwned": ""
}

# Proxy Settings
PROXY = {
    "enabled": False,
    "url": "http://proxy.example.com:8080"
}

# Scanner Settings
SCANNER_SETTINGS = {
    "timeout": 5,
    "max_threads": 10,
    "retries": 2
}

# Database
DATABASE_PATH = "data/toolkit.db"

# Logging
LOG_LEVEL = "INFO"
LOG_DIR = "logs"

# Common Ports
COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    3306, # MySQL
    3389, # RDP
    5432, # PostgreSQL
    8080, # HTTP Alt
    8443  # HTTPS Alt
]
