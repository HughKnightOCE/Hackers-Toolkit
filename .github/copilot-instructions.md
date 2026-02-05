# Hackers Toolkit - GitHub Copilot Instructions

This is a professional cybersecurity analysis toolkit with a modern GUI for penetration testing and security auditing.

## Project Structure

- `src/` - Source code
  - `tools/` - Core security analysis tools
  - `gui/` - PyQt5 GUI components
  - `utils/` - Utility functions and helpers
- `main.py` - Application entry point
- `config.py` - Configuration settings
- `requirements.txt` - Python dependencies

## Key Components

### Security Tools
- Port Scanner with range and common port scanning
- DNS Lookup with A, MX, NS, TXT record support
- IP Geolocation with location and ISP information
- SSL/TLS Certificate analyzer
- Network reconnaissance utilities
- Password strength analyzer
- Hash analyzer and identifier
- Vulnerability scanner

### GUI Features
- Multi-tab interface for different tools
- Real-time scanning with progress updates
- Worker threads for non-blocking operations
- Result logging and storage
- Error handling and status messages

## Setup and Run

1. Install dependencies: `pip install -r requirements.txt`
2. Run application: `python main.py`

## Development Guidelines

- All tools inherit from base classes for consistency
- Utilities handle logging, validation, and API calls
- GUI uses PyQt5 with worker threads for long operations
- Results stored in SQLite database
- All user input validated before processing

## Common Tasks

- Adding new tools: Create in `src/tools/` and add tab to `src/gui/main_window.py`
- Configuring APIs: Update `config.py` with API keys
- Checking logs: View in `logs/` directory
- Database queries: Use `Database` class from utils

## Important Notes

- This is for authorized security testing only
- All operations are logged
- Input validation is enforced
- Worker threads prevent GUI freezing
- Results are persistent in SQLite database
