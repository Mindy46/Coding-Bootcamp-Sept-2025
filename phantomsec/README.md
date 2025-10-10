# Threat Detection System

A Python-based security tool that analyzes system and application logs to detect potential security threats including brute force attacks, port scans, injection attempts, and suspicious IP behavior.

## 🎯 Project Overview

This tool was built as a capstone project to demonstrate practical cybersecurity concepts including log analysis, pattern matching, threat detection, and automated reporting.

## ✨ Features

- **Multiple Log Format Support**: Apache, Nginx, Firewall, Authentication logs
- **Threat Detection**:
  - Brute force attack detection
  - Port scanning identification
  - SQL injection & XSS attempt detection
  - Suspicious IP behavior analysis
  - Path traversal attempts
- **Configurable Detection Rules**: Customize thresholds and sensitivity
- **Comprehensive Reporting**: Generates detailed text reports with findings
- **Alert System**: Console and file-based alerts for critical threats
- **IP Intelligence**: Reverse DNS, geolocation support (extensible)

## 📋 Requirements

Python 3.7+ (no external dependencies - uses standard library only)

### Python Standard Library Modules Used
- `re` - Regular expression operations
- `datetime` - Date and time handling
- `collections` - Specialized container datatypes
- `json` - JSON encoding and decoding
- `argparse` - Command-line parsing
- `socket` - Network interface
- `hashlib` - Secure hashes and message digests
- `os` - Operating system interface
- `sys` - System-specific parameters

**No external packages required!** This project is entirely self-contained.

## 📁 File Structure

ThreatDetectionSystem/
├── main.py                     # Main entry point
├── log_parser.py               # Log parsing for different formats
├── threat_detector.py          # Core threat detection algorithms
├── report_generator.py         # Report generation
├── alert_system.py             # Alert handling
├── config_loader.py            # Configuration management
├── ip_utils.py                 # IP address utilities
├── utils.py                    # General helper functions
├── config.json                 # Configuration file
└── README.md                   # This file

## 🚀 Getting Started

### Step 1: Verify Python Installation: Check that Python 3.7+ is installed
### Step 2: Verify Project Files: You should see all 10 files listed in the File Structure section above.
### Step 3: Quick Start Test: Create a test log file and run the analyzer.

# Create a test log with multiple threat patterns such as:

cat > test.log << 'EOF'
192.168.1.100 - - [07/Oct/2025:10:00:00 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.100 - - [07/Oct/2025:10:00:01 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.100 - - [07/Oct/2025:10:00:02 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.100 - - [07/Oct/2025:10:00:03 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.100 - - [07/Oct/2025:10:00:04 +0000] "POST /login HTTP/1.1" 401 512
192.168.1.100 - - [07/Oct/2025:10:00:05 +0000] "POST /login HTTP/1.1" 401 512
45.142.212.61 - - [07/Oct/2025:10:01:00 +0000] "GET /admin HTTP/1.1" 403 256
45.142.212.61 - - [07/Oct/2025:10:01:01 +0000] "GET /wp-admin HTTP/1.1" 404 256
103.216.221.19 - - [07/Oct/2025:10:02:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 128
EOF

# Run the analyzer
python main.py --log test.log --format apache

Command Line Options

--log: Path to log file (required)
--format: Log format type (apache, nginx, firewall, auth)
--config: Path to config file (default: config.json)
--output: Output report filename (default: report.txt)
--verbose or -v: Enable verbose output

### Step 4: Review the Report

# View the generated report
cat report.txt

# Or on Windows
type report.txt

⚙️ Configuration

The system uses config.json for customizable settings.

Edit config.json to customize detection thresholds:

{
  "brute_force_threshold": 5,
  "brute_force_window_minutes": 10,
  "port_scan_threshold": 10,
  "alert_methods": ["console", "file"],
  "ip_whitelist": [],
  "ip_blacklist": []
}

Key Configuration Options

- brute_force_threshold: Number of failed login attempts to trigger alert
- brute_force_window_minutes: Time window for counting attempts
- port_scan_threshold: Number of unique ports before flagging as scan
- alert_methods: How to send alerts (console, file)
- ip_whitelist: IPs to never flag as suspicious
- ip_blacklist: IPs to always flag

📊 Understanding the Output

Report Sections

- Executive Summary: High-level overview of threats
- Critical Threats: IPs exhibiting multiple threat types
- Brute Force Attacks: Failed login clustering
- Suspicious IP Behavior: Anomalous access patterns
- Port Scan Activity: Port scanning attempts
- Injection Attempts: SQL injection, XSS, path traversal
- Recommendations: Actionable security advice

Severity Levels

- CRITICAL: Multiple threat types from same IP
- HIGH: Confirmed malicious activity
- MEDIUM: Suspicious but not confirmed
- LOW: Minor anomalies

🔧 Extending the Tool
- Adding Custom Detection Rules: Edit threat_detector.py and add your own detection methods
- Adding New Log Formats: Edit log_parser.py and add a new parsing method
- Integrating External APIs: Edit ip_utils.py to add API integrations

🎓 Learning Objectives

This project demonstrates:

- Log parsing and text processing
- Pattern matching with regular expressions
- Data structure usage (dictionaries, sets, lists)
- Time-based analysis and sliding windows
- Configuration management
- File I/O operations
- Modular code organization
- Command-line argument parsing
- Error handling

⚠️ Limitations

- Does not provide real-time monitoring (batch analysis only)
- Email alerts not fully implemented
- External API integrations (geolocation, threat intel) are stubs
- No GUI interface
- Limited to text-based reports

🔜 Future Enhancements

 - Real-time log monitoring mode
 - HTML/PDF report generation
 - Machine learning for anomaly detection
 - Web dashboard interface
 - Database storage for historical analysis
 - Complete threat intelligence API integration
 - Email notification system
 - Log visualization graphs

📝 Notes

This is an educational project, not production security software
Please test on sample data before running on production logs
Some features are intentionally simplified for learning purposes

📄 License
Educational use. Free to use and modify for learning purposes.

📧 Contact
For questions about this project, please contact:

Author: Thibault Gardet
Email: gardet.thibault@gmail.com
GitHub: https://github.com/Thibault13320