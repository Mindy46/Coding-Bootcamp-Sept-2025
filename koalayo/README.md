# SSH Log Analyzer - Security Monitoring Tool

A Python-based log analyzer for detecting SSH brute-force attacks in real-time with Discord alerts and threat intelligence integration.

##  Project Overview

This tool monitors SSH authentication logs and automatically detects potential brute-force attacks based on configurable rules. When suspicious activity is detected, it sends alerts to Discord and enriches the data with threat intelligence from AbuseIPDB.

##  Features

- **Real-time Log Monitoring**: Analyzes SSH logs for failed authentication attempts
- **Configurable Detection Rules**: Customize thresholds and time windows
- **Discord Integration**: Automatic alerts sent to Discord webhook
- **Threat Intelligence**: IP reputation lookup via AbuseIPDB API
- **Robust Error Handling**: Comprehensive validation and user-friendly error messages
- **Flexible Configuration**: YAML-based configuration system

##  Requirements

- Python 3.7+
- Required packages (install via `pip install -r requirements.txt`):
  - requests
  - PyYAML

##  Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd <your-directory>
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the Tool

Copy the example configuration file:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` and add your credentials:

```yaml
alerts:
  discord:
    enabled: true
    webhook_url: 'YOUR_ACTUAL_DISCORD_WEBHOOK_URL'

threat_intelligence:
  abuseipdb:
    enabled: true
    api_key: 'YOUR_ACTUAL_ABUSEIPDB_API_KEY'
```

### 4. Run the Analyzer

```bash
# Analyze a log file
python log_analyzer.py /var/log/auth.log

# Quiet mode (less verbose output)
python log_analyzer.py -q /var/log/auth.log

# Use sample log for testing
python log_analyzer.py sample_auth.log
```

##  Project Structure

```
.
├── log_analyzer.py           # Main application
├── config.yaml.example       # Configuration template
├── .gitignore               # Git ignore rules
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── sample_auth.log         # Sample log for testing
```

##  Configuration Options

### Detection Rules

```yaml
rules:
  - name: 'SSH Brute-Force Attack'
    enabled: true
    pattern: 'Failed password for'
    threshold: 5              # Number of attempts
    time_window_minutes: 1    # Within this time frame
```

### Alert Settings

- **Discord Webhook**: Enable/disable Discord notifications
- **Threat Intelligence**: Toggle AbuseIPDB lookups

##  Testing

Use the included sample logs to test the tool:

```bash
# Test with sample log
python log_analyzer.py sample_auth.log

# Test with sample that triggers alerts
python log_analyzer.py sample_auth2.log
```

##  Security Notes

- **Never commit `config.yaml`** - Contains sensitive credentials
- **Keep your webhook URL private** - Anyone with it can send messages
- **Rotate API keys regularly** - Follow security best practices
- **Use `.gitignore`** - Already configured to exclude sensitive files

##  Sample Output

```
=== Starting log analysis ===
File: sample_auth.log
Rule: 'SSH Brute-Force Attack'
Threshold: 5 attempts in 1 min

!!! ALERT: 183.89.65.173 exceeded threshold (6 attempts) !!!

✓ Alert sent to Discord

=== Analysis complete ===
Lines processed: 11
Lines matched: 7
Unique IPs: 2
Alerts sent: 1
```

##  Troubleshooting

### "Can't find config file"
- Make sure `config.yaml` exists (copy from `config.yaml.example`)

### "No read permission"
- Try running with `sudo` for system log files

### "Processed X lines but found 0 matches"
- Check if you're using the correct log file
- Common SSH logs: `/var/log/auth.log` or `/var/log/secure`

##  How to Get API Keys

### Discord Webhook
1. Go to Discord Server Settings → Integrations → Webhooks
2. Create a new webhook
3. Copy the webhook URL

### AbuseIPDB API Key
1. Register at [AbuseIPDB](https://www.abuseipdb.com/)
2. Go to Account → API
3. Generate a new API key

##  Learning Outcomes

This project demonstrates:
- Log file parsing with regular expressions
- Real-time threat detection algorithms
- External API integration
- Error handling and validation
- Configuration management
- Security best practices

##  License

This is a capstone project for educational purposes.

##  Author

Created as part of The Cyber Instructor Community Coding Bootcamp - October 2025

---