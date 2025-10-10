"""
Sends alerts when critical threats are detected
Currently supports: console output, file logging
TODO: Add email, Slack, webhook support?
Dependencies: Only standard library (datetime, json)
"""

from datetime import datetime
from typing import Dict, List
import json


class AlertSystem:
    """
    Handles alerting for security threats
    """
    
    def __init__(self, config: Dict):
        """
        Initialize alert system
        
        Args:
            config: Configuration with alert settings
        """
        self.config = config
        self.alert_methods = config.get('alert_methods', ['console', 'file'])
        self.alert_file = config.get('alert_log_file', 'alerts.log')
        
        # Email settings (not implemented yet but good to have)
        self.email_enabled = config.get('email_alerts', False)
        self.email_recipient = config.get('email_recipient', None)
    
    def send_alerts(self, threats: Dict):
        """
        Send alerts based on detected threats
        
        Args:
            threats: Dictionary of threats from ThreatDetector
        """
        if not threats.get('critical'):
            return  # only alert on critical stuff
        
        alert_message = self._build_alert_message(threats)
        
        # Send via different methods
        if 'console' in self.alert_methods:
            self._send_console_alert(alert_message)
        
        if 'file' in self.alert_methods:
            self._send_file_alert(alert_message)
        
        # Placeholder for future methods
        if 'email' in self.alert_methods and self.email_enabled:
            self._send_email_alert(alert_message)
    
    def _build_alert_message(self, threats: Dict) -> str:
        """
        Build a formatted alert message
        """
        lines = []
        lines.append("="*60)
        lines.append("!!! SECURITY ALERT !!!")
        lines.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("="*60)
        lines.append("")
        
        critical_threats = threats.get('critical', [])
        lines.append(f"Critical threats detected: {len(critical_threats)}")
        lines.append("")
        
        # List the critical IPs
        for i, threat in enumerate(critical_threats, 1):
            lines.append(f"{i}. IP: {threat['ip']}")
            lines.append(f"   Threat types: {', '.join(threat['threat_types'])}")
            lines.append(f"   Severity: CRITICAL")
            lines.append("")
        
        lines.append("ACTION REQUIRED: Review these threats immediately")
        lines.append("="*60)
        
        return '\n'.join(lines)
    
    def _send_console_alert(self, message: str):
        """
        Print alert to console with some color/emphasis
        """
        # ANSI color codes for terminal (might not work on all systems)
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'
        
        try:
            print(f"\n{RED}{BOLD}{message}{END}\n")
        except:
            # Fallback if colors don't work
            print(f"\n{message}\n")
    
    def _send_file_alert(self, message: str):
        """
        Append alert to a log file
        """
        try:
            with open(self.alert_file, 'a') as f:
                f.write(message + '\n\n')
            print(f"[+] Alert logged to: {self.alert_file}")
        except Exception as e:
            print(f"[WARNING] Could not write to alert file: {e}")
    
    def _send_email_alert(self, message: str):
        """
        Send email alert (not implemented yet)
        
        Would use smtplib or an email service API
        """
        print("[WARNING] Email alerts not implemented yet")
        # TODO: Implement email sending
        # import smtplib
        # from email.mime.text import MIMEText
        # ...
        pass
    
    def log_threat_summary(self, threats: Dict, output_file: str = 'threat_summary.json'):
        """
        Save a JSON summary of all threats for later analysis
        This could be useful for trend analysis
        """
        summary = {
            'timestamp': datetime.now().isoformat(),
            'threat_counts': {
                'critical': len(threats.get('critical', [])),
                'brute_force': len(threats.get('brute_force', [])),
                'suspicious_ips': len(threats.get('suspicious_ips', [])),
                'port_scans': len(threats.get('port_scans', [])),
                'injections': len(threats.get('injections', []))
            },
            'critical_ips': [t['ip'] for t in threats.get('critical', [])],
            'all_threats': threats  # full data
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            print(f"[+] Threat summary saved to: {output_file}")
        except Exception as e:
            print(f"[WARNING] Could not save threat summary: {e}")


# Quick test
if __name__ == '__main__':
    print("Testing alert_system.py...")
    
    # Create dummy config
    config = {
        'alert_methods': ['console', 'file'],
        'alert_log_file': 'test_alerts.log'
    }
    
    # Create dummy threats with critical
    threats = {
        'critical': [
            {'ip': '1.2.3.4', 'threat_types': ['brute_force', 'injection'], 'threat_count': 2}
        ],
        'brute_force': [],
        'suspicious_ips': [],
        'port_scans': [],
        'injections': []
    }
    
    alert_system = AlertSystem(config)
    alert_system.send_alerts(threats)
    
    import os
    if os.path.exists('test_alerts.log'):
        print("✓ Alert file created successfully")
        os.remove('test_alerts.log')
    else:
        print("✗ Alert file creation failed")