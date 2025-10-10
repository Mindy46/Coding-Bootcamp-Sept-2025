#!/usr/bin/env python3
"""
Main entry point for the Threat Detection System
This script ties everything together.
"""

import sys
import os
from datetime import datetime
import argparse

# Import our custom modules
from log_parser import LogParser
from threat_detector import ThreatDetector
from report_generator import ReportGenerator
from alert_system import AlertSystem
from config_loader import ConfigLoader

# Yeah I know global variables aren't ideal but this makes it easier
CONFIG = None
VERBOSE = False


def print_banner():
    """
    Prints a cool ASCII banner because why not
    """
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║     SECURE LOG ANALYZER & THREAT DETECTION        ║
    ║              Version 1.0 - October 2025           ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(banner)


def setup_argparse():
    """Setup command line arguments"""
    parser = argparse.ArgumentParser(
        description='Analyze logs for security threats',
        epilog='Example: python main.py --log access.log --config config.json'
    )
    
    parser.add_argument(
        '--log', 
        required=True,
        help='Path to the log file to analyze'
    )
    
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    parser.add_argument(
        '--output',
        default='report.txt',
        help='Output report filename'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--format',
        choices=['apache', 'nginx', 'firewall', 'auth'],
        default='apache',
        help='Log format type'
    )
    
    return parser


def main():
    """
    Main function - orchestrates the whole analysis process
    """
    global CONFIG, VERBOSE
    
    print_banner()
    
    # Parse command line args
    parser = setup_argparse()
    args = parser.parse_args()
    
    VERBOSE = args.verbose
    
    if VERBOSE:
        print(f"[*] Starting analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Log file: {args.log}")
        print(f"[*] Config file: {args.config}")
    
    # Check if log file exists (basic error handling)
    if not os.path.exists(args.log):
        print(f"[ERROR] Log file not found: {args.log}")
        sys.exit(1)
    
    # Load configuration
    try:
        config_loader = ConfigLoader(args.config)
        CONFIG = config_loader.load_config()
        if VERBOSE:
            print("[+] Configuration loaded successfully")
    except Exception as e:
        print(f"[WARNING] Could not load config: {e}")
        print("[*] Using default configuration...")
        CONFIG = ConfigLoader.get_default_config()
    
    # Initialize components
    print("\n[*] Initializing log parser...")
    parser = LogParser(args.log, log_format=args.format)
    
    print("[*] Parsing log entries...")
    log_entries = parser.parse_logs()
    
    if not log_entries:
        print("[!] No log entries found or parsed. Exiting.")
        sys.exit(0)
    
    print(f"[+] Successfully parsed {len(log_entries)} log entries")
    
    # Run threat detection
    print("\n[*] Running threat detection algorithms...")
    detector = ThreatDetector(CONFIG)
    threats = detector.analyze(log_entries)
    
    # Generate report
    print("[*] Generating security report...")
    report_gen = ReportGenerator(args.output)
    report_gen.generate_report(threats, log_entries)
    
    print(f"[+] Report saved to: {args.output}")
    
    # Send alerts if there are critical threats
    if threats.get('critical', []):
        print("\n[!] CRITICAL THREATS DETECTED!")
        alert_system = AlertSystem(CONFIG)
        alert_system.send_alerts(threats)
    
    # Print summary
    print("\n" + "="*50)
    print("ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total log entries analyzed: {len(log_entries)}")
    print(f"Brute force attempts detected: {len(threats.get('brute_force', []))}")
    print(f"Suspicious IPs: {len(threats.get('suspicious_ips', []))}")
    print(f"Port scan attempts: {len(threats.get('port_scans', []))}")
    print(f"Injection attempts: {len(threats.get('injections', []))}")
    print("="*50)
    
    if VERBOSE:
        print(f"\n[*] Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n[✓] Done!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        if VERBOSE:
            import traceback
            traceback.print_exc()
        sys.exit(1)