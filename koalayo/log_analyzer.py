import re
import requests
import yaml
import argparse
from datetime import datetime, timedelta
import time
from collections import defaultdict
import os

# global state 
failed_attempts = defaultdict(list)
alerted_ips = set()

def load_config(path='config.yaml'):
    """Loads configuration from a YAML file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            print(f"✓ Config loaded from {path}")
            return config
    except FileNotFoundError:
        print(f"✗ Can't find config file: {path}")
        print("  Make sure config.yaml exists in the same directory as this script")
        return None
    except yaml.YAMLError as e:
        print(f"✗ YAML parsing failed: {e}")
        print("  Check your config.yaml syntax - maybe a tab/space issue?")
        return None

def validate_config(config):
    """Quick sanity check on config values"""
    if not config:
        return False
    
    # check if rules exist
    if 'rules' not in config or not config['rules']:
        print("✗ No rules defined in config")
        return False
    
    rule = config['rules'][0]
    required = ['name', 'pattern', 'threshold', 'time_window_minutes']
    missing = [f for f in required if f not in rule]
    
    if missing:
        print(f"✗ Rule missing required fields: {', '.join(missing)}")
        return False
    
    # warn if threshold seems weird
    if rule['threshold'] < 1:
        print("⚠ Warning: threshold < 1 doesn't make sense, using 1")
        rule['threshold'] = 1
    
    if rule['time_window_minutes'] < 1:
        print("⚠ Warning: time window < 1 min is too aggressive, using 1")
        rule['time_window_minutes'] = 1
    
    return True

def check_log_file(path):
    """Pre-flight checks on the log file"""
    if not os.path.exists(path):
        print(f"✗ Log file doesn't exist: {path}")
        print("  Did you specify the right path?")
        return False
    
    if not os.path.isfile(path):
        print(f"✗ Path is not a file: {path}")
        return False
    
    # check if file is readable
    if not os.access(path, os.R_OK):
        print(f"✗ No read permission for: {path}")
        print("  Try running with sudo or check file permissions")
        return False
    
    # warn if file is empty
    if os.path.getsize(path) == 0:
        print(f"⚠ Warning: Log file is empty: {path}")
        print("  This is probably not what you want...")
        return True  # not fatal, just weird
    
    
    return True

def parse_log_line(line, pattern):
    # check if line matches our pattern
    if not re.search(pattern, line):
        return None
    
    # extract timestamp and IP
    match = re.search(r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).* from ([\d\.]+)', line)
    if not match:
        return None
        
    log_time_str = match.group(1)
    ip_address = match.group(2)
    
    # assume current year since logs don't include it
    current_year = datetime.now().year
    try:
        log_time = datetime.strptime(f"{current_year} {log_time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        # sometimes log formats are weird
        return None
    
    return log_time, ip_address

def send_discord_alert(webhook_url, message):
    """Sends an alert message to a Discord webhook."""
    if not webhook_url:
        print("No webhook URL configured, skipping alert")
        return
    
    try:
        resp = requests.post(webhook_url, json={"content": message}, timeout=10)
        resp.raise_for_status()
        print("✓ Alert sent to Discord")
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to send Discord alert: {e}")

def query_abuseipdb(ip_address, api_key):
    """Queries AbuseIPDB for IP reputation data."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()['data']
        
        return {
            'score': data.get('abuseConfidenceScore', 'N/A'),
            'country': data.get('countryCode', 'N/A'),
            'isp': data.get('isp', 'N/A')
        }
    except requests.exceptions.RequestException as e:
        print(f"⚠ AbuseIPDB query failed: {e}")
        return None

def main():
    """Main function to run the log analyzer."""
    # setup arg parsing
    parser = argparse.ArgumentParser(
        description="SSH log analyzer for detecting brute-force attacks",
        epilog="Example: python log_analyzer.py /var/log/auth.log"
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("-q", "--quiet", action="store_true", 
                       help="Suppress line-by-line output")
    args = parser.parse_args()
    
    log_file_path = args.logfile
    quiet_mode = args.quiet

    # load and validate config
    config = load_config()
    if not config or not validate_config(config):
        print("\n✗ Config validation failed, exiting")
        return
    
    # check log file before we start
    if not check_log_file(log_file_path):
        print("\n✗ Log file check failed, exiting")
        return

    # parse config
    discord_webhook_url = config.get('alerts', {}).get('discord', {}).get('webhook_url')
    ti_config = config.get('threat_intelligence', {}).get('abuseipdb', {})
    
    rule = config['rules'][0]  # support multiple rules
    failure_threshold = rule['threshold']
    time_window = timedelta(minutes=rule['time_window_minutes'])
    log_pattern = rule['pattern']

    # debug counters
    lines_processed = 0
    lines_matched = 0
    CHECK_INTERVAL = 50
    
    print(f"\n=== Starting log analysis ===")
    print(f"File: {log_file_path}")
    print(f"Rule: '{rule['name']}'")
    print(f"Threshold: {failure_threshold} attempts in {rule['time_window_minutes']} min\n")

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                lines_processed += 1
                
                if not quiet_mode:
                    print(f">> {line.strip()}")
                    time.sleep(0.1)  # slow down for demo

                result = parse_log_line(line, log_pattern)
                if not result:
                    continue
                
                lines_matched += 1
                current_time, ip = result
                failed_attempts[ip].append(current_time)
                
                # cleanup old attempts
                relevant = [t for t in failed_attempts[ip] if current_time - t < time_window]
                failed_attempts[ip] = relevant
                
                # check threshold
                if len(relevant) > failure_threshold and ip not in alerted_ips:
                    print(f"\n!!! ALERT: {ip} exceeded threshold ({len(relevant)} attempts) !!!\n")
                    
                    ip_info = None
                    if ti_config.get('enabled') and ti_config.get('api_key'):
                        ip_info = query_abuseipdb(ip, ti_config['api_key'])

                    # build alert
                    msg = f"🚨 **Security Alert: `{rule['name']}` Detected!**\n"
                    msg += f"> **Source IP**: `{ip}`\n"
                    
                    if ip_info:
                        msg += f"> **Country**: {ip_info['country']}\n"
                        msg += f"> **ISP**: {ip_info['isp']}\n"
                        msg += f"> **Abuse Score**: **{ip_info['score']}/100**\n"
                    
                    msg += f"> **Details**: `{len(relevant)}` failed attempts in `{rule['time_window_minutes']}` min\n"
                    msg += f"> **Last Attempt**: `{current_time}`"
                    
                    if config.get('alerts', {}).get('discord', {}).get('enabled'):
                        send_discord_alert(discord_webhook_url, msg)
                    
                    alerted_ips.add(ip)
                
                elif ip in alerted_ips and len(relevant) <= failure_threshold:
                    alerted_ips.remove(ip)
                
                # periodic check - maybe wrong log file?
                if lines_processed % CHECK_INTERVAL == 0 and lines_matched == 0:
                    print(f"\n⚠ Processed {lines_processed} lines but found 0 matches")
                    print(f"  Are you sure this log contains '{log_pattern}'?")
                    print(f"  Common SSH logs: /var/log/auth.log or /var/log/secure\n")

    except FileNotFoundError:
        print(f"✗ Log file disappeared: {log_file_path}")
    except UnicodeDecodeError:
        print(f"✗ Can't decode file - might be binary or wrong encoding")
        print(f"  Try: file {log_file_path}")
    except PermissionError:
        print(f"✗ Permission denied while reading")
        print("  Try running with sudo")
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    

    print("\n=== Analysis complete ===")
    print(f"Lines processed: {lines_processed}")
    print(f"Lines matched: {lines_matched}")
    if lines_matched > 0:
        print(f"Unique IPs: {len(failed_attempts)}")
        print(f"Alerts sent: {len(alerted_ips)}")

if __name__ == "__main__":
    main()