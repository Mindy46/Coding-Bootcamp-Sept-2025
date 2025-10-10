"""
Handles parsing of different log formats
Supports multiple formats like Apache, Nginx, etc.
Dependencies: None (only standard library)
"""

import re
from datetime import datetime
from typing import List, Dict, Optional


class LogParser:
    """
    Parses various log file formats and extracts relevant information
    """
    
    def __init__(self, log_file_path: str, log_format: str = 'apache'):
        """
        Initialize the parser
        
        Args:
            log_file_path: Path to the log file
            log_format: Type of log format (apache, nginx, firewall, auth)
        """
        self.log_file_path = log_file_path
        self.log_format = log_format.lower()
        
        # Regex patterns for different log formats
        # Apache/Nginx combined log format
        self.apache_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<size>\d+|-)'
        )
        
        # Auth log pattern (like /var/log/auth.log)
        self.auth_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<host>\S+) '
            r'(?P<process>\S+): (?P<message>.*)'
        )
        
        # Firewall log pattern (simplified)
        self.firewall_pattern = re.compile(
            r'(?P<timestamp>[\d\-\: ]+) (?P<action>ACCEPT|DENY|DROP) '
            r'(?P<protocol>\w+) (?P<src_ip>[\d\.]+):(?P<src_port>\d+) '
            r'-> (?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
        )
    
    def parse_logs(self) -> List[Dict]:
        """
        Main parsing function - reads file and parses each line
        
        Returns:
            List of dictionaries containing parsed log entries
        """
        parsed_entries = []
        line_count = 0
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_count += 1
                    line = line.strip()
                    
                    # Skip empty lines (duh)
                    if not line:
                        continue
                    
                    # Parse based on format
                    entry = None
                    if self.log_format == 'apache' or self.log_format == 'nginx':
                        entry = self._parse_apache_line(line)
                    elif self.log_format == 'auth':
                        entry = self._parse_auth_line(line)
                    elif self.log_format == 'firewall':
                        entry = self._parse_firewall_line(line)
                    else:
                        # Fallback - try apache format
                        entry = self._parse_apache_line(line)
                    
                    if entry:
                        entry['line_number'] = line_count
                        entry['raw_log'] = line
                        parsed_entries.append(entry)
        
        except FileNotFoundError:
            print(f"[ERROR] File not found: {self.log_file_path}")
            return []
        except Exception as e:
            print(f"[ERROR] Error reading log file: {e}")
            return []
        
        return parsed_entries
    
    def _parse_apache_line(self, line: str) -> Optional[Dict]:
        """
        Parse Apache/Nginx format log line
        
        Example: 192.168.1.100 - - [01/Oct/2025:10:30:45 +0000] "GET /login HTTP/1.1" 401 512
        """
        match = self.apache_pattern.match(line)
        if match:
            data = match.groupdict()
            
            # Try to parse timestamp
            try:
                # Apache format: 01/Oct/2025:10:30:45 +0000
                timestamp_str = data['timestamp'].split()[0]  # ignore timezone for now
                dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
            except:
                # If parsing fails just use current time (not ideal but whatever)
                dt = datetime.now()
            
            return {
                'type': 'web',
                'ip': data['ip'],
                'user': data['user'] if data['user'] != '-' else None,
                'timestamp': dt,
                'method': data['method'],
                'path': data['path'],
                'protocol': data['protocol'],
                'status_code': int(data['status']),
                'size': int(data['size']) if data['size'] != '-' else 0
            }
        
        return None
    
    def _parse_auth_line(self, line: str) -> Optional[Dict]:
        """
        Parse authentication log line
        
        Example: Oct  1 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100
        """
        match = self.auth_pattern.match(line)
        if match:
            data = match.groupdict()
            
            # Parse timestamp (this is tricky because it doesn't have year)
            try:
                # Add current year because auth logs don't include it
                current_year = datetime.now().year
                timestamp_str = f"{data['timestamp']} {current_year}"
                dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S %Y')
            except:
                dt = datetime.now()
            
            # Extract IP from message if present
            ip_match = re.search(r'from ([\d\.]+)', data['message'])
            ip = ip_match.group(1) if ip_match else None
            
            # Check for failed login
            is_failure = 'failed' in data['message'].lower() or 'invalid' in data['message'].lower()
            
            return {
                'type': 'auth',
                'timestamp': dt,
                'host': data['host'],
                'process': data['process'],
                'message': data['message'],
                'ip': ip,
                'is_failure': is_failure
            }
        
        return None
    
    def _parse_firewall_line(self, line: str) -> Optional[Dict]:
        """
        Parse firewall log line
        
        Example: 2025-10-01 10:30:45 DENY TCP 192.168.1.100:54321 -> 10.0.0.1:22
        """
        match = self.firewall_pattern.match(line)
        if match:
            data = match.groupdict()
            
            try:
                dt = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
            except:
                dt = datetime.now()
            
            return {
                'type': 'firewall',
                'timestamp': dt,
                'action': data['action'],
                'protocol': data['protocol'],
                'src_ip': data['src_ip'],
                'src_port': int(data['src_port']),
                'dst_ip': data['dst_ip'],
                'dst_port': int(data['dst_port'])
            }
        
        return None
    
    def get_unique_ips(self, entries: List[Dict]) -> set:
        """
        Extract all unique IP addresses from parsed entries
        
        This is useful for later analysis
        """
        ips = set()
        for entry in entries:
            if 'ip' in entry and entry['ip']:
                ips.add(entry['ip'])
            if 'src_ip' in entry:
                ips.add(entry['src_ip'])
        
        return ips
    
    def sort_by_timestamp(self, entries: List[Dict]) -> List[Dict]:
        """
        Sort log entries by timestamp
        Could use binary search later for efficiency
        """
        # using sorted() instead of .sort() to keep original list intact
        return sorted(entries, key=lambda x: x.get('timestamp', datetime.min))


# Quick test if run directly
if __name__ == '__main__':
    print("Testing log_parser.py...")
    
    # Create a small test file
    with open('test_log.txt', 'w') as f:
        f.write('192.168.1.1 - - [07/Oct/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234\n')
    
    parser = LogParser('test_log.txt', 'apache')
    entries = parser.parse_logs()
    
    if entries:
        print(f"✓ Parsed {len(entries)} entries")
        print(f"✓ First entry IP: {entries[0]['ip']}")
    else:
        print("✗ Parsing failed")
    
    import os
    os.remove('test_log.txt')