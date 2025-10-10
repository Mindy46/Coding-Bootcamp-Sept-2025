"""
This is where the magic happens - we analyze parsed logs
and detect various security threats like brute force, port scans, etc.
Dependencies: Only standard library (datetime, collections, re)
TODO: Maybe add machine learning later? That would be cool
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict
import re


class ThreatDetector:
    """
    Detects various security threats in log data
    """
    
    def __init__(self, config: Dict):
        """
        Initialize detector with configuration
        
        Args:
            config: Configuration dictionary with thresholds and settings
        """
        self.config = config
        
        # Get thresholds from config (with defaults)
        self.brute_force_threshold = config.get('brute_force_threshold', 5)
        self.brute_force_window = config.get('brute_force_window_minutes', 10)
        self.port_scan_threshold = config.get('port_scan_threshold', 10)
        
        # Known malicious patterns for injection detection
        self.injection_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL injection
            r"(<script|<iframe|javascript:|onerror=)",  # XSS
            r"(\.\./|\.\.\\)",  # Path traversal
            r"(union.*select|concat\(|load_file)",  # SQL injection advanced
        ]
        
        # Compile patterns for better performance (learned this the hard way)
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.injection_patterns]
    
    def analyze(self, log_entries: List[Dict]) -> Dict:
        """
        Main analysis function - runs all detection algorithms
        
        Returns a dictionary with different threat categories
        """
        threats = {
            'brute_force': [],
            'suspicious_ips': [],
            'port_scans': [],
            'injections': [],
            'critical': []
        }
        
        # Run different detection algorithms
        print("  [*] Checking for brute force attacks...")
        threats['brute_force'] = self.detect_brute_force(log_entries)
        
        print("  [*] Analyzing IP behavior...")
        threats['suspicious_ips'] = self.detect_suspicious_ips(log_entries)
        
        print("  [*] Looking for port scan activity...")
        threats['port_scans'] = self.detect_port_scans(log_entries)
        
        print("  [*] Scanning for injection attempts...")
        threats['injections'] = self.detect_injections(log_entries)
        
        # Identify critical threats (intersection of multiple threat types)
        threats['critical'] = self._identify_critical_threats(threats)
        
        return threats
    
    def detect_brute_force(self, entries: List[Dict]) -> List[Dict]:
        """
        Detect brute force login attempts
        
        Logic: If an IP has multiple failed login attempts within a time window,
        flag it as potential brute force
        """
        brute_force_attacks = []
        
        # Group failed attempts by IP
        failed_attempts = defaultdict(list)
        
        for entry in entries:
            # Check web logs for 401 status codes
            if entry.get('type') == 'web' and entry.get('status_code') == 401:
                failed_attempts[entry['ip']].append(entry)
            
            # Check auth logs for failed attempts
            elif entry.get('type') == 'auth' and entry.get('is_failure'):
                ip = entry.get('ip')
                if ip:
                    failed_attempts[ip].append(entry)
        
        # Analyze each IP's failed attempts
        for ip, attempts in failed_attempts.items():
            if len(attempts) < self.brute_force_threshold:
                continue
            
            # Sort by timestamp to check time windows
            attempts.sort(key=lambda x: x['timestamp'])
            
            # Sliding window approach to find clusters of failures
            for i in range(len(attempts)):
                window_end = attempts[i]['timestamp'] + timedelta(minutes=self.brute_force_window)
                
                # Count attempts in this window
                window_attempts = [a for a in attempts 
                                   if attempts[i]['timestamp'] <= a['timestamp'] <= window_end]
                
                if len(window_attempts) >= self.brute_force_threshold:
                    brute_force_attacks.append({
                        'ip': ip,
                        'attempt_count': len(window_attempts),
                        'first_attempt': attempts[i]['timestamp'],
                        'last_attempt': window_attempts[-1]['timestamp'],
                        'severity': 'high' if len(window_attempts) > 10 else 'medium',
                        'details': window_attempts[:5]  # Store first 5 for reference
                    })
                    break  # Found one, move to next IP
        
        return brute_force_attacks
    
    def detect_suspicious_ips(self, entries: List[Dict]) -> List[Dict]:
        """
        Detect suspicious IP behavior patterns
        
        Looks for:
        - IPs accessing unusual endpoints
        - High request rates
        - Mixed success/failure patterns
        """
        suspicious = []
        ip_activity = defaultdict(lambda: {
            'total_requests': 0,
            'failed_requests': 0,
            'unique_paths': set(),
            'suspicious_paths': 0,
            'timestamps': []
        })
        
        # Suspicious path patterns
        suspicious_path_keywords = ['admin', 'wp-admin', '.env', 'config', 'phpMyAdmin', 
                                     'backup', '.git', 'shell', 'cmd']
        
        # Aggregate activity by IP
        for entry in entries:
            ip = entry.get('ip') or entry.get('src_ip')
            if not ip:
                continue
            
            activity = ip_activity[ip]
            activity['total_requests'] += 1
            activity['timestamps'].append(entry.get('timestamp'))
            
            # Track failures
            if entry.get('status_code') in [401, 403, 404]:
                activity['failed_requests'] += 1
            
            # Track paths accessed
            if 'path' in entry:
                path = entry['path']
                activity['unique_paths'].add(path)
                
                # Check for suspicious paths
                if any(keyword in path.lower() for keyword in suspicious_path_keywords):
                    activity['suspicious_paths'] += 1
        
        # Analyze each IP's behavior
        for ip, activity in ip_activity.items():
            suspicion_score = 0
            reasons = []
            
            # High failure rate
            if activity['total_requests'] > 5:
                failure_rate = activity['failed_requests'] / activity['total_requests']
                if failure_rate > 0.7:
                    suspicion_score += 3
                    reasons.append(f"High failure rate: {failure_rate:.1%}")
            
            # Accessing many different paths (reconnaissance)
            if len(activity['unique_paths']) > 20:
                suspicion_score += 2
                reasons.append(f"Accessed {len(activity['unique_paths'])} unique paths")
            
            # Accessing suspicious paths
            if activity['suspicious_paths'] > 0:
                suspicion_score += 4
                reasons.append(f"Accessed {activity['suspicious_paths']} suspicious paths")
            
            # High request rate (simple check)
            if len(activity['timestamps']) > 2:
                # Calculate requests per minute
                time_span = (max(activity['timestamps']) - min(activity['timestamps'])).total_seconds() / 60
                if time_span > 0:
                    rpm = activity['total_requests'] / time_span
                    if rpm > 30:  # More than 30 requests/minute
                        suspicion_score += 2
                        reasons.append(f"High request rate: {rpm:.1f} req/min")
            
            # If suspicious enough, add to results
            if suspicion_score >= 4:
                suspicious.append({
                    'ip': ip,
                    'suspicion_score': suspicion_score,
                    'total_requests': activity['total_requests'],
                    'failed_requests': activity['failed_requests'],
                    'unique_paths': len(activity['unique_paths']),
                    'reasons': reasons,
                    'severity': 'high' if suspicion_score >= 7 else 'medium'
                })
        
        return suspicious
    
    def detect_port_scans(self, entries: List[Dict]) -> List[Dict]:
        """
        Detect port scanning activity in firewall logs
        
        A port scan is when an IP tries to connect to many different ports
        in a short time period
        """
        port_scans = []
        
        # Only relevant for firewall logs
        firewall_entries = [e for e in entries if e.get('type') == 'firewall']
        
        if not firewall_entries:
            return port_scans
        
        # Group by source IP
        ip_port_activity = defaultdict(lambda: {
            'ports': set(),
            'timestamps': [],
            'blocked_count': 0
        })
        
        for entry in firewall_entries:
            src_ip = entry['src_ip']
            dst_port = entry['dst_port']
            
            activity = ip_port_activity[src_ip]
            activity['ports'].add(dst_port)
            activity['timestamps'].append(entry['timestamp'])
            
            if entry['action'] in ['DENY', 'DROP']:
                activity['blocked_count'] += 1
        
        # Analyze for port scanning behavior
        for ip, activity in ip_port_activity.items():
            if len(activity['ports']) >= self.port_scan_threshold:
                # Calculate time span
                if len(activity['timestamps']) > 1:
                    time_span = (max(activity['timestamps']) - min(activity['timestamps'])).total_seconds()
                else:
                    time_span = 0
                
                port_scans.append({
                    'ip': ip,
                    'ports_scanned': len(activity['ports']),
                    'blocked_attempts': activity['blocked_count'],
                    'time_span_seconds': time_span,
                    'severity': 'high',
                    'ports': sorted(list(activity['ports']))[:20]  # First 20 ports
                })
        
        return port_scans
    
    def detect_injections(self, entries: List[Dict]) -> List[Dict]:
        """
        Detect injection attempts (SQL injection, XSS, etc.)
        
        This looks for malicious patterns in request paths and parameters
        """
        injection_attempts = []
        
        for entry in entries:
            if entry.get('type') != 'web':
                continue
            
            path = entry.get('path', '')
            
            # Check path against injection patterns
            for i, pattern in enumerate(self.compiled_patterns):
                if pattern.search(path):
                    injection_attempts.append({
                        'ip': entry['ip'],
                        'timestamp': entry['timestamp'],
                        'path': path,
                        'pattern_matched': self.injection_patterns[i],
                        'injection_type': self._classify_injection_type(i),
                        'severity': 'high',
                        'status_code': entry.get('status_code')
                    })
                    break  # One match is enough per entry
        
        return injection_attempts
    
    def _classify_injection_type(self, pattern_index: int) -> str:
        """Helper to classify injection type based on pattern index"""
        types = ['SQL Injection', 'XSS', 'Path Traversal', 'SQL Injection']
        return types[pattern_index] if pattern_index < len(types) else 'Unknown'
    
    def _identify_critical_threats(self, threats: Dict) -> List[Dict]:
        """
        Identify critical threats that appear in multiple categories
        
        For example, an IP doing both brute force AND port scanning is extra suspicious
        """
        critical = []
        
        # Get all IPs from different threat types
        brute_force_ips = {t['ip'] for t in threats['brute_force']}
        suspicious_ips = {t['ip'] for t in threats['suspicious_ips']}
        port_scan_ips = {t['ip'] for t in threats['port_scans']}
        injection_ips = {t['ip'] for t in threats['injections']}
        
        # Find IPs appearing in multiple categories
        all_ips = brute_force_ips | suspicious_ips | port_scan_ips | injection_ips
        
        for ip in all_ips:
            threat_types = []
            if ip in brute_force_ips:
                threat_types.append('brute_force')
            if ip in suspicious_ips:
                threat_types.append('suspicious_activity')
            if ip in port_scan_ips:
                threat_types.append('port_scan')
            if ip in injection_ips:
                threat_types.append('injection')
            
            # If IP appears in 2+ categories, it's critical
            if len(threat_types) >= 2:
                critical.append({
                    'ip': ip,
                    'threat_types': threat_types,
                    'threat_count': len(threat_types),
                    'severity': 'critical'
                })
        
        return critical


# Quick test
if __name__ == '__main__':
    print("Testing threat_detector.py...")
    from config_loader import ConfigLoader
    
    config = ConfigLoader.get_default_config()
    detector = ThreatDetector(config)
    
    # Create fake brute force pattern
    fake_entries = []
    for i in range(10):
        fake_entries.append({
            'type': 'web',
            'ip': '1.2.3.4',
            'timestamp': datetime.now(),
            'status_code': 401,
            'path': '/login'
        })
    
    threats = detector.analyze(fake_entries)
    if threats['brute_force']:
        print(f"✓ Detected {len(threats['brute_force'])} brute force attack(s)")
    else:
        print("✗ Detection failed")