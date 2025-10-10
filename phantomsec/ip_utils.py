"""
Helper functions for working with IP addresses
Includes geolocation lookup, threat intel, etc.

Note: Some features require API keys which aren't implemented yet
"""

import socket
import re
from typing import Optional, Dict
import json


class IPUtils:
    """
    Utility functions for IP address analysis
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize IP utils
        
        Args:
            config: Configuration dict with API keys if needed
        """
        self.config = config or {}
        self.cache = {}  # Simple cache to avoid repeat lookups
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if string is a valid IPv4 address
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid, False otherwise
        """
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not pattern.match(ip):
            return False
        
        # Check each octet is 0-255
        parts = ip.split('.')
        for part in parts:
            if int(part) > 255:
                return False
        
        return True
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP is in private range
        
        Private ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        """
        if not IPUtils.is_valid_ip(ip):
            return False
        
        parts = list(map(int, ip.split('.')))
        
        # Check private ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:  # localhost
            return True
        
        return False
    
    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup on IP
        
        Args:
            ip: IP address
            
        Returns:
            Hostname if found, None otherwise
        """
        # Check cache first
        if ip in self.cache:
            return self.cache[ip].get('hostname')
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.cache[ip] = {'hostname': hostname}
            return hostname
        except (socket.herror, socket.gaierror):
            return None
        except Exception as e:
            print(f"[DEBUG] Reverse DNS error for {ip}: {e}")
            return None
    
    def get_geolocation(self, ip: str) -> Optional[Dict]:
        """
        Get geolocation for IP address
        
        This would use an API like ip-api.com or ipinfo.io
        Not fully implemented - would need API integration
        
        Args:
            ip: IP address
            
        Returns:
            Dict with location info or None
        """
        # Check if we have API key configured
        if not self.config.get('use_ip_geolocation'):
            return None
        
        # Check cache
        if ip in self.cache and 'geo' in self.cache[ip]:
            return self.cache[ip]['geo']
        
        # TODO: Implement actual API call
        # For now just return None
        # Would look something like:
        # import requests
        # response = requests.get(f'http://ip-api.com/json/{ip}')
        # data = response.json()
        
        print(f"[DEBUG] Geolocation lookup not implemented for {ip}")
        return None
    
    def check_threat_intel(self, ip: str) -> Dict:
        """
        Check if IP is known malicious using threat intelligence
        
        Would integrate with services like AbuseIPDB, VirusTotal, etc.
        Not fully implemented yet
        
        Args:
            ip: IP address to check
            
        Returns:
            Dict with threat info
        """
        if not self.config.get('use_threat_intel'):
            return {'is_malicious': False, 'confidence': 0}
        
        # Check cache
        if ip in self.cache and 'threat' in self.cache[ip]:
            return self.cache[ip]['threat']
        
        # TODO: Implement actual API integration
        # Would use services like:
        # - AbuseIPDB
        # - VirusTotal
        # - AlienVault OTX
        
        print(f"[DEBUG] Threat intel lookup not implemented for {ip}")
        return {'is_malicious': False, 'confidence': 0, 'reason': 'Not checked'}
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """
        Convert IP address to integer for range comparisons
        
        Useful for checking if IP is in a CIDR range
        """
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])
    
    @staticmethod
    def int_to_ip(num: int) -> str:
        """
        Convert integer back to IP address
        """
        return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}." \
               f"{(num >> 8) & 0xFF}.{num & 0xFF}"
    
    def is_in_blacklist(self, ip: str) -> bool:
        """
        Check if IP is in configured blacklist
        """
        blacklist = self.config.get('ip_blacklist', [])
        return ip in blacklist
    
    def is_in_whitelist(self, ip: str) -> bool:
        """
        Check if IP is in configured whitelist
        """
        whitelist = self.config.get('ip_whitelist', [])
        return ip in whitelist
    
    def get_ip_info_summary(self, ip: str) -> Dict:
        """
        Get comprehensive info about an IP
        
        Combines multiple lookups into one summary
        """
        info = {
            'ip': ip,
            'is_valid': self.is_valid_ip(ip),
            'is_private': self.is_private_ip(ip),
            'hostname': self.get_reverse_dns(ip),
            'is_blacklisted': self.is_in_blacklist(ip),
            'is_whitelisted': self.is_in_whitelist(ip),
        }
        
        # Add geolocation if enabled
        geo = self.get_geolocation(ip)
        if geo:
            info['geolocation'] = geo
        
        # Add threat intel if enabled
        threat = self.check_threat_intel(ip)
        if threat:
            info['threat_intel'] = threat
        
        return info